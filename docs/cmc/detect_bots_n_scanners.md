# CMC Module: `Detect_bots_n_scanners`

## Overview

`Detect_bots_n_scanners` is a KrakenWaf CMC (Custom Multi-signal Check) module
that inspects the request **`User-Agent`** header for known
scanner / crawler / offensive-tooling substrings (Nikto, sqlmap, Nmap,
masscan, Nessus, OpenVAS, gobuster, dirbuster, Arachni, Nuclei, wfuzz,
commix, Acunetix, Havij, …).

The module replaces the previously hard-wired scanner-UA block that lived
inside the WAF detection engine. All scanner-UA matching now flows through
this single CMC module — toggling `Detect_bots_n_scanners: false` in
`rules/cmc/config.yaml` disables scanner-UA blocking entirely, without
recompilation.

---

## Research Basis

The pattern set is loaded verbatim from `rules/user_agents/scanners.txt`,
which derives from the OWASP Core Rule Set
[`scanners-user-agents.data`](https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data)
data file. The shipped list contains ~78 substrings covering the
mainstream offensive tooling families used by penetration testers and
opportunistic bots.

Lines that are empty or start with `#` are skipped. Each remaining line is
matched **case-insensitively** as a substring against the verbatim
`User-Agent` header value.

---

## Detection Architecture

### Pattern file

Patterns live at `rules/user_agents/scanners.txt`. The file is consumed at
WAF startup; no per-request I/O.

### Startup compilation

When the module is enabled the WAF:

1. Reads every line from the file and filters out comments / empty lines.
2. Builds a case-insensitive `aho_corasick::AhoCorasick` multi-pattern
   automaton (leftmost-first match semantics) for the CPU fast path.
3. *(Vectorscan path)* When `--enable-vectorscan` is passed, a Hyperscan
   `BlockDatabase` is built from the regex-escaped, `CASELESS | SINGLEMATCH`
   patterns and used instead.

### Per-request cost

- Called from the early request phase in `WafEngine::inspect_early()`,
  immediately after IP filtering and rate-limit checks.
- One Aho-Corasick scan over the `User-Agent` value (typically ≤ 256 bytes).
  No allocation on the clean path.
- No effect at all when the module is disabled — the check is `Option::None`
  short-circuit in the CMC manager.

---

## Action Policy

The module honours the global `Untrust` level configured in
`rules/cmc/config.yaml`:

| `Untrust` | Action | Severity |
|---|---|---|
| `>= 60` (default) | **Block** — WAF returns 403; request never reaches the upstream | Low |
| `< 60` | **Silent log** — request is forwarded; a `tracing::warn!` is emitted | — |

When the module blocks, the finding is logged at **`Low`** severity to all
three security outputs (raw, JSONL, SQLite). Low is the appropriate level
because a scanner-UA match indicates **reconnaissance** — a bot or scanner
sweep against the protected origin — not a confirmed exploitation attempt.

The log includes the matched pattern (e.g. `pattern=nikto`), the full
`User-Agent` value as `request_payload`, and `engine=cmc`.

---

## Configuration

Enable the module by adding `Detect_bots_n_scanners: true` under `CMC-Rules`
in `rules/cmc/config.yaml`:

```yaml
global-options:
  Untrust: 60                       # >= 60 blocks; < 60 silent-logs

CMC-Rules:
  Detect_bots_n_scanners: true      # Set to false to disable
  # ...other modules
```

Set to `false` (or omit the key entirely) to disable the module — no
scanner-UA blocking will happen, regardless of the contents of
`scanners.txt`.

---

## Tuning the pattern set

`rules/user_agents/scanners.txt` is plain-text and read at startup. Add a
substring per line; comments use `#`. Reload via `kill -HUP <pid>` on Linux
or restart the WAF.

```
# rules/user_agents/scanners.txt
nikto
sqlmap
nmap
masscan
...
```

No regex syntax is supported — every line is matched as a literal byte
substring (case-insensitive). The Vectorscan path regex-escapes patterns
automatically, so writing `nmap (compatible)` works as a literal even with
the parentheses.

---

## CWE & References

- **CWE-200** — *Information Exposure*. Scanner traffic is a reconnaissance
  signal that, left unblocked, hands attackers a free probe channel.
- OWASP CRS data source:
  [`scanners-user-agents.data`](https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data)

---

## Related modules

- [`Detect_bad_artifacts`](detect_bad_artifacts.md) — URI-path based
  reconnaissance detection (dotfiles, `/proc`, framework configs).
- [`Anti_exposed_backup`](anti_exposed_backup.md) — backup-suffix URI
  exposure detection.

Together, these three modules form the CMC reconnaissance-detection layer.

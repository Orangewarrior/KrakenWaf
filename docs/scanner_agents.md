# Scanner / Crawler User-Agent Blocking

KrakenWAF ships a built-in scanner and crawler User-Agent blocklist,
derived from the **OWASP Core Rule Set** (CRS)
`scanners-user-agents.data` file.

> **Now owned by a dedicated CMC module.** Since the introduction of
> [`Detect_bots_n_scanners`](cmc/detect_bots_n_scanners.md), all scanner-UA
> blocking flows through that single CMC module — the file
> `rules/user_agents/scanners.txt` is consumed exclusively by it.
> The module is opt-in: set `Detect_bots_n_scanners: true` (or `false` to
> disable scanner-UA blocking entirely) under `CMC-Rules` in
> [`conf/filter.yaml`](../conf/filter.yaml). Blocking is also
> gated by the global `Untrust` level (≥ 60 blocks; < 60 silent-logs).
> See [`docs/cmc/detect_bots_n_scanners.md`](cmc/detect_bots_n_scanners.md)
> for the full action-policy matrix and severity rationale.

## How it works

On every incoming request — provided `Detect_bots_n_scanners` is enabled —
KrakenWAF extracts the `User-Agent` header and matches it
(case-insensitively) against every pattern in
`rules/user_agents/scanners.txt`.

- **Match** with `Untrust ≥ 60` → HTTP 403 + Alert logged at **Low** severity
  to JSON, raw, and SQLite (treated as a bot/scanner reconnaissance sweep).
- **Match** with `Untrust < 60` → request forwarded; a `tracing::warn!` line
  is emitted with the matched pattern.
- **No match** → request continues through the normal inspection pipeline.

The matching engine used depends on the build:

| Build | Engine |
|-------|--------|
| Default | Aho-Corasick (multi-pattern substring search) |
| `--features vectorscan-engine` + `--enable-vectorscan` | Vectorscan |

## Pattern file format

`rules/user_agents/scanners.txt`:

```
# Lines starting with # are comments.
# One substring per line — matched case-insensitively against User-Agent.
nikto
sqlmap
nmap
```

Patterns are substrings, not full regex. A pattern matches if it appears
anywhere inside the `User-Agent` value.

## Covered tools (v2.10.0)

The bundled list includes patterns for 78 tools, among them:

`arachni`, `burpsuite`, `commix`, `dirbuster`, `gobuster`, `havij`,
`masscan`, `metasploit`, `nessus`, `nikto`, `nmap`, `openvas`, `sqlmap`,
`wfuzz`, `zaproxy`, and many others.

## Customisation

Add or remove lines in `rules/user_agents/scanners.txt` to tune the list.
Changes take effect after a hot-reload (`kill -HUP <pid>` on Linux) or a
WAF restart.

To disable scanner-UA blocking entirely, set
`Detect_bots_n_scanners: false` under `CMC-Rules` in
`conf/filter.yaml` (or omit the key altogether). Removing or emptying
`scanners.txt` while leaving the module enabled is also tolerated — the
module logs a load error at startup and disables itself.

# KrakenWAF CMC Module Schema

KrakenWAF ships a set of opt-in, zero-allocation anomaly detectors modelled after
Deterministic Finite Automata (CMC).  Each module is a focused, single-pass Rust
scanner that operates on borrowed string slices — no heap allocation in the fast
path, no `unsafe` code, and no global state.  All modules are loaded at startup
from a single YAML manifest and are individually togglable without recompiling.

---

## Loading the CMC modules

Pass the config file path to `--cmc-load`:

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load rules/cmc/config.yaml
```

The default manifest lives at `rules/cmc/config.yaml`.  Each key under
`CMC-Rules` maps directly to a field on the internal `CmcConfig` struct;
unknown keys are silently ignored, absent keys default to `false`.

### `global-options`

A top-level `global-options` section controls parameters that apply across all
CMC modules:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `Untrust` | integer 0–100 | `60` | Global paranoia level.  Governs the 2-signal and 1-signal blocking thresholds in score-based detectors (currently `Java_deserialize_detect`). |

```yaml
# rules/cmc/config.yaml
global-options:
  Untrust: 60   # 0 = lenient; 100 = paranoid

CMC-Rules:
  SQLi_comments_detect: true
  Overflow_detect: true
  SSTI_detect: true
  SSI_injection_detect: true
  ESI_injection_detect: true
  CRLF_injection_detect: true
  Request_Smuggling_detect: true
  NOSQL_injection_detect: true
  XXE_attack_detect: true
  Anti_exposed_backup: true
  Anti_passwd_leak: true
  Java_deserialize_detect: true
```

---

## Module catalogue

| Key | CWE | Severity | Doc |
|-----|-----|----------|-----|
| `SQLi_comments_detect` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | High | [sqli_comments_detect.md](sqli_comments_detect.md) |
| `Overflow_detect` | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | High / Medium | [overflow_detect.md](overflow_detect.md) |
| `SSTI_detect` | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | High | [ssti_detect.md](ssti_detect.md) |
| `SSI_injection_detect` | [CWE-97](https://cwe.mitre.org/data/definitions/97.html) | High | [ssi_injection_detect.md](ssi_injection_detect.md) |
| `ESI_injection_detect` | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | High | [esi_injection_detect.md](esi_injection_detect.md) |
| `CRLF_injection_detect` | [CWE-93](https://cwe.mitre.org/data/definitions/93.html) | High | [crlf_injection_detect.md](crlf_injection_detect.md) |
| `Request_Smuggling_detect` | [CWE-444](https://cwe.mitre.org/data/definitions/444.html) | High | [request_smuggling_detect.md](request_smuggling_detect.md) |
| `NOSQL_injection_detect` | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | High | [nosql_injection_detect.md](nosql_injection_detect.md) |
| `XXE_attack_detect` | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | High | [xxe_attack_detect.md](xxe_attack_detect.md) |
| `Anti_exposed_backup` | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | Medium | [anti_exposed_backup.md](anti_exposed_backup.md) |
| `Anti_passwd_leak` | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | Critical | [anti_passwd_leak.md](anti_passwd_leak.md) |
| `Java_deserialize_detect` | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Critical | [java_deserialize_detect.md](java_deserialize_detect.md) |

---

## Module summaries

### [`SQLi_comments_detect`](sqli_comments_detect.md)

Counts `/* */`-style SQL block-comment pairs.  Attackers embed two or more pairs to
break up SQL keywords and defeat simple substring filters (`UN/**/ION SE/**/LECT`).
The detector increments a counter on every `/*` open token and fires when it reaches
two — a threshold that virtually never occurs in legitimate traffic but is essential
to every comment-evasion payload.

### [`Overflow_detect`](overflow_detect.md)

Two independent sub-detectors run in sequence:

**Shellcode recognition** — decodes escape sequences in any of the forms `\xNN`,
`%NN`, `0xNN`, or `\u00NN` to a raw byte slice, then scores the decoded bytes against
weighted opcode-cluster tables for x86-32, x86-64, and ARM/Thumb.  NOP sleds
(`0x90…`, ARM `00 00 a0 e1`, Thumb `c0 46`) are detected before the cluster check.
A cumulative score ≥ 3 fires the shellcode finding.

**Repeated-character flooding** — a single iterator pass counts consecutive identical
characters (threshold: 10), long digit runs (30), format specifiers `%n/%p/%s/…` (5),
and `../` traversal segments (5).  This sub-detector is allocation-free and exits
early on the first threshold breach.

### [`SSTI_detect`](ssti_detect.md)

Recognises the delimiter pairs of **22 template-engine families** including Jinja2,
Twig, Handlebars, Velocity, Freemarker, Ruby ERB, Thymeleaf, Slim, Tornado, and
Vue.js.  The scanner searches for an open token and then performs a bounded scan of
at most `max_len` bytes for the matching close token — bounded to prevent worst-case
quadratic behaviour on adversarial inputs.  Patterns are tested in most-to-least-
specific order so that longer aliases (e.g. `{{=`) shadow shorter ones (`{{`).

### [`SSI_injection_detect`](ssi_injection_detect.md)

Detects Server-Side Include directives in two dialects:

* **Apache / Nginx** — `<!--#keyword … -->` with any whitespace between `<!--`, `#`,
  and the keyword.  Twelve directives are recognised: `include`, `exec`, `echo`,
  `config`, `fsize`, `flastmod`, `printenv`, `set`, `if`, `elif`, `else`, `endif`.
* **JSP / JSTL / ColdFusion** — `<jsp:include`, `<jsp:forward`, `<c:import`,
  `<cfinclude`, `<cfexecute`.

`memchr` (SSE2/AVX2/NEON) locates every `<` in one O(n/16) SIMD pass; only the
handful of bytes surrounding each hit are then examined.

### [`ESI_injection_detect`](esi_injection_detect.md)

Detects Edge Side Include tags processed by Varnish, Squid, Akamai, and Fastly.
Thirteen `<esi:…>` directives are matched case-insensitively, plus the HTML-comment
form `<!--esi … -->`.  Like the SSI detector, `memchr` drives the outer scan; per-hit
inspection is a bounded byte comparison.

### [`CRLF_injection_detect`](crlf_injection_detect.md)

Covers three injection vectors — raw `\r`/`\n` control characters, 26 escape and
percent-encoded variants (`%0d%0a`, `%250d%250a`, `%u000d%u000a`, …), and 6 Unicode
surrogate forms (U+010A, U+010D, U+2028, U+2029, …).

A line-break alone is not sufficient to fire; the bytes **immediately following** the
break must resemble an injected HTTP element: a header name from a 56-entry table, an
HTTP status line, an HTML tag, or a chunked-transfer digit.  Normal `\r\n` framing
inside a well-formed request block is explicitly excluded.

### [`Request_Smuggling_detect`](request_smuggling_detect.md)

Flags three smuggling indicators that appear as header injections: a
`Transfer-Encoding: chunked` directive in a field that should not contain it, an
`X-Session-Hijack: true` marker (used by some bypass toolkits), and a
`Content-Length` value of 4 or fewer bytes (common in CL.0 / CL.TE desync probes).
A header-boundary guard prevents false positives from query parameters that happen to
contain the same substrings.

### [`NOSQL_injection_detect`](nosql_injection_detect.md)

Uses a **two-list conjunction**: both a list-A operator marker and a list-B value
marker must be present in the same inspected string before the detector fires.  A
single operator or value in isolation is ignored — the conjunction eliminates the
false positives that plague single-keyword NoSQL filters.

**List A — operators (16 markers)**

`$gt`, `$nin`, `$where`, `$save`, `$exists`, `$remove`, `$in`, `$comment`,
`selector`, `$or`, `$and`, `this.password.match`, `db.stores.mapReduce`,
`db.injection.insert`, `&&`, `||`

**List B — values (21 markers + numeric pattern)**

`==1`, `== 1`, `]=1`, `] = 1`, `true`, `sleep(`, `logins`, `admin`, `pass`, `user`,
`undefined`, `Date`, `null`, `root`, `new%`, `%00`, `{}`, `success`, `.insert`,
`while(true)`, `dropDatabase(`

The pattern `==[1-9]` / `== [1-9]` is treated as an additional list-B match
implemented as a CMC digit check rather than a literal, keeping Vectorscan
acceleration available for the literal lists while covering the numeric equality form
that commonly appears in authentication-bypass payloads.

When compiled with the `vectorscan-engine` feature and started with
`--enable-vectorscan`, both lists are scanned with Vectorscan `BlockDatabase`
(`CASELESS | SINGLEMATCH`) — a single SIMD pass per list.

### [`XXE_attack_detect`](xxe_attack_detect.md)

Also uses a **two-list conjunction**: an XML entity / include marker (list A) must
appear alongside a suspicious target or context marker (list B).

**List A — entity / include markers (2 markers)**

`entity`, `xi:include`

**List B — suspicious context markers (10 markers)**

`xxe`, `system`, `etc/password`, `eval`, `exfil`, `xmlns:xi`, `send`, `doctype`,
`soap`, `file`

All comparisons are case-insensitive.  Before running the conjunction check, the
detector probes for UTF-16 LE/BE encoding (≥ 50 % NUL-interleaved bytes) and, if
found, decodes the payload and re-runs the check — closing a common evasion path
used to bypass ASCII-only WAF filters.  The `decoded_utf16` flag in the finding
records whether evasion decoding was needed.

### [`Anti_exposed_backup`](anti_exposed_backup.md)

Matches request paths against a compiled list of backup-file suffixes and editor
artefacts (`.bak`, `.old`, `.orig`, `.swp`, `.un~`, `~`, `.DS_Store`, etc.).  The
check is URI-only and runs in `inspect_early()`, before the request body is assembled,
so it adds no latency to normal traffic.

### [`Anti_passwd_leak`](anti_passwd_leak.md)

Operates on the **response body** rather than the request.  The detector fires when
two or more structurally-distinctive tokens from `/etc/passwd` (`PASSWD_TOKENS` — 9
patterns) or `/etc/shadow` (`SHADOW_TOKENS` — 8 patterns) appear in the same buffered
response body.  A single token in isolation (e.g. `/bin/bash` in a documentation
response) is deliberately below the threshold to avoid false positives.

This is one of the CMC modules that acts as a data-loss-prevention (DLP) filter — it
blocks the upstream *response* before it reaches the attacker, rather than blocking an
attacker *request* before it reaches the upstream.

### [`Java_deserialize_detect`](java_deserialize_detect.md)

Detects **Java deserialization attack payloads** in both request inputs and upstream
responses.  The detector uses a three-signal scoring model:

* **Signal A — magic bytes / encoding prefixes**: raw binary `\xAC\xED` / `\x1f\x8b`,
  base64 forms (`rO0A`, `rO0AB`, `H4sI`), URL-encoded (`%AC%ED`, `%ac%ed`), ASCII hex
  (`aced`).
* **Signal B — Java content headers**: `Content-Type: application/x-java-serialized-object`
  or `Accept: application/x-java-serialized-object` (case-insensitive).
* **Signal C — base64 prefix patterns**: `rO0`, `rO0A`, `rO0AB` (case-sensitive).

Blocking thresholds depend on the global `Untrust` level:
3 signals → always block; 2 signals + `Untrust ≥ 60` → block; 2 signals + `Untrust < 60`
→ silent log; 1 signal + `Untrust > 80` → informative log.

Unlike all other request-side detectors, this module also inspects the upstream
**response** body and headers — e.g., to block a backend that accidentally echoes back
a serialized Java object.

---

## Vectorscan SIMD acceleration

Modules that use Aho-Corasick for multi-keyword matching (`NOSQL_injection_detect`,
`XXE_attack_detect`, `Anti_passwd_leak`, `Java_deserialize_detect`) can switch to
Vectorscan `BlockDatabase` when:

1. KrakenWAF is compiled with the `vectorscan-engine` Cargo feature.
2. The process is started with `--enable-vectorscan`.

Vectorscan processes each pattern list in a single SIMD pass and terminates on the
first match (`SINGLEMATCH`), reducing per-request latency for long pattern lists.
All other modules use `memchr`, `str::find`, or hand-rolled byte-comparison loops
that are already SIMD-accelerated by `memchr` or by the compiler's auto-vectoriser.

---

## Detection event pipeline

When any CMC module fires, KrakenWAF emits a structured block event through the same
pipeline used by regex, keyword, Vectorscan, and libinjection detectors:

| Sink | Detail |
|------|--------|
| **JSONL log** | Machine-readable structured finding |
| **Critical log** | Human-readable one-liner for log aggregators |
| **SQLite row** | Persistent evidence record for the dashboard |
| **Prometheus counter** | `waf_blocks_total{engine="cmc"}` incremented |

Every finding carries a `rule_match` field of the form
`cmc::<module>:<details>` and a `rule_line_match` of
`cmc/<module>.rs:generated`, making it straightforward to correlate log entries
back to the specific detector implementation.

---

## Implementation notes

All CMC modules are written in safe Rust with no `unsafe` blocks.  Each module:

* Operates on a `&str` or `&[u8]` borrow — zero copies on the happy path.
* Performs at most one or two linear passes over the input.
* Uses early-return / `?` propagation so a confirmed match exits immediately
  without evaluating remaining patterns.
* Is structured in the *generated-CMC* style (`match state { … }`) to facilitate a
  future migration to `re2rust`-generated automata if throughput requirements grow.

The `CmcManager` struct owns one instance of each enabled detector and exposes the
following entry points called from the WAF engine:

* `inspect_uri(&str)` — URI-only check, called from `inspect_early()` before body
  assembly (used by `Anti_exposed_backup`).
* `inspect(&str)` — full-payload check on a lowercased, URL-decoded string, called
  once the complete request string is available (used by all injection detectors).
* `inspect_response_body(&str)` — response-body check, called from `inspect_response()`
  after the full upstream response body is buffered (used by `Anti_passwd_leak`).
* `inspect_java_deser(&str, &[u8])` — score-based check on the original
  (non-lowercased) text plus raw body bytes; called from both the request and response
  pipelines.  Accepts a combined headers+body string so that Signal B (header check)
  and Signals A/C (body scan) are evaluated in a single call.

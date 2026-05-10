# SQLi-Comments-Detect DFA

Detects SQL injection evasion via repeated block-comment obfuscation.  Attackers
wrap payloads in `/* */` to split keywords and bypass naive string-matching filters
(`SE/*bypass*/LECT`, `UN/**/ION`, `/*!50000SELECT*/`).  KrakenWAF counts every
complete `/* ... */` block comment in the inspected string; two or more triggers a
block — enough signal to catch obfuscation while ignoring the isolated comment that
may appear in a legitimate SQL `EXPLAIN` or ORM-generated query.

---

## How it works

| Step | Detail |
|------|--------|
| **State machine** | A single-pass byte scanner opens on `/*` and advances until `*/` closes the comment, then increments a counter and resets. |
| **Threshold** | Default threshold is **2**. The first comment is treated as noise; the second reliably indicates evasion. |
| **No preprocessing** | The detector operates on the raw inspected string — URL decoding and normalisation have already been applied by the engine before DFA inspection. |
| **No vectorscan** | The pattern is too short for SIMD multi-pattern gain; a plain state machine is faster for this specific case. |

---

## Enabling the module

Add `SQLi_comments_detect: true` to your DFA config file (default location
`rules/dfa/config.yaml`) and load it with the `--dfa-load` flag:

```yaml
# rules/dfa/config.yaml
DFA-Rules:
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
```

Start the WAF:

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --dfa-load rules/dfa/config.yaml
```

To disable, set the value to `false` or remove the line entirely.

---

## Detection finding

When a request is blocked the following structured finding is emitted (visible in
logs, the Prometheus `/metrics` endpoint, and the SQLite database):

| Field | Value |
|-------|-------|
| Title | `DFA SQLi comment evasion detection` |
| Severity | `High` |
| CWE | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL Injection |
| Reference | [OWASP – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) |
| `rule_match` | `dfa::sqli_comments_detect:comments-total=<N>` |
| `rule_line_match` | `dfa/sqli_comments_detect.rs:generated` |

---

## Examples

### Blocked requests (payload reaches threshold ≥ 2 comments)

```
GET /search?q=SE/**/LECT/*bypass*/1,2,3--     → 403 Forbidden   (2 block comments)
POST /login  payload=UN/**/ION/**/SELECT ...  → 403 Forbidden   (2 block comments)
GET /q=/*!50000SELECT*/ /*!*/1                → 403 Forbidden   (2 MySQL version comments)
```

### Allowed requests (single isolated comment — below threshold)

```
GET /api?q=SELECT%20/*normal%20comment*/%201  → forwarded   (1 comment — noise tolerance)
GET /products?desc=Price%20/*%20excl.%20VAT%20*/%20shown  → forwarded   (1 comment)
```

---

## Evasion-resistance notes

The detector tolerates nested-looking comment text and arbitrary whitespace inside
the comment body — it matches on `/*` … `*/` boundaries only, not on content.
Attackers who attempt to split across both a comment and a different technique (e.g.
hex encoding) are caught by the complementary regex and libinjection engines; this
DFA specifically targets the comment-stacking pattern that regex engines often miss
due to exponential backtracking on deeply nested input.

---

## False-positive guidance

False positives are rare: two SQL block comments in a user-visible field genuinely
require justification.  If your application legitimately receives payloads with two
or more `/* */` comments:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml` so it
   bypasses all WAF inspection.
2. **Disable the module**: set `SQLi_comments_detect: false` in the DFA config.

---

## Performance notes

* The state machine is a single linear pass — **O(n)** in input length with no
  backtracking and a working set of two bytes (`/`, `*`).
* No heap allocation is performed during detection; the counter and state live on
  the stack.
* The check runs inside `inspect()` on the fully assembled request payload (headers
  + body or URI depending on engine phase).

---

## Source files

| File | Purpose |
|------|---------|
| `src/dfa/sqli_comments_detect.rs` | Detector implementation and unit tests |
| `src/dfa/mod.rs` | Module registration, `DfaConfig` field, `DfaManager` field, `inspect()` call |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `rules/dfa/config.yaml` | Default config — `SQLi_comments_detect: true` |

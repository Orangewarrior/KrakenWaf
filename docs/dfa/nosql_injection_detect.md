# NoSQL-Injection-Detect DFA

Detects NoSQL injection payloads targeting document-store databases such as MongoDB,
CouchDB, and similar query engines.  NoSQL injection exploits operator-based query
languages where attacker-controlled input can inject comparison operators (`$gt`,
`$where`), logical connectors (`$or`, `&&`), or JavaScript execution directives
(`this.password.match(…)`, `db.stores.mapReduce(…)`), bypassing authentication or
exfiltrating data without any SQL involved.

---

## How it works

Detection requires **one marker from list A AND one marker from list B** to be
present in the same inspected string.  A single marker from either list alone is
insufficient — the conjunction eliminates the false positives that plague single-list
approaches on benign data containing words like `admin` or `null`.

Additionally, a separate inline check detects the numeric equality pattern `==[1-9]`
(and `== [1-9]`) that appears in MongoDB `$where` JavaScript comparisons, counted as
a list B match.

### List A — operators and selectors (16 markers)

`$gt`, `$nin`, `$where`, `$save`, `$exists`, `$remove`, `$in`, `$comment`,
`selector`, `$or`, `$and`, `this.password.match`, `db.stores.mapreduce`,
`db.injection.insert`, `&&`, `||`

### List B — values and control-flow (21 markers + numeric pattern)

`==1`, `== 1`, `]=1`, `] = 1`, `true`, `sleep(`, `logins`, `admin`, `pass`,
`user`, `undefined`, `date`, `null`, `root`, `new%`, `%00`, `{}`, `success`,
`.insert`, `while(true)`, `dropdatabase(`

Plus: `==[1-9]` and `== [1-9]` via the dedicated numeric-equality scan.

### Engine selection

| Mode | Mechanism |
|------|-----------|
| Default | Aho-Corasick (case-insensitive, leftmost-first match) on both lists |
| `--enable-vectorscan` | Vectorscan `BlockDatabase` with `CASELESS \| SINGLEMATCH` flags — one SIMD pass per list; Aho-Corasick kept as fallback |

When Vectorscan is enabled, the SIMD engine is used for both list A and list B;
the numeric-equality scan always runs in plain Rust regardless of engine.

---

## Enabling the module

Add `NOSQL_injection_detect: true` to your DFA config file (default location
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

To enable the Vectorscan SIMD engine (requires `vectorscan-engine` Cargo feature):

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --dfa-load rules/dfa/config.yaml \
  --enable-vectorscan
```

To disable, set the value to `false` or remove the line entirely.

---

## Detection finding

When a request is blocked the following structured finding is emitted (visible in
logs, the Prometheus `/metrics` endpoint, and the SQLite database):

| Field | Value |
|-------|-------|
| Title | `DFA NoSQL injection detection` |
| Severity | `High` |
| CWE | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) — Improper Neutralization of Special Elements in Data Query Logic |
| Reference | [OWASP – Testing for NoSQL Injection](https://owasp.org/www-community/attacks/Testing_for_NoSQL_injection) |
| `rule_match` | `dfa::nosql_injection_detect:list_A=<marker-a> list_B=<marker-b>` |
| `rule_line_match` | `dfa/nosql_injection_detect.rs:generated` |

---

## Examples

### Blocked requests

```
GET  /api/users?filter={"user":{"$gt":""},"pass":"admin"}
   → 403   (list_A=$gt  list_B=admin)

GET  /search?q=selector[$where]=this.password.match(/admin/)
   → 403   (list_A=selector  list_B=admin)

POST /login  body={"$or":[{"role":"root"}]}
   → 403   (list_A=$or  list_B=root)

POST /api  body={"$where":"sleep(5000)"}
   → 403   (list_A=$where  list_B=sleep()

POST /query  body={"$where":"this.age==7"}
   → 403   (list_A=$where  list_B===[1-9] numeric pattern)
```

### Allowed requests (single list only — no conjunction)

```
GET  /search?q={"$gt":""}
   → forwarded   (list_A only — list_B absent)

GET  /page?desc=Find%20the%20admin%20user
   → forwarded   (list_B=admin — list_A absent)

POST /form  body=user=admin&pass=secret
   → forwarded   (list_B=admin, list_B=pass — list_A absent)
```

---

## False-positive guidance

The two-list conjunction means benign queries containing `admin`, `null`, or `true`
alone never fire.  A false positive requires the same string to also contain a
MongoDB operator (`$gt`, `$where`, etc.) or logical connector (`&&`, `||`).

If your application legitimately passes MongoDB operators in fields (e.g. an
admin query builder):

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `NOSQL_injection_detect: false` in the DFA config.

---

## Performance notes

* **Aho-Corasick** compiles all list patterns into a single automaton at startup;
  per-request cost is a single O(n) pass per list regardless of list size.
* **Vectorscan** processes the entire list in one SIMD scan per list, terminating
  immediately on first match (`SINGLEMATCH`).
* The numeric-equality scan is an O(n) byte walk with two-byte look-ahead.
* No heap allocation is performed during detection (patterns are `'static` references).

---

## Source files

| File | Purpose |
|------|---------|
| `src/dfa/nosql_injection_detect.rs` | Detector, list tables, Aho-Corasick/Vectorscan matchers, numeric equality scan, unit tests |
| `src/dfa/mod.rs` | Module registration, `DfaConfig` field, `DfaManager` field, `inspect()` call |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `rules/dfa/config.yaml` | Default config — `NOSQL_injection_detect: true` |

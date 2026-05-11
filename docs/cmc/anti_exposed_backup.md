# Anti-Exposed-Backup CMC

Blocks GET and HEAD requests whose URI path ends with a known backup, temporary,
or configuration-leak file extension.  Attackers routinely probe web roots for
files left behind by editors, deployment scripts, or careless operators
(`wp-config.php.bak`, `.env`, `database.dump`, Vim swap files, etc.).  If the
WAF sees such a request it blocks it immediately — the upstream application is
never reached.

---

## How it works

| Step | Detail |
|------|--------|
| **Method filter** | Only `GET` and `HEAD` are inspected. `POST`, `PUT`, `PATCH`, `DELETE` are never blocked by this module. |
| **Path extraction** | The query-string (`?…`) and fragment (`#…`) are stripped from the URI before matching, so appending `?v=1` to a backup path cannot bypass the rule. |
| **Suffix matching** | The cleaned path is compared — case-insensitively — against every entry in `HIGH_CONFIDENCE_BACKUP_SUFFIXES`. A match is accepted only when the suffix appears at the **very end** of the path. |
| **Vectorscan** | When `--enable-vectorscan` is active, all 18 patterns are fed into a single Hyperscan/Vectorscan `BlockDatabase`. The SIMD engine scans the path in one pass; a match is accepted only when its end-offset equals the path length. This is faster than a plain loop on long URIs with many path segments. |

### Monitored suffixes

```
.bak   .bkp   .backup   .old   .orig   .save   .sav
.swp   .swo   .swn      .swx   .un~    .tmp    .temp
.wbk   .env   .sql.     .dump
```

---

## Enabling the module

Add `Anti_exposed_backup: true` to your CMC config file (default location
`rules/cmc/config.yaml`) and load it with the `--cmc-load` flag:

```yaml
# rules/cmc/config.yaml
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
  Anti_exposed_backup: true   # ← add this line
```

Start the WAF:

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load rules/cmc/config.yaml
```

To disable, set the value to `false` or remove the line entirely.

---

## Detection finding

When a request is blocked the following structured finding is emitted (visible in
logs, the Prometheus `/metrics` endpoint, and the SQLite database):

| Field | Value |
|-------|-------|
| Title | `CMC exposed backup/temp file detection` |
| Severity | `High` |
| CWE | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) — File and Directory Information Exposure |
| Reference | [OWASP – Insecure Direct Object References](https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_References) |
| `rule_match` | `cmc::anti_exposed_backup:suffix=<matched_suffix>` |
| `rule_line_match` | `cmc/anti_exposed_backup.rs:generated` |

---

## Examples

### Blocked requests

```
GET /wp-config.php.bak          HTTP/1.1   → 403 Forbidden
GET /.env                        HTTP/1.1   → 403 Forbidden
HEAD /database.sql.bak           HTTP/1.1   → 403 Forbidden
GET /admin/dump.backup           HTTP/1.1   → 403 Forbidden
GET /config.PHP.BAK              HTTP/1.1   → 403 Forbidden   (case-insensitive)
GET /config.bak?v=2              HTTP/1.1   → 403 Forbidden   (query string stripped)
```

### Allowed requests

```
POST /upload/file.bak            HTTP/1.1   → forwarded   (POST is not inspected)
GET  /test_get?file=backup.bak   HTTP/1.1   → forwarded   (.bak is in query string, not path)
GET  /file.bak.txt               HTTP/1.1   → forwarded   (suffix is not at end of path)
GET  /index.html                 HTTP/1.1   → forwarded   (no backup suffix)
```

---

## False-positive guidance

This module has a **very low** false-positive rate by design: only backup-specific
extensions trigger it, and only on read-only methods.  If your application
legitimately serves files with these extensions (unlikely for a production
service), you have two options:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml` so it
   bypasses all WAF inspection.
2. **Disable the module**: set `Anti_exposed_backup: false` in the CMC config.

---

## Performance notes

* On a modern CPU with Vectorscan enabled the check costs roughly **1–3 µs** per
  request (SIMD scan of ≤ 18 patterns on a typical URI).
* Without Vectorscan the plain fallback iterates at most 18 `ends_with` comparisons
  on the lowercased path string — negligible overhead for any realistic URI length.
* The check runs in `inspect_early()`, **before** the request body is read or
  assembled into the full inspection payload, so it adds zero body-read latency.

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/anti_exposed_backup.rs` | Detector implementation, Vectorscan helper, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` field, `CmcManager` field, `inspect_uri()` |
| `src/waf/engine.rs` | Integration — `inspect_uri()` called in `inspect_early()` |
| `rules/cmc/config.yaml` | Default config — `Anti_exposed_backup: true` |
| `tests/server_real_test.rs` | Integration tests (`dfa_anti_exposed_backup_*`) |
| `src/bin/attack.rs` | Attack-sweep payloads (`BACKUP_URI_PAYLOADS`) |
| `src/bin/demo_server.rs` | Wildcard `/*path` route for bypass detection |

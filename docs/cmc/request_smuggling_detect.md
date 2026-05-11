# Request-Smuggling-Detect CMC

Detects HTTP request smuggling indicators in attacker-controlled input.  Request
smuggling exploits disagreements between a front-end proxy and a back-end server
about where one HTTP request ends and the next begins.  By injecting a crafted
`Transfer-Encoding` or `Content-Length` header, an attacker can prepend hidden data
to the next user's request, bypass access controls, or poison shared caches.

---

## How it works

The detector looks for three specific smuggling indicators, each guarded by a
header-boundary check to avoid false positives on innocent query-parameter values:

| Indicator | What is checked |
|-----------|-----------------|
| `Transfer-Encoding: chunked` | Header name `transfer-encoding` followed by `:` then value `chunked` |
| `X-Session-Hijack: true` | Header name `x-session-hijack` followed by `:` then value `true` |
| `Content-Length: ≤ 4` | Header name `content-length` followed by `:` then a numeric value 1–4 immediately terminated by whitespace or delimiter |

### Header-boundary guard

To prevent matching on innocent text like `payload=transfer-encoding: chunked` (which
is not a real header), each candidate header name is validated against boundary bytes
on both sides:

* **Before the name**: must be the start of the string or one of `\r`, `\n`, ` `, `\t`,
  `&`, `?`, `#`, `;`, `=`, `/`, `\0`.
* **After the name**: must be `:` or optional whitespace followed by `:`.

The value check uses `starts_with_token` which additionally requires the value to be
followed by a terminator (`\r`, `\n`, `;`, `,`, ` `, `\t`, `&`) or end-of-string,
preventing `chunkedXXX` from matching `chunked`.

### Matching flow

```
input
 ├─ has_header_value(input, "transfer-encoding", "chunked")  → transfer-encoding:chunked
 ├─ has_header_value(input, "x-session-hijack", "true")      → x-session-hijack:true
 └─ has_small_content_length(input)                          → content-length<=4
         ↓ first match
       → Some(RequestSmugglingMatch { pattern })
```

---

## Enabling the module

Add `Request_Smuggling_detect: true` to your CMC config file (default location
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
  Anti_exposed_backup: true
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
| Title | `CMC request smuggling detection` |
| Severity | `High` |
| CWE | [CWE-444](https://cwe.mitre.org/data/definitions/444.html) — Inconsistent Interpretation of HTTP Requests |
| Reference | [PortSwigger – HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) |
| `rule_match` | `cmc::request_smuggling_detect:<pattern>` where `<pattern>` is `transfer-encoding:chunked`, `x-session-hijack:true`, or `content-length<=4` |
| `rule_line_match` | `cmc/request_smuggling_detect.rs:generated` |

---

## Examples

### Blocked requests

```
POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n
   → 403   (transfer-encoding:chunked header in request)

GET  /search?payload=transfer-encoding:%20chunked
   → 403   (chunked injected into query parameter)

POST /api  body=x-session-hijack: true
   → 403   (session-hijack marker in body)

POST /upload HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd
   → 403   (content-length ≤ 4 — classic CL.0 / CL.TE setup)
```

### Allowed requests

```
POST /upload HTTP/1.1\r\nContent-Length: 2048\r\n\r\n<body>
   → forwarded   (content-length > 4)

GET  /page?encoding=gzip
   → forwarded   (transfer-encoding: gzip — not chunked)

POST /api  body=x-session-hijack: false
   → forwarded   (value is false, not true)
```

---

## False-positive guidance

The header-boundary guard prevents the most common false positives (strings like
`transfer-encoding: chunked` embedded inside a normal query value are matched only
when boundary bytes confirm a header context).  Legitimate requests with a real
`Content-Length: 1`–`4` header for a tiny body (e.g. a health-check endpoint that
sends a 4-byte `{""}` body) will be blocked.

Options:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml` so it
   bypasses all WAF inspection.
2. **Disable the module**: set `Request_Smuggling_detect: false` in the CMC config.

---

## Performance notes

* Each indicator performs at most two `str::find` scans (header name + header value),
  with constant-time boundary and token checks at each match site.
* All three indicators short-circuit after the first match.
* No heap allocation is performed during detection.

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/request_smuggling_detect.rs` | Detector implementation, boundary helpers, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` field, `CmcManager` field, `inspect()` call |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `rules/cmc/config.yaml` | Default config — `Request_Smuggling_detect: true` |

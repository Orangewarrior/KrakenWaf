# CRLF-Injection-Detect CMC

Detects CRLF injection and HTTP response-splitting payloads in attacker-controlled
input.  CRLF injection occurs when unvalidated `\r` or `\n` bytes smuggled into a
response header allow an attacker to inject arbitrary headers, forge new HTTP
responses, or embed HTML/JavaScript into the response body — enabling cookie theft,
phishing, and cache poisoning.

The detector covers **three independent injection vectors**:

| Vector | Example tokens |
|--------|----------------|
| **Control characters** | Literal `\r`, `\n`, `\r\n` in the input string |
| **Escaped sequences** | `\r\n`, `
`, `%u000d%u000a`, `%0d%0a`, double-encoded `%250d%250a`, etc. |
| **Unicode surrogates** | `嘊` (U+5620A), `嘍` (U+5620D), `Ċ` (U+010A), `č` (U+010D), U+2028, U+2029 — used to bypass ASCII-only filters |

A line break alone is not sufficient to fire the detector — the text **immediately
following** the break must also look like an injected HTTP element:

* An HTTP header name followed by `:` (matched against a 56-entry table of common
  headers including `Set-Cookie`, `Location`, `Content-Type`, `X-Forwarded-For`, etc.)
* An HTTP status line (`HTTP/1.1`, `HTTP/2`)
* An HTML open tag (`<script`, `<html`, `<body`, `<svg`, `<img`, `<iframe`, etc.)
* A chunked-transfer terminator (`0\r`, `0\n`, `1\r`, `1\n`)

---

## How it works

### Normal HTTP framing — smart bypass resistance

Legitimate HTTP requests themselves contain `\r\n` between headers.  The detector
distinguishes injected breaks from normal framing by checking whether the line break
occurs **inside a well-formed HTTP request block** that began with a valid request
line (`GET /path HTTP/1.1`).  A break that satisfies this invariant and is followed
by a syntactically valid header is treated as normal framing and not flagged.

CRLF injected into the URI or a header value corrupts the first line and breaks the
invariant, so the subsequent content is correctly flagged.

### Detection pipeline

```
input
 ├─ has_control_line_injection()   — raw \r / \n bytes
 ├─ has_escaped_line_injection()   — 26 escape/encode variants
 └─ has_unicode_line_injection()   — 6 Unicode surrogate forms
         ↓ any of the above found AND line_after_break_is_injected()
       → Some(CrlfMatch { pattern })
```

### Monitored escape sequences (26 variants)

`\\r\\n`, `\\r`, `\\n`, `\\u000d\\u000a`, `\\u000a`, `\\u000d`,
`%u000d%u000a`, `%u000a`, `%u000d`,
`%250d%250a`, `%250a`, `%250d`,
`%25250d%25250a`, `%%0d0d%%0a0a`,
`%e5%98%8a`, `%e5%98%8d`, `%c4%8a`, `%c4%8d`,
`%e2%80%a8`, `%e2%80%a9`, `%c0%8a`, `%c0%8d`,
`%e0%80%8a`, `%e0%80%8d`, `%25e0%2580%258a`, `%25e0%2580%258d`

### Monitored Unicode forms (6 variants)

`嘊` (U+5620A), `嘍` (U+5620D), `Ċ` (U+010A), `č` (U+010D),
U+2028 (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR)

---

## Enabling the module

Add `CRLF_injection_detect: true` to your CMC config file (default location
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
| Title | `CMC CRLF injection detection` |
| Severity | `High` |
| CWE | [CWE-93](https://cwe.mitre.org/data/definitions/93.html) — Improper Neutralization of CRLF Sequences |
| Reference | [OWASP – CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection) |
| `rule_match` | `cmc::crlf_injection_detect:<vector>` where `<vector>` is `control-line-header`, `escaped-line-header`, or `unicode-line-header` |
| `rule_line_match` | `cmc/crlf_injection_detect.rs:generated` |

---

## Examples

### Blocked requests

```
GET  /redir?url=http://x.test%0d%0aSet-Cookie:admin=true          → 403   (control vector)
GET  /search?q=value\r\nLocation:http://evil.test                  → 403   (escaped vector)
GET  /q=value
set-cookie:session=hijacked               → 403   (escaped unicode)
GET  /path?next=/home%0d%0aHTTP/1.1%20200%20OK%0d%0a              → 403   (response split)
GET  /login?next=/home\r\n\r\n<script>alert(1)</script>            → 403   (HTML injection)
GET  /x=%25e0%2580%258d%25e0%2580%258aset-cookie%3aadmin=true      → 403   (double-encoded)
GET  /x=嘊嘍set-cookie:admin=true                                   → 403   (Unicode surrogate)
```

### Allowed requests — normal HTTP framing

```
GET  /test_get?payload_test=hello HTTP/1.1\r\nHost: localhost\r\n\r\n   → forwarded
GET  /login HTTP/1.1\r\nHost: x\r\nCookie: sess=abc\r\n\r\n             → forwarded
GET  /search?q=normal+query                                              → forwarded
```

---

## False-positive guidance

The dual requirement — line break **and** injected HTTP element — keeps the false-
positive rate very low.  A `\n` inside a JSON or base64 body value is not flagged
unless the text following the newline looks like an HTTP header or status line.

If your application legitimately receives multiline header-like content in fields:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `CRLF_injection_detect: false` in the CMC config.

---

## Performance notes

* The control-character scan is a single O(n) byte walk with constant look-ahead.
* Each of the 26 escape sequences is searched with a simple `str::find` call;
  matches trigger a secondary check only at the match position.
* The 6 Unicode surrogate forms use `str::find` on UTF-8 encoded byte sequences.
* All checks short-circuit on first confirmed match.

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/crlf_injection_detect.rs` | Detector, escape table, Unicode table, framing helpers, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` field, `CmcManager` field, `inspect()` call |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `rules/cmc/config.yaml` | Default config — `CRLF_injection_detect: true` |

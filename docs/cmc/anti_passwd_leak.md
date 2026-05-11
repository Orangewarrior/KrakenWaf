# Anti-Passwd-Leak CMC

Detects **Unix password and shadow file leaks** in upstream HTTP responses.
When an application is compromised, an attacker may use path-traversal, file-inclusion,
or XXE vulnerabilities to exfiltrate `/etc/passwd` or `/etc/shadow` through the HTTP
response body.  Without a response-side WAF filter, this data reaches the attacker
unimpeded.

The detector intercepts the response *before* it is forwarded to the client.  If the
body contains two or more structurally-distinctive tokens from the `/etc/passwd` or
`/etc/shadow` format, the WAF returns **HTTP 403** and the sensitive data never leaves
the network perimeter.

---

## How it works

| Step | Detail |
|------|--------|
| **Response hook** | Runs in `inspect_response_body()`, called after the full response body is buffered in `inspect_response()` — never on the request side. |
| **Two-list structure** | `PASSWD_TOKENS` and `SHADOW_TOKENS` are independent pattern lists.  Each list is checked independently; a match on either list is sufficient to block. |
| **Conjunction threshold** | A single token present in the response (e.g. `/bin/bash` alone) is not enough to block — **two or more distinct tokens** from the same list must appear. |
| **Priority** | `PASSWD_TOKENS` is checked first; if it fires, `SHADOW_TOKENS` is not evaluated. |
| **Case-sensitive** | Token matching is case-sensitive.  On all Unix-like systems `/etc/passwd` and `/etc/shadow` use lowercase field separators and shell paths. |
| **No preprocessing** | The raw (non-URL-decoded) response body is matched.  Structural tokens in these files are never percent-encoded in legitimate leaks. |

### PASSWD_TOKENS (9 tokens — threshold: 2 distinct)

| Token | Significance |
|-------|--------------|
| `root:x:0:0:` | Root entry with shadow-password placeholder |
| `daemon:x:` | Daemon service account |
| `bin:x:` | System bin account |
| `nobody:` | Unprivileged nobody account |
| `/bin/bash` | Default interactive shell |
| `/bin/sh` | POSIX shell reference |
| `/bin/false` | Shell set to false (locked account) |
| `/usr/sbin/nologin` | No-login shell (nologin variant) |
| `/sbin/nologin` | No-login shell (sbin variant) |

### SHADOW_TOKENS (8 tokens — threshold: 2 distinct)

| Token | Significance |
|-------|--------------|
| `root:$y$` | Root entry with yescrypt hash |
| `root:$6$` | Root entry with SHA-512 hash |
| `root:$5$` | Root entry with SHA-256 hash |
| `root:$1$` | Root entry with MD5 hash |
| `root:!:` | Root entry with locked password |
| `daemon:` | Daemon shadow entry |
| `nobody:` | Nobody shadow entry |
| `:0:99999:7:::` | Typical shadow aging fields (no min/max/warn) |

### Engine selection

| Mode | Mechanism |
|------|-----------|
| Default | Aho-Corasick (`find_iter` — case-sensitive, collects all distinct pattern IDs) |
| `--enable-vectorscan` | Vectorscan `BlockDatabase` with `SINGLEMATCH` — one SIMD pass per token list; matched IDs collected in the scan callback |

---

## Enabling the module

Add `Anti_passwd_leak: true` to your CMC config file (default location
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
  Anti_passwd_leak: true
```

Start the WAF:

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load rules/cmc/config.yaml
```

To enable Vectorscan SIMD acceleration (requires `vectorscan-engine` Cargo feature):

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load rules/cmc/config.yaml \
  --enable-vectorscan
```

To disable, set the value to `false` or remove the line entirely.

---

## Detection finding

When a response is blocked the following structured finding is emitted (visible in
logs, the Prometheus `/metrics` endpoint, and the SQLite database):

### passwd leak

| Field | Value |
|-------|-------|
| Title | `CMC passwd/shadow file leak detection` |
| Severity | `Critical` |
| CWE | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) — Insertion of Sensitive Information into Externally-Accessible File or Directory |
| Reference | [OWASP – Sensitive Data Exposure](https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure) |
| `rule_match` | `cmc::anti_passwd_leak:passwd:token_a=<a> token_b=<b> count=<N>` |
| `rule_line_match` | `cmc/anti_passwd_leak.rs:generated` |

### shadow leak

| Field | Value |
|-------|-------|
| Title | `CMC passwd/shadow file leak detection` |
| Severity | `Critical` |
| CWE | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) |
| Reference | [OWASP – Sensitive Data Exposure](https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure) |
| `rule_match` | `cmc::anti_passwd_leak:shadow:token_a=<a> token_b=<b> count=<N>` |
| `rule_line_match` | `cmc/anti_passwd_leak.rs:generated` |

---

## Examples

### Blocked responses

```
# Upstream leaks /etc/passwd via path traversal:
GET /download?file=../../../../etc/passwd
  upstream body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:…\n"
  → WAF intercepts response → 403   (passwd: token_a=root:x:0:0: token_b=/bin/bash count=3)

# Upstream leaks /etc/shadow via XXE:
POST /parse-xml  body=<xxe>
  upstream body: "root:$6$salt$hash:19000:0:99999:7:::\ndaemon:*:18858:0:99999:7:::\n"
  → WAF intercepts response → 403   (shadow: token_a=root:$6$ token_b=:0:99999:7::: count=2)
```

### Allowed responses (single token — below threshold)

```
# Only one PASSWD_TOKEN present — not enough to block:
GET /doc  body="The default shell /bin/bash is widely used"
  → forwarded (1 distinct passwd token — threshold not reached)

# Normal API response — no tokens:
GET /api/users  body={"users":[{"name":"alice"}]}
  → forwarded (no tokens)
```

---

## False-positive guidance

The two-token conjunction is deliberately conservative.  A single occurrence of
`/bin/bash` in documentation, a log snippet, or a shell-command explanation does not
fire.  Two or more structurally co-occurring tokens (as they would appear in an actual
passwd or shadow file) are required.

Common false-positive scenarios and mitigations:

| Scenario | Risk | Mitigation |
|----------|------|------------|
| Configuration UI showing sample passwd entries | Low (2 tokens needed) | Allow the specific endpoint via `rules/allowpaths/lists.yaml` |
| Security documentation API returning passwd-format examples | Medium | Allow the documentation path |
| `/bin/bash` appears in a log or error response alongside `/bin/sh` | Low | Allow the path or reduce token overlap |

If your application legitimately returns multiple passwd/shadow tokens in response
bodies:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `Anti_passwd_leak: false` in the CMC config.

---

## Performance notes

* The check runs **once per buffered response**, after all response bytes have been
  received — never during streaming.
* Aho-Corasick uses a single `find_iter` pass over the body; the iteration stops
  collecting after the second distinct pattern is found (early exit from counting).
* Vectorscan scans the body in one SIMD pass with `SINGLEMATCH`; the callback
  collects pattern IDs without issuing a `Scan::Terminate` until two IDs are found.
* No heap allocation is performed in the Aho-Corasick path beyond the `HashSet` used
  for deduplication; the set holds at most 9 (passwd) or 8 (shadow) entries.

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/anti_passwd_leak.rs` | Detector, `PASSWD_TOKENS`, `SHADOW_TOKENS`, `MultiMatcher`, Aho-Corasick/Vectorscan backends, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` field, `CmcManager` field, `inspect_response_body()` entry point |
| `src/waf/engine.rs` | Integration — `inspect_response_body()` called at the end of `inspect_response()` |
| `rules/cmc/config.yaml` | Default config — `Anti_passwd_leak: true` |

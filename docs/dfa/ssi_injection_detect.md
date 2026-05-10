# SSI-Injection-Detect DFA

Detects Server-Side Include (SSI) injection payloads in attacker-controlled input.
SSI injection lets an adversary embed directives that are executed by the web server
before the response is sent to the client, enabling file disclosure, command
execution, and lateral movement (`<!--#exec cmd="id"-->`,
`<!--#include file="/etc/passwd"-->`).

The detector covers two distinct SSI dialects:

* **Apache / Nginx `<!--#`** — the classic NCSA-style directive comment form.
* **JSP / JSTL / ColdFusion** — Java and CF server-side include/forward/execute tags.

---

## How it works

| Step | Detail |
|------|--------|
| **`<` scanning** | `memchr` finds every `<` in O(n) using SIMD on supported platforms, then the surrounding bytes are inspected. |
| **`<!--#` matching** | After `<!--`, optional whitespace, and a `#` character, the detector looks for any recognised SSI keyword before the closing `-->`. |
| **JSP/CF matching** | The raw tag bytes (e.g. `<jsp:include`) are compared case-insensitively at the current `<` position. |
| **Case-insensitive** | All keyword comparisons use byte-level ASCII case folding so `<!--#EXEC`, `<!--#Exec`, and `<!--#exec` are equivalent. |
| **Whitespace-tolerant** | Spaces and tabs between `<!--`, `#`, and the keyword are skipped. |

### Recognised Apache/Nginx directives

`include`, `exec`, `echo`, `config`, `fsize`, `flastmod`, `printenv`, `set`,
`if`, `elif`, `else`, `endif`

### Recognised JSP / JSTL / ColdFusion patterns

| Pattern | Label |
|---------|-------|
| `<jsp:include` | `<jsp:include` |
| `<jsp:forward` | `<jsp:forward` |
| `<c:import` | `<c:import` |
| `<cfinclude` | `<cfinclude` |
| `<cfexecute` | `<cfexecute` |

---

## Enabling the module

Add `SSI_injection_detect: true` to your DFA config file (default location
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
| Title | `DFA SSI injection detection` |
| Severity | `High` |
| CWE | [CWE-97](https://cwe.mitre.org/data/definitions/97.html) — Improper Neutralization of Server-Side Includes within a Web Page |
| Reference | [OWASP – SSI Injection](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection) |
| `rule_match` | `dfa::ssi_injection_detect:<matched-keyword>` |
| `rule_line_match` | `dfa/ssi_injection_detect.rs:generated` |

---

## Examples

### Blocked requests

```
GET  /page?name=<!--%23include%20file="/etc/passwd"%20-->   → 403   (include directive)
POST /search  body=<!-- #exec cmd="id" -->                  → 403   (exec directive)
GET  /q=<!--#PRINTENV-->                                    → 403   (printenv, upper-case)
GET  /tmpl=<!--# set var="x" value="owned" -->             → 403   (set directive with spaces)
GET  /x=<jsp:include page="/admin/config" />                → 403   (JSP include)
GET  /x=<cfexecute name="/bin/sh" arguments="-c id" />      → 403   (ColdFusion execute)
```

### Allowed requests

```
GET  /page?q=hello                                          → forwarded   (no SSI pattern)
GET  /article?title=The<!--comment-->article                → forwarded   (HTML comment, no #)
POST /form  body=user=admin                                 → forwarded   (no SSI syntax)
```

---

## False-positive guidance

Standard HTML comments (`<!-- ... -->`) and XML comments do not contain `#` after
the `<!--` token and are never matched.  False positives require input that literally
contains `<!--#keyword` or one of the JSP/CF tag prefixes — extremely unlikely in
normal application traffic.

If your application legitimately passes SSI-style content:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `SSI_injection_detect: false` in the DFA config.

---

## Performance notes

* `memchr` uses SIMD (SSE2/AVX2/NEON) to scan for `<` in one pass — **O(n/16)**
  on modern hardware for the initial scan.
* Per `<` hit, only a short bounded inspection (a few dozen bytes) is performed.
* No heap allocation; the detected label is a `String` but only allocated on match.

---

## Source files

| File | Purpose |
|------|---------|
| `src/dfa/ssi_injection_detect.rs` | Detector implementation, keyword tables, JSP patterns, unit tests |
| `src/dfa/mod.rs` | Module registration, `DfaConfig` field, `DfaManager` field, `inspect()` call |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `rules/dfa/config.yaml` | Default config — `SSI_injection_detect: true` |

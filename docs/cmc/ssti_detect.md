# SSTI-Detect CMC

Detects Server-Side Template Injection payloads across **22 template engine families**.
SSTI allows an attacker who can influence a template string to execute arbitrary code
on the server — escalating from reflected-XSS to RCE in a single step.  The CMC
recognises the distinctive delimiter pairs and control-directive forms of every major
template engine in production use.

---

## How it works

| Step | Detail |
|------|--------|
| **Delimiter scanning** | The detector scans the input for `open` tokens and then searches within a bounded window (`max_len`) for the matching `close` token.  Finding both within the window fires the rule. |
| **Specificity ordering** | Longer or more-specific patterns are tested before shorter aliases to prevent prefix shadowing (e.g. `{{=` is checked before `{{`, `$!{` before `${`). |
| **Velocity whitespace** | Velocity `#set(`, `#foreach(`, `#if(`, `#while(` directives also match with arbitrary whitespace between the keyword and the opening parenthesis (`#set  (` is valid Velocity). |
| **Freemarker bracket** | `[#letter…]` and `[/#letter…]` bracket-directive forms are detected by inspecting the character following `[#` or `[/#` for any ASCII letter. |
| **No preprocessing** | URL decoding and case normalisation have already been applied by the engine; the CMC operates on the ready-to-inspect string. |

### Recognised rules

| Rule ID | Pattern | Engine family |
|---------|---------|---------------|
| 1 | `{{ ... }}` | Jinja2, Twig, Nunjucks, Pebble, Handlebars |
| 2 | `${ ... }` | Velocity, Spring EL, Freemarker, JSP-EL |
| 3 | `#{ ... }` | Ruby, Kotlin, Scala string interpolation |
| 4 | `<%= ... %>` | Ruby ERB, ASP classic |
| 5 | `<% ... %>` | ERB, ASP classic block |
| 6 | `{{= ... }}` | Handlebars raw output, Angular |
| 7 | `{= ... }` | Slim |
| 8 | `\n= ... \n` | Slim line expression |
| 9 | `*{ ... }` | Thymeleaf selection variable |
| 10 | `@{ ... }` | Thymeleaf URL expression |
| 11 | `@( ... )` | Razor, Blazor |
| 12 | `{% ... %}` | Jinja2, Django, Twig block tags |
| 13 | `<# ... >` | Apache Freemarker angle-bracket directive |
| 14 | `#set( ... )` | Apache Velocity |
| 15 | `[[ ... ]]` | Tornado, Vue.js |
| 16 | `$!{ ... }` | Velocity null-safe output reference |
| 17 | `[# ... ]` | Freemarker bracket-directive form |
| 18 | `[= ... ]` | Freemarker inline expression |
| 19 | `#foreach( ... )` | Apache Velocity |
| 20 | `#if( ... )` | Apache Velocity |
| 21 | `#while( ... )` | Apache Velocity |
| 22 | `~{ ... }` | Thymeleaf fragment expression |

---

## Enabling the module

Add `SSTI_detect: true` to your CMC config file (default location
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
| Title | `CMC SSTI detection` |
| Severity | `High` |
| CWE | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) — Improper Neutralization of Special Elements in Template Engines |
| Reference | [OWASP WSTG – Testing for SSTI](https://owasp.org/www-project-web-security-testing-guide/) |
| `rule_match` | `cmc::ssti_detect:<id>:<pattern>` |
| `rule_line_match` | `cmc/ssti_detect.rs:generated` |

---

## Examples

### Blocked requests

```
GET /greet?name={{7*7}}                          → 403   (Jinja2/Twig — rule 1)
GET /page?tmpl={% debug %}                       → 403   (Jinja2 block — rule 12)
POST /render  body=${''.class.forName('...')}    → 403   (Spring EL — rule 2)
GET /doc?x=<#assign%20x=7>                      → 403   (Freemarker — rule 13)
GET /msg?v=#set($x%20=%207*7)                    → 403   (Velocity — rule 14)
GET /item?q=[[user.name]]                        → 403   (Tornado/Vue — rule 15)
GET /price?v=*{T(java.lang.Runtime).exec('id')} → 403   (Thymeleaf — rule 9)
```

### Allowed requests

```
GET /search?q=hello+world                        → forwarded   (no template delimiter)
GET /items?filter=price>10                       → forwarded   (no matching open+close pair)
POST /form  body=user=admin&pass=secret          → forwarded   (no template syntax)
```

---

## False-positive guidance

Many of the delimiters (`{{ }}`, `${ }`, `#{ }`) appear in legitimate JSON,
shell scripts, or code-containing fields.  The detector requires **both** an
opening and a closing token within a 256–512 byte window, which reduces false
positives on inputs that contain only one half.

If your application legitimately accepts template-like syntax in fields:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `SSTI_detect: false` in the CMC config.

---

## Performance notes

* Each pattern performs at most **two substring scans** (open token + close token).
  The bounded window (`max_len`) caps the inner scan length regardless of input size.
* Patterns are tested in most-to-least-specific order; once a match is found the
  remaining patterns are skipped.
* No heap allocation is performed; all scanning operates on borrowed slices of the
  input string.

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/ssti_detect.rs` | Detector implementation, rule enum, bounded-search helpers, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` field, `CmcManager` field, `inspect()` call |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `rules/cmc/config.yaml` | Default config — `SSTI_detect: true` |

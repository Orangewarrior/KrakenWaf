# Overflow-Detect CMC

Detects two distinct classes of overflow-style attack: **shellcode injection** and
**repeated-character flooding**.  These are the two most common payload shapes used
to exploit buffer overflows, format-string vulnerabilities, and path-traversal
parsers in HTTP request fields.

---

## How it works

The module runs two independent sub-detectors on each inspected string.

### Sub-detector 1 — Shellcode opcode recognition

| Step | Detail |
|------|--------|
| **Byte extraction** | The input is scanned for escape sequences in any of the forms `\xNN`, `%NN`, `0xNN`, or `\u00NN` and decoded to a raw byte slice. Unrecognised characters are skipped. |
| **NOP-sled detection** | Four or more consecutive `0x90` bytes ⇒ x86/x64 NOP sled. Two or more `00 00 a0 e1` sequences ⇒ ARM NOP. Four or more `c0 46` sequences ⇒ Thumb NOP. These patterns fire with a score proportional to the sled length. |
| **Opcode cluster scoring** | Each architecture has a weighted pattern list. Matched patterns accumulate a score; a score ≥ 3 fires the detector with the architecture label and first-matched pattern. |

**x86-32 patterns scored**

| Byte sequence | Label |
|---------------|-------|
| `cd 80` | Linux `int 0x80` syscall |
| `31 c0 50 68` | `xor eax / push` shellcode prologue |
| `31 db 31 c9 31 d2` | Zero `ebx/ecx/edx` registers |
| `6a 0b 58 99 52` | `execve` syscall setup |
| `31 c0 b0 0b` | `execve` eax syscall number |
| `eb 1f 5e 89 76` | JMP-CALL-POP decoder stub |
| `2f 62 69 6e 2f 73 68` | Embedded `/bin/sh` |

**x86-64 patterns scored**

| Byte sequence | Label |
|---------------|-------|
| `0f 05` | Linux `syscall` instruction |
| `48 31 d2` | `xor rdx, rdx` |
| `48 31 f6` | `xor rsi, rsi` |
| `48 31 ff` | `xor rdi, rdi` |
| `48 bb` | `movabs rbx` immediate |
| `6a 3b 58 0f 05` | `execve` syscall setup |
| `48 89 e7` | `mov rdi, rsp` |
| `2f 62 69 6e 2f 73 68` | Embedded `/bin/sh` |

**ARM / Thumb patterns scored**

| Byte sequence | Label |
|---------------|-------|
| `01 30 8f e2` | ARM ADR/ADD PC shellcode prologue |
| `13 ff 2f e1` | ARM-to-Thumb `bx` transition |
| `0b 27 01 df` | Thumb `execve svc` |
| `78 46 0a 30` | Thumb PC-relative shellcode setup |
| `04 e0 2d e5` | ARM `push lr / stmdb sp` |
| `2f 62 69 6e 2f 73 68` | Embedded `/bin/sh` |

### Sub-detector 2 — Repeated-character / overflow flooding

| Pattern | Threshold | Triggered as |
|---------|-----------|--------------|
| Same character repeated consecutively | 10 chars | `ch` = repeated character |
| Consecutive ASCII digit run | 30 digits | `ch = '0'` |
| Format specifiers (`%n`, `%p`, `%s`, `%x`, `%d`, `%u`) | 5 specifiers | `ch = '%'` |
| Path traversal segments (`../`) | 5 segments | `ch = '.'` |

---

## Enabling the module

Add `Overflow_detect: true` to your CMC config file (default location
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

## Detection findings

Two distinct findings can be emitted depending on which sub-detector fires:

### Shellcode finding

| Field | Value |
|-------|-------|
| Title | `CMC shellcode opcode detection` |
| Severity | `High` |
| CWE | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) — Improper Control of Generation of Code |
| Reference | [OWASP – Buffer Overflow Attack](https://owasp.org/www-community/attacks/Buffer_overflow_attack) |
| `rule_match` | `cmc::overflow_detect:shellcode:<arch>:<pattern> score=<N>` |
| `rule_line_match` | `cmc/overflow_detect.rs:generated` |

### Repeated-character finding

| Field | Value |
|-------|-------|
| Title | `CMC repeated-character overflow detection` |
| Severity | `Medium` |
| CWE | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) — Uncontrolled Resource Consumption |
| Reference | [CWE-400 detail](https://cwe.mitre.org/data/definitions/400.html) |
| `rule_match` | `cmc::overflow_detect:repeated-char=<ch> count=<N>` |
| `rule_line_match` | `cmc/overflow_detect.rs:generated` |

---

## Examples

### Blocked requests

```
GET /search?q=AAAAAAAAAAAAA                      → 403   (repeated 'A', count=13)
POST /upload  body=%90%90%90%90%90%cc            → 403   (x86 NOP sled)
GET /name=%n%n%n%n%n%n                           → 403   (format specifiers, count=6)
GET /../../../../../../etc/passwd                → 403   (traversal, segments=6)
POST /exec  body=\x31\xc0\x50\x68...\xcd\x80    → 403   (x86 execve shellcode)
```

### Allowed requests

```
GET /search?q=hello                              → forwarded   (no overflow pattern)
GET /path/to/resource                            → forwarded   (normal path, no traversal)
POST /form  body=param=value                     → forwarded   (no repeated chars above threshold)
```

---

## False-positive guidance

* **Repeated-character flooding** may fire on legitimate base64 payloads with long
  runs of the same character (e.g. `AAAA...` padding).  Increase the threshold or
  allow the specific endpoint.
* **Shellcode detection** targets encoded binary sequences; plain text never matches.
  False positives require a field that literally contains `\x90\x90...` — unusual in
  production traffic.

Options to address false positives:

1. **Allow-path**: add the specific path to `rules/allowpaths/lists.yaml`.
2. **Disable the module**: set `Overflow_detect: false` in the CMC config.

---

## Performance notes

* Byte extraction is a single O(n) pass with a small write buffer.
* NOP-sled and opcode-cluster checks iterate the extracted byte slice once each.
* Repeated-character flooding is a single-pass character iterator — no heap allocation.
* Shellcode detection only runs if the byte-extraction pass yields at least one
  decoded byte, so inputs with no escape sequences exit early.

---

## Source files

| File | Purpose |
|------|---------|
| `src/cmc/overflow_detect.rs` | Detector implementation, opcode tables, unit tests |
| `src/cmc/mod.rs` | Module registration, `CmcConfig` field, `CmcManager` field, `inspect()` calls |
| `src/waf/engine.rs` | Integration — `inspect()` called in the main WAF pipeline |
| `rules/cmc/config.yaml` | Default config — `Overflow_detect: true` |

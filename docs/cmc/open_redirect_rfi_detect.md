# Open Redirect & RFI CMC

Detects and blocks **Open Redirect** and **Remote/Local File Inclusion (RFI)**
attacks by inspecting redirect/inclusion-prone request *parameters* — the URL
query string on `GET`, and the body on `POST` (and other body-bearing methods).
When a "hot" parameter carries a value that resolves to an external /
scheme-relative URL, a dangerous scheme, a PHP/inclusion wrapper, or a
path-truncation marker, the WAF blocks the request before the upstream
application is ever reached.

---

## How it works

The decision is two-stage: a **hot-parameter gate** followed by a **value
classification**.

### 1. Hot-parameter gate

A parameter is only inspected when its (decoded, lowercased) **name** matches a
redirect/inclusion-prone token. The base list, `hot_params_english`, is always
active:

```
redirect  url     return    open   u    r    href   next   callback  last
dest      uri     target    continue   page   module   path   template
file      include inc       doc    document   folder   root   dir   view
load      show
```

Matching is:

| Token kind | Rule | Example |
|------------|------|---------|
| Multi-character (`page`, `redirect`, `url`, …) | **substring containment** | `homepage` matches `page`; `redirect_url` matches both `redirect` and `url` |
| Single-character (`u`, `r`) | **exact** match only | `u` matches `u`, but `username` does **not** |

The single-character tokens use exact matching on purpose — substring matching
on `u`/`r` would flag almost every parameter and produce noise.

### 2. Value classification

The matched parameter's **value** is decoded through the global normalizer
(UTF-16BE/LE transcode → repeated percent-decode up to 4 passes → `+`→space),
then its **leading control/whitespace bytes are stripped**
(`strip_control_and_space_prefix`). The cleaned value is then tested:

| Condition | Verdict | Severity | CWE |
|-----------|---------|----------|-----|
| Decoded value **starts with** an `OPEN_REDIRECT_STARTS_WITH` entry | **Open Redirect** | High | CWE-601 |
| Decoded value **starts with** an `RFI_STARTS_WITH` entry | **RFI** | High | CWE-98 |
| Decoded value **ends with** `?` or `%00` (NUL) | **RFI** | High | CWE-98 |

`OPEN_REDIRECT_STARTS_WITH`:

```
//   ///   \\   \   /\   \/
http:  https:  ws:  wss:  ftp:  ftps:  file:  javascript:  data:
vbscript:  blob:  about:  view-source:  intent:  android-app:
market:  itms-services:
```

`RFI_STARTS_WITH`:

```
php:  php://  php://filter  php://input  php://memory  php://temp
expect:  expect://  zip:  zip://  phar:  gopher:  dict:  ldap:  ldaps:
glob:  zlib:  compress.zlib:  compress.bzip2:  rar:  ogg:
```

A single-slash relative path such as `homepage=/test/local` is **not** flagged:
it starts with one `/`, not `//`, and carries no dangerous scheme or marker.

---

## Encoding-evasion coverage

Every decoding step is delegated to the shared normalizer, so the module sees
through the obfuscations pentesters use:

| # | Payload | Decoded | Verdict |
|---|---------|---------|---------|
| 1 | `next=//evil.example/path` | `//evil.example/path` | Open Redirect |
| 2 | `next=%2f%2fevil.example` | `//evil.example` | Open Redirect |
| 3 | `next=%252f%252fevil.example` | `//evil.example` | Open Redirect (double-encoded) |
| 4 | `next=https%3a%2f%2fevil.example` | `https://evil.example` | Open Redirect |
| 5 | `next=hTtPs://evil.example` | `https://evil.example` | Open Redirect (mixed case) |
| 6 | `next=\\evil.example\login` | `\\evil.example\login` | Open Redirect (backslash) |
| 7 | `next=%5c%5cevil.example` | `\\evil.example` | Open Redirect (encoded backslash) |
| 8 | `next=https://trusted.example@evil.example` | userinfo confusion | Open Redirect |
| 9 | `next=https%3a%2f%2ftrusted.example%40evil.example` | encoded userinfo | Open Redirect |
| 10 | `next=%09%0d%0ahttps://evil.example` | `https://evil.example` after control-prefix strip | Open Redirect |

Case 10 is the reason the control-prefix strip lives in the **normalizer**
(`strip_control_and_space_prefix`) rather than in this module alone: stripping a
leading run of C0 control characters and spaces — mirroring the WHATWG URL
parser — is a global hardening that benefits **every** CMC module that inspects
a decoded field. Control bytes in the *middle* of a value (e.g. an injected CRLF)
are preserved so other detectors still see them.

---

## Multi-language hot parameters

By default only `hot_params_english` is used. To inspect localized parameter
names too, set `multiple-languages-params: true` and enable the specific
languages under `custom-languages-params`. Each enabled language adds its list
to the search set **in addition to** English.

```yaml
# rules/cmc/config.yaml
multiple-languages-params: true
custom-languages-params:
  russian: false
  japanese: true        # adds hot_params_japanese (リダイレクト, 戻り, …)
  german: false
  bengali: false
  indonesian: false
  french: false
  arabic_modern: false           # alias of arabic_modern_standard
  arabic_modern_standard: false
  spanish: true         # adds hot_params_spanish (redirigir, destino, …)
  chinese_mandarin: false   # pinyin list (chongdingxiang, fanhui, …)
  chinese: false            # Han characters list (重定向, 返回, …)
  hindi: false
  portuguese: false     # adds hot_params_portuguese (redirecionamento, carregar, …)
```

Notes:

* The master switch `multiple-languages-params` must be `true` for **any**
  localized list to apply; with it `false`, only English is used even if
  individual language flags are `true`.
* `chinese_mandarin` (romanized pinyin) and `chinese` (Han characters) are
  **separate** lists — enable whichever your traffic uses.
* `arabic_modern` and `arabic_modern_standard` both map to the single Arabic
  Modern Standard list.
* Every language defaults to `false`; customise for your application's audience.

---

## Enabling the module

Add `Open_redirect_n_RFI_detect: true` to your CMC config (default
`rules/cmc/config.yaml`) under `CMC-Rules:` and load it with `--cmc-load`.
Setting it to `false` (the default) disables the module entirely.

```yaml
# rules/cmc/config.yaml
CMC-Rules:
  # … other modules …
  Open_redirect_n_RFI_detect: true   # ← add this line
```

```sh
krakenwaf \
  --no-tls \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --cmc-load rules/cmc/config.yaml
```

---

## Reporting

Every detection is logged to **all** outputs (raw, JSONL, SQLite) at **High**
severity and the engine returns **HTTP 403** to the attacker. The finding's
`rule_match` records the verdict, the parameter, the matched hot token, and the
prefix/marker that triggered it, e.g.:

```
cmc::open_redirect_rfi_detect:kind=open_redirect parameter=next token=next marker=https:
cmc::open_redirect_rfi_detect:kind=rfi parameter=file token=file marker=php://filter
cmc::open_redirect_rfi_detect:kind=rfi parameter=file token=file marker=trailing-%00
```

---

## Source

* Detector + classification: `src/cmc/open_redirect_rfi_detect.rs`
* Config wiring: `src/cmc/mod.rs`
* Normalizer mitigation: `src/waf/engine/normalize.rs`
  (`strip_control_and_space_prefix`)
* Engine entry point: `WafEngine::inspect_open_redirect_rfi` in
  `src/waf/engine/mod.rs`, called from `src/proxy/mod.rs`
* DAST sweep: `OPEN_REDIRECT_RFI_PAYLOADS` in `src/bin/attack.rs`
* Integration test: `cmc_open_redirect_rfi_payload_sweep_get_and_post` in
  `tests/server_real_test.rs`

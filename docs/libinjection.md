# Vendored libinjection FFI

KrakenWAF vendors **libinjection 4.0.0** under `ffi/libinjection/vendor/libinjection-4.0.0/src`
and builds it with `cc` when the `libinjection-engine` feature is enabled.

## Build
- `build.rs` compiles:
  - `libinjection_sqli.c`
  - `libinjection_xss.c`
  - `libinjection_html5.c`
  - `ffi/libinjection/vendor/kwaf_libinjection.c`

## Rust entry points
- `src/ffi/libinjection/mod.rs`
  - `detect_sqli(input: &[u8])`
  - `detect_xss(input: &[u8])`

## CLI
- `--enable-libinjection-sqli`
- `--enable-libinjection-xss`

## Notes
- SQLi returns the native libinjection fingerprint when present.
- XSS returns `xss-match` because libinjection XSS exposes a boolean detector.


## Full request scope

Libinjection inspection now receives the full HTTP request view assembled by KrakenWaf: method, URI, headers, and body. This ensures GET query parameters, POST form fields, JSON bodies, and other REST payloads are inspected consistently.

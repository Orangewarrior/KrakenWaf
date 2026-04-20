## [2.8.0] - 2026-04-20

### Security — Critical & High severity fixes (AppSec + Rust expert review)

#### Network / Request handling
- **H1 — XFF IP spoofing**: replaced leftmost `X-Forwarded-For` parsing with rightmost-trusted algorithm (RFC 7239 §5.3); client-controlled headers can no longer spoof the rate-limiter or block-list (`src/proxy.rs`).
- **H4 — Unbound upstream response / OOM**: `response.bytes()` replaced with a chunked streaming loop bounded by `--max-upstream-response-bytes` (default 100 MiB); a malicious upstream can no longer exhaust process memory (`src/proxy.rs`, `src/cli.rs`).
- **H9 — Semaphore acquired after `accept()`**: connection-limit semaphore is now acquired *before* `listener.accept()`, preventing SYN-flood exhaustion of the semaphore pool (`src/server.rs`).

#### WAF engine
- **H2 — `std::sync::RwLock` poisoning**: migrated WAF engine locks to `parking_lot::RwLock`, which never poisons; removed all `.unwrap_or_else(|p| p.into_inner())` fallbacks (`src/waf/engine.rs`).
- **H5 — Hot-path `to_lowercase` allocation**: DFA lowercasing is now scoped to the DFA phase only; keyword and regex phases reuse the already-normalized buffer (`src/waf/engine.rs`).
- **Issue 7 — Race condition on rules hot-reload**: introduced `RulesSnapshot` struct holding `Arc<RuleSet>` + `EngineMatchers` behind a single `RwLock<Arc<RulesSnapshot>>`; `reload_from_dir` swaps the arc atomically so in-flight requests always see a consistent rule set (`src/waf/engine.rs`).

#### Storage / Persistence
- **H6 — SQL string interpolation**: `sea-orm` raw query replaced with `Statement::from_sql_and_values` parameterised binding; no SQL injection possible via rule-name input (`src/storage.rs`).
- **Issue 8 — Non-atomic rate-limit snapshot write**: snapshot is now written to a `.json.tmp` sibling file then `fs::rename`d into place; a crash mid-write can no longer corrupt the persisted counters (`src/waf/rate_limit.rs`).
- **H7 — TLS SNI logged before move**: SNI string is extracted before `ClientHello` is consumed; fallback-cert selection now logs a `WARN` with the SNI value instead of silently swallowing the event (`src/tls.rs`).

#### Configuration / YAML
- **H8 — YAML boolean coercion (`true` → 0)**: DFA config loader uses a `#[serde(untagged)] BoolOrInt` enum; `true`/`false` YAML values are mapped to `1`/`0` with a warning instead of silently disabling DFA engines (`src/dfa/mod.rs`).

#### FFI / C interop
- **Issue 1 — FFI fingerprint buffer overflow**: `collect_fingerprint` no longer calls `CStr::from_ptr` on a C buffer that may lack a null terminator; scans for the null byte within known bounds and casts byte-by-byte (`src/ffi/libinjection/mod.rs`).

#### Input validation
- **Issue 3 — Path traversal in `--blockmsg`**: `std::fs::canonicalize` + `starts_with(root)` check prevents reading files outside the process working directory even under symlink or `../` attacks (`src/main.rs`).

#### Logging
- **Issue 9 — Log injection via unquoted key=value fields**: `sanitize_for_log` now escapes embedded `"` characters; all fields in `write_critical` are quoted, preventing injected payloads from forging extra key=value pairs in the critical log (`src/logging.rs`).

#### H3 / Response builder panics
- `Response::builder()` call sites migrated to `.unwrap_or_else` fallbacks; server no longer panics on malformed header construction (`src/proxy.rs`, `src/server.rs`).

### Build system
- **Duplicate-symbol linker error**: removed erroneous `--whole-archive` + triple `cargo:rustc-link-lib` directives that caused `rust-lld: duplicate symbol: libinjection_is_xss` on lld-based toolchains (`build.rs`).
- **Undefined-symbol linker error**: added `cargo:rustc-link-arg=<OUT_DIR>/libkwaf_libinjection.a` to pass the C archive as a direct positional argument to the binary linker. Fixes a Cargo edge case where `cargo:rustc-link-lib=static=` is not propagated from lib → bin within the same package on lld/Fedora toolchains (`build.rs`).

---

## [2.7.37] - 2026-04-16

### Added
- Vendored **real libinjection 4.0.0** C sources under `ffi/libinjection/vendor/libinjection-4.0.0/src`.
- Added a real `cc` build pipeline in `build.rs` for libinjection SQLi/XSS FFI.
- Added `docs/libinjection.md` documenting the vendored FFI integration.
- Added `docs/deployment.md` documenting trusted reverse-proxy deployment for rate limiting and real-client IP extraction.

### Changed
- Replaced the placeholder compatibility shim with a real FFI wrapper built on top of libinjection 4.0.0.
- Optimized `src/dfa/esi_injection_detect.rs` to use `memchr` + byte scanning instead of `to_lowercase()` + repeated `contains()`.
- Optimized `src/dfa/ssi_injection_detect.rs` to use `memchr` + byte scanning instead of `to_lowercase()` + repeated `contains()`.
- Added CLI support for trusted proxy CIDRs and a configurable real-IP header:
  - `--trusted-proxy-cidrs`
  - `--real-ip-header`

### Fixed
- Recovered safely from poisoned `RwLock` guards in the WAF engine instead of panicking.
- Emitted explicit warnings when the lenient DFA YAML parser yields an empty/invalid configuration instead of silently disabling DFA engines.

## [2.7.22] - 2026-04-06

### Added
- New `enable` field support across all JSON rule files under `rules/`.
- Rules with `"enable": 0` are now skipped during KrakenWAF initialization.

### Changed
- Updated bundled JSON rule files to include `"enable": 1` before `title` in every rule entry.

## 2.7.21

- cleaned up DFA integration warnings reported during build
- removed unused `SstiRule` re-export
- removed unused `dfa_manager` field from `AppState`
- removed unused `DfaManager::enabled()` helper
- removed unused `OverflowDfa::detect_overflow()` helper

## 2.7.20

- added safe DFA modules under `src/dfa` for SQLi comment evasion, repeated-character overflow, SSTI, SSI injection and ESI injection
- added lenient YAML DFA config loader with `--dfa-load` and example config at `rules/dfa/config.yaml`
- integrated DFA findings into the normal KrakenWAF block pipeline, including JSONL, raw critical log and SQLite evidence storage
- documented DFA schema and runtime behavior in `docs/dfa/schema.md`


## 2.7.19

- added focused regex packs for LFI/RFI/traversal, SSRF, command injection, protocol anomalies, and suspicious header patterns
- added optional response header protection injection via `--header-protection-injection`
- shipped five response header policy templates under `rules/headers_http/`
- injects configured response hardening headers on forwarded and local responses while skipping websocket upgrade responses
- fixed response/header formatting regressions in proxy helpers

## 2.7.18
- Fixed vendored libinjection FFI static linking by explicitly linking the cc-built archive from the Rust bindings.
- Silenced unused internal libinjection detection warnings.

## 2.7.17

- Replaced the deprecated external `libinjection-rs` build chain with an internal vendored C FFI module under `ffi/libinjection/vendor`, removing the old Python 2 / make dependency from KrakenWaf builds.
- Added versioned Rust bindings in `src/ffi/libinjection/bindings.rs` and a safe wrapper API in `src/ffi/libinjection/mod.rs`.
- Added a `build.rs` that uses `cc` only when the `libinjection-engine` feature is enabled.
- Added independent runtime flags `--enable-libinjection-sqli` and `--enable-libinjection-xss` while keeping the legacy hidden `--enable-libinjection` flag as a compatibility shortcut.
- Integrated libinjection-compatible SQLi and XSS detections into the existing finding / JSONL / raw / SQLite logging pipeline so matches now produce normal structured block events.

## 2.7.16

- Refactored security-event persistence and logging so blocked GET and POST requests now emit a complete structured event with `engine`, `reference_url`, `fullpath_evidence`, `method`, `uri`, `rule_match`, and `rule_line_match` in the text and JSON logs.
- Fixed the body-streaming block path to propagate the original finding instead of collapsing it into a generic warning, so Vectorscan and regex POST detections now persist the same rich context as early/query detections.
- Reworked the SQLite `vulnerabilities` schema for forensics and CSIRT workflows:
  - `title VARCHAR(256)`
  - `severity VARCHAR(32)`
  - `cwe VARCHAR(128)`
  - `occurred_at TIMESTAMP`
  - `rule_line_match VARCHAR(256)`
  - `client_ip VARCHAR(64)`
  - `http_method VARCHAR(16)`
  - `engine VARCHAR(32)`
  - `request_uri TEXT`
  - `fullpath_evidence TEXT`
  - `request_payload TEXT`
- Added an automatic schema migration from the older all-`TEXT` table to the richer v2 table, preserving prior rows and inferring the engine where possible.
- Kept the full raw request (request line + headers + captured payload) only in SQLite for forensics, while intentionally excluding it from JSONL and raw line logs to avoid oversized log lines.

## 2.7.15

- Improved Vectorscan rule compilation errors to report the exact failing rule number, source file, source line, title, and `rule_match` content.
- Added an isolated per-rule fallback check when the full Vectorscan database fails to compile, so malformed patterns are easier to identify.
- Clarified Vectorscan error guidance to explain that metacharacters such as `(` may need escaping, with an example like `sleep\(`.

## 2.7.14
- fixed Vectorscan matcher compilation against `vectorscan-rs 0.0.6` by removing an invalid `.map_err()` call on `Pattern::new`, which returns a `Pattern` directly
- kept Vectorscan rules as literals instead of regex-escaped patterns
- improved Vectorscan rule validation with clear errors for empty literals and embedded NUL bytes

## 2.7.13

- Fixed invalid packaged regex rule files by converting the bundled JSON regex patterns to valid JSON-escaped strings in `rules/regex/body_regex.json` and `rules/regex/path_regex.json`.
- Restored the packaged SQLi regex rules for URI/query and POST body inspection.
- Fixed Vectorscan rule compilation by treating packaged Vectorscan rules as **literal strings** before compiling them for `vectorscan-rs`, so strings like `sleep(` no longer crash startup.
- Improved Vectorscan startup errors to show the source file, rule index, title, and literal content when a user-authored rule cannot be compiled.
- Updated `README.md` with the corrected local DVWA lab instructions, including the exact OpenSSL command, the correct `rules/tls/sni_map.csv` contents, and the final command line used to run KrakenWaf in front of DVWA with Vectorscan enabled.
- Bumped crate version to `2.7.13`.

## 2.7.12

- Fixed invalid regex patterns in `rules/regex/body_regex.json` and `rules/regex/path_regex.json` that were missing a closing parenthesis and caused startup failure with `Pattern compilation failed`.
- Bumped crate version to `2.7.12`.

## [2.7.11] - 2026-04-05

### Fixed
- Corrigido erro de compilação em `src/waf/engine.rs` causado por caracteres literais de nova linha/carriage return/NUL em `inspection_views`, substituindo-os por escapes válidos (`\n`, `\r`, `\0`).

# Changelog

## [2.7.10] - 2026-04-05

### Fixed
- Corrected body inspection for long and multi-field requests by retaining overlap from the full inspection window instead of only the last bytes of the newest chunk.
- Normalized `application/x-www-form-urlencoded` payloads more accurately by converting `+` to spaces before percent-decoding, allowing literal SQLi and XSS signatures to match real DVWA form submissions.
- Expanded payload inspection so normalized request content is evaluated both as a whole buffer and as per-field/per-line segments split on `&`, newlines, and NUL bytes, improving Vectorscan and regex coverage on attacker-controlled POST bodies.

### Detection
- Refreshed the bundled Vectorscan fast-literal bundle with 10 OWASP-aligned rules covering SQLi, XSS, traversal, command injection, and downloader activity.
- Added regression tests for form-urlencoded `+` payloads and long POST payloads that previously could evade the smaller streaming overlap behavior.

### Changed
- Bumped the crate version to `2.7.10`.

## [2.7.9] - 2026-04-05

### Fixed
- Corrected request inspection so attacker-controlled GET query strings are actively inspected before proxying upstream, instead of only being forwarded in `path_and_query`.
- Normalized attacker-controlled GET and POST payloads before matching by percent-decoding and converting to lowercase, reducing bypasses based on mixed-case payloads and encoded delimiters.
- Preserved original payload samples in findings/logging while matching against normalized content internally.

### Detection
- Applied the normalization pass consistently to URI, headers, and full request payload inspection so keyword, regex, optional libinjection, and optional Vectorscan checks all evaluate canonical lowercase content.
- Added regression tests for encoded DVWA-style GET SQLi payloads and uppercase encoded POST XSS payloads.

### Changed
- Bumped the crate version to `2.7.9`.

## [2.7.8] - 2026-04-05

### Fixed
- Replaced the incompatible `vectorscan = 0.1.0` integration with the current stable `vectorscan-rs = 0.0.6` API.
- Reworked `src/waf/engine.rs` to build a `BlockDatabase` from literal `Pattern` values and scan request bodies with `BlockScanner`, fixing the unresolved import and callback API breakage seen with newer stable Vectorscan crates.
- Added `Clone` support to the internal `VectorscanMatcher` so matcher snapshots remain reload-safe.

### Detection
- Expanded bundled URI, body, regex, and Vectorscan rule sets with DVWA-oriented SQLi, XSS, traversal, and command-execution probes for easier lab validation.
- Preserved fast literal matching for attacker-controlled request content in both GET query strings and POST bodies.
- Added integration tests that assert the WAF blocks representative DVWA GET and POST payloads, plus a feature-gated Vectorscan fast-literal test.

### Changed
- Bumped the crate version to `2.7.8`.
- Kept the TLS/SNI and hot-reload behaviour from the previous branch while refreshing the packaged rules for easier out-of-the-box testing.

## [1.2.7] - 2026-04-04

### Fixed
- Corrigido o parser de reparo de escapes JSON em `src/rules/loader.rs`, substituindo literais de caractere inválidos por escapes corretos com `\\`, eliminando o erro `E0762: unterminated character literal`.
- Mantido o diretório raiz do artefato alinhado com a versão atual do projeto.

### Changed
- Atualizado `crypto-common` para `0.1.7`.
- Atualizado `generic-array` para `1.3.5`.

## [1.2.6] - 2026-04-04

### Fixed
- Updated the reqwest feature set for the 0.13.x line by replacing the removed `rustls-tls` feature with the current `rustls` feature.
- Resolved Cargo dependency selection failure when building with the latest stable reqwest release.

### Changed
- Bumped the package version to 1.2.6.
- Renamed the packaged project root directory to `Kraken_v1.2.6`.


## [1.2.5] - 2026-04-04

### Fixed
- Repaired `src/rules/loader.rs` JSON escape repair logic to correctly match and emit backslash character literals, fixing the `E0762 unterminated character literal` build failure reported by `cargo test`.
- Kept the JSON rule loader tolerant of regex-style escape sequences embedded in JSON rule files while using valid Rust character escaping.

### Changed
- Bumped package version to `1.2.5`.
- Updated `reqwest` to `0.13.2`.
- Updated `thiserror` to `2.0.18`.
- Added explicit `generic-array = "0.14.9"` in `Cargo.toml` so the manifest reflects the newer stable line requested for the dependency set.

## [1.2.4] - 2026-04-04

### Fixed
- Made the JSON rule loader tolerant to regex-style backslash escapes inside rule files generated by tests and operator-authored bundles, automatically repairing invalid JSON string escapes like `\s`, `\d`, and similar regex tokens before deserialization. This fixes the failing `loads_external_rule_tree` integration test for `regex/body_regex.json`.
- Preserved the prior `vectorscan = 0.1.0` dependency alignment and versioned release metadata.

### Packaging
- Versioned the release as `1.2.4` and prepared the ZIP to open under a versioned root directory instead of the old `KrakenWaf-1.1` folder name.

## [1.2.3] - 2026-04-04

### Fixed
- Restored the missing `std::path::PathBuf` import in `src/app.rs` after the AppState cleanup/refactor, fixing the `cannot find type PathBuf in this scope` build failure reported by `cargo test`.
- Kept the previously applied Hyper builder lifetime fix, `Arc<AppState>` ownership fix, and `vectorscan = 0.1.0` dependency alignment intact in this patch release.

### Maintenance
- Bumped the crate version to `1.2.3` to clearly mark the post-patch compilation fix release.

## [1.2.2] - 2026-04-04

### Fixed
- Fixed rate limiter background persistence so unit and integration tests can construct the WAF without an active Tokio runtime; the persistence task now starts only when a runtime handle is available.
- Removed the unused public re-export of `RateLimiter` from `src/waf/mod.rs` to eliminate the unused import warning.
- Removed the unused `root_dir` field from `AppState` and its initialization path.
- Marked logging guard retention fields as intentionally kept for process lifetime, preventing dead-code noise while preserving non-blocking logger safety.
- Marked rule-set storage fields that are intentionally retained for future Vectorscan expansion to avoid dead-code warnings without changing runtime behavior.

### Maintenance
- Performed a warning cleanup pass after the v1.2.1 patch release to keep the crate clean under `cargo test`.


# CHANGELOG

## 1.1 Coded by Orangewarrior, forked for my old version... but initial code is based in CoolerVoid's OctopusWAF, little WAF written in C language...

### Security hardening
- Replaced string-based IP blocklist checks with canonical `IpAddr` parsing.
- Added CIDR-aware range matching with `ipnet`.
- Preserved compatibility with legacy dotted prefix rules by normalizing entries such as `192.168.1.` into `/24`.
- Normalized allow-listed URL paths with percent-decoding and traversal collapse before comparison.
- Added upstream validation to reject local/private literal upstream targets by default.
- Added optional `--allow-private-upstream` escape hatch for controlled internal deployments.
- Removed the always-on `x-krakenwaf: true` fingerprinting header.
- Added configurable `--internal-header-name` for optional internal signaling without product disclosure.
- Added typed `Severity` enum and removed fragile string comparisons for persistence decisions.
- Sanitized forensic payloads with `ammonia::clean` plus control-character escaping before raw logging and persistence.

### Detection engine improvements
- Added Aho-Corasick for case-insensitive keyword detection without allocating lowercase copies of every request chunk.
- Enabled complete-payload inspection for every active engine, including Vectorscan when the feature is enabled.
- Added chunk-overlap inspection to reduce evasions where payloads cross chunk boundaries.
- Optimized finding payload truncation with `Cow<str>` and UTF-8 boundary-safe slicing.

### Storage and async architecture
- Replaced the mutex-based `rusqlite` hot-path writes with `SeaORM` and an async SQLite connection pool.
- Added an async event queue so blocking responses no longer wait on SQLite fsync in the request hot path.
- Added batched background inserts for security findings.
- Fixed the SQLite schema names:
  - `vulnerabilities`
  - `occurred_at`
- Added schema bootstrap with `PRAGMA user_version=1`.

### Rate limiting and availability
- Replaced the in-memory limiter mutex with an async Tokio mutex.
- Added eviction of expired counters to prevent unbounded memory growth.
- Added snapshot persistence for limiter state to reduce bypass-by-restart on single-instance deployments.
- Added Prometheus-style `/metrics` endpoint.
- Added `/__krakenwaf/health` endpoint.
- Added connection semaphore limiting to reduce slow-connection exhaustion.

### TLS and operations
- Added explicit default certificate selection through a fourth `default=true` column in the SNI CSV.
- Added SIGHUP-driven hot reload for rule files without full process restart.
- Switched text, JSON, and critical log sinks to daily rotation.

### CLI changes
- `--blocklist-ip` is now a proper boolean flag.
- Added `--allow-private-upstream`
- Added `--internal-header-name`
- Added `--max-connections`
- Added `--connection-timeout-secs`

### Notes
- Multi-instance global rate limiting still requires an external shared backend such as Redis.
- Hostname-based upstream SSRF prevention still depends on deployment-side DNS and network policy because literal-IP validation cannot prove what every hostname resolves to at runtime.

## 1.2.1 - patch fixes

### Fixed
- Updated `vectorscan` dependency to `0.1.0` in `Cargo.toml` so dependency resolution matches crates.io.
- Fixed Hyper connection builder lifetime in `src/server.rs` by binding the builder before `serve_connection`.
- Fixed moved `Arc<AppState>` usage in `src/server.rs` by cloning state and client IP explicitly for the request service closure.

### Cleaned
- Removed unused `Severity` import from `src/storage.rs`.
- Removed unused `ActiveModelTrait` import from `src/storage.rs`.
- Removed unused `Ipv6Addr` import from `src/waf/engine.rs`.
- Silenced the non-feature `vectorscan_enabled` warning in `src/waf/engine.rs` without changing runtime behavior.

## 2.7.28.1
- Removed unused compatibility shim files (`libinjection_compat.c` / `.h`) from the vendored libinjection integration.

## 2.7.28.2
- Fixed compile error E0596 in `src/proxy.rs` by making the `trusted_proxy_cidrs` iterator mutable before calling `.any(...)`.

## 2.7.28.3
- Fixed libinjection FFI static linking: corrected library name and removed invalid rustc-link-lib directive causing build failure.

## 2.7.28.4
- Fixed libinjection FFI linking properly: removed #[link(...)] attribute and relied on cc::Build automatic linkage.


## 2.7.28.5
- Removed unused `libinjection_sqli_enabled` and `libinjection_xss_enabled` fields from `WafEngine`, fixing dead-code warnings.
- Suppressed dead-code warning noise for vendored libinjection FFI wrappers in `src/ffi/libinjection/mod.rs` and `bindings.rs`.
- Consolidated today's fixes in the changelog:
  - real libinjection 4.0.0 vendored FFI integration
  - static-link / build.rs fixes
  - proxy iterator mutability compile fix
  - removal of unused `libinjection_compat.*` shim files
- No behavior change in runtime detection logic.


## 2.7.28.6
- Fixed constructor mismatch in `main.rs` (E0061): removed extra arguments after refactor of `WafEngine::new`.
- Cleaned integration after removal of libinjection flags from struct.
- Build now compiles without errors.


## 2.7.28.7
- Fixed `main.rs` constructor call for `WafEngine::new` when building with `vectorscan-engine`.
- Restored the missing `cli.enable_vectorscan` argument so the call matches the current constructor signature.
- Kept prior libinjection/linker/build fixes intact.


## 2.7.28.8
- Fixed request-scope inspection bug for DFA and libinjection.
- KrakenWaf now inspects a synthesized full-request payload composed of method, URI, headers, and body bytes.
- Removed query-only inspection path and replaced it with full-request inspection after body assembly.
- Streaming body inspection now evaluates a rolling full-request window, improving POST / REST payload detection before forwarding upstream.
- Documented the inspection scope in `docs/libinjection.md` and `docs/deployment.md`.


## 2.7.29
- Fixed warning in `src/waf/engine.rs` by annotating the currently-unused `inspect_body_chunk` method with `#[allow(dead_code)]`.
- Preserved the full-request inspection fix so DFA and libinjection evaluate GET, POST, REST-style requests, including body payloads.
- Consolidated this release after the recent libinjection FFI, vectorscan constructor, proxy iterator, linker, and warning cleanup fixes.


## 2.7.30
- Added GET request URL decoding before inspection
- Unified inspection pipeline for DFA, libinjection, vectorscan
- Improved detection for URL-encoded attacks


## 2.7.31
- Fixed request inspection precedence so normalization happens before detector evaluation.
- Added unified `inspect_complete_payload_with_context(...)` path and routed proxy body/full-request inspection through it.
- Reintroduced libinjection runtime flags into `WafEngine` and wired FFI detections into the active inspection pipeline.
- Normalized GET requests with URL decoding before DFA, vectorscan, libinjection and regex/keyword rule evaluation.
- Left POST request bodies undecoded so body payloads are inspected as-sent.
- Evaluated DFA/libinjection/vectorscan before keyword/regex rules, keeping rule filters as the last stage.
- Disabled SSRF regex rules by default in bundled rule files to allow localhost/127.0.0.1 testing.
- Updated integration tests for the current `WafEngine::new(...)` signature.


## 2.7.31.1
- Fixed compile error `E0425` in `src/waf/engine.rs` by exporting `format_request_prefix_bytes` from `src/proxy.rs` as `pub(crate)`.
- Kept the request-normalization / full-request inspection changes from 2.7.31 intact.


## 2.7.31.2
- Reworked `normalize_request_bytes` to avoid unnecessary allocation on non-GET requests.
- Replaced `payload.to_vec()` fallback with `Cow<[u8]>`, so non-GET requests now borrow the original byte slice and only GET normalization allocates.
- Updated call sites in `src/waf/engine.rs` to use `normalized_bytes.as_ref()`.


## 2.7.31.3
- Fixed malformed import insertion in `src/waf/engine.rs` introduced by the previous normalization patch.
- Added the missing `use crate::proxy::format_request_prefix_bytes;` import to resolve `E0425`.
- Added the missing `use std::borrow::Cow;` import at module scope to resolve parsing/import errors.
- Preserved the `Cow<[u8]>` normalization optimization for non-GET requests.


## 2.7.31.4
- Fixed duplicate `Cow` import in `src/waf/engine.rs` (`E0252`).
- Removed the extra `use std::borrow::Cow;` line while keeping the grouped `std::{borrow::Cow, ...}` import.
- Preserved the request normalization and full-request inspection changes from 2.7.31.x.


## 2.7.31.5
- Fixed dead_code warnings for libinjection flags in WafEngine


## 2.7.32
- Fixed invalid Cargo.toml version (SemVer compliant)
- Removed `cfg(feature = "libinjection-engine")` so libinjection is always compiled
- Libinjection is now always available at runtime and controlled only via argv flags
- Removed dead_code workaround since fields are now used in all builds


## 2.7.32.1
- Fixed `Cargo.toml` syntax regression by updating only the `[package]` version field.
- Preserved the always-built libinjection integration and runtime argv control.


## 2.7.32.2
- Fixed `Cargo.toml` corruption where a dependency inline table (`chrono`) had been overwritten with an invalid version string.
- Preserved package version as valid SemVer (`2.7.32`) and limited version normalization to the package section.


## 2.7.32.3
- Repaired `Cargo.toml` dependency syntax corruption introduced by earlier automated version replacement.
- Restored sane dependency specifications for `clap`, `hyper`, `hyper-util`, `reqwest`, `rustls`, `sea-orm`, `serde`, `tokio`, `tokio-util`, `tower`, `tracing-subscriber`, and `vectorscan-rs`.
- Kept the package version as valid SemVer (`2.7.32`).
- Removed the unused `libinjection-engine` feature from `[features]`; libinjection remains built-in and runtime-controlled by argv.


## 2.7.32.4
- Fixed `tracing_subscriber::fmt::Layer::json()` build error by enabling the `json` feature in `tracing-subscriber`.
- Preserved the Cargo.toml dependency repairs from 2.7.32.3.


## 2.7.32.5
- Fixed linker errors for libinjection (undefined symbols)
- Added build.rs compiling libinjection C sources via cc crate
- libinjection now properly linked into binary


## 2.7.33
- Fixed libinjection native build paths in `build.rs`.
- Switched from nonexistent `src/ffi/libinjection/*.c` paths to the vendored sources under `ffi/libinjection/vendor/libinjection-4.0.0/src/`.
- Added compilation of `ffi/libinjection/vendor/kwaf_libinjection.c`, which exports `kwaf_libinjection_sqli` and `kwaf_libinjection_xss`.
- Added required include directories for the wrapper and vendored libinjection headers.


## 2.7.34
- Fixed native libinjection linkage by making the `build.rs` export explicit `cargo:rustc-link-search` and `cargo:rustc-link-lib=static=kwaf_libinjection`.
- Kept compilation of the vendored wrapper (`kwaf_libinjection.c`) plus libinjection SQLi/XSS/HTML5 sources.
- Added `-Wno-enum-int-mismatch` for the vendored libinjection 4.0.0 C sources to suppress upstream enum/int signature mismatch warnings during the C build.


## 2.7.35
- Fixed unresolved symbols `kwaf_libinjection_*` by adding explicit Rust FFI linkage:
  #[link(name = "kwaf_libinjection", kind = "static")]
- Ensures Rust linker pulls symbols from cc-built static lib.


## 2.7.36
- Fixed missing symbol export in kwaf_libinjection.c (removed static/inline)
- Added -fvisibility=default in build.rs


## 2.7.37
- Forced linker to include libinjection symbols using --whole-archive

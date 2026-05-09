## [2.14.0] - 2026-05-09

### Security

#### Body streaming slow-loris mitigation
- `src/proxy.rs`: each `body.frame().await` is now wrapped in a 30 s `BODY_FRAME_TIMEOUT`; an attacker sending chunks at 1 byte/s no longer holds a worker indefinitely.
- Timeout returns **HTTP 408 Request Timeout** via new `BodyInspectionError::Timeout` variant.

#### Request header size enforced before allocation
- `src/proxy.rs`: added `exceeds_header_limits` pre-check that rejects requests exceeding 100 headers or 32 KiB of header bytes **before** `flatten_headers()` allocates; returns **HTTP 431 Request Header Fields Too Large**.
- Previously the limit was checked after flattening, meaning oversized headers were already allocated.

#### SSRF — DNS rebinding mitigation
- `src/proxy.rs::validate_upstream`: upstream hostname is now resolved eagerly at startup; private/loopback IPs returned by DNS are refused.
- Resolved IPs are logged at startup (`info!`) for operator auditability.
- Hard connection-time pinning would require a custom reqwest resolver; operators needing it should configure the upstream as an explicit IP literal (documented inline).

#### WebSocket upgrade responses now receive security headers
- `src/response_headers.rs`: WS upgrade responses now carry `X-Content-Type-Options: nosniff` and `Referrer-Policy: strict-origin-when-cross-origin`.
- `Content-Security-Policy` and `X-Frame-Options` are intentionally omitted (not meaningful for WS).

### Fixed

#### CI — Clippy `redundant_static_lifetimes`
- `src/dfa/overflow_detect.rs`: removed `&'static` from `X86_PATTERNS`, `X64_PATTERNS`, `ARM_PATTERNS` const type annotations. References in `const` items are always `'static` implicitly.

#### CI — attack-sweep WAF start command
- `.github/workflows/security.yml`: added `--dfa-load $GITHUB_WORKSPACE/rules/dfa/config.yaml` (activates all 9 DFA detectors) and `--rate-limit-per-minute 100000` (prevents GCRA from blocking score-engine "allow" cases at concurrency 25).

#### CI — SCA made advisory-only
- `cargo-audit` and `cargo-deny` jobs now use `continue-on-error: true`, matching the policy already in place for Semgrep and OSV Scanner. Findings surface in the job log and GitHub Security tab without blocking the workflow.

### Changed

#### Rust quality — graceful shutdown
- `src/server.rs`: added `wait_for_shutdown_signal` (SIGINT + SIGTERM on Unix); in-flight request counter + `Notify`-based 30 s drain window before process exit. Previously, connections were abandoned on shutdown.

#### Rust quality — resilient rule loading
- `src/rules/loader.rs`: a JSON rule file with an invalid regex no longer aborts WAF startup. The bad rule is logged as a warning and skipped; remaining rules load normally.
- Added test `invalid_regex_rule_is_skipped_but_others_load`.

#### Rust quality — defensive `.unwrap()` removal
- `src/proxy.rs`: replaced the sole `.unwrap()` in `plain_response` static-header builder with an infallible `unwrap_or_else` fallback.

#### Rust quality — SQL binding safety comment
- `src/storage.rs`: added `SAFETY` comment on all query sites confirming that every untrusted value is bound through SeaORM `ActiveModel` or positional `?` placeholders (no string interpolation).

### Dependencies
- `cargo update`: bumped 14 transitive deps to latest compatible patch versions including `h2 0.4.13→0.4.14`, `tokio 1.52.1→1.52.3`, `tower-http 0.6.8→0.6.10`.

### Tests
- `src/waf/engine.rs`: added `url_decode_handles_double_and_triple_encoded_percent` confirming `%2525→%25→%` across multi-pass decode.
- `src/waf/engine.rs`: added `inspection_views_first_view_is_full_normalized_text` confirming score accumulates over the full text for `&`/`;`/`\n`-delimited payloads.
- `tests/malformed_payloads.rs`: added three cross-segment score accumulation regression tests.

### PR
- https://github.com/Orangewarrior/KrakenWaf/pull/16

---

## [2.13.0] - 2026-05-08

### Changed

#### Rate limiter rewritten as lock-free GCRA-sharded
- `src/waf/rate_limit.rs` rewritten from a single global `Mutex<HashMap>` to a 64-shard GCRA design.
- Per-client TAT (Theoretical Arrival Time) stored in `Arc<AtomicU64>`; admission is a CAS loop with no mutex on the hot path (~20–30 ns per request for tracked IPs).
- 64 shards (`parking_lot::RwLock<AHashMap>`) eliminate contention; read-lock fast-path for known IPs, write-lock only for first-insertion of a new IP (with double-checked locking).
- `tolerance_ns = window_ns` (burst = exactly `limit` requests) — fixes a textbook off-by-one where `tolerance = window − emit` admitted only `limit − 1` requests in a same-instant burst.
- Stable FNV-1a IP hash (deterministic across restarts) so persisted `(ip_hash, tat_ns)` pairs re-hydrate into the correct shard.
- Background sweeper task evicts drained entries every 30 s; `MAX_PER_SHARD = 4 096` (262 144 unique IPs total) with eviction-of-expired-or-LRU when full.

### Added

#### `--wal-mode` flag selecting the rate-limiter persistence backend
- New CLI option `--wal-mode {sqlite|bincode}` (default `sqlite`).
- `sqlite` uses SQLite + WAL (`PRAGMA journal_mode=WAL`, `synchronous=NORMAL`); state lives in `tmp_cache/rate_limit_state.db` and is inspectable via `sqlite3 cli`.
- `bincode` serialises the entire `Vec<(u64, u64)>` snapshot with an 8-byte `KWAFRL01` magic, writes to `rate_limit_state.bin.tmp`, `fsync`s, and atomically renames into place. Roughly 10–50× faster snapshot/re-hydrate than SQLite for this workload.
- New `PersistenceMode` enum exposed from `waf::rate_limit`; internal `Backend` enum (`Sqlite(Connection)` / `Bincode(PathBuf)`) replaces the bare `Connection` field on `RateLimiter`.
- `WafEngine::new` gains a `rate_limit_persistence: PersistenceMode` parameter; integration tests updated.
- Snapshot directory is `tmp_cache/` at the process working directory.
- New documentation: [`docs/rate_limit.md`](docs/rate_limit.md).

### Fixed

- **Vectorscan: scanner-agent compilation failure.** Patterns from `rules/user_agents/scanners.txt` are plain string literals (e.g. `Mozilla/5.0 (compatible; Panoptic`), but were passed to Vectorscan as PCRE — unbalanced `(` triggered "Missing close parenthesis" at engine boot. New `build_vectorscan_literal_matcher` in `engine.rs` runs every UA pattern through `regex_escape_literal` (escapes `. ^ $ * + ? ( ) [ ] { } | \`) before compilation. The original unescaped UA strings remain on `VectorscanMatcher::keywords` so findings still report the raw substring.

### Dependencies
- Added `ahash = "0.8"`, `bincode = "1.3"`, `rusqlite = "0.32"` (with `bundled` feature) — used by the new rate-limiter implementation and persistence backends.

## [2.12.5] - 2026-05-07

### Added

- Added `score` to regex and Vectorscan JSON rules. Existing bundled rules now default to `1000`.
- Implemented score-ranked blocking for regex and Vectorscan request/response inspection: matches with `score >= 600` block immediately, while lower scores accumulate per rule list until they reach `600`.
- Added score-engine laboratory rules and attack-tool GET, POST, and response sweeps for expected allow/block behavior.
- Documented score-ranked rule behavior in `docs/score_rank.md`.

### Fixed

- Fixed response-rule enforcement returning `502 Bad Gateway` after a response match. Response blocks now use the normal WAF enforcement path and return the configured block response, including `403 Forbidden` in block mode.

### Changed

- Bumped the crate and README version to `2.12.5`.

---

## [2.12.4] - 2026-05-06

### Added

#### XXE attack DFA coverage
- Added `src/dfa/xxe_attack_detect.rs` to detect XXE attacks by requiring at least one marker from list A (`ENTITY`, `xi:include`) and at least one marker from list B (`xxe`, `SYSTEM`, `etc/password`, `eval`, `exfil`, `xmlns:xi`, `send`, `DOCTYPE`, `soap`, `file`).
- Added UTF-16LE/BE recovery for NUL-interleaved request text produced after URL decoding encoded XML payload bytes.
- The DFA can be enabled with `XXE_attack_detect: true` in `rules/dfa/config.yaml`.
- When the `vectorscan-engine` feature is compiled and `--enable-vectorscan` is set, the XXE detector uses Vectorscan for literal list matching.
- Extended `src/bin/attack.rs` with 15 XXE attack payloads and GET/POST sweeps, including a UTF-16LE percent-encoded payload.

### Tests

- Added real end-to-end GET/POST XXE blocking tests against the protected WAF subprocess in `tests/server_real_test.rs`.
- Added XXE DFA unit tests for list correlation and UTF-16LE encoded payload recovery.

---

## [2.12.3] - 2026-05-06

### Added

#### NoSQL injection DFA coverage
- Added `src/dfa/nosql_injection_detect.rs` to detect NoSQL injection by requiring at least one marker from list A (`$gt`, `$where`, `$or`, `$and`, `selector`, `this.password.match`, `&&`, `||`, and related operators) and at least one marker from list B (`true`, `admin`, `pass`, `user`, `null`, `sleep(`, `%00`, `{}`, `.insert`, `dropDatabase(`, equality probes, and related values).
- Added support for `==[1-9]` and `== [1-9]` as list B matches.
- The DFA can be enabled with `NOSQL_injection_detect: true` in `rules/dfa/config.yaml`.
- When the `vectorscan-engine` feature is compiled and `--enable-vectorscan` is set, the NoSQL detector uses Vectorscan for literal list matching and keeps the numeric equality DFA check for the digit pattern.
- Extended `src/bin/attack.rs` with 15 NoSQL injection payloads and GET/POST sweeps.

### Tests

- Added real end-to-end GET/POST NoSQL injection blocking tests against the protected WAF subprocess in `tests/server_real_test.rs`.
- Added NoSQL DFA unit tests for list correlation and numeric equality probes.

---

## [2.12.2] - 2026-05-05

### Added

#### DFA attack sweeps in real WAF tests
- Added end-to-end DFA sweeps in `tests/server_real_test.rs` with `--dfa-load rules/dfa/config.yaml` enabled.
- Added GET and POST coverage for Overflow, SSTI, SSI injection, and ESI injection payloads so URI and request body inspection are both validated through the real KrakenWAF subprocess.
- Extended `src/bin/attack.rs` to send the same DFA-focused payload families in GET and POST attack sweeps.

#### Overflow DFA shellcode detection
- `src/dfa/overflow_detect.rs` now detects common shellcode opcode clusters in addition to repeated-character and structured overflow patterns.
- Added detection for x86-32, x86-64, and ARM/Thumb payloads, including NOP sleds (`\x90`, ARM `00 00 a0 e1`, Thumb `c0 46`) and common Linux shellcode sequences such as `int 0x80`, `syscall`, `execve`, and embedded `/bin/sh`.
- Added parsing for common byte encodings in payload text: `\xNN`, `%NN`, `0xNN`, and `\u00NN`.
- `DfaManager` now emits a dedicated high-severity `DFA shellcode opcode detection` finding for these matches.

#### SSTI DFA coverage
- `src/dfa/ssti_detect.rs` now detects additional SSTI families: `{% ... %}`, FreeMarker `<# ... >`, Velocity `#set(...)`, and `[[ ... ]]` expressions.

#### SSI and ESI DFA coverage
- `src/dfa/ssi_injection_detect.rs` now detects SSI directives with spacing and case variants, including `<!-- #exec ... -->` and `<!--# set ... -->`.
- `src/dfa/esi_injection_detect.rs` now detects additional ESI directives including `vars`, `remove`, `choose`, `when`, `otherwise`, `try`, `attempt`, `except`, `comment`, and `assign`, with case and spacing variants.

#### CRLF injection DFA coverage
- Added `src/dfa/crlf_injection_detect.rs` to detect CRLF injection and HTTP response-splitting payloads.
- The DFA can be enabled with `CRLF_injection_detect: true` in `rules/dfa/config.yaml`.
- Added coverage for raw CR/LF, URL-encoded, double/triple-encoded, `%u000d/%u000a`, `\u000d/\u000a`, Unicode newline bypasses, and injected HTTP header/status/body patterns from the payload-box CRLF injection list.

#### Request smuggling DFA coverage
- Added `src/dfa/request_smuggling_detect.rs` to detect request smuggling indicators in headers, URI, and body content.
- The DFA can be enabled with `Request_Smuggling_detect: true` in `rules/dfa/config.yaml`.
- Added detection for `Transfer-Encoding: chunked`, `X-Session-Hijack: true`, `Content-Length` values `<= 4`, and injected `Transfer-Encoding: chunked` patterns in request bodies or URI parameters.

### Fixed

- Closed the real-test Overflow bypass for repeated format-string specifiers such as `%n%n%n...`.
- Closed the real-test SSI bypass for spaced directives such as `<!--# set var="x" value="owned" -->`.
- Closed the real-test ESI bypass for `<esi:vars>$(HTTP_COOKIE)</esi:vars>`.

### Tests

- Added unit tests for Overflow shellcode detection, SSTI families, SSI spacing/case variants, and ESI directive variants.
- Added real GET/POST CRLF injection sweeps using representative payloads from `payload-box/crlf-injection-payload-list`.
- Added real GET/POST request smuggling sweeps with 10 payloads covering transfer-encoding, short content-length, and session-hijack markers.
- Verified DFA payload sweeps block in both GET query strings and POST form bodies.

---

## [2.11.1] - 2026-05-05

### Fixed

#### `serde_yml` → `serde_yaml 0.9` (RUSTSEC-2025-0068)
- `serde_yml 0.0.12` was archived upstream after a soundness bug was discovered in its `Serializer` (segfault via `Serializer.emitter`). Replaced with `serde_yaml 0.9.34`, which carries no active advisory (`RUSTSEC-2018-0005` is patched for all versions `>= 0.8.4`). API is identical; no behaviour change.

#### Removed stale advisory ignores
- `RUSTSEC-2023-0071` (Marvin Attack / `rsa` crate) is no longer present in the dependency tree — `sqlx-mysql` was dropped when `sea-orm` resolved to `sqlx-sqlite` only. Removed the `--ignore` flag from `cargo audit` in CI and the `ignore` entry from `deny.toml`, leaving both files with zero exceptions.

#### Clippy bug fixes
- `proxy.rs`: removed redundant `event.clone()` before move into `store.enqueue()`.
- `proxy.rs`: hoisted duplicate `partial_body` expression out of both branches of the `Blocked` match arm.
- `proxy.rs`: replaced `.map(...).unwrap_or(false)` with `.is_some_and(...)` on the `Connection: upgrade` header check.
- `tls.rs`: replaced `.map(...).unwrap_or(false)` with `.is_some_and(...)` for the `is_default` SNI field.
- `engine.rs`: annotated the `u32 → u8` cast in `url_decode_once` as provably safe (hex digit pair is always 0–255).
- `engine.rs`: made the wildcard `IpAddr` match arm explicit (`IpAddr::V4(_)`) to future-proof against new variants.
- `rules/mod.rs`: combined identical `Component::RootDir` and `Component::CurDir` match arms.
- `ffi/libinjection/mod.rs`: replaced `c as u8` (sign-loss from `i8`) with `c.cast_unsigned()`.

#### Test path fix
- `tests/rules_and_limits.rs`: the `loads_external_rule_tree` test was writing the IP blocklist to the old path `blocklist_ip.txt` at the root, but the loader has read from `addr/blocklist.txt` since v2.10.0. Updated the test fixture path to match.

---

## [2.11.0] - 2026-05-04

### Added

#### `X-Request-Id` correlation ID
- UUID v4 generated once per request at the proxy entry point (compact 32-char lowercase hex, no hyphens — fits `VARCHAR(32)` exactly).
- Propagated through the full request lifecycle:
  - `InspectionContext.request_id` — carried through all WAF inspection phases.
  - `SecurityEvent.request_id` — included in the JSON event log and `critical.log`.
  - `x-request-id` header forwarded to the upstream on every proxied request.
  - `x-request-id` header added to every response (blocked or forwarded) so clients can include it in support tickets.
  - Tracing spans for `request detected` and `response blocked` events now include `request_id`.
- SQLite `vulnerabilities` table gains `request_id VARCHAR(32) NOT NULL DEFAULT ''` (schema v3).
  - New index `idx_vulnerabilities_request_id` for O(log n) lookup by correlation ID.
  - Existing databases upgraded automatically via a non-destructive `ALTER TABLE ADD COLUMN` migration; historical rows receive an empty string.
  - Example query: `SELECT * FROM vulnerabilities WHERE request_id = 'a3f2...';`

#### `--max-body-bytes` — hard cap on request body size
- New optional CLI flag (default **100 MiB**).
- Acts as an absolute ceiling: `effective_limit = min(per_route_rule_limit, --max-body-bytes)`. No per-route rule can exceed this cap regardless of its configuration.
- Requests whose bodies exceed the effective limit are rejected with **HTTP 413 Payload Too Large**.

### Changed

#### `serde_yaml` → `serde_yml`
- Replaced `serde_yaml 0.9` (backed by `unsafe-libyaml` C bindings) with `serde_yml 0.0.12`, a pure-Rust fork with an identical API.
- Call sites in `src/allowpaths.rs` and `src/dfa/mod.rs` updated; no behaviour change.

#### `rustls-pemfile` removed — PEM parsing via `rustls-pki-types`
- `rustls-pemfile` (RUSTSEC-2025-0134 — unmaintained) removed from the dependency tree.
- `src/tls.rs` now uses the `PemObject` trait from `rustls-pki-types` directly:
  - `CertificateDer::pem_file_iter()` — iterates all certificates in a PEM file.
  - `PrivateKeyDer::from_pem_file()` — auto-detects PKCS#8, RSA PRIVATE KEY, and EC PRIVATE KEY formats, removing the previous two-pass open-file fallback.
- `RUSTSEC-2025-0134` advisory ignore removed from `deny.toml` and the `cargo audit` CI step.

### Security

- Eliminated `unsafe-libyaml` C dependency (YAML parsing is now fully safe Rust).
- Removed unmaintained `rustls-pemfile` crate (RUSTSEC-2025-0134).
- Request body size now bounded by an operator-configurable hard cap (`--max-body-bytes`), preventing memory exhaustion from unbounded body accumulation.

---

## [2.10.0] - 2026-04-29

### Added

#### Response inspection via `http_action` (Point 1)
- New `http_action` field (`"Request"` | `"Response"`, default `"Request"`) added to all rule JSON files.
- `DetectionRule` and `CompiledDetectionRule` carry `http_action: HttpAction`.
- `EngineMatchers` split into `req_*` / `resp_*` pools: separate Aho-Corasick matchers and Vectorscan databases built per phase at startup.
- New `ResponseContext { status, headers, body }` struct passed to `inspect_response()`.
- New `WafEngine::inspect_response(&ResponseContext) -> Decision` method — runs Response-phase rules against the buffered upstream body and headers.
- `proxy.rs`: after buffering the upstream response body, calls `inspect_response()`; a Block result returns HTTP 403 to the client and logs the finding.
- `rules/Vectorscan/strings2block.json` and `rules/regex/*.json` updated with `"http_action": "Request"`.
- New documentation: `docs/http_action.md`.

#### Integration test server (Point 2)
- New `tests/server_real_test.rs`: Axum micro-backend on port 9077 with four routes (`/test_one`, `/test_get`, `/test_two`, `/test_post`).
- KrakenWAF spawned as subprocess in `--no-tls` mode; unique port allocated per test via atomic counter.
- Six test cases: XSS POST blocked, SQLi GET blocked, scanner UA blocked, blocklisted IP blocked, clean GET passes, clean POST passes.
- `axum` added to `[dev-dependencies]`.
- New documentation: `docs/integration_tests.md`.

#### Scanner User-Agent blocklist (Point 3)
- New `rules/user_agents/scanners.txt`: 78 scanner/crawler UA substrings from the OWASP CRS `scanners-user-agents.data`.
- `RuleSet` gains `scanner_agents: Vec<String>` loaded via `load_scanner_agents()`.
- `EngineMatchers` gains `req_scanner_agents: Option<KeywordMatcher>` (Aho-Corasick) and, when Vectorscan is enabled, `scanner_vectorscan`.
- `inspect_early()` extracts the `User-Agent` header and matches it against the scanner pool; a match returns HTTP 403 + Alert logged to JSON, raw critical, and SQLite.
- New documentation: `docs/scanner_agents.md`.

#### Address blocklist / allowlist (Point 5)
- `rules/addr/blocklist.txt` **replaces** `rules/blocklist_ip.txt` — one IPv4/IPv6/CIDR per line.
- `rules/addr/allowlist.txt` — only listed IPs may access `/__krakenwaf/health` and `/metrics`; empty file disables the check.
- `RuleSet` gains `allowed_ips: Vec<String>` and `blocked_ips` now loaded from `addr/blocklist.txt`.
- New `RuleSet::is_ip_allowed(&str) -> bool` — returns `true` (allow all) when `allowed_ips` is empty.
- `server.rs` enforces the allowlist before serving management endpoints.
- `safe_join()` helper added to `loader.rs` — canonicalises paths and rejects traversal out of the rules root.
- New documentation: `docs/blockaddrs_allowaddrs.md`.

#### `--no-tls` mode (Point 4)
- New `--no-tls` CLI flag; when set the WAF listens on plain HTTP, ignoring `--sni-map`. Useful for deployments where TLS is terminated by an upstream load balancer, and required for integration tests.
- `server::run_plain()` added alongside the existing `server::run()`.

### Changed
- `--blocklist-ip` now reads `rules/addr/blocklist.txt` instead of `rules/blocklist_ip.txt`.
- README CLI table updated: `--blocklist-ip`, `--no-tls` entries added/updated; directory structure updated.

### Fixed
- `proxy.rs`: `method` move-before-use compile error fixed by saving `method_str` before moving `method` into the reqwest builder.

---

## [2.9.0] - 2026-04-25

### Added

#### Rule IDs (Point 1)
- All rule JSON files now carry a per-file sequential `"id"` field (5-digit zero-padded, e.g. `"00001"`).
  - `rules/rules.json` — `uri_keywords`, `header_keywords`, `body_keywords` sections
  - `rules/regex/path_regex.json`, `body_regex.json`, `header_regex.json`
  - `rules/Vectorscan/strings2block.json`
- `DetectionRule` struct gains an `id: String` field populated from the JSON file.
- IDs are sequenced per-file, starting at `00001` in each file independently.
- Rules not present in JSON (DFA, libinjection, rate-limit, IP-block) receive the sentinel value `"00000"`.

#### Rule ID in logs (Point 2)
- `Finding` struct gains `rule_id: String` carrying the rule's file-local ID.
- `SecurityEvent` struct gains `rule_id: String` field — present in the JSON event log.
- `write_critical` now emits `rule_id="…"` in the structured key=value log line.
- The `info!` tracing span in `proxy.rs` emits `rule_id` for every blocked or detected request.

#### `--mode` flag (Point 3)
- New `WafMode` enum (`block` | `silent`) added to `src/cli.rs`.
- New `--mode <block|silent>` CLI flag (default: `block`).
  - `block` — existing behaviour: matching requests receive HTTP 403.
  - `silent` — WAF inspects all traffic, logs detections and increments the `blocked` metric counter, but **never** returns 403. All requests are forwarded to upstream. Useful for tuning rules in production before enabling enforcement.
- `AppState` carries `mode: WafMode`; `proxy.rs` calls `log_and_enforce` which returns `None` in silent mode and `Some(403)` in block mode.

#### Allow-Paths (Point 5)
- New `--allow-paths <path>` CLI flag accepting a YAML file path.
- New `src/allowpaths.rs` module:
  - `AllowPathConfig` / `AllowPathEntry` structs deserialized from YAML.
  - `load_and_validate(path)` validates presence of `title` and non-empty `paths` on startup.
  - `is_allowed(uri_path)` performs prefix matching after URL normalization.
- `AppState` carries `allow_path_config: Option<AllowPathConfig>`.
- In `proxy::handle()`, URIs matching an allow-path bypass WAF inspection entirely and are forwarded without inspection (takes precedence over `--mode`).
- Optional `log: true` per entry emits an `info` log line on each match.
- New example file: `rules/allowpaths/lists.yaml`.
- New documentation: `docs/allowpaths.md` (format reference, matching rules, CMS/SIEM/health-check examples).

#### RulesSnapshot consistency (Point 4)
- The `RulesSnapshot` struct (introduced in 2.8.0) holds `Arc<RuleSet>` + `EngineMatchers` behind a single `RwLock<Arc<RulesSnapshot>>`. Hot-reload swaps the arc atomically — readers always see a consistent rule/matcher pair. No additional changes needed.

### Changed
- `proxy.rs` `block_response` renamed to `log_and_enforce` returning `Option<Response>` to support silent mode.
- Startup `info!` log now includes `mode` and `allow_paths_file` fields.

---

## [2.8.1] - 2026-04-24

### Changed
- Bumped `Cargo.toml` version to reflect the full `2.8.0` security hardening already shipped.
- `normalize_request_bytes` now applies up to 4 URL-decode passes (multi-pass) to defeat double/triple-encoding evasion; previously only a single pass was performed for GET requests. All payloads (GET and POST) are normalised before pattern matching.

### Fixed
- Integration tests (`dvwa_payloads`) were silently skipped due to pre-existing linker errors (`kwaf_libinjection_*` duplicate/undefined symbols). Build script now passes the C archive by full path via `cargo:rustc-link-arg`, resolving a Cargo edge case where `cargo:rustc-link-lib=static` is not propagated from lib → bin within the same package.

---

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

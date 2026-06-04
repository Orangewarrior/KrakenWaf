## [2.34.1] - 2026-06-04

> **WAF login fix + updater status reporting.** Two operator-facing fixes landed
> in the current tree. First, the proxy now normalizes split HTTP/2 `Cookie`
> headers into a single semicolon-delimited header before forwarding upstream,
> which restores DVWA login and setup flows through the WAF. Second,
> `soldier_update` now prints clear progress for address-list and MaxMind
> updates: it tells you when a download starts, which file it is writing to,
> how far the download has progressed, when extraction finishes, and the final
> save path. The updater still returns the same errors as before, but it no
> longer looks stalled while a large database is being fetched.

### Proxy cookie forwarding fix (`src/proxy.rs`)

- Multiple request `Cookie` headers received over HTTP/2 are now merged into one
  backend-safe header using `"; "` separators before the request is forwarded to
  upstream.
- This resolves the browser-only DVWA login/setup failure where Chrome and
  Firefox could store the session cookie but the backend would receive it in an
  invalid format and restart the login flow with `302 /login.php`.
- Added regression coverage for split HTTP/2 cookies and for redirect rewriting
  of absolute upstream `Location` values back to the public origin.

### `soldier_update` progress reporting (`src/bin/soldier_update.rs`, `src/update.rs`)

- `soldier_update` now prints an initial status line showing which mode is
  running and which config file is being used.
- Address-list downloads now report the target directory, the source URL, the
  current byte count / percentage, completion, and the final saved file.
- `maxmind-geo` downloads now report the `.tar.gz` source, progress, extraction
  into `db/geo/GeoLite2-City.mmdb`, and the final saved database path.
- The reporting is plumbed through a small update-event abstraction so the
  existing silent callers keep working unchanged.

## [2.34.0] - 2026-05-31

> **HTTP Parameter Pollution release.** A new CMC module, **`HPP_detect`**,
> detects HTTP Parameter Pollution — the same parameter name supplied two or
> more times in a single location — across the query string (GET) **and** the
> request body (POST/PUT/DELETE/any method). It normalizes each location first,
> counts `=` on the normalized form, parses parameter names (split on `&`, key =
> substring before the first `=`), and flags any duplicate name compared
> **case-insensitively** (`email` vs `eMail`). Findings are `Critical` and feed
> the existing untrust scoring, so a clear duplicate blocks at the shipped
> `Untrust >= 60` gate and is reported to the JSONL, raw, and SQLite sinks like
> every other CMC finding. The module is toggled with `HPP_detect` in
> `rules/cmc/config.yaml` (no-op when `false`/absent). To make the detector
> encoding-bypass resistant, the **global normalizer was hardened** with UTF-16
> LE/BE transcoding (BOM and interleaved-NUL ASCII) added ahead of the existing
> recursive percent-decoding — a change that benefits every CMC module and rule.
> Full `cargo test` suite passes (0 failures; new HPP + UTF-16 unit tests) and
> `cargo clippy --all-targets` is clean.

### New CMC module — `HPP_detect` (`src/cmc/hpp_detect.rs`, `src/cmc/mod.rs`, `rules/cmc/config.yaml`)

- **Detection.** For the query string and the body independently: normalize via
  the global `normalize_str`, gate on `>= 2` `=` characters, parse keys, and
  report the first case-insensitively duplicated parameter name as an
  `HppMatch { parameter, location }`. Values containing `=` (e.g. base64 padding
  `==`) do not create false duplicates because only the first `=` of each
  segment splits the key.
- **Severity / blocking.** `CMC HTTP Parameter Pollution detection`, `Critical`,
  [CWE-235](https://cwe.mitre.org/data/definitions/235.html); blocks at
  `Untrust >= 60` and logs to JSONL + raw + SQLite via the shared finding path.
- **Config.** New `HPP_detect` key in `rules/cmc/config.yaml` and the matching
  `hpp_detect` field on `CmcConfig` (`from_map("HPP_detect")`); disabled when the
  flag is `false` or absent.
- **Pipeline.** `WafEngine::inspect_hpp(query, body)` is invoked from
  `src/proxy.rs` once the body is available; the raw query string and body are
  passed so the normalizer — not the proxy — owns all decoding.

### Global normalizer hardening — UTF-16 transcoding (`src/waf/engine/normalize.rs`)

- **UTF-16 LE/BE → UTF-8** is now applied at the start of
  `normalize_request_bytes` (and the new public `normalize_str`): a `FF FE` /
  `FE FF` BOM, or the whole-buffer interleaved-NUL pattern of ASCII-range UTF-16,
  is transcoded before percent-decoding. Binary bodies with scattered NULs are
  left untouched (the pattern must hold for the entire buffer). Recursive
  single/double/triple percent-decoding (existing `MAX_URL_DECODE_PASSES = 4`)
  then runs over the transcoded bytes, so separators hidden behind UTF-16 **and**
  multi-layer percent-encoding are revealed. The change is additive — existing
  decodings and public signatures are preserved.
- **`normalize_str`** is exported through `crate::waf` as the single public
  entry point CMC modules use to fully decode one field.

### Tests + DAST

- **Unit tests.** New tests in `src/cmc/hpp_detect.rs` (clean vs duplicate,
  case-insensitivity, value-with-`=`, `=`-count gate, body location, percent and
  double-percent separator decoding, and the pure helpers) and in
  `src/cmc/mod.rs` (config parsing, disabled no-op, enabled block + body
  pollution). New UTF-16 tests in `src/waf/engine/normalize.rs` (BOM LE/BE,
  BOM-less heuristic LE/BE, ASCII not misread, UTF-16-then-percent-decode).
- **DAST.** `src/bin/attack.rs` gains `HPP_PAYLOADS` (50 payloads) plus
  `sweep_hpp_get` / `sweep_hpp_post`, run over both the GET query string and the
  POST body. Payloads obfuscate the `=`/`&` separators with plain,
  single/double/triple percent-encoding, mixed-case hex, `+`-for-space, UTF-16,
  and mixed forms; each must be blocked (a `200` is a real encoding bypass). Run
  with `--concurrency 50` and `--enable-vectorscan` for the full engine.

### Documentation

- New module guide [docs/cmc/hpp_detect.md](docs/cmc/hpp_detect.md); module
  added to the README CMC list + YAML, [docs/cmc/schema.md](docs/cmc/schema.md)
  catalogue, [docs/normalization.md](docs/normalization.md) (UTF-16 section), and
  [docs/attack_tool.md](docs/attack_tool.md) (HPP coverage).

### Version

- Bumped workspace version **2.33.0 → 2.34.0** (`Cargo.toml`).

---

## [2.33.0] - 2026-05-30

> **Config-file ergonomics release.** Two groups of previously CLI-only flags can
> now be driven from YAML under `conf/`, so production deployments keep the
> command line terse and version-control their topology instead. (1) The
> connection / body-size guards (`--max-connections`, `--connection-timeout-secs`,
> `--max-body-bytes`, `--max-upstream-response-bytes`) gained matching keys in
> `conf/ratelimit.yaml`. (2) The proxy flags (`--listen`, `--upstream`, … through
> `--blockmsg`) can be loaded as a group from the new `conf/proxy.yaml` via
> `--external-proxy-conf`. Both loaders are validated at startup (fail-fast) and
> fully backward-compatible: defaults are unchanged, an explicit CLI flag still
> wins, and an empty YAML field keeps the built-in default. The full `cargo test`
> suite passes (0 failures; +31 new tests) and `cargo clippy --all-targets` is
> clean (default **and** `vectorscan-engine` features). Validated end-to-end with
> the `attack` sweep (`--concurrency 50`) over a **full-TLS** topology —
> client→WAF over TLS, WAF→upstream over TLS (verified via the new
> `--upstream-ca`), and a **TLS Redis** (`rediss://`) rate-limiter active — with
> `--enable-vectorscan` and banning OFF: **477/477 payloads blocked, 0 bypassed,
> 0 errors**.

### `conf/ratelimit.yaml` now carries the connection & body-size caps (`src/ratelimit_config.rs`, `src/cli.rs`, `src/app.rs`, `src/main.rs`, `src/server.rs`, `conf/ratelimit.yaml`)

- Four new keys mirror the matching CLI flags: **`max_connections`**,
  **`connection_timeout_secs`**, **`max_body_bytes`**, and
  **`max_upstream_response_bytes`**. When the corresponding flag is omitted the
  value is loaded from the file into the limiting context. Resolution order
  (highest wins): CLI flag → `conf/ratelimit.yaml` →
  `rules/cmc/config.yaml :: memory-limits` → built-in default. Behaviour at the
  shipped defaults is unchanged.
- `--connection-timeout-secs` is now **optional** (`Option<u64>`), matching the
  pattern already used by `--tls-handshake-timeout-secs` and
  `--body-frame-timeout-secs`. The resolved value lives on
  `AppState.connection_timeout_secs`; the TLS and plain-HTTP accept loops read it
  instead of the raw CLI field.
- The byte/connection caps use a `0` sentinel in the file meaning "defer to the
  next source", so the auto-discovered `conf/ratelimit.yaml` never silently
  clobbers an operator's `rules/cmc/config.yaml` memory-limits.
  `connection_timeout_secs` ships its real `30` s default and must be `>= 1`.
- New resolvers `RateLimitConfig::effective_max_connections` /
  `effective_connection_timeout_secs` / `effective_max_body_bytes` /
  `effective_max_upstream_response_bytes`, plus a `RateLimitConfig::validate()`
  that rejects `connection_timeout_secs: 0`.

### New `conf/proxy.yaml` + `--external-proxy-conf` (`src/proxy_config.rs`, `src/cli.rs`, `src/main.rs`, `conf/proxy.yaml`)

- `--external-proxy-conf` loads the proxy flags as a group from a YAML file.
  Passed bare (`--external-proxy-conf`) it auto-loads `conf/proxy.yaml`; pass a
  path to use a different file. Covers `listen`, `upstream`,
  `upstream-timeout-secs`, `upstream-ca`, `allow-private-upstream`,
  `internal-header-name`, `real-ip-header`, `trusted-proxy-cidrs`, `sni-map`,
  `no-tls`, `header-protection-injection`, and `blockmsg`.
- **New `--upstream-ca` flag** (also `upstream-ca` in `conf/proxy.yaml`): trusts a
  private / internal-CA certificate (PEM, single or bundle) as an **additional**
  root for the TLS upstream connection. The cert is *added* to the built-in
  public roots — full chain verification is still enforced (it is **not** an
  "accept any cert" switch) — so KrakenWaf can front a backend that presents a
  private-PKI certificate. Without it, `reqwest`/`hyper-rustls` trusts only the
  bundled webpki roots, so a private/self-signed upstream cert fails with 502.
- The file is a deliberately flat `key: value` document. The parser ignores `#`
  comments (full-line and inline), splits on the **first** colon so values may
  contain colons (e.g. `https://host:8080`), and treats an empty value as "keep
  the WAF default" — an empty `internal-header-name` leaves the internal header
  disabled, an empty `upstream-timeout-secs` keeps the built-in 15 s default.
- Precedence: an explicitly-passed CLI flag always wins over the file; an empty
  field never overrides. The merge runs first thing at startup so the resolved
  values flow through the listener, upstream client, TLS store, custom block
  page, and response-header policy.

### Validators for the `conf/` YAML parsers (`src/proxy_config.rs`, `src/ratelimit_config.rs`)

- `ProxyConfig::validate()` checks every populated field: `listen` parses as a
  socket address, `upstream` as an http(s) URL, each `trusted-proxy-cidrs` entry
  as a CIDR, and the header-name fields as valid HTTP tokens. A malformed value
  aborts startup with a descriptive error instead of producing a half-configured
  proxy (covered by `tests/config_inputs_test.rs`).
- `RateLimitConfig::validate()` rejects `connection_timeout_secs: 0`. Both
  loaders run their validator on load (fail-fast), matching the
  `conf/banning.yaml` pattern.

### Tests & docs

- +29 unit tests (`src/proxy_config.rs`, `src/ratelimit_config.rs`, `src/proxy.rs`)
  covering the canonical `conf/proxy.yaml` format (spacing + inline comments +
  empty fields), every parse/validation error path, the CLI-wins merge, the new
  resolver chains, and the `--upstream-ca` read/parse/error paths.
- New `tests/config_inputs_test.rs`: spawns the WAF with **only**
  `--external-proxy-conf` + `--ratelimit-by-file-conf` (no proxy flags on the
  command line) and proves the files drive `listen` / `upstream` / `no-tls` /
  `allow-private-upstream` / `header-protection-injection` / `blockmsg` and the
  `max_body_bytes` cap (413 on an oversized clean body); a second case proves an
  invalid proxy config aborts startup.
- `README.md` (CLI table + new "Proxy configuration file" section),
  `docs/rate_limit.md`, and `docs/deployment.md` updated.

## [2.32.1] - 2026-05-29

> **Follow-up to 2.32.0.** Makes the anti-Slowloris `--tls-handshake-timeout-secs`
> flag optional and config-file driven, matching the resolution pattern already
> used by the other connection-level guards (`--body-frame-timeout-secs`,
> `--max-inflight-body-bytes`, `--max-per-ip-body-bytes`, `--rate-limit-per-minute`).
> No behaviour change at the default: the effective timeout is still **10 s** when
> nothing is set. Also fixes a startup crash when the WAF is restarted from the
> same working directory (`SQLite` schema-migration idempotency). All ~330 tests
> pass and `cargo clippy --all-targets -D warnings` is clean. Validated end-to-end
> with the `attack` sweep (banning off, Vectorscan on, `--concurrency 50`):
> **477/477 payloads blocked, 0 bypassed**.

### `--tls-handshake-timeout-secs` now falls back to `conf/ratelimit.yaml` (`src/cli.rs`, `src/ratelimit_config.rs`, `src/app.rs`, `src/main.rs`, `src/server.rs`, `conf/ratelimit.yaml`)

- The flag is now **optional** (`Option<u64>`). When the CLI argument is absent
  the WAF falls back to a new **`tls_handshake_timeout_secs`** key in
  `conf/ratelimit.yaml`, and finally to the built-in **10 s** anti-DoS default.
  Resolution order (highest wins): `--tls-handshake-timeout-secs` →
  `conf/ratelimit.yaml` → `10`. This mirrors how `body_frame_timeout_secs` and the
  body-byte caps already resolve.
- Added `RateLimitConfig::effective_tls_handshake_timeout_secs()` and a resolved
  `AppState.tls_handshake_timeout_secs`; the TLS accept loop reads the resolved
  value instead of the raw CLI field. The effective value is echoed in the
  `KrakenWaf initialized` startup log line for observability.
- `conf/ratelimit.yaml` ships the key with a safe, conservative default of `10`.
  `0` (from either source) still disables the bound (not recommended — it removes
  the anti-DoS guard and lets half-open TLS sockets pin connection slots).
- Docs: `docs/rate_limit.md` field reference, example config, and priority chain
  updated; new unit test covers the CLI → YAML → default fallback chain.

### Fix: idempotent `SQLite` schema migration — no more restart crash (`src/storage.rs`)

- **Bug:** restarting the WAF from the **same working directory** panicked at
  startup with `failed to add country column (schema v4): duplicate column name:
  country`. `create_latest_schema` builds the full v4 table but stamped
  `PRAGMA user_version = 3`, so on the next boot the v4 step re-ran and issued an
  `ALTER TABLE … ADD COLUMN country` against a column that already existed. (The
  integration tests never hit this because each spawns the WAF in a fresh
  `tempdir`.)
- **Fix:** a single `LATEST_SCHEMA_VERSION` constant is now the source of truth and
  is stamped on freshly created databases, and the column migrations were made
  **idempotent** via an `add_column_if_missing` helper (`SQLite` has no
  `ADD COLUMN IF NOT EXISTS`). A re-run is now a safe no-op instead of a hard
  failure — this also **self-heals** databases already mis-stamped by an earlier
  build (`user_version` is brought up to date on the next start).
- Added three regression tests (`src/storage.rs`): fresh schema is stamped at the
  latest version, `init_schema` is idempotent across simulated restarts (the exact
  repro), and a legacy unstamped DB upgrades cleanly.
- Docs: the `## SQLite schema` block in `README.md` was stale (missing the v4
  `country` / `continent_name` GeoIP columns); it now matches `create_latest_schema`
  exactly (column set and order).

## [2.32.0] - 2026-05-29

> **Security hardening release.** Closes seven findings from an AppSec / blue-team
> review of the request path and operational surface: a TLS-handshake Slowloris
> vector, unbounded per-IP memory growth, a world-readable `/metrics` default, a
> committed dev TLS key, silent rate-limiter fail-open, env-only secret handling,
> and the request-normalisation contract. No detection-engine behaviour was
> weakened — all ~330 tests pass and `cargo clippy --all-targets -D warnings` is
> clean.

### Anti-Slowloris: bounded TLS handshake (`src/server.rs`, `src/cli.rs`)

- The TLS `accept()` call is now wrapped in a timeout. Previously a client could
  open a socket and never finish the handshake, pinning the connection task **and
  its `--max-connections` semaphore permit** indefinitely; a few dozen stalled
  sockets could exhaust the accept budget and lock out legitimate traffic.
- New flag **`--tls-handshake-timeout-secs`** (default **10**, `0` disables).
  Handshake timeouts are logged at `warn` (distinct from genuine handshake
  failures) so they can be alerted on separately.

### Bounded per-IP state — memory-exhaustion fix (`src/server.rs`, `src/main.rs`)

- The `ip_connections` and `ip_body_bytes` `DashMap`s previously grew without
  bound — one entry per distinct source IP, never reclaimed — so a client
  rotating addresses (trivial across an IPv6 /64) could drive a slow OOM.
- A background **janitor task** (`spawn_ip_map_janitor`, 30 s interval) now reaps
  entries whose counter is zero (no in-flight connection/body), mirroring the
  GCRA rate-limiter's existing shard sweep. Live requests are never disturbed.

### `/metrics` is fail-closed by default (`src/server.rs`, `src/rules`)

- `/metrics` exposes operational intelligence (per-module block counts, latency,
  which engines fire). It previously fell **open** when no IP allowlist was
  configured. It is now restricted to **loopback** unless the scraper IP is in
  `rules/addr/allowlist.txt` (or the allow-paths YAML). Liveness/readiness
  endpoints are unchanged (orchestrator probes keep working).

### Dev TLS key removed from version control (`.gitignore`, `scripts/`)

- `certs/key.pem` / `certs/cert.pem` (a self-signed `CN=localhost` dev pair) are
  **untracked** and `certs/*.pem` is git-ignored. Added
  **`scripts/gen-dev-certs.sh`** to (re)generate the pair locally with `chmod 600`
  on the key. Production deployments mount CA/ACME-issued certs.

### Rate-limiter fail mode is observable and configurable (`src/waf/rate_limit.rs`, `src/metrics.rs`, `conf/ratelimit.yaml`)

- A Redis outage that silently disabled rate limiting is now visible: new
  counters **`krakenwaf_redis_rate_limit_failopen_total`** and
  **`…_failclosed_total`** plus a structured `warn` on every fall-through.
- New `redis.fail_open` config key (**default `true`** = preserve prior
  fail-open). Set `false` for **fail-closed** (HTTP 429 on Redis unavailability)
  when the limiter is a hard security control.

### File-based secrets with env fallback (`src/secrets.rs`, new)

- New `secrets::load_secret(NAME)` resolves, in order: **`<NAME>_FILE`** →
  **`/run/secrets/krakenwaf/<NAME>`** → the **`NAME`** environment variable.
  This keeps credentials out of `/proc/<pid>/environ`, crash dumps, and child
  process environments while remaining backward compatible.
- Applied to `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`, `SPAMHAUS_DQS_KEY`,
  `REDIS_PASSWORD`, `REDIS_USERNAME`. Example: a Docker/K8s secret mounted at
  `/run/secrets/krakenwaf/MAXMIND_LICENSE_KEY` is picked up with no config.
- Documented in **`docs/secrets.md`**; every env-var reference in the docs and
  config now notes the file option.

### Request-normalisation contract documented & hardened (`src/waf/engine/normalize.rs`, `src/waf/engine/mod.rs`)

- The normalisation model (percent-decode passes, `+`→space, null-byte and
  Latin-1 dual-forms, and what is intentionally *not* normalised) is now
  documented in the module and in **`docs/normalization.md`**, and **pinned by
  regression tests** so it cannot drift silently.
- The keyword/regex matchers now also inspect the **raw (pre-decode) views**,
  de-duplicated — bringing them to parity with the CMC, libinjection and
  vectorscan engines (which already inspected the original form) and closing an
  encoding-evasion inconsistency. Additive only: no detection was removed.

## [2.31.0] - 2026-05-29

> Adds **GeoIP enrichment** (MaxMind GeoLite2-City) to every security event,
> moves MaxMind credentials to environment variables, consolidates the
> geo-update command into `soldier_update --addr-list maxmind-geo`, and sets
> `Banning_mode: false` as the development default to prevent self-banning
> during test loops. Fixes all Clippy regressions introduced by Rust 1.96.
> **All ~330 tests pass (lib + 9 integration binaries, vectorscan + Redis TLS
> active).**

### New `GeoIP` enrichment (`src/geo.rs`, `src/update.rs`)

- New module **`src/geo.rs`** wraps `maxminddb 0.27` with a
  `GeoIpReader` that resolves any source IP to `country_name` and
  `continent_name` via `db/geo/GeoLite2-City.mmdb`.
  - Private / loopback / unresolvable IPs return empty strings (never
    an error).
  - `GeoIpReader` is wrapped in `Arc` and injected into the proxy
    pipeline at startup; no disk I/O on the hot path.
  - IPv4 and IPv6 lookups both supported.
- **`country`** and **`continent_name`** fields are now populated in
  every security event:
  - SQLite vulnerability log (`logs/db/vulns_alert.db`)
  - JSONL event stream (`logs/json/`)
  - Raw critical log (`logs/console_local/`)
- The GeoIP database is loaded **only** when `conf/update.yaml ::
  maxmind-geo.active` is `true` (default). When `active: false` both
  fields are stored as empty strings — no lookup is attempted even if
  the `.mmdb` file is present.

### `soldier_update --addr-list maxmind-geo`

- The `--geo-update` flag has been **removed**; geo downloads now follow
  the same `--addr-list <name>` pattern used by spamhaus / firehol /
  blocklist.
- `update_addr_list("maxmind-geo")` downloads, verifies, and installs
  `GeoLite2-City.mmdb` under `db/geo/`.
- Cron scheduling lives in `conf/update.yaml :: maxmind-geo.cron`
  (default `"0 18 1 * *"` — 1st of each month at 18:00).
- The `scheduled_soldier_jobs_for_values` function emits
  `["--addr-list", "maxmind-geo"]` so the existing cron harness drives
  geo updates alongside all other address-list refreshes.

### Credential security

- `account_id` and `key` fields **removed** from `conf/update.yaml` and
  from `MaxmindGeoConfig`. Hard-coded credentials can no longer be
  checked in by accident.
- Credentials are now read exclusively from environment variables at
  download time:
  ```bash
  export MAXMIND_ACCOUNT_ID='your_account_id'
  export MAXMIND_LICENSE_KEY='your_license_key'
  ./soldier_update --addr-list maxmind-geo
  ```
- If either variable is absent or empty when `active: true`, an error
  is written to `logs/console_local/errors.txt` and the download is
  skipped gracefully (WAF continues running with the existing `.mmdb`).

### Dependency

- `maxminddb` upgraded **0.24 → 0.27.3**.
  - Fixes **RUSTSEC-2025-0132** (`Reader::open_mmap` unsoundness in
    0.24; `open_readfile` was used so the advisory was not exploitable,
    but `cargo deny` blocked the unpatched version).
  - Adopts the `0.27` API: `lookup()` → `LookupResult::decode::<City>()`,
    `names.english` instead of `BTreeMap::get("en")`.

### Tests

- New **`tests/geoip_test.rs`** — 14 unit tests covering `GeoIpReader`
  lookups (US / EU / IPv6 / private / loopback / invalid IP), YAML
  config parsing (`maxmind_geo.active`, `cron`, missing section
  defaults), and cron scheduling (fires on day=1, skipped on day=15,
  inactive module never schedules).
- New **`tests/geoip_waf_test.rs`** — 4 end-to-end integration tests
  that spawn the real `krakenwaf` binary and verify `country` /
  `continent_name` are correctly saved in `vulns_alert.db`:
  - `geo_country_saved_in_sqlite_for_external_ip` — `8.8.8.8` →
    `United States / North America`.
  - `geo_country_saved_for_european_ip` — `185.220.101.34` → `Europe`.
  - `geo_fields_empty_for_private_ip` — `127.0.0.1` → empty.
  - `geo_disabled_via_active_false_saves_empty_fields` — `active: false`
    yields empty fields even for `8.8.8.8`.
  All four tests skip automatically when `db/geo/GeoLite2-City.mmdb` is
  absent.
- New **`docs/geoip.md`** — setup guide, env var instructions, cron
  reference, and credential error handling section.
- README updated with GeoIP setup steps (`export` + `--addr-list`).

### Development default

- `conf/banning.yaml :: Banning_mode` set to **`false`** to prevent
  test loops on `127.0.0.1` from self-banning the loopback address.
  Re-enable for production deployments.

### Clippy (Rust 1.96)

- Fixed `clippy::duration_suboptimal_units` — 8 occurrences across
  `src/banning/`, `src/main.rs`, and 5 test files:
  `from_secs(n*60)` → `from_mins(n)`,
  `from_secs(n*3600)` → `from_hours(n)`.
- Fixed `map_unwrap_or` / `result_map_or` — 3 occurrences:
  `.map(f).unwrap_or(d)` → `.map_or(d, f)` and `.is_ok_and(f)`.

### Version bump

`Cargo.toml :: version` 2.30.0 → **2.31.0**.

---

## [2.30.0] - 2026-05-27

> Adds a first-class **BAN list** that short-circuits repeat offenders
> and confirmed scanners at the server layer, before any WAF inspection
> runs. The subsystem is opt-in via `conf/banning.yaml` — when the file
> is absent or `Banning_mode: false`, KrakenWaf behaves exactly like
> 2.29.0. **All 307 tests pass (lib + 8 integration binaries).**

### New `Banning` subsystem (`src/banning/`)

- New module `src/banning/{mod,config,sqlite_store,redis_store}.rs`
  exposes `BanManager` with two methods on the request hot path:
  - `check(ip) -> Option<banned_until>` (server-layer short-circuit)
  - `record_block(ip, reason)` (called from `proxy.rs::log_and_enforce`)
- New configuration file **`conf/banning.yaml`** (auto-discovered at
  startup):
  ```yaml
  Banning_mode: true
  Ban_context:
    security_scanners: true     # one Detect_bots_n_scanners hit → ban
    tolerance_block_count: 3    # 3 blocks (any engine) → ban
    Ban_wait_time: 30m          # asymptotic: N × Ban_wait_time
  ```
  Validator enforces `tolerance_block_count >= 1` and a non-zero
  `humantime` duration. Both canonical (`Banning_mode`) and snake_case
  (`banning_mode`) keys are accepted.
- **Hybrid storage backend** — Redis/Valkey when
  `conf/ratelimit.yaml :: redis` is set (the existing `fred::Pool` is
  reused, no second connection), SQLite at `logs/db/banning.db`
  otherwise. The SQLite file is `chmod 0600` on Unix to match the
  existing `vulns_alert.db`.
- **Asymptotic ban duration** — 1st offense `= Ban_wait_time`, 2nd
  `= 2× …`, Nth `= N × …`. Counter resets after 30 days of inactivity.
- **Single Lua-scripted atomic operation** for the Redis backend with a
  150 ms per-call timeout. Fails open on Redis errors so a hung Redis
  cannot brick the WAF.

### Server / proxy wiring

- `src/server.rs::handle` now runs `ban_manager.check(effective_ip)`
  before the per-IP concurrency gate, the memory-backpressure gate, or
  the WAF engine. Rejected requests get HTTP 403 with body
  `"Banned by KrakenWaf"` and a `Low` severity log entry
  (`engine="banning"`, `title="Banned IP — request rejected"`,
  `rule_match="banning::active_ban"`, `cwe="CWE-693"`).
- `src/proxy.rs::log_and_enforce` records every Block-mode rejection
  through the BAN manager via `tokio::spawn`, so a slow Redis never
  delays the WAF response. The block reason is classified
  (`SecurityScanner` / `RateLimit` / `IpReputation` / `RuleDetection`)
  so the `security_scanners` fast-track only triggers for
  `Detect_bots_n_scanners` hits.
- New Prometheus label: `krakenwaf_blocked_total{engine="banning:active_ban"}`.

### Validator + tests

- 13 unit tests for `BanConfig` (parse / alias / required fields /
  zero/missing rejections / canonical YAML round-trip).
- 7 unit tests for `SqliteBanStore` (threshold, asymptotic extension,
  scanner fast-track, lookup expiry, retention reset, purge).
- 3 unit tests for `RedisBanStore` outcome parsing (pure, no Redis
  required for the test).
- New integration binary **`tests/banning_real_test.rs`** spawns the
  real `krakenwaf` binary in `--no-tls` mode with
  `--trusted-proxy-cidrs 127.0.0.0/8 --real-ip-header x-forwarded-for`
  and a backing Axum server, then forges different attacker IPs via
  `X-Forwarded-For` (the simulated "free proxy" path). Three scenarios:
  - `nikto_request_then_clean_request_is_banned` — one scanner UA →
    instant ban → next clean request is rejected by the BAN list.
  - `three_blocks_triggers_ban_on_fourth_request` — cumulative
    tolerance path.
  - `banning_is_per_ip_other_clients_unaffected` — proves the ban is
    keyed on the *effective* client IP (X-Forwarded-For), not the
    loopback peer.

### Misc

- `RateLimiter::redis_pool()` helper exposes the underlying
  `fred::Pool` so the BAN manager can reuse it (single TLS pool serves
  both subsystems).
- New `humantime = "2.1"` dependency (small, no transitive bloat) for
  `Ban_wait_time` parsing.
- New docs at **[`docs/banning.md`](docs/banning.md)** — full lifecycle
  diagram, schema reference, log/metric format, and a manual-test
  recipe with `curl`.
- README gains a "🚫 Banning" section that links into the new doc.

### Version bump

`Cargo.toml :: version` 2.29.0 → **2.30.0**.

---

## [2.29.0] - 2026-05-23

> Large hardening + performance refactor on top of 2.28.0. This release
> replaces several long-standing assumptions in the request/response
> pipeline, lowers default memory caps drastically, closes a handful of
> detection-bypass vectors, and trades a `RwLock` on the hot path for a
> wait-free atomic. **All 238 upstream tests continue to pass.**

### Memory-pressure overhaul (drastically lower defaults)

- New module `src/limits.rs` centralises every buffering ceiling and is
  loaded from `rules/cmc/config.yaml :: memory-limits` (or
  `conf/limits.yaml` as a fallback) at startup. Sits alongside the
  inflight-byte accounting added in 2.28.0 (which gates *concurrent*
  buffering); the new knobs cap *per-request* buffer sizes.
- New YAML knobs (see `rules/cmc/config.yaml`):
  - `max_request_body_buffered_bytes` — default **8 MiB** (was 100 MiB).
  - `max_response_body_buffered_bytes` — default **8 MiB** (was 100 MiB).
  - `max_streaming_inspection_window_bytes` — default 256 KiB.
  - `max_decompress_ratio` — default 32× (zip-bomb guard).
  - `max_connections` — optional pin; otherwise RAM-derived.
- CLI defaults updated:
  - `--max-body-bytes` / `--max-upstream-response-bytes` now default to **0**
    (fall through to YAML / built-in 8 MiB). Pass an explicit value to
    override.
  - `--max-connections` defaults to **0**; KrakenWaf derives a conservative
    value from `/proc/meminfo` (≈ 1 connection per 2 MiB, clamped to
    `[64, 4096]`) when neither CLI nor YAML pin a value.
- Startup log reports the resolved caps and `max_decompress_ratio`.

### Detection-bypass closures

- **Body decompression before inspection** (`src/body_decode.rs`). The proxy
  now decodes `Content-Encoding: gzip | x-gzip | deflate | br | zstd` (and
  any RFC-compliant comma-separated chain, up to 4 layers) before handing
  bytes to the detection engines. Two guards bound the work: an absolute
  byte cap equal to the request body limit and an expansion-ratio guard
  (`max_decompress_ratio`, default 32×). A POST sent with
  `Content-Encoding: gzip` is no longer free-pass for SQLi/XSS payloads.
- **`multipart/form-data` parser** (`src/multipart_extract.rs`). Each part's
  body is extracted and inspected independently; payloads can no longer
  hide behind boundary + MIME headers. Caps: 256 parts per body, 70-char
  boundary length (RFC 2046).
- **`Connection:`-listed headers stripped** (`proxy::connection_listed_headers`).
  RFC 9110 §7.6.1 / RFC 7230 §6.1: every token in `Connection:` is now
  deleted before forwarding. Closes `Connection: X-Auth-Internal` smuggling
  against permissive backends.
- **Quadratic detection loop removed**. `consume_and_inspect_body` no
  longer re-runs the full engine stack against every chunk window followed
  by *another* full-body pass — it buffers and inspects exactly once on
  the cleartext view. For a 100 MiB body with 8 KiB chunks this removes
  ≈ 12 500 redundant passes.
- **Inspect-headers-only for binary response types** (`proxy::response_body_should_be_inspected`).
  When the upstream advertises an image / video / audio /
  `application/octet-stream` content-type the WAF scans only the headers
  and forwards the body without further allocation pressure.

### Security hardening

- **GCRA key canonicalisation** (`src/waf/rate_limit.rs :: hash_ip`).
  Counters are now keyed by `IpAddr::octets()` so `192.168.1.1`,
  `192.168.001.001`, and `::ffff:192.168.1.1` collapse to one bucket.
  Previously each textual form had a separate limiter — trivial bypass
  closed.
- **Monotonic clock for the rate limiter**. The hot path derives time from
  `Instant::now()` anchored to a wall-clock snapshot taken once at
  startup. Immune to NTP skew and ≈ 3× cheaper than `SystemTime::now()`.
- **Admission control on shard fill** (`Shard::check`). Under DDoS the
  shard previously evicted the *oldest TAT*, which despatched the
  legitimate incumbent and admitted the attacker. The new behaviour
  sweeps expired entries opportunistically and, when every slot is still
  live, **rejects the new arrival** — returning the same 429 path a
  rate-limit miss would.
- **RFC 7239 `Forwarded:` header parser** (`proxy::forwarded_header_real_ip`)
  + `X-Real-IP` fallback. Modern proxies (HAProxy 2.x, recent nginx with
  the realip module) emit `Forwarded:` instead of `X-Forwarded-For`; the
  real-IP resolver walks the chain right-to-left and selects the first
  untrusted hop.
- **TLS 1.3 only** (`src/tls.rs`). `ServerConfig` is built with
  `&[&TLS13]`; ALPN advertises `h2` then `http/1.1`; 0-RTT
  (`max_early_data_size`) is pinned to 0 to prevent POST replay through
  `early_data`. Key-file permissions checked at startup — a permissive
  `chmod` emits a `tracing::warn!` referencing CIS §1.2.

### Performance

- **`ArcSwap` snapshot** (`src/waf/engine/mod.rs`). The
  `RwLock<Arc<RulesSnapshot>>` is replaced by
  `arc_swap::ArcSwap<RulesSnapshot>`. Inspection reads become a single
  atomic load (wait-free); hot-reload still publishes a new snapshot
  atomically.
- **Aho-Corasick walks every overlap** (`matchers::keyword_match`).
  Previously the leftmost match short-circuited the walk so additive
  score-only rules could not accumulate. Now `find_iter` aggregates score
  across every hit until the block threshold is reached.
- **`flatten_headers` preserves bytes**. The previous
  `to_str().unwrap_or("<binary>")` dropped non-UTF-8 header values to a
  static placeholder, hiding payloads carried in binary trailers. We now
  do a lossy decode that keeps every ASCII byte verbatim.
- **`tokio` features trimmed**. `["full"]` → `["rt-multi-thread", "net",
  "time", "signal", "sync", "macros", "io-util", "fs", "process"]`.
  Reduces compile surface; dev-dependency `tokio` still uses `["full"]`
  so integration tests are unaffected.
- **HTTP/2 enabled at the listener**. `hyper = ["http1", "http2",
  "server"]` and `hyper-util = [..., "http2"]` — clients negotiating ALPN
  `h2` are now served natively instead of being forced to downgrade.

### New dependencies

- `arc-swap = "1.7"` — wait-free atomic rule snapshot.
- `flate2 = "1.0"` — gzip / deflate decompression.
- `brotli = "7.0"` — `Content-Encoding: br`.
- `zstd = "0.13"` (default-features off) — `Content-Encoding: zstd`.

### Caveats / known gaps (tracked for 2.30.0)

- ReDoS hardening for operator-supplied regex rules (per-match wall-clock
  deadline via `spawn_blocking`) is **not** in this release. Bound your
  payload sizes via `max_request_body_buffered_bytes` until the
  follow-up lands.
- Hard DNS-pinning for upstream hostnames (custom `reqwest::dns::Resolver`)
  is still deferred — the startup-time resolution warning remains.
- Vectorscan `scratch` pooling per worker is deferred to a later release.

## [2.28.0] - 2026-05-23

### Added

#### New CMC module: `Detect_bots_n_scanners`

Scanner / crawler / offensive-tooling `User-Agent` blocking — previously a
hard-wired check inside the WAF detection engine — has been extracted into a
dedicated CMC module: [`Detect_bots_n_scanners`](docs/cmc/detect_bots_n_scanners.md)
(CWE-200, **Low** severity).

```yaml
# rules/cmc/config.yaml
global-options:
  Untrust: 60                    # >= 60 blocks; < 60 silent-logs

CMC-Rules:
  Detect_bots_n_scanners: true   # set to false to disable scanner-UA blocking
```

* Patterns are loaded from `rules/user_agents/scanners.txt` (OWASP CRS
  [`scanners-user-agents.data`](https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data),
  ~78 substrings). Case-insensitive Aho-Corasick on the CPU fast path; Hyperscan
  `BlockDatabase` (regex-escaped, `CASELESS | SINGLEMATCH`) when
  `--enable-vectorscan` is active.
* Action gating mirrors the other reconnaissance modules:
  - `Untrust >= 60` (default) → **block** (HTTP 403). Finding is logged at
    **Low** severity to all three security outputs (raw, JSONL, SQLite) and
    framed as a bot/scanner reconnaissance sweep.
  - `Untrust < 60` → silent log via `tracing::warn!`; request is forwarded.
* Called from `WafEngine::inspect_early()` immediately after IP filtering, via
  a new `CmcManager::inspect_user_agent(&str) -> Option<Finding>` entry point.
* Toggling `Detect_bots_n_scanners: false` (or omitting the key) now
  **disables scanner-UA blocking entirely** — the file is no longer read and
  the matcher is not built. The YAML toggle is authoritative rather than
  informational.

### Changed

* `RuleSet::scanner_agents`, `EngineMatchers::req_scanner_agents` and
  `EngineMatchers::scanner_vectorscan` (plus the now-dead
  `build_vectorscan_literal_matcher` helper and `regex_escape_literal`
  companion) are removed — the engine no longer owns scanner-UA matching.
  The single source of truth is the `Detect_bots_n_scanners` CMC module.
* Tests: `tests/server_real_test.rs::scanner_ua_sweep` now spawns the WAF
  with `--cmc-load rules/cmc/config.yaml` (scanner-UA blocking is no longer
  the default). A new companion test,
  `scanner_ua_not_blocked_when_cmc_disabled`, asserts that with the module
  off, representative scanner UAs (Nmap, OpenVAS, wfuzz, gobuster,
  Arachni — all exclusive to `scanners.txt`) reach the upstream unchanged.

## [2.27.0] - 2026-05-22

### Added

#### Per-path IP restriction (`only_addrs`) in allow-paths YAML

A new optional `only_addrs` field in `rules/allowpaths/lists.yaml` restricts
access to specific URI prefixes by client IP address. When set, only IPs in
the referenced file may reach the protected paths; all other source IPs
receive **HTTP 403** — even when the WAF is running in `silent` or
`detect-only` mode.

```yaml
allow:
  - order: 2
    title: "Health check endpoint"
    log: false
    only_addrs: rules/addr/allowlist/allow_addrs.txt  # new field
    paths:
      - /metrics
      - /healthz
      - /readyz
      - /livez
```

The IP allowlist file (`rules/addr/allowlist/allow_addrs.txt`) supports:

- **Exact IP**: `127.0.0.1`
- **CIDR**: `10.0.0.0/8`, `127.0.0.0/25`
- **Start–end range**: `192.168.1.1-192.168.1.50`

Lines starting with `#` and blank lines are ignored. Line scanning uses
`memchr::memchr_iter` for zero-copy performance; range-separator detection
uses `memchr::memchr` instead of `str::contains`.

The restriction also fires when the protected path appears in the **query
string** or elsewhere in the full URI (scanned with `memchr::memmem::find`),
preventing redirect-parameter bypasses such as `GET /api?next=/healthz`.

#### Effective IP resolution for WAF built-in endpoints

The `only_addrs` check on the WAF's own endpoints (`/metrics`, `/readyz`,
`/livez`, `/__krakenwaf/health`) now uses the **effective client IP** (honours
`--real-ip-header` / `--trusted-proxy-cidrs`) instead of the raw TCP peer
address, so the restriction works correctly behind a load balancer.

#### `rules/addr/allowlist/allow_addrs.txt` — default IP allowlist

A new companion file `rules/addr/allowlist/allow_addrs.txt` ships with
loopback addresses pre-populated. The bundled `lists.yaml` references this
file for the "Health check endpoint" entry so observability endpoints
(`/metrics`, `/healthz`, `/readyz`, `/livez`) are restricted to localhost
out of the box.

### Changed

- `allowpaths::load_and_validate` now requires a `base_dir: &Path` parameter
  used to resolve relative `only_addrs` paths. `main.rs` passes the WAF root
  directory (`std::env::current_dir()`).
- `proxy::effective_client_ip` promoted to `pub(crate)` so `server.rs` can
  reuse the same IP-resolution logic for built-in endpoint access control.
- `server.rs` handle function computes the effective IP once at the top of the
  built-in path handler and passes it to both the `only_addrs` check and the
  existing `allowlist.txt` check.
- All file open operations in `allowpaths.rs` (YAML file, `only_addrs` file)
  use `fs::canonicalize` before opening to prevent path traversal.

### Security

- Path traversal attempts against `only_addrs` file paths are rejected at
  startup by `fs::canonicalize`.
- Encoded or obfuscated traversal in request URIs (e.g.
  `/foo/../healthz`, `%2fhealthz`) normalises to the canonical form before
  the IP restriction is evaluated.
- The `only_addrs` Block decision is enforced regardless of WAF mode (`block`,
  `silent`, `detect-only`).

### Tests

- 10 new unit tests in `src/allowpaths.rs` (`#[cfg(test)]`) covering:
  exact IP, CIDR, range, comment/blank-line handling, path check variants,
  URI query-string restriction, and the no-restriction bypass case.
- 12 new integration tests in `tests/allowpaths_addr.rs` covering:
  localhost allowed, foreign IP blocked (via `X-Forwarded-For` spoofing),
  `/healthz` and `/readyz` both proxied and built-in paths, URI query-string
  blocking, path traversal normalisation, real attack payloads blocked on
  unrestricted paths (XSS, SQLi), and WAF metrics accessibility.

### Documentation

- `docs/allowpaths.md` — full `only_addrs` reference including file format,
  CIDR/range syntax, load-balancer interaction, and security notes.
- `docs/observability.md` — new "Metrics access control" section documenting
  the `only_addrs` configuration for Prometheus/Grafana scraping.
- `README.md` — metrics and allow-lists sections updated.

---

## [2.26.0] - 2026-05-22

### Added

#### Rate-limit / backpressure CLI flags configurable via `conf/ratelimit.yaml`

The five v2.24.0 backpressure flags now have matching YAML fields, so operators
can avoid passing every flag on the command line and keep all rate-limit-related
tuning in one auditable file. Resolution order for every field is identical:

```
CLI flag (highest)  >  conf/ratelimit.yaml  >  built-in default
```

New YAML fields under `conf/ratelimit.yaml`:

- `body_frame_timeout_secs` (default 30) — overrides `--body-frame-timeout-secs`
- `max_inflight_body_bytes` (default 1073741824 / 1 GiB) — overrides
  `--max-inflight-body-bytes`
- `max_per_ip_body_bytes` (default 209715200 / 200 MiB) — overrides
  `--max-per-ip-body-bytes`

Existing fields `rate_limit_per_minute` and `max_coroutines_per_ip` keep the
same priority chain.

#### Detection-engine globals configurable via `rules/cmc/config.yaml`

The two detection-engine flags now have matching YAML fields under
`global-options` in the CMC config file:

- `Anomaly_threshold` (default 600) — overrides `--anomaly-threshold`
- `Max_inspection_ms` (default 0, disabled) — overrides `--max-inspection-ms`

Resolution order:

```
CLI flag (highest)  >  rules/cmc/config.yaml global-options  >  built-in default
```

### Changed

- CLI flag types for the five fields above changed from `T` (with `default_value_t`)
  to `Option<T>` (no clap default) so an absent flag transparently falls through
  to the YAML / built-in default chain. Passing the flag explicitly overrides
  any value present in the YAML file, exactly as `--rate-limit-per-minute` has
  always behaved.
- README CLI table cross-links each affected flag to its YAML counterpart.
- `docs/rate_limit.md` documents the unified priority chain and field table.
- `proxy.rs` reads `body_frame_timeout_secs` from `AppState` instead of the
  raw `cli` struct so the resolved (CLI-or-YAML-or-default) value is used.

### Tests

- 3 new unit tests in `ratelimit_config.rs` covering defaults, YAML, and
  CLI-overrides-YAML for the new resolvers.
- 3 new unit tests in `cmc/mod.rs` covering the same for the
  detection-engine resolvers.
- 367 tests total, all passing with vectorscan active.

## [2.25.0] - 2026-05-21

### Fixed

#### Score accumulator double-counting (false positive) — CRITICAL

- `inspect_payload_inner` carried `sum_score` across all inspection views,
  causing the same rule to contribute its score twice whenever the rule's
  literal appeared both in the full normalized payload **and** in a sub-view
  created by `inspection_views` splitting on `\n`, `&`, `;`, `?`, `\r`, `\0`.
- Concrete reproduction: `POST /test_post` with body
  `payload_test=kwaf-score-post-near` (rule score = 599, default threshold =
  600). View 1 (the full request) matched once (sum_score = 599, below
  threshold). The newline-delimited segment view "payload_test=kwaf-score-post-near"
  re-matched the same rule (sum_score = 1198 ≥ 600) and produced a spurious
  403.
- `sum_score` is now reset at the start of each view iteration. Cross-segment
  attacks (e.g. `kwaf-score-low-a&kwaf-score-low-b&kwaf-score-low-c`) remain
  blocked because the full-payload view already accumulates across all
  segments via `find_iter` (keywords) or per-rule iteration (regex).
- Verified end-to-end with `attack --concurrency 50` against a live
  `demo_server`+`krakenwaf` stack: 477 attack payloads, 477 blocked, 0
  bypassed, 0 errors, 0 score expectation failures.

#### Integration-test concurrency: fixed-port collisions removed

- `tests/ratelimit_real_test.rs` previously bound backend to fixed port 9500
  and allocated WAF ports from an `AtomicU16` starting at 9510, causing
  port-already-in-use failures whenever two `cargo test` processes ran in
  parallel.
- `tests/server_real_test.rs` had the same anti-pattern with backend port
  9077 and WAF ports starting at 9090.
- Both files now use OS-allocated ephemeral ports via `pick_free_port()` (the
  same pattern as the Redis integration tests in `src/waf/rate_limit.rs`).
  The backend port is resolved once per process via `OnceLock<u16>`; each WAF
  instance gets its own freshly-allocated port.

#### Test client / readiness timing

- `wait_for_waf` polling window extended to 45 s (150 × 300 ms) so the WAF
  binary can come up even when many parallel `cargo test` processes saturate
  the CPU.
- `reqwest::Client::timeout` for per-request HTTP calls raised from 5 s to
  25 s; a WAF that has not responded to an attack request within 25 s is
  treated as broken rather than slow.

#### Redis rate limiter hardening (production)

- Wrapped `pool.eval()` in a 150 ms per-call `tokio::time::timeout` so a hung
  Redis instance cannot stall WAF request processing — on timeout the
  limiter fails open and emits a `tracing::warn` with the IP and elapsed ms.
- Wrapped `pool.init()` in a 10 s `tokio::time::timeout` so a misconfigured
  Redis URL fails fast at startup rather than blocking the supervisor loop.

#### Redis integration tests: ephemeral ports + readiness probe

- `try_spawn_test_redis` now allocates a free TCP port via `TcpListener::bind(":0")`
  and probes the spawned `redis-server` with `PING` until it responds, with
  up to 5 retry attempts on a different port on each retry. Replaces the
  previous fixed-port + `sleep(400ms)` approach that collided when tests ran
  in parallel cargo invocations.

## [2.24.0] - 2026-05-21

### Added

#### HTTP/2 ALPN negotiation

- `TlsConfigStore` now advertises `h2` and `http/1.1` in TLS ALPN during
  handshake so clients can negotiate HTTP/2 without any additional configuration.
- ALPN protocols are applied inside `build_tls_config` after the `ServerConfig`
  is built; no changes to SNI resolution or certificate selection logic.

#### `TlsConfigStore` hot-reload factory

- `TlsConfigStore` (in `src/tls.rs`) wraps `Arc<parking_lot::RwLock<Arc<ServerConfig>>>`
  for wait-free reads in the accept loop while supporting atomic cert swaps on SIGHUP.
- SIGHUP handler now calls `tls_store.reload()` instead of rebuilding a raw
  `TlsAcceptor`; the new config is visible to all active connections without a
  restart.

#### Root-path health and liveness probes

- `/livez` and `/readyz` are now available as root-level aliases alongside the
  existing `/__krakenwaf/livez` and `/__krakenwaf/readyz` paths. Kubernetes
  deployments no longer need to configure a path prefix.

#### Memory backpressure gates

- New global gate: when `inflight_body_bytes` reaches `max_inflight_body_bytes`
  (default 1 GiB), new requests return HTTP 503 with `Retry-After: 5` until
  memory is freed.
- New per-IP gate: when a single IP's `ip_body_bytes` reaches
  `max_per_ip_body_bytes` (default 200 MiB), that IP receives HTTP 503 with
  `Retry-After: 5`.
- Both limits are configurable via `--max-inflight-body-bytes` and
  `--max-per-ip-body-bytes`; 0 disables each gate independently.
- `BodyTracker` RAII struct in `proxy.rs` increments the global and per-IP
  counters on each body chunk and releases them atomically on drop (Ok, Err,
  or panic).

#### W3C traceparent propagation improvements

- Incoming `traceparent` headers with a valid 32-hex trace-id are now preserved:
  the trace-id is kept and a new parent-id span is generated.
- If no valid incoming traceparent exists, both trace-id and parent-id are
  freshly generated from UUID v4.
- `traceparent_forwarded` and `traceparent_generated` Prometheus counters track
  which path was taken per request.

#### Inspection deadline (`--max-inspection-ms`)

- New `--max-inspection-ms` CLI flag sets a per-request wall-clock cap on WAF
  rule inspection. When the deadline is reached the inspection loop exits and the
  request proceeds (fail-open). 0 = unlimited (default).

#### Body frame timeout (`--body-frame-timeout-secs`)

- New `--body-frame-timeout-secs` CLI flag controls how long the WAF waits for
  a single body frame before timing out (RUDY/slow-body defence).
  Default: 30 s.

#### Anomaly-score threshold (`--anomaly-threshold`)

- New `--anomaly-threshold` CLI flag exposes the global anomaly score block
  threshold previously hardcoded in the engine. Default: 600.

#### WAL persistence mode (`--wal-mode`)

- New `--wal-mode` CLI flag selects between `sqlite` (WAL journal, queryable)
  and `bincode` (flat binary, atomic rename, much faster) persistence backends
  for the rate-limiter state snapshot. Default: `sqlite`.

### Changed

- `server::run()` now accepts a `TlsConfigStore` instead of a raw `TlsAcceptor`,
  enabling atomic cert rotation without restarting the accept loop.
- `AppState` extended with `inflight_body_bytes`, `max_inflight_body_bytes`,
  `ip_body_bytes`, and `max_per_ip_body_bytes` fields.
- `WafEngine` construction now uses the `WafEngineFactory::create(WafEngineConfig)`
  pattern, keeping the engine constructor stable as optional fields are added.

## [2.23.0] - 2026-05-21

### Added

#### Rate-limit configuration file (`--ratelimit-by-file-conf`)

- New CLI flag `--ratelimit-by-file-conf <path>` loads all rate-limit settings
  from a YAML file, eliminating the need to pass individual rate-limit arguments.
- KrakenWaf **auto-discovers** `conf/ratelimit.yaml` in the working directory;
  no flag needed when the file is present.
- Priority chain: explicit `--rate-limit-per-minute` CLI flag → value in the
  config file → built-in default (240 req/min).
- Config fields:
  - `rate_limit_per_minute` — per-IP request rate (0 = defer to CLI/default).
  - `max_coroutines_per_ip` — per-IP concurrency cap (see below).
  - `redis` — Redis backend configuration (see below).
- Template file shipped at `conf/ratelimit.yaml` with full inline documentation.

#### Per-IP concurrency limiter (`max_coroutines_per_ip`)

- New `max_coroutines_per_ip` field (config file) caps the number of
  simultaneous in-flight requests accepted from a single IP address.
- Excess connections are rejected immediately with **HTTP 429** and
  `Retry-After: 5` before any WAF inspection or upstream proxying occurs.
- Implemented as a lock-free `AtomicUsize` per IP stored in a `DashMap`
  with RAII `ConnGuard` semantics — no per-request allocation on the hot path.
- Default: 64. Set to 0 to disable.

#### Redis distributed rate-limiter backend

- When a `redis:` section is present in `conf/ratelimit.yaml`, KrakenWaf
  replaces the local GCRA limiter with a Redis-backed counter, enabling
  consistent rate limiting across multiple WAF instances.
- Rate limiting uses an **atomic Lua script** (`INCR` + conditional `EXPIRE`)
  executed server-side — no MULTI/EXEC round-trips, no TOCTOU window.
- **Fail-open policy**: Redis unavailability emits a `tracing::warn!` and
  allows the request through rather than causing an outage.
- **CIS Redis Benchmark hardening enforced at startup**:
  - URL must use `rediss://` (TLS mandatory — runtime error otherwise).
  - Credentials (`REDIS_PASSWORD`, `REDIS_USERNAME`) read from environment
    variables — never stored in the config file, safe for container secrets vaults.
  - Custom CA certificate supported via `ca_cert_path` for private PKI / mTLS.
- Connection pool size, key namespace prefix, and window duration configurable.

### Tests

- New unit tests in `src/waf/rate_limit.rs`:
  - `redis_allows_within_limit` — Redis allows exactly `limit` requests.
  - `redis_ips_are_independent` — separate counters per IP.
  - `redis_window_resets` — counter expires after the configured window.
  - All Redis tests auto-skip when `redis-server` is not on `PATH`.
- New integration test file `tests/ratelimit_real_test.rs` (11 tests):
  - `local_rate_limit_blocks_burst` — GCRA blocks after configured limit.
  - `local_rate_limit_ips_are_independent` — IPs have isolated counters.
  - `ratelimit_by_file_conf_sets_rate_limit` — config file sets effective limit.
  - `cli_rate_limit_overrides_file_conf` — CLI flag takes precedence.
  - `max_coroutines_per_ip_blocks_excess_concurrent` — concurrent cap enforced.
  - `max_coroutines_per_ip_zero_disables_limit` — cap=0 allows all.
  - `attack_burst_is_rate_limited` — burst of 10 requests, limit=5, rest blocked.
  - `attack_scanner_rate_limited_regardless_of_ua` — UA rotation doesn't bypass limit.
  - `attack_concurrent_flood_is_throttled` — flood of 20 concurrent requests throttled.
  - `attack_slowloris_concurrent_blocked` — slow-connection Slowloris simulation.

---

## [2.22.0] - 2026-05-20

### Added

#### `Detect_bad_artifacts` CMC module

- New CMC module `Detect_bad_artifacts` inspects request **URI paths** for
  sensitive file/directory artifacts that should never be publicly accessible:
  dotfiles, configuration files, debug logs, credentials, framework-specific
  files, `/proc` and `/sys` entries, and more (CWE-538).
- Pattern research basis: OWASP ModSecurity Core Rule Set (CRS)
  [`restricted-files.data`](https://github.com/coreruleset/coreruleset/blob/main/rules/restricted-files.data)
  — covering Apache dotfiles, home-level dotfiles, generic config filenames,
  compressed database dumps, CI/CD files, CMS-specific paths (WordPress,
  Symfony, Drupal, PrestaShop, Magento), framework configs (ASP.NET, Node,
  Composer), OS artefacts, and Linux pseudo-filesystem entries (`/proc/`,
  `/sys/`).
- Pattern file: `rules/artifacts/file_pitfalls.txt` (500+ literal substrings).
- Matching uses `memchr::memmem::Finder` (Boyer-Moore-like SIMD) on the CPU
  fast path. With `--enable-vectorscan` a Hyperscan `BlockDatabase` with
  `SINGLEMATCH` is used.
- Action gated by global `Untrust` level:
  - `>= 60` (default) → **block** (HTTP 403), log to raw / JSONL / SQLite (`High`).
  - `< 60` → **silent log** only; request is forwarded. Finding logged via `tracing::warn!`.
- Activated by adding `Detect_bad_artifacts: true` to `rules/cmc/config.yaml`.
  **Disabled by default** for backwards compatibility; enabled in the default
  config file at `rules/cmc/config.yaml`.
- 10 new demo routes added to `demo_server` (`.env`, `.git/config`,
  `wp-config.php`, `proc/cpuinfo`, `.aws/credentials`, `config.json`,
  `.ssh/id_rsa`, `debug.log`, `composer.json`, `.htpasswd`).
- `attack` tool gains `BAD_ARTIFACT_PATHS` constant and sweep.
- Documentation: `docs/cmc/detect_bad_artifacts.md`, `docs/cmc/schema.md`
  updated, README CMC section updated.

### Tests

- 10 unit tests in `src/cmc/detect_bad_artifacts.rs` (pattern loading,
  detection across dotfiles / config files / /proc entries, comment-skipping).
- 12 new integration tests in `tests/server_real_test.rs`:
  - 10 tests: artifact URI → 403 at `untrust=60`.
  - 1 test: artifact URI → 200 at `untrust=30` (silent log mode).
  - 1 test: clean URI → not 403 at `untrust=60`.

---

## [2.21.0] - 2026-05-20

### Added

#### `Silent_sql_errors` CMC module

- New CMC module `Silent_sql_errors` inspects upstream HTTP **response bodies**
  for verbose DBMS error fingerprints (OWASP ModSecurity Core Rule Set's
  `sql-errors.data` literal list) and — depending on the global `Untrust`
  level — either **scrubs** the matched substring or **blocks** the
  response entirely (CWE-209).
- Pattern research basis: the OWASP CRS data file
  [`rules/sql-errors.data`](https://github.com/coreruleset/coreruleset/blob/main/rules/sql-errors.data)
  — the same literals CRS uses for its `942100–942999` SQLi response
  detection rule range, repurposed locally as a fingerprint set.
- Pattern file: `rules/error_msgs/sql_errors_static.txt` (160+ literal
  substrings) covering MySQL, MariaDB, Drizzle, PostgreSQL, Oracle, MSSQL,
  SQLite, IBM DB2, Informix, Firebird, Sybase, Ingres, HSQLDB/H2/Derby,
  MonetDB, Vertica, Presto/Trino, MemSQL, CrateDB, Snowflake, Virtuoso,
  Altibase, FrontBase, Mimer, Neo4j/Cypher, plus connector identifiers
  (`Npgsql.`, `Zend_Db_Adapter_*_Exception`,
  `org.postgresql.util.PSQLException`,
  `System.Data.SqlClient.SqlException`, `OracleException`, etc.).
- Matching uses `memchr::memmem::Finder` (Boyer-Moore-like, SIMD-accelerated
  on x86_64) on the CPU fast path. With `--enable-vectorscan` a Hyperscan
  `BlockDatabase` with `SOM_LEFTMOST | SINGLEMATCH` is used so the SIMD
  engine reports the exact match offsets needed for the scrub.
- Action gated by `Untrust`:
  - `>= 80` → **block** (HTTP 403), log to raw / JSONL / SQLite (`High`).
  - `< 80` (default) → **silent scrub**: replace the matched literal with a
    single ASCII space, recompute `Content-Length`, forward the response;
    finding logged with `Low` severity.
- New `Decision::SilentReplace { finding, body }` engine variant and
  `CmcResponseDecision::SilentReplace { finding, body }` CMC variant
  propagate the modified body from the CMC layer all the way to the proxy,
  which updates `Content-Length` before forwarding.
- Activated by adding `Silent_sql_errors: true` to `rules/cmc/config.yaml`.
  **Disabled by default** for backwards compatibility.
- 10 new `/leak/static/*` routes added to `demo_server` for manual testing
  and the attack sweep tool. `attack` now exercises all 10 paths against
  the configured WAF target.
- Documentation: `docs/cmc/silent_sql_errors.md`, `docs/cmc/schema.md`
  updated with module summary + conflict note for `Detect_db_errors`,
  README CMC section updated.

### Tests

- 12 new unit tests in `src/cmc/silent_sql_errors.rs` (pattern loading,
  detection across 8 DBMS families, leftmost-match, scrub helper).
- 12 new integration tests in `tests/server_real_test.rs`:
  - 10 scrub-mode tests (one per `/leak/static/*` route) verify HTTP 200,
    fingerprint absent from response body, `Content-Length` matches scrubbed
    body length.
  - 1 block-mode test (`Untrust = 80`) verifies HTTP 403.
  - 1 clean-response test verifies non-leak routes are not modified.

### Changed

- Version bumped 2.20.0 → 2.21.0 (Cargo.toml, Cargo.lock, README).
- `rules/cmc/config.yaml` ships with `Silent_sql_errors: true` by default
  alongside the other CMC modules.

---

## [2.20.0] - 2026-05-19

### Added

#### `Detect_db_errors` CMC module

- New CMC module `Detect_db_errors` intercepts upstream HTTP **response bodies**
  containing verbose DBMS error messages before they reach the client, cutting off
  the error-based SQL/NoSQL injection feedback loop that tools like SQLmap and
  NoSQLmap rely on to enumerate schema, data, and blind boolean conditions.
- Patterns are loaded from `rules/error_msgs/sql_errors.txt` at WAF startup.
  200+ PCRE-compatible regexes covering all major SQL and NoSQL engines:
  MySQL/MariaDB/Drizzle/TiDB, PostgreSQL, Oracle, MSSQL, SQLite, IBM DB2,
  Informix, Firebird, SAP MaxDB, Sybase, Ingres, HSQLDB/H2/Derby, MonetDB,
  Vertica, Presto/Trino, ClickHouse, CrateDB, Snowflake, Virtuoso, Altibase,
  FrontBase, Mimer, MongoDB/Mongoose, CouchDB, Couchbase/N1QL, Elasticsearch,
  Redis, Memcached, and Neo4j/Cypher.
- Pattern research basis: the same error-fingerprint databases used internally by
  **SQLmap** (`sqlmap/data/errormessages/`) and **NoSQLmap** — those patterns help
  attackers confirm DBMS type from error responses; KrakenWaf inverts that
  knowledge to block the exfiltration channel.
- All patterns are compiled into a single `regex::RegexSet` at startup — per-response
  cost is exactly one linear scan with no per-pattern overhead.
- Vectorscan/Hyperscan `BlockDatabase` acceleration: when `--enable-vectorscan` is
  active a SIMD scan replaces the CPU path; falls back to `RegexSet` if any pattern
  fails Hyperscan compilation.
- Threshold-gated action via the global `Untrust` level:
  - `Untrust ≥ 60` (default) → **block** response (HTTP 403) + log to raw/JSONL/SQLite.
  - `Untrust < 60` → **monitor** — upstream response is forwarded to the client but
    the finding is written to all log outputs (new `Decision::Monitor` engine variant).
- Activated by adding `Detect_db_errors: true` to `rules/cmc/config.yaml`.
  **Disabled by default** for backwards compatibility.
- New `Decision::Monitor(Box<Finding>)` WAF engine variant (in addition to existing
  `Allow` and `Block`) represents detections that should be logged but not blocked.
- Added `CmcResponseDecision` enum (`Block(Finding)` | `Monitor(Finding)`) in the
  CMC layer to propagate monitor-vs-block intent from CMC modules to the engine.
- Added `rules/error_msgs/sql_errors.txt` with the full pattern set.
- Added `docs/cmc/detect_db_errors.md` documenting the module, research basis,
  detection architecture, configuration, findings format, and limitations.
- Demo server (`src/bin/demo_server.rs`) gains five new leak routes:
  `/leak/db-error/{mysql,pgsql,oracle,mssql,mongo}`.

### Tests

- 7 new integration tests in `tests/server_real_test.rs` verifying that:
  MySQL, PostgreSQL, Oracle, MSSQL, and MongoDB error responses are blocked (HTTP 403);
  clean responses are allowed (HTTP 200); and a disabled-CMC configuration passes
  DB error strings through.
- 9 unit tests in `src/cmc/detect_db_errors.rs` covering detection of all major DBMS
  error types, clean-response non-triggering, matched pattern reporting, and
  comment/empty-line skipping in the pattern file.

---

## [2.19.0] - 2026-05-15

### Added

- Added the repository default `conf/update.yaml` with scheduled update
  sections for KrakenWaf source updates, Blocklist.de feeds, Spamhaus DROP,
  and Firehol feeds.
- Added Firehol address-list updates through `conf/update.yaml` and
  `soldier_update --addr-list firehol`, downloading configured feeds into
  `rules/addr/firehol/`.
- Address-list downloads now allow up to 300 seconds per request so large
  reputation feeds can complete on slower links.
- Added `src/bin/watch_tower.rs` as the scheduler binary. It reads
  `conf/update.yaml` by default and schedules `soldier_update` jobs for
  KrakenWaf, Blocklist.de, Spamhaus, and Firehol when their YAML cron
  expressions match.
- The WAF now automatically loads `rules/addr/firehol/` alongside existing
  downloaded blocklist and Spamhaus directories.
- Added `docs/firehol_updates.md` and updated address-list/update docs with
  Firehol configuration and scheduler usage.

### Changed

- Spamhaus `DQS-key` is now `false` in the default `conf/update.yaml`, so
  `soldier_update --addr-list spamhaus` downloads the configured DROP file
  without requiring `SPAMHAUS_DQS_KEY` unless DQS validation is explicitly
  enabled.
- Replaced the broken C2 Tracker Firehol URL with the raw Firehol
  `blocklist-ipsets` feed:
  `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/c2_tracker.ipset`.

### Security

- Address-list directories and files are canonicalized before use, rejecting
  symlinks that resolve outside the rules tree.

### Tests

- Added coverage for Firehol YAML parsing, local Firehol feed downloads,
  scheduler job selection, WAF blocking from `rules/addr/firehol/`, and
  symlink rejection for external address-list files.
- Added focused Firehol tests for direct feed downloads, `c2_tracker.ipset`
  output naming, metadata headers, and missing `firehol.lists.url_file`
  validation.

## [2.18.0] - 2026-05-11

### Added

#### CMC rename (DFA → CMC)
- Renamed all internal modules, types, CLI flags, and YAML keys from `DFA`/`dfa` to `CMC`/`cmc` ("Custom Module Code") throughout the entire codebase — Rust structs (`CmcConfig`, `CmcManager`, `CmcManagerBuilder`), CLI (`--cmc-load`), YAML key (`CMC-Rules:`), rule match strings (`cmc::`), docs (`docs/cmc/`), rules dir (`rules/cmc/`), integration tests.

#### `EngineMode::DetectOnly`
- New `--mode detect-only` value: runs all inspection engines and emits findings + increments metrics, but always returns Allow. Intended for shadow-mode validation of new rule sets against live traffic before enabling blocking. Documented in `docs/detect_only_mode.md`.

#### Engine module split
- Broke the 1091-line `src/waf/engine.rs` into focused sub-modules: `engine/mod.rs` (public API + `WafEngine`), `engine/normalize.rs` (URL-decode pipeline), `engine/finding.rs` (`Finding` struct + helpers), `engine/ip_filter.rs` (IP canonicalization + CIDR parsing), `engine/matchers.rs` (all Aho-Corasick, Vectorscan, regex, and libinjection matchers).

#### cargo-fuzz targets
- Added `fuzz/` workspace with three `cargo-fuzz` targets: `cmc_inspect` (full CMC pipeline), `url_decode` (URL-decode normalisation), `parse_rules` (CMC YAML config parser). Documented in `docs/fuzzing.md`.

#### Prometheus per-module metrics
- New `krakenwaf_module_blocks_total{engine,module}` counter broken down by detection engine and CMC module name. Documented in `docs/observability.md`.

#### Clippy pedantic lints
- Added `[lints.clippy]` section to `Cargo.toml` with `pedantic = "warn"`, `cast_possible_truncation = "warn"`, and `unwrap_used = "warn"` as a baseline for future hardening.

### Changed
- `dashmap` added as a dependency for the per-module metrics `DashMap`.

## [2.17.0] - 2026-05-10

### Added

#### CMC — Java Deserialize Detect (`Java_deserialize_detect`)

A new three-signal scoring detector blocks Java deserialization attack payloads
on both incoming requests and upstream responses.

**Signal categories:**
- **Signal A (magic bytes / encoding prefixes)**: raw binary `\xAC\xED` (Java stream magic), `\x1f\x8b` (GZIP), and text-encoded forms `rO0A`, `rO0AB`, `H4sI`, `%AC%ED`, `%ac%ed`, `aced`.
- **Signal B (Java content headers)**: `Content-Type: application/x-java-serialized-object` or `Accept: application/x-java-serialized-object` (case-insensitive).
- **Signal C (base64 prefix patterns)**: `rO0`, `rO0A`, `rO0AB` (case-sensitive).

**Scoring thresholds** (governed by the new global `Untrust` level):
- 3 signals → always block.
- 2 signals + `Untrust ≥ 60` → block.
- 2 signals + `Untrust < 60` → silent `WARN` log; no block.
- 1 signal + `Untrust > 80` → informative `WARN` log; no block.

**Global-options YAML section**: a new top-level `global-options` key in the CMC config accepts `Untrust: <0–100>` (default 60), which applies to all score-based detectors.

**Dual-pipeline inspection**: `inspect_java_deser(&str, &[u8])` is called from both `inspect_complete_payload_with_context()` (request) and `inspect_response()` (response). The request path uses the original non-lowercased payload to preserve case-sensitive base64 magic detection.

**Engine support**: Aho-Corasick (three independent automata, per-signal) with optional Vectorscan `BlockDatabase` acceleration. Signal B uses `Flag::CASELESS`; Signals A and C use `Flag::SINGLEMATCH` (case-sensitive).

**New files:**
- `src/cmc/java_deserialize_detect.rs` — detector implementation with 20 unit tests.
- `docs/cmc/java_deserialize_detect.md` — full documentation with scoring tables, examples, and false-positive guidance.

**Modified files:**
- `src/cmc/mod.rs` — new module, `DfaConfig.java_deserialize_detect`, `DfaConfig.untrust_level`, `DfaManager.java_deserialize`, `DfaManager::inspect_java_deser()`, updated `parse_lenient_yaml()` for `global-options`.
- `src/waf/engine.rs` — `inspect_java_deser` called in both request and response pipelines.
- `rules/cmc/config.yaml` — added `global-options.Untrust: 60`, `Java_deserialize_detect: true`.
- `src/bin/demo_server.rs` — new `/java-deser` POST endpoint.
- `src/bin/attack.rs` — 10 Java deserialization payloads + `sweep_java_deser()` with `Content-Type` header.
- `tests/server_real_test.rs` — 6 integration tests covering block/allow/disabled scenarios.
- `docs/cmc/schema.md` — `global-options` section, `Java_deserialize_detect` in module catalogue and summaries.
- `README.md` — updated CMC module list and config snippet.

---

## [2.16.0] - 2026-05-10

### Added

#### CMC — Anti-Passwd-Leak detector (`Anti_passwd_leak`)

- `src/cmc/anti_passwd_leak.rs`: new **response-side** CMC module that intercepts
  upstream responses whose body contains ≥ 2 distinct structural tokens from either
  `/etc/passwd` (`PASSWD_TOKENS` — 9 patterns: `root:x:0:0:`, `daemon:x:`, `bin:x:`,
  `nobody:`, `/bin/bash`, `/bin/sh`, `/bin/false`, `/usr/sbin/nologin`,
  `/sbin/nologin`) or `/etc/shadow` (`SHADOW_TOKENS` — 8 patterns: `root:$y$`,
  `root:$6$`, `root:$5$`, `root:$1$`, `root:!:`, `daemon:`, `nobody:`,
  `:0:99999:7:::`).
- A single token present in the response is **not** sufficient to block — the
  two-token conjunction requirement eliminates false positives from documentation or
  log output that incidentally contains one of the tokens.
- This is the only CMC module that acts as a **data-loss-prevention (DLP) filter**:
  it blocks the upstream *response* before the sensitive data reaches the attacker,
  rather than blocking the attacker's request.
- `PASSWD_TOKENS` is checked before `SHADOW_TOKENS`; if the passwd check fires, the
  shadow check is skipped (short-circuit evaluation).
- When `--enable-vectorscan` is active, both token lists are compiled into a Hyperscan
  `BlockDatabase` with `Flag::SINGLEMATCH`; matched pattern IDs are collected in the
  scan callback and counted without a premature `Scan::Terminate`.
- Activated via `Anti_passwd_leak: true` in the CMC config YAML.
- `src/cmc/mod.rs`: `inspect_response_body(body: &str)` entry-point added to
  `DfaManager`; `anti_passwd_leak_detect` field added to `DfaConfig`; YAML key
  `Anti_passwd_leak` wired in `from_map()`.
- `src/waf/engine.rs`: `inspect_response_body()` hooked into `inspect_response()`
  after the existing keyword/regex body checks, operating on the raw (non-URL-decoded)
  response body.
- `rules/cmc/config.yaml`: `Anti_passwd_leak: true` added to the default config.
- `src/bin/demo_server.rs`: two new routes added:
  - `GET /leak/passwd` — returns a realistic 4-line `/etc/passwd` dump.
  - `GET /leak/shadow` — returns a realistic 3-line `/etc/shadow` dump.
- `src/bin/attack.rs`: `PASSWD_LEAK_PATHS` list (`/leak/passwd`, `/leak/shadow`) and
  `sweep_leak_paths()` function added; the sweep makes direct GET requests and expects
  403 (WAF blocks the response).
- `tests/server_real_test.rs`: four new integration tests:
  `dfa_anti_passwd_leak_response_is_blocked`, `dfa_anti_shadow_leak_response_is_blocked`,
  `dfa_anti_passwd_leak_normal_response_allowed`,
  `dfa_anti_passwd_leak_disabled_allows_response`.
  The test backend gains `/leak/passwd` and `/leak/shadow` routes.
- `src/cmc/anti_passwd_leak.rs` ships 9 unit tests covering: realistic dump detection
  for both file types, single-token below-threshold cases, benign body pass-through,
  passwd-takes-priority ordering, and shadow-only content classification.
- `docs/cmc/anti_passwd_leak.md`: full documentation (behaviour, token tables,
  engine selection, config, examples, false-positive guidance, performance notes).
- `docs/cmc/schema.md`: module catalogue updated with `Anti_passwd_leak` entry and
  `inspect_response_body()` entry-point documented; DLP nature of the module noted.
- `README.md`: CMC bullet list and YAML config snippet updated.
- Detection finding: severity **Critical**, CWE-538, OWASP Sensitive Data Exposure.

---

## [2.15.0] - 2026-05-10

### Added

#### CMC — Anti-Exposed-Backup detector (`Anti_exposed_backup`)
- `src/cmc/anti_exposed_backup.rs`: new CMC module that blocks `GET` and `HEAD` requests
  whose URI path ends with a known backup/temporary/config-leak extension (`.bak`, `.bkp`,
  `.backup`, `.old`, `.orig`, `.save`, `.sav`, `.swp`, `.swo`, `.swn`, `.swx`, `.un~`,
  `.tmp`, `.temp`, `.wbk`, `.env`, `.sql.`, `.dump`).
- Matching is **case-insensitive** and **suffix-only** (the extension must appear at the end
  of the path; `/file.bak.txt` is never blocked).
- Query-strings and fragments are stripped before matching so `?v=1` appended to a backup
  path cannot bypass the rule.
- `POST`/`PUT`/`PATCH`/`DELETE` are never inspected by this module.
- When `--enable-vectorscan` is active, all 18 patterns are compiled into a Hyperscan
  `BlockDatabase` and scanned in a single SIMD pass with end-offset filtering.
- Activated via `Anti_exposed_backup: true` in the CMC config YAML.
- `src/cmc/mod.rs`: `inspect_uri(method, path)` method added to `DfaManager`; called from
  `inspect_early()` before the full request payload is assembled — zero body-read latency.
- `src/waf/engine.rs`: `inspect_uri()` hooked into `inspect_early()`.
- `rules/cmc/config.yaml`: `Anti_exposed_backup: true` added to the default config.
- `src/bin/demo_server.rs`: wildcard `/*path` GET route added so the attack-sweep tool
  can distinguish a WAF bypass (HTTP 200) from a WAF block (HTTP 403).
- `src/bin/attack.rs`: `BACKUP_URI_PAYLOADS` list (20 paths) + `sweep_backup_uris()` function
  added; exposed-backup sweep included in the main attack-tool run.
- `tests/server_real_test.rs`: four new integration tests:
  `dfa_anti_exposed_backup_get_is_blocked`, `dfa_anti_exposed_backup_post_is_allowed`,
  `dfa_anti_exposed_backup_normal_paths_allowed`,
  `dfa_anti_exposed_backup_suffix_in_query_string_not_blocked`.
- `docs/cmc/anti_exposed_backup.md`: full documentation (behaviour, config, examples,
  false-positive guidance, performance notes).
- Detection finding: severity **High**, CWE-538, OWASP Insecure Direct Object References.

---

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
- `src/cmc/overflow_detect.rs`: removed `&'static` from `X86_PATTERNS`, `X64_PATTERNS`, `ARM_PATTERNS` const type annotations. References in `const` items are always `'static` implicitly.

#### CI — attack-sweep WAF start command
- `.github/workflows/security.yml`: added `--cmc-load $GITHUB_WORKSPACE/rules/cmc/config.yaml` (activates all 9 CMC detectors) and `--rate-limit-per-minute 100000` (prevents GCRA from blocking score-engine "allow" cases at concurrency 25).

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

#### XXE attack CMC coverage
- Added `src/cmc/xxe_attack_detect.rs` to detect XXE attacks by requiring at least one marker from list A (`ENTITY`, `xi:include`) and at least one marker from list B (`xxe`, `SYSTEM`, `etc/password`, `eval`, `exfil`, `xmlns:xi`, `send`, `DOCTYPE`, `soap`, `file`).
- Added UTF-16LE/BE recovery for NUL-interleaved request text produced after URL decoding encoded XML payload bytes.
- The CMC can be enabled with `XXE_attack_detect: true` in `rules/cmc/config.yaml`.
- When the `vectorscan-engine` feature is compiled and `--enable-vectorscan` is set, the XXE detector uses Vectorscan for literal list matching.
- Extended `src/bin/attack.rs` with 15 XXE attack payloads and GET/POST sweeps, including a UTF-16LE percent-encoded payload.

### Tests

- Added real end-to-end GET/POST XXE blocking tests against the protected WAF subprocess in `tests/server_real_test.rs`.
- Added XXE CMC unit tests for list correlation and UTF-16LE encoded payload recovery.

---

## [2.12.3] - 2026-05-06

### Added

#### NoSQL injection CMC coverage
- Added `src/cmc/nosql_injection_detect.rs` to detect NoSQL injection by requiring at least one marker from list A (`$gt`, `$where`, `$or`, `$and`, `selector`, `this.password.match`, `&&`, `||`, and related operators) and at least one marker from list B (`true`, `admin`, `pass`, `user`, `null`, `sleep(`, `%00`, `{}`, `.insert`, `dropDatabase(`, equality probes, and related values).
- Added support for `==[1-9]` and `== [1-9]` as list B matches.
- The CMC can be enabled with `NOSQL_injection_detect: true` in `rules/cmc/config.yaml`.
- When the `vectorscan-engine` feature is compiled and `--enable-vectorscan` is set, the NoSQL detector uses Vectorscan for literal list matching and keeps the numeric equality CMC check for the digit pattern.
- Extended `src/bin/attack.rs` with 15 NoSQL injection payloads and GET/POST sweeps.

### Tests

- Added real end-to-end GET/POST NoSQL injection blocking tests against the protected WAF subprocess in `tests/server_real_test.rs`.
- Added NoSQL CMC unit tests for list correlation and numeric equality probes.

---

## [2.12.2] - 2026-05-05

### Added

#### CMC attack sweeps in real WAF tests
- Added end-to-end CMC sweeps in `tests/server_real_test.rs` with `--cmc-load rules/cmc/config.yaml` enabled.
- Added GET and POST coverage for Overflow, SSTI, SSI injection, and ESI injection payloads so URI and request body inspection are both validated through the real KrakenWAF subprocess.
- Extended `src/bin/attack.rs` to send the same CMC-focused payload families in GET and POST attack sweeps.

#### Overflow CMC shellcode detection
- `src/cmc/overflow_detect.rs` now detects common shellcode opcode clusters in addition to repeated-character and structured overflow patterns.
- Added detection for x86-32, x86-64, and ARM/Thumb payloads, including NOP sleds (`\x90`, ARM `00 00 a0 e1`, Thumb `c0 46`) and common Linux shellcode sequences such as `int 0x80`, `syscall`, `execve`, and embedded `/bin/sh`.
- Added parsing for common byte encodings in payload text: `\xNN`, `%NN`, `0xNN`, and `\u00NN`.
- `DfaManager` now emits a dedicated high-severity `CMC shellcode opcode detection` finding for these matches.

#### SSTI CMC coverage
- `src/cmc/ssti_detect.rs` now detects additional SSTI families: `{% ... %}`, FreeMarker `<# ... >`, Velocity `#set(...)`, and `[[ ... ]]` expressions.

#### SSI and ESI CMC coverage
- `src/cmc/ssi_injection_detect.rs` now detects SSI directives with spacing and case variants, including `<!-- #exec ... -->` and `<!--# set ... -->`.
- `src/cmc/esi_injection_detect.rs` now detects additional ESI directives including `vars`, `remove`, `choose`, `when`, `otherwise`, `try`, `attempt`, `except`, `comment`, and `assign`, with case and spacing variants.

#### CRLF injection CMC coverage
- Added `src/cmc/crlf_injection_detect.rs` to detect CRLF injection and HTTP response-splitting payloads.
- The CMC can be enabled with `CRLF_injection_detect: true` in `rules/cmc/config.yaml`.
- Added coverage for raw CR/LF, URL-encoded, double/triple-encoded, `%u000d/%u000a`, `\u000d/\u000a`, Unicode newline bypasses, and injected HTTP header/status/body patterns from the payload-box CRLF injection list.

#### Request smuggling CMC coverage
- Added `src/cmc/request_smuggling_detect.rs` to detect request smuggling indicators in headers, URI, and body content.
- The CMC can be enabled with `Request_Smuggling_detect: true` in `rules/cmc/config.yaml`.
- Added detection for `Transfer-Encoding: chunked`, `X-Session-Hijack: true`, `Content-Length` values `<= 4`, and injected `Transfer-Encoding: chunked` patterns in request bodies or URI parameters.

### Fixed

- Closed the real-test Overflow bypass for repeated format-string specifiers such as `%n%n%n...`.
- Closed the real-test SSI bypass for spaced directives such as `<!--# set var="x" value="owned" -->`.
- Closed the real-test ESI bypass for `<esi:vars>$(HTTP_COOKIE)</esi:vars>`.

### Tests

- Added unit tests for Overflow shellcode detection, SSTI families, SSI spacing/case variants, and ESI directive variants.
- Added real GET/POST CRLF injection sweeps using representative payloads from `payload-box/crlf-injection-payload-list`.
- Added real GET/POST request smuggling sweeps with 10 payloads covering transfer-encoding, short content-length, and session-hijack markers.
- Verified CMC payload sweeps block in both GET query strings and POST form bodies.

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
- Call sites in `src/allowpaths.rs` and `src/cmc/mod.rs` updated; no behaviour change.

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
- Rules not present in JSON (CMC, libinjection, rate-limit, IP-block) receive the sentinel value `"00000"`.

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
- **H5 — Hot-path `to_lowercase` allocation**: CMC lowercasing is now scoped to the CMC phase only; keyword and regex phases reuse the already-normalized buffer (`src/waf/engine.rs`).
- **Issue 7 — Race condition on rules hot-reload**: introduced `RulesSnapshot` struct holding `Arc<RuleSet>` + `EngineMatchers` behind a single `RwLock<Arc<RulesSnapshot>>`; `reload_from_dir` swaps the arc atomically so in-flight requests always see a consistent rule set (`src/waf/engine.rs`).

#### Storage / Persistence
- **H6 — SQL string interpolation**: `sea-orm` raw query replaced with `Statement::from_sql_and_values` parameterised binding; no SQL injection possible via rule-name input (`src/storage.rs`).
- **Issue 8 — Non-atomic rate-limit snapshot write**: snapshot is now written to a `.json.tmp` sibling file then `fs::rename`d into place; a crash mid-write can no longer corrupt the persisted counters (`src/waf/rate_limit.rs`).
- **H7 — TLS SNI logged before move**: SNI string is extracted before `ClientHello` is consumed; fallback-cert selection now logs a `WARN` with the SNI value instead of silently swallowing the event (`src/tls.rs`).

#### Configuration / YAML
- **H8 — YAML boolean coercion (`true` → 0)**: CMC config loader uses a `#[serde(untagged)] BoolOrInt` enum; `true`/`false` YAML values are mapped to `1`/`0` with a warning instead of silently disabling CMC engines (`src/cmc/mod.rs`).

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
- Optimized `src/cmc/esi_injection_detect.rs` to use `memchr` + byte scanning instead of `to_lowercase()` + repeated `contains()`.
- Optimized `src/cmc/ssi_injection_detect.rs` to use `memchr` + byte scanning instead of `to_lowercase()` + repeated `contains()`.
- Added CLI support for trusted proxy CIDRs and a configurable real-IP header:
  - `--trusted-proxy-cidrs`
  - `--real-ip-header`

### Fixed
- Recovered safely from poisoned `RwLock` guards in the WAF engine instead of panicking.
- Emitted explicit warnings when the lenient CMC YAML parser yields an empty/invalid configuration instead of silently disabling CMC engines.

## [2.7.22] - 2026-04-06

### Added
- New `enable` field support across all JSON rule files under `rules/`.
- Rules with `"enable": 0` are now skipped during KrakenWAF initialization.

### Changed
- Updated bundled JSON rule files to include `"enable": 1` before `title` in every rule entry.

## 2.7.21

- cleaned up CMC integration warnings reported during build
- removed unused `SstiRule` re-export
- removed unused `dfa_manager` field from `AppState`
- removed unused `DfaManager::enabled()` helper
- removed unused `OverflowDfa::detect_overflow()` helper

## 2.7.20

- added safe CMC modules under `src/cmc` for SQLi comment evasion, repeated-character overflow, SSTI, SSI injection and ESI injection
- added lenient YAML CMC config loader with `--cmc-load` and example config at `rules/cmc/config.yaml`
- integrated CMC findings into the normal KrakenWAF block pipeline, including JSONL, raw critical log and SQLite evidence storage
- documented CMC schema and runtime behavior in `docs/cmc/schema.md`


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
- Fixed request-scope inspection bug for CMC and libinjection.
- KrakenWaf now inspects a synthesized full-request payload composed of method, URI, headers, and body bytes.
- Removed query-only inspection path and replaced it with full-request inspection after body assembly.
- Streaming body inspection now evaluates a rolling full-request window, improving POST / REST payload detection before forwarding upstream.
- Documented the inspection scope in `docs/libinjection.md` and `docs/deployment.md`.


## 2.7.29
- Fixed warning in `src/waf/engine.rs` by annotating the currently-unused `inspect_body_chunk` method with `#[allow(dead_code)]`.
- Preserved the full-request inspection fix so CMC and libinjection evaluate GET, POST, REST-style requests, including body payloads.
- Consolidated this release after the recent libinjection FFI, vectorscan constructor, proxy iterator, linker, and warning cleanup fixes.


## 2.7.30
- Added GET request URL decoding before inspection
- Unified inspection pipeline for CMC, libinjection, vectorscan
- Improved detection for URL-encoded attacks


## 2.7.31
- Fixed request inspection precedence so normalization happens before detector evaluation.
- Added unified `inspect_complete_payload_with_context(...)` path and routed proxy body/full-request inspection through it.
- Reintroduced libinjection runtime flags into `WafEngine` and wired FFI detections into the active inspection pipeline.
- Normalized GET requests with URL decoding before CMC, vectorscan, libinjection and regex/keyword rule evaluation.
- Left POST request bodies undecoded so body payloads are inspected as-sent.
- Evaluated CMC/libinjection/vectorscan before keyword/regex rules, keeping rule filters as the last stage.
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

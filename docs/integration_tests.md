# Integration Tests

KrakenWAF ships end-to-end integration tests in `tests/server_real_test.rs`
that exercise the full request path:

```
reqwest  →  KrakenWAF (--no-tls)  →  Axum micro-backend
```

---

## Architecture

| Component | Address | Role |
|-----------|---------|------|
| Axum backend | `127.0.0.1:9077` | Renders `payload_test` param unsanitised in `<h1>` — intentionally vulnerable to test detection |
| KrakenWAF | `127.0.0.1:909x` (unique per test) | WAF under test, started as a subprocess |
| reqwest client | — | Sends crafted HTTP requests and asserts response status codes |

The backend is started once per test binary via `std::sync::OnceLock`. Each
test allocates a unique WAF port via an atomic counter to avoid `TIME_WAIT`
collisions when tests run in parallel.

---

## Backend routes

| Method | Path | Behaviour |
|--------|------|-----------|
| `GET` | `/test_one` | Returns an HTML form that submits `GET` to `/test_get` |
| `GET` | `/test_get?payload_test=…` | Returns `<h1>{payload_test}</h1>` |
| `GET` | `/test_two` | Returns an HTML form that submits `POST` to `/test_post` |
| `POST` | `/test_post` | Returns `<h1>{payload_test}</h1>` from form body |

---

## Test cases

| Test | Payload | Expected |
|------|---------|----------|
| `post_xss_is_blocked` | `<script>alert(1)</script>` in POST body | HTTP 403 |
| `get_sqli_is_blocked` | `' or '1'='1` in GET query | HTTP 403 |
| `scanner_ua_is_blocked` | `User-Agent: nikto/2.1.6` | HTTP 403 |
| `blocklisted_ip_is_blocked` | `X-Real-IP: 10.10.10.1` (WAF trusts loopback proxy) | HTTP 403 |
| `clean_get_passes_through` | `payload_test=hello world` | HTTP 200 |
| `clean_post_passes_through` | `payload_test=safe value` | HTTP 200 |

---

## Running the tests

```sh
# Default (debug) build — all integration tests including server_real_test.rs
cargo test

# Release build
cargo build --release && cargo test --release

# Run only the integration tests
cargo test --test server_real_test

# Run a single test with output
cargo test --test server_real_test -- post_xss_is_blocked --nocapture
```

> **Note**: The `CARGO_BIN_EXE_krakenwaf` environment variable is set
> automatically by Cargo during `cargo test`. The integration tests use it to
> locate and spawn the WAF binary.

---

## Dependencies

The following crates are added as `[dev-dependencies]` in `Cargo.toml`:

- `axum` — micro-backend HTTP framework
- `reqwest` — async HTTP client for assertions
- `tokio` — async runtime (re-exported from the main dependency with `full` features)
- `tempfile` — temporary directories for per-test WAF state

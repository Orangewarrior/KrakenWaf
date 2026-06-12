# Attack Tool & Demo Server

KrakenWAF ships two standalone binaries for manual end-to-end testing:

| Binary | Source | Role |
|--------|--------|------|
| `demo_server` | `src/bin/demo_server.rs` | Intentionally vulnerable Axum HTTP backend |
| `attack` | `src/bin/attack.rs` | Payload sweep tool — sends attacks and reports block/pass |

---

## Architecture

```
attack  →  KrakenWAF (:8080)  →  demo_server (:9077)
```

`demo_server` renders user input unsanitised in the HTML response — intentionally
vulnerable to XSS and SQLi. `attack` fires payloads at the WAF and checks
whether each one is blocked (HTTP 403) or bypassed (any other status).

---

## Step 1 — Build the binaries

```sh
cargo build --bin demo_server --bin attack
# or release build
cargo build --release --bin demo_server --bin attack
```

---

## Step 2 — Start the vulnerable backend

```sh
cargo run --bin demo_server
# Demo backend listening on http://0.0.0.0:9077

# Custom port
cargo run --bin demo_server -- 9999
```

Routes exposed by `demo_server`:

| Method | Path | Behaviour |
|--------|------|-----------|
| `GET` | `/` | HTML page with test forms |
| `GET` | `/test_get?payload_test=…` | Reflects `payload_test` unsanitised |
| `POST` | `/test_post` | Reflects `payload_test` (form body) unsanitised |

---

## Step 3 — Start KrakenWAF in front of the backend

```sh
cargo run -- \
  --no-tls \
  --allow-private-upstream \
  --listen 0.0.0.0:8080 \
  --upstream http://127.0.0.1:9077 \
  --rules-dir ./rules
```

Wait for the banner — the WAF is ready when `/__krakenwaf/health` returns HTTP 200.

---

## Step 4 — Run the attack sweep

```sh
# Summary only
cargo run --bin attack -- --target http://127.0.0.1:8080

# Verbose — show each payload line
cargo run --bin attack -- --target http://127.0.0.1:8080 --verbose
```

### Expected output (all payloads blocked)

```
╔══════════════════════════════════════════════════════════╗
║           KrakenWAF Attack Tool                         ║
╚══════════════════════════════════════════════════════════╝
  Target : http://127.0.0.1:8080
  Verbose: false

━━━ XSS — POST /test_post (50 payloads) ━━━
  → 50 blocked  |  0 bypassed  |  0 errors

━━━ XSS — GET /test_get (50 payloads) ━━━
  → 50 blocked  |  0 bypassed  |  0 errors

━━━ SQLi — GET /test_get (50 payloads) ━━━
  → 50 blocked  |  0 bypassed  |  0 errors

━━━ SQLi — POST /test_post (50 payloads) ━━━
  → 50 blocked  |  0 bypassed  |  0 errors

━━━ Scanner UA — GET /test_get (15 UAs) ━━━
  → 15 blocked  |  0 bypassed  |  0 errors

╔══════════════════════════════════════════════════════════╗
║  SUMMARY                                                ║
╠══════════════════════════════════════════════════════════╣
║  Total requests : 215                                   ║
║  Blocked        : 215                                   ║
║  Bypassed       : 0                                     ║
║  Errors         : 0                                     ║
║  Status         : ALL PAYLOADS BLOCKED ✓               ║
╚══════════════════════════════════════════════════════════╝
```

The tool exits with code **0** when every payload is blocked and **1** if any
payload bypasses the WAF.

---

## Payload coverage

| Sweep | Direction | Count |
|-------|-----------|-------|
| XSS payloads | POST body | 50 |
| XSS payloads | GET query string | 50 |
| SQLi payloads | GET query string | 50 |
| SQLi payloads | POST body | 50 |
| HPP payloads | GET query string | 50 |
| HPP payloads | POST body | 50 |
| Open Redirect / RFI payloads | GET query string | 50 |
| Open Redirect / RFI payloads | POST body | 50 |
| Scanner `User-Agent` strings | GET | 15 |
| **Total** | | **415** |

> The table above lists the headline sweeps; the tool also runs the remaining
> CMC sweeps (SSTI, SSI, ESI, CRLF, request smuggling, NoSQL, XXE, exposed
> backup, passwd/shadow leak, silent SQL errors, Java deserialization, bad
> artifacts) — see the `run_sweep!` calls in `src/bin/attack.rs`.

XSS patterns include: `<script>`, event handlers (`onerror=`, `onload=`, etc.),
`javascript:` URIs, `<iframe>`, `<svg>`, encoded variants.

SQLi patterns include: boolean blind (`' OR '1'='1`), union-based, stacked
queries (`;DROP TABLE`), time-based (`SLEEP()`, `WAITFOR DELAY`), error-based
(`EXTRACTVALUE`, `UPDATEXML`), `xp_cmdshell`, and double-quote variants.

HPP (HTTP Parameter Pollution) payloads each carry a duplicated parameter name
(case-insensitive, e.g. `email`/`eMail`) and try to evade the
[`HPP_detect`](cmc/hpp_detect.md) module by obfuscating the `=`/`&` separators:
plain, single/double/triple percent-encoding, mixed-case hex, `+`-for-space,
UTF-16 LE/BE, and mixed (some separators encoded, some not). The raw string is
sent verbatim as the query string (GET) and the body (POST) so the encodings
reach the WAF undecoded — the global normalizer must peel them before the
duplicate is detectable. All 50 must be blocked over each direction; a `200` is
a real encoding bypass.

Open Redirect / RFI payloads each carry a `hot_param=value` pair where the value
is an open-redirect or file-inclusion attempt against the
[`Open_redirect_n_RFI_detect`](cmc/open_redirect_rfi_detect.md) module. They span
every documented evasion: scheme-relative `//`, triple-encoded slashes, mixed-case
schemes, userinfo host confusion, backslash/UNC confusion, control-char prefixes
(`%09%0d%0a`), PHP/inclusion wrappers (`php://`, `expect://`, `zip://`, `phar:`,
`gopher:`, `ldap:`, …), and trailing `?`/`%00` truncation markers. The raw string
is sent verbatim as the query string (GET) and body (POST). All 50 must be blocked
over each direction; a `200` is a real bypass to fix in the detector or normalizer.

Scanner UAs are drawn from `rules/user_agents/scanners.txt` (subset of 15).
Note: scanner-UA blocking is now owned by the
[`Detect_bots_n_scanners`](cmc/detect_bots_n_scanners.md) CMC module — start
the WAF with `--cmc-load rules/cmc/config.yaml` for these payloads to be
blocked.

---

## CLI reference

### `demo_server`

```
USAGE:
    demo_server [PORT]

ARGS:
    PORT    TCP port to listen on [default: 9077]
```

### `attack`

```
USAGE:
    attack [OPTIONS]

OPTIONS:
    --target <URL>            Base URL of the WAF to attack [default: http://127.0.0.1:8080]
    --verbose                 Print each payload with its outcome
    --concurrency <N>         Requests in-flight at once [default: 20]
    --cacert <PEM>            Trust this CA root when --target is HTTPS
    --insecure-skip-verify    Disable TLS certificate validation (debug only)
    --metrics-target <URL>    Base URL of the observability port to probe (e.g. https://127.0.0.1:4343)
    --metrics-token <TOKEN>   Bearer token for the observability port (printed only as ****)
    --metrics-only            Run just the observability bearer-token probe and exit
    -h, --help                Print help
```

### Observability bearer-token probe

The WAF's dedicated observability port (default `4343`) requires
`Authorization: Bearer <token>` once a token is provisioned (see
[docs/observability.md](observability.md)). The attack tool validates the gate:
it sends `/metrics` with **no token** (expects `401`), a **wrong token**
(`401`), and the **correct token** (`200` + a Prometheus body). The token is
never printed — only the mask `****` appears in the output.

```bash
# Probe only the observability gate (TLS, with the WAF's CA), then exit.
cargo run --bin attack -- \
    --metrics-target https://127.0.0.1:4343 \
    --metrics-token "$BEARER_PASSWORD" \
    --metrics-only \
    --cacert /tmp/krakenwaf-tls/ca.pem
```

`--metrics-only` exits `0` when every expectation holds and `1` otherwise, so it
slots directly into CI. Without `--metrics-only`, the probe runs first and its
failures are folded into the overall exit code alongside the payload sweeps.

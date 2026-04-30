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
| Scanner `User-Agent` strings | GET | 15 |
| **Total** | | **215** |

XSS patterns include: `<script>`, event handlers (`onerror=`, `onload=`, etc.),
`javascript:` URIs, `<iframe>`, `<svg>`, encoded variants.

SQLi patterns include: boolean blind (`' OR '1'='1`), union-based, stacked
queries (`;DROP TABLE`), time-based (`SLEEP()`, `WAITFOR DELAY`), error-based
(`EXTRACTVALUE`, `UPDATEXML`), `xp_cmdshell`, and double-quote variants.

Scanner UAs are drawn from `rules/user_agents/scanners.txt` (subset of 15).

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
    --target <URL>    Base URL of the WAF to attack [default: http://127.0.0.1:8080]
    --verbose         Print each payload with its outcome
    -h, --help        Print help
```

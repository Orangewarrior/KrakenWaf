# KrakenWaf v2.20.0

## 🚀 Overview

KrakenWaf is a modern, high-performance Web Application Firewall (WAF) written in Rust.
It is designed for real-world deployments, combining security, performance, and simplicity.

![logo](https://github.com/Orangewarrior/KrakenWaf/blob/main/docs/img/logo2waf.png)

## 🧠 Architecture Overview

KrakenWaf is built on:

- **Tokio (async runtime)** → high concurrency, non-blocking I/O
- **Reverse proxy model** → sits in front of your application
- **Streaming inspection pipeline** → analyzes requests in chunks
- **Modular WAF engine** → rule-based + advanced detection engines
- **Modular custom CMC** → to detect anomalys

### Flow

Client → TLS (KrakenWaf) → Inspection → Upstream → Response

---

## ⚡ Detection Engines

KrakenWaf supports multiple detection layers:

### 🔹 Regex Engine
- Flexible rule-based detection

### 🔹 Aho-Corasick
- Fast keyword matching

### 🔹 Vectorscan (Hyperscan-based)
- SIMD optimized
- Extremely fast multi-pattern matching
- Used in tools such as Suricata for high-speed pattern matching

### 🔹CMC (Custom Module Code)

Single-pass, zero-allocation Rust scanners — each module is individually togglable
via `rules/cmc/config.yaml`.  See [docs/cmc/schema.md](docs/cmc/schema.md) for the
full module catalogue.

- [SQLi comments evasion](docs/cmc/sqli_comments_detect.md) — counts `/* */` block-comment pairs used to break up SQL keywords (CWE-89)
- [Overflow detect](docs/cmc/overflow_detect.md) — shellcode opcode clusters (x86/x64/ARM) + repeated-character flooding (CWE-94 / CWE-400)
- [SSTI detect](docs/cmc/ssti_detect.md) — 22 template-engine families (Jinja2, Twig, Velocity, Freemarker, ERB, Thymeleaf, …) (CWE-1336)
- [SSI injection detect](docs/cmc/ssi_injection_detect.md) — Apache `<!--#…-->` directives + JSP/JSTL/ColdFusion include tags (CWE-97)
- [ESI injection detect](docs/cmc/esi_injection_detect.md) — `<esi:…>` tags processed by Varnish, Squid, Akamai, Fastly (CWE-94)
- [CRLF injection detect](docs/cmc/crlf_injection_detect.md) — control chars + 26 escape forms + 6 Unicode surrogates, with smart HTTP-framing bypass resistance (CWE-93)
- [Request smuggling detect](docs/cmc/request_smuggling_detect.md) — TE.CL / CL.0 desync indicators (CWE-444)
- [NoSQL injection detect](docs/cmc/nosql_injection_detect.md) — two-list conjunction (operators ∩ values), Aho-Corasick / Vectorscan (CWE-943)
- [XXE attack detect](docs/cmc/xxe_attack_detect.md) — two-list conjunction with UTF-16 LE/BE evasion bypass (CWE-611)
- [Anti exposed backup](docs/cmc/anti_exposed_backup.md) — backup-file suffixes and editor artefacts in request paths (CWE-538)
- [Anti passwd/shadow leak](docs/cmc/anti_passwd_leak.md) — blocks upstream **responses** leaking `/etc/passwd` or `/etc/shadow` content (CWE-538, Critical)
- [Java deserialize detect](docs/cmc/java_deserialize_detect.md) — three-signal scoring (magic bytes + header + encoded prefix) for Java deserialization gadget chains; inspects both requests and responses (CWE-502, Critical)
- [Detect DB errors](docs/cmc/detect_db_errors.md) — intercepts upstream responses leaking verbose DBMS error messages, cutting off the error-based SQLi/NoSQLi feedback loop; 200+ patterns covering SQL and NoSQL engines sourced from SQLmap/NoSQLmap research (CWE-209, High)

### 🔹 libinjection
- Detects SQLi and XSS
- Industry standard approach for injection-focused detection

---

## 🏗️ Build Options

Default build:
```bash
cargo build --release
```

With Vectorscan:
```bash
cargo build --release --features "vectorscan-engine"
```

---

## 🔐 TLS Setup

### Generate certificate
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout blog.key \
  -out blog.crt \
  -days 365 \
  -nodes
```

### Configure SNI

File:
```
rules/tls/sni_map.csv
```

Example:
```
blog.local,/opt/certs/blog.crt,/opt/certs/blog.key,true
```

### How `sni_map.csv` works

Each line maps a hostname to a certificate and private key:

```csv
hostname,cert_path,key_path,is_default
```

Example:
```csv
blog.local,/opt/certs/blog.crt,/opt/certs/blog.key,true
```

Meaning:
- `hostname` → domain the client will access
- `cert_path` → certificate file for that domain
- `key_path` → private key file for that domain
- `is_default` → `true` means fallback certificate if no SNI match is found

---


### Custom block page

The argument for a custom block page is:

```bash
--blockmsg ./blockpages/blocked.html
```

When KrakenWaf blocks a request, it returns the contents of that file instead of a generic error body.  
This is useful for:
- a branded security page
- an incident reference number
- internal helpdesk instructions
- a friendly message for legitimate users blocked by policy

Example `blocked.html`:
```html
<html>
  <head><title>Request Blocked</title></head>
  <body>
    <h1>Request blocked by KrakenWaf</h1>
    <p>Your request matched a security policy.</p>
    <p>If you believe this is a mistake, contact the administrator.</p>
  </body>
</html>
```

---

## 🧪 Testing

KrakenWAF ships two complementary test strategies: automated integration tests
and standalone binaries for manual end-to-end validation.

### Automated tests

```sh
# All tests (unit + integration)
cargo test

# Integration tests only (spawns real WAF subprocesses)
cargo test --test server_real_test

# Single test with stdout
cargo test --test server_real_test -- xss_payload_sweep_post --nocapture
```

Each integration test in `tests/server_real_test.rs` starts a real WAF
subprocess with a unique port and isolated SQLite directory, then fires
crafted HTTP requests through it. Eight cases: XSS sweep (POST/GET),
SQLi sweep (GET/POST), scanner UA sweep, blocklisted IP, clean GET/POST
pass-through.

→ Full details: [docs/integration_tests.md](docs/integration_tests.md)

---

### Manual end-to-end with `demo_server` + `attack`

Two standalone binaries are provided for manual validation and demos:

| Binary | Description |
|--------|-------------|
| `demo_server` | Intentionally vulnerable Axum HTTP backend on `:9077` |
| `attack` | Payload sweep tool — 215 requests, reports `[BLOCK]`/`[PASS ]` per payload |

```sh
# 1. Build
cargo build --bin demo_server --bin attack

# 2. Start the vulnerable backend
cargo run --bin demo_server

# 3. Start KrakenWAF in front of it (separate terminal)
cargo run -- --no-tls --allow-private-upstream \
             --listen 0.0.0.0:8080 \
             --upstream http://127.0.0.1:9077 \
             --rules-dir ./rules

# 4. Run the attack sweep
cargo run --bin attack -- --target http://127.0.0.1:8080 --verbose
```

Expected result: **215 blocked | 0 bypassed | 0 errors**
(50 XSS POST + 50 XSS GET + 50 SQLi GET + 50 SQLi POST + 15 scanner UAs)

→ Full details: [docs/attack_tool.md](docs/attack_tool.md)

---

## 🧪 Example: Protect DVWA for Testing attacks
With Vectorscan:
```bash
git clone https://github.com/Orangewarrior/KrakenWaf
cd KrakenWaf
cargo clean
cargo build --release --features "vectorscan-engine"
```
Prepare certs:
```bash
mkdir certs
openssl req -x509 -nodes -days 365 -newkey rsa:4096   -keyout certs/key.pem   -out certs/cert.pem   -config rules/tls/localhost.cnf
```
Set `rules/tls/sni_map.csv` like this:

```bash
cat rules/tls/sni_map.csv
localhost,./certs/cert.pem,./certs/key.pem,true
```
Example DVWA container:

```bash
docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
```
## Run KrakenWaf in front of DVWA

Use this exact command for the local DVWA lab:

```bash
target/release/krakenwaf \
  --listen 127.0.0.1:8443 \
  --upstream http://127.0.0.1:8080 \
  --rules-dir ./rules \
  --sni-map ./rules/tls/sni_map.csv \
  --blockmsg ./alert/blockalert.html \
  --verbose \
  --allow-private-upstream \
  --enable-vectorscan \
  --enable-libinjection-sqli \
  --enable-libinjection-xss \
  --cmc-load ./rules/cmc/config.yaml \
  --real-ip-header X-Forwarded-For \
  --trusted-proxy-cidrs 127.0.0.1/32
```

Access the protected app at:

```text
https://localhost:8443
```
Login admin, password is password.


## Rule model

KrakenWaf loads three rule families:
- `rules/rules.json`: keyword rules for URI, headers, and body
- `rules/regex/*.json`: Rust regex rules
- `rules/Vectorscan/strings2block.json`: Vectorscan rules — **`rule_match` is compiled as PCRE**, escape your metacharacters; see [docs/vectorscan_rules.md](docs/vectorscan_rules.md)

Regex and Vectorscan JSON rules support a numeric `score`. A direct match with
`score >= 600` blocks immediately. Matches below `600` are accumulated inside
the current rule list; the request or response is blocked when the accumulated
score reaches `600`.

This is useful for validating:
- XSS detection
- SQLi detection
- regex rule hits
- keyword rule hits
- custom block responses
- logging and metrics behavior

---

## 📊 Metrics

[Observability docs for more info, example:](https://github.com/Orangewarrior/KrakenWaf/blob/main/docs/observability.md)
```bash
curl -k https://localhost/metrics
```

---

## ❤️ Health

```bash
curl -k https://localhost/__krakenwaf/health
```

---

## 🗄 Logs

- `logs/krakenwaf.log`
- `logs/json/krakenwaf.jsonl`
- `logs/raw/critical.log`

Example show a slice of jsonl log:
```bash
cat logs/json/krakenwaf.jsonl.2026-04-06 | tail -10
{"timestamp":"2026-04-06T01:18:56.145800Z","level":"INFO","fields":{"message":"request blocked","title":"Remote payload downloader","severity":"high","cwe":"CWE-494","engine":"vectorscan","ip":"127.0.0.1","method":"POST","uri":"/vulnerabilities/xss_s/","fullpath_evidence":"/vulnerabilities/xss_s/","rule":"wget http","rule_source":"Vectorscan/strings2block.json:10","reference_url":"https://owasp.org/www-community/attacks/Command_Injection"},"target":"krakenwaf"}
{"timestamp":"2026-04-06T01:19:26.146276Z","level":"ERROR","fields":{"message":"connection timed out: deadline has elapsed"},"target":"krakenwaf"}
```

SQLite:
```
logs/db/vulns_alert.db
```

Inspect the database:
```bash
$ sqlite3 logs/db/vulns_alert.db "SELECT id,title,severity,engine,http_method,request_uri,fullpath_evidence,rule_match,reference_url,occurred_at FROM vulnerabilities ORDER BY id DESC LIMIT 10;"
1|Remote payload downloader|high|vectorscan|POST|/vulnerabilities/xss_s/|/vulnerabilities/xss_s/|wget http|https://owasp.org/www-community/attacks/Command_Injection|2026-04-06T01:18:56.145777535+00:00
```
Note: If you need to inspect the full request, refer to the "request_payload" field. Use it in the SQL query SELECT.

---

## ⚙️ CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--listen` | `0.0.0.0:8443` | Bind address and port used by KrakenWaf |
| `--upstream` | `http://127.0.0.1:8080` | Backend origin URL — see [docs/deployment.md](docs/deployment.md) |
| `--rules-dir` | `./rules` | Root directory containing rule files, blocklists, regex rules, and TLS files |
| `--sni-map` | `./rules/tls/sni_map.csv` | Path to the TLS SNI CSV file mapping hostnames to certificate and key files |
| `--mode` | `block` | Enforcement mode: `block` returns HTTP 403 on detections; `silent` logs and counts detections without blocking — useful for tuning rules in production |
| `--allow-paths` | — | Path to a YAML file listing URI prefixes that bypass WAF inspection entirely — see [docs/allowpaths.md](docs/allowpaths.md) |
| `--blocklist-ip` | `false` | Enable IP and CIDR blocklist enforcement from `rules/addr/blocklist.txt` — see [docs/blockaddrs_allowaddrs.md](docs/blockaddrs_allowaddrs.md) |
| `--no-tls` | `false` | Disable TLS and listen on plain HTTP — useful when TLS termination is handled upstream or for integration testing |
| `--allow-private-upstream` | `false` | Allow RFC1918/loopback upstream targets — see [docs/deployment.md](docs/deployment.md) |
| `--enable-libinjection-sqli` | `false` | Enable libinjection-based SQL injection detection — see [docs/libinjection.md](docs/libinjection.md) |
| `--enable-libinjection-xss` | `false` | Enable libinjection-based XSS detection — see [docs/libinjection.md](docs/libinjection.md) |
| `--enable-vectorscan` | `false` | Enable Vectorscan-based fast multi-pattern matching (requires `vectorscan-engine` feature) |
| `--rate-limit-per-minute` | `240` | Maximum admissions per client IP per minute (GCRA-sharded) — see [docs/rate_limit.md](docs/rate_limit.md) |
| `--wal-mode` | `sqlite` | Persistence backend for the rate-limiter snapshot: `sqlite` (inspectable, WAL journal) or `bincode` (atomic-rename binary, 10–50× faster) — see [docs/rate_limit.md](docs/rate_limit.md) |
| `--upstream-timeout-secs` | `15` | Timeout in seconds for upstream requests |
| `--connection-timeout-secs` | `30` | Timeout in seconds for client connections accepted by the WAF |
| `--max-connections` | `2048` | Maximum simultaneous client connections |
| `--max-upstream-response-bytes` | `104857600` (100 MiB) | Hard ceiling on upstream response body buffered in memory; prevents a misbehaving upstream from exhausting WAF heap |
| `--internal-header-name` | — | Optional header added to forwarded requests to mark them as processed by KrakenWaf |
| `--blockmsg` | — | Path to a custom HTML or text file returned when a request is blocked |
| `--verbose` | `false` | Enable debug-level logging |
| `--header-protection-injection` | — | Path to a YAML file that injects custom security headers into all responses; see examples in `rules/headers_http/` |
| `--cmc-load` | — | Path to CMC config YAML enabling/disabling each CMC detector — see [docs/cmc/schema.md](docs/cmc/schema.md) |
| `--real-ip-header` | — | HTTP header containing the real client IP forwarded by a trusted proxy — see [docs/deployment.md](docs/deployment.md) |
| `--trusted-proxy-cidrs` | — | Comma-separated list of trusted proxy CIDRs for real-IP extraction — see [docs/deployment.md](docs/deployment.md) |
| `--help` | — | Show CLI help and exit |
| `--version` | — | Print the current KrakenWaf version and exit |

---

## 🚀 Why KrakenWaf?

- Rust memory safety
- Async Tokio architecture
- High performance reverse-proxy design
- Modern detection engines
- Operational simplicity
- Easy deployment in front of real applications

---

## 🔥 Final Notes

KrakenWaf is built for:
- sysadmins
- pentesters
- developers
- self-hosters
- blue teams that want a small auditable Rust WAF

Deploy it in minutes and protect your apps with modern Rust-based security.


## SQLite schema

KrakenWaf creates the `vulnerabilities` table automatically in `logs/db/vulns_alert.db`:

```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title VARCHAR(256) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    cwe VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    reference_url TEXT NOT NULL,
    occurred_at TIMESTAMP NOT NULL,
    rule_match TEXT NOT NULL,
    rule_line_match VARCHAR(256) NOT NULL,
    client_ip VARCHAR(64) NOT NULL,
    http_method VARCHAR(16) NOT NULL,
    request_uri TEXT NOT NULL,
    fullpath_evidence TEXT NOT NULL,
    engine VARCHAR(32) NOT NULL,
    request_payload TEXT NOT NULL,
    request_id VARCHAR(32) NOT NULL DEFAULT ''
);

CREATE INDEX idx_vulnerabilities_occurred_at
    ON vulnerabilities(occurred_at DESC);
CREATE INDEX idx_vulnerabilities_severity
    ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_engine
    ON vulnerabilities(engine);
CREATE INDEX idx_vulnerabilities_title
    ON vulnerabilities(title);
CREATE INDEX idx_vulnerabilities_request_id
    ON vulnerabilities(request_id);
```

## Main rules local

- rules/
- `rules/regex/path_regex.json`
- `rules/regex/header_regex.json`
- `rules/Vectorscan/strings2block.json`
- KrakenWaf have 100 rules or more with CMC...

---

## YAML rule files

### Allow-paths — `rules/allowpaths/lists.yaml`

Defines URI prefixes that bypass WAF inspection entirely.
Loaded via `--allow-paths rules/allowpaths/lists.yaml`.

```yaml
allow:
  - order: 1
    title: "WordPress admin panel"
    description: "Trusted admin resource — restrict access at the network level"
    log: true          # emit a log entry when this path is bypassed
    paths:
      - /wp-admin
      - /wp-json

  - order: 2
    title: "Health check endpoint"
    description: "Load-balancer liveness probe — safe to bypass WAF inspection"
    log: false
    paths:
      - /healthz
      - /readyz
```

Fields:

| Field | Type | Description |
|-------|------|-------------|
| `order` | int | Evaluation priority (lower = first) |
| `title` | string | Human-readable label for logs |
| `description` | string | Operator notes |
| `log` | bool | Whether to log bypassed requests |
| `paths` | list | URI prefixes — matched with `starts_with` |

→ Full details: [docs/allowpaths.md](docs/allowpaths.md)

---

### CMC config — `rules/cmc/config.yaml`

Toggles each CMC detector independently at startup.
Loaded via `--cmc-load rules/cmc/config.yaml`.

```yaml
global-options:
  Untrust: 60                   # Global paranoia level 0–100 (default 60)

CMC-Rules:
  SQLi_comments_detect: true    # SQL comment evasion (/**/, --, #)
  Overflow_detect: true         # Buffer overflow patterns
  SSTI_detect: true             # Server-side template injection
  SSI_injection_detect: true    # Server-side include injection
  ESI_injection_detect: true    # Edge-side include injection
  CRLF_injection_detect: true   # CRLF injection / HTTP response splitting
  Request_Smuggling_detect: true # HTTP request smuggling
  NOSQL_injection_detect: true  # NoSQL injection marker correlation
  XXE_attack_detect: true       # XML external entity attack marker correlation
  Anti_exposed_backup: true     # Backup-file / editor-artefact path exposure
  Anti_passwd_leak: true        # Response-body /etc/passwd and /etc/shadow leak detection
  Java_deserialize_detect: true # Java deserialization gadget chains (req + resp)
  Detect_db_errors: true        # Response-body DBMS error fingerprint detection (200+ patterns, CWE-209)
```

Set any key to `false` to disable that detector without recompiling.

`NOSQL_injection_detect` blocks when the same URI/body inspection payload contains at least one NoSQL operator/selector marker such as `$gt`, `$where`, `$or`, `$and`, `selector`, `this.password.match`, `&&` or `||`, and at least one suspicious value/control marker such as `true`, `admin`, `pass`, `user`, `null`, `sleep(`, `dropDatabase(`, `%00`, `{}`, `.insert`, `==1`, `== 1`, `]=1`, `] = 1`, or `==` followed by a digit from `1` to `9`.

`XXE_attack_detect` blocks when the same URI/body inspection payload contains at least one XML entity/include marker (`ENTITY` or `xi:include`) and at least one XXE context marker such as `xxe`, `SYSTEM`, `etc/password`, `eval`, `exfil`, `xmlns:xi`, `send`, `DOCTYPE`, `soap`, or `file`. UTF-16LE/BE payloads that arrive after URL decoding as NUL-interleaved text are decoded before XXE matching.

→ Full details: [docs/cmc/schema.md](docs/cmc/schema.md)

---

### Security header profiles — `rules/headers_http/`

Plain-text files (one `Header-Name: value` per line) injected into every
upstream response. Loaded via `--header-protection-injection`.

Available profiles:

| File | Description |
|------|-------------|
| `strict.headers` | Maximum hardening — `frame-ancestors none`, strict CSP, HSTS preload |
| `balanced.headers` | Balanced defaults suitable for most web apps |
| `relax.headers` | Minimal headers for APIs or legacy apps with relaxed CSP |
| `locked_down.headers` | Zero-trust profile — denies cross-origin resource sharing |
| `api_compat.headers` | API-compatible — omits frame/CSP headers that break JSON clients |

Example (`strict.headers`):

```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

Usage:

```sh
krakenwaf ... --header-protection-injection rules/headers_http/strict.headers
```

---

## CI/CD

### Security pipeline (`.github/workflows/security.yml`)

Runs on every push/PR and weekly (Monday 06:00 UTC):

| Job | Tool | Type |
|-----|------|------|
| `clippy` | cargo clippy | SAST — deny warnings |
| `semgrep` | Semgrep (p/rust, p/owasp-top-ten, p/secrets) | SAST → SARIF to Security tab |
| `cargo-audit` | RustSec advisory database | SCA |
| `cargo-deny` | licenses + bans + advisories (`deny.toml`) | SCA |
| `osv-scan` | [osv.dev](https://osv.dev) OSV Scanner | SCA → SARIF to Security tab |

### Monthly artifacts (`.github/workflows/artifacts.yml`)

Runs automatically on the **1st of each month at 02:00 UTC** (also triggerable manually via Actions → Run workflow).

Produces 4 downloadable artifacts per run (retained 90 days):

```
Actions → Monthly Release Artifacts → [run] → Artifacts

  📦 security-reports-<run_id>/
       semgrep.sarif / .json          ← SAST
       cargo-audit.txt / .json        ← SCA RustSec
       cargo-deny.txt  / .json        ← SCA licenses + bans
       osv-scanner.sarif / .json / .txt ← SCA osv.dev

  📦 krakenwaf-v*-x86_64-unknown-linux-gnu.tar.gz
  📦 krakenwaf-v*-aarch64-unknown-linux-gnu.tar.gz
  📦 krakenwaf-v*-x86_64-pc-windows-msvc.tar.gz
```

---

## Notes

- Every public function is documented with Rust doc comments so `cargo doc` can render API documentation.
- Regex rules are compiled once during startup.
- The primary rules format is JSON via `rules/rules.json`.
- Vectorscan and libinjection are runtime-toggleable through CLI flags and compile-time optional through Cargo features.
- The custom block page is optional; when omitted, KrakenWaf returns a plain text fallback block message.
- - DOcs about CMC https://github.com/Orangewarrior/KrakenWaf/blob/main/docs/cmc/schema.md


## Scheduler and auto update

KrakenWaf includes two isolated update robots:

- `soldier_update`: runs manual updates with `--kraken-update` or `--addr-list <name>`.
- `watch_tower`: reads `conf/update.yaml` and runs scheduled updates using cron-style expressions.

Example:

```yaml
KrakenWaf:
  cron: "0 18 */15 * *"
blocklist:
  title: "Blocklist site"
  lists:
    url_file:
      - "https://lists.blocklist.de/lists/bruteforcelogin.txt"
      - "https://lists.blocklist.de/lists/bots.txt"
  cron: "0 12 */3 * *"
spamhaus:
  title: "Spamhaus site"
  lists:
    url_file: "https://www.spamhaus.org/drop/drop.lasso"
  DQS-key: false
  zones:
    - sbl
    - xbl
    - authbl
  cron: "0 12 */3 * *"
firehol:
  title: "Firehol"
  lists:
    url_file:
      - "https://iplists.firehol.org/files/firehol_proxies.netset"
      - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/c2_tracker.ipset"
  cron: "0 12 */3 * *"
```

Manual commands:

```bash
cargo build --release --bin soldier_update --bin watch_tower
target/release/soldier_update --kraken-update
target/release/soldier_update --addr-list blocklist
target/release/soldier_update --addr-list firehol
target/release/soldier_update --addr-list spamhaus
target/release/watch_tower
```

Files from `blocklist.lists.url_file` are downloaded into
`rules/addr/blocklist/`; files from `spamhaus.lists.url_file` are downloaded
into `rules/addr/spamhaus/`; Firehol files are downloaded into
`rules/addr/firehol/`. Spamhaus SBL, XBL, and AuthBL are queried through
DQS DNS at runtime only when `DQS-key: true`, `SPAMHAUS_DQS_KEY` is set, and
`--blocklist-ip` is enabled.
Alerts include the YAML `title`, downloaded file or DQS zone, and local source
path in raw, JSON, and SQLite logs.

See [docs/spamhaus_dqs_updates.md](docs/spamhaus_dqs_updates.md) for DQS setup,
token handling, DQS zones, and scheduler configuration.


## Operational notes

- Rate limiting is enforced per-IP and per-process by a lock-free GCRA-sharded limiter (64 shards, ~20–30 ns admission on the hot path) with snapshots persisted to `tmp_cache/` so brief restarts do not give blocked clients a fresh budget. The on-disk format is selectable via `--wal-mode` (`sqlite` or `bincode`). For full algorithm, sharding, persistence and tuning details see [docs/rate_limit.md](docs/rate_limit.md). Clustered/global enforcement across multiple WAF instances still requires a shared backend such as Redis.
- SNI CSV accepts an optional fourth column (`true`/`false`) to select the default certificate.
- Send `SIGHUP` to hot-reload rule files without restarting the process.
- `/metrics` exposes Prometheus text counters and `/__krakenwaf/health` exposes a liveness endpoint.

 ![MTG nadir kraken](https://github.com/Orangewarrior/KrakenWaf/blob/main/docs/img/krakenWAF.png?raw=true)

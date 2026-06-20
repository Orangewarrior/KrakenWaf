![Rust](https://img.shields.io/badge/language-Rust-orange)
![Security](https://img.shields.io/badge/focus-AppSec-blue)

## 🚀 KrakenWAF Overview

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

See the [visual architecture and runtime flows](docs/visual_architecture.md) for
editable draw.io diagrams covering local SQLite/Postcard and distributed Redis
deployments, request processing, GCRA admission, metrics, and rule management.

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
- [Silent SQL errors](docs/cmc/silent_sql_errors.md) — scrubs (or blocks) upstream responses leaking OWASP-CRS DBMS error fingerprints; below `Untrust=80` the matched literal is replaced with a single space and the response is forwarded with an updated `Content-Length`, above `Untrust=80` the response is blocked. memchr fast path + Vectorscan acceleration (CWE-209, Low→High)
- [Detect bad artifacts](docs/cmc/detect_bad_artifacts.md) — blocks (or silently logs) requests whose URI path contains a sensitive file artifact: dotfiles (`.env`, `.git/`, `.ssh/`), credential files, framework config leaks (`wp-config.`, `composer.json`), `/proc` and `/sys` kernel entries, and 400+ other patterns sourced from the OWASP CRS `restricted-files.data` research; memchr fast path + Vectorscan acceleration (CWE-538, High)
- [Detect bots & scanners](docs/cmc/detect_bots_n_scanners.md) — blocks (or silently logs) requests whose `User-Agent` matches a known scanner/crawler/offensive tooling substring (Nikto, sqlmap, Nmap, masscan, Nessus, OpenVAS, gobuster, dirbuster, Arachni, Nuclei, wfuzz, commix, Acunetix, …) loaded from `rules/user_agents/scanners.txt` (OWASP CRS `scanners-user-agents.data`); Aho-Corasick fast path + Vectorscan acceleration. Action gated by `Untrust ≥ 60`; logged as a bot/scanner reconnaissance sweep (CWE-200, Low)
- [HPP detect](docs/cmc/hpp_detect.md) — HTTP Parameter Pollution: normalizes the query string **and** body (percent, double/recursive percent, UTF-16 LE/BE), counts `=` on the normalized form and, when ≥ 2, parses parameter names and flags any duplicated name (case-insensitive) per location. Gated by `Untrust ≥ 60` (Critical). Encoding-bypass resistant via the global normalizer (CWE-235)
- [Open Redirect & RFI detect](docs/cmc/open_redirect_rfi_detect.md) — inspects redirect/inclusion-prone parameters (query on `GET`, body on `POST`); when a "hot" parameter (`next`, `url`, `redirect`, `file`, `include`, … — substring match, single-char tokens `u`/`r` exact) carries a value resolving to a scheme-relative/external URL or dangerous scheme it blocks as **Open Redirect** (CWE-601), and a PHP/inclusion wrapper or trailing `?`/`%00` marker blocks as **RFI** (CWE-98). Encoding-bypass resistant (percent, double/triple percent, UTF-16 LE/BE, mixed-case scheme, backslash confusion, control-char prefix) via the global normalizer + the new `strip_control_and_space_prefix` mitigation. Optional localized hot-parameter lists for 12 languages via `multiple-languages-params` (High)

### 🔹 libinjection
- Detects SQLi and XSS
- Industry standard approach for injection-focused detection

---

## 🎛️ Real-time rule management

A dedicated, isolated control plane (default port `4342`) lets an operator
inspect and **toggle CMC detection modules at runtime** — no restart — via
`GET /rule/control/cmc/list` and `POST /rule/control/cmc/update` (partial patch;
the detection table is hot-swapped atomically). It is protected by two
independent gates: a CIDR-aware IP allowlist (`403`) and the **Rorschach
Token** — a rotating, body-bound bearer credential built on BLAKE2b keyed MAC
(`orion`), recomputed every 5-minute window, verified in constant time with
anti-replay (`401`). Secrets come from ENV with FILE fallback (no hard-coded
credentials); the control plane is fail-closed and opt-in.

The same control plane also **edits regex, keyword and scanner rule files in
real time**: `POST /rule/control/regex/view` returns a managed rule file's
content, and `POST /rule/control/regex/update/<name>` replaces every rule in a
context and hot-reloads the engine atomically — no restart. Editing is limited
to a closed allowlist of five files (`body_regex`, `header_regex`, `path_regex`,
`vectorscan_list`, `scanners`); any other name is rejected. See
[docs/rule_management.md](docs/rule_management.md).

---

## 📊 User interface

KrakenWAF have a external software for user interface [kraken-ui](https://github.com/Orangewarrior/kraken-ui),hardened web application for operating a KrakenWAF deployment: manage operators, watch blocked attacks in real time, and read live WAF metrics from a single TLS-only console. It is written in Rust with Axum, Askama and SeaORM, ships no CDN assets and runs no inline JavaScript.


## 🛡️ Rate Limiting

KrakenWaf includes two complementary throttling mechanisms. Full reference: **[docs/rate_limit.md](docs/rate_limit.md)**.

### Per-IP request rate (GCRA / Redis)

Limits the number of requests a single IP may make per minute.

```bash
# Quick start — 60 req/min, no config file needed
krakenwaf --rate-limit-per-minute 60 [...]

# Or load from conf/ratelimit.yaml (auto-discovered)
krakenwaf --ratelimit-by-file-conf conf/ratelimit.yaml [...]
```

`conf/ratelimit.yaml` controls all rate-limit settings including the Redis backend:

```yaml
rate_limit_per_minute: 240     # req/min per IP (0 = use CLI flag or default)
max_coroutines_per_ip: 64      # simultaneous connections per IP (0 = disabled)

# Connection & body-size caps (mirror the matching CLI flags).
# 0 = defer to the CLI flag / rules/cmc/config.yaml memory-limits / built-in.
max_connections: 0                 # 0 = derive from system RAM
connection_timeout_secs: 30        # client connection timeout (>= 1)
http_header_read_timeout_secs: 10  # HTTP/1 incomplete-header timeout
max_body_bytes: 0                  # 0 = 8 MiB default
max_upstream_response_bytes: 0     # 0 = 8 MiB buffered text default

# Uncomment to enable Redis distributed rate limiting:
# redis:
#   url: "rediss://redis.internal:6380/0"   # rediss:// (TLS) required
#   pool_size: 4
#   key_prefix: "krakenwaf:rl"
#   window_secs: 60
```

Priority chain: `--rate-limit-per-minute` CLI flag → file value → built-in default (240 req/min).
The connection/body-size caps resolve CLI flag → `conf/ratelimit.yaml` → `rules/cmc/config.yaml` memory-limits → built-in default.

### Per-IP concurrency cap (`max_coroutines_per_ip`)

Caps simultaneous in-flight connections from the same IP. Excess connections receive `HTTP 429 Retry-After: 5` before any WAF inspection or upstream connection is opened.

| Mechanism | Metric | Response |
|-----------|--------|----------|
| GCRA (local or Redis) | requests / minute | `HTTP 429 Retry-After` |
| Concurrency cap | simultaneous connections | `HTTP 429` |

### Redis — multi-node deployments

When `redis:` is configured, all WAF replicas share the same GCRA TAT and use
Redis server time for atomic admission decisions:

```bash
# Credentials are loaded file-first, then env vars (never in config files).
# Preferred: /run/secrets/krakenwaf/REDIS_PASSWORD (see docs/secrets.md).
# Fallback:
export REDIS_PASSWORD="strong-secret-here"
export REDIS_USERNAME="krakenwaf"      # optional: Redis 6+ ACL

krakenwaf --ratelimit-by-file-conf conf/ratelimit.yaml [...]
```

KrakenWaf enforces CIS Redis Benchmark controls: TLS (`rediss://`) mandatory,
credentials loaded file-first with an env-var fallback, and a configurable
fail mode on Redis unavailability (`redis.fail_open`, default fail-open).

→ Full guide: [docs/rate_limit.md](docs/rate_limit.md)

---

## 🧩 Proxy Configuration File (`conf/proxy.yaml`)

The proxy-level flags can be loaded as a group from a YAML file instead of the
command line, keeping deployments terse and version-controllable. Load it with
`--external-proxy-conf` — passed bare it auto-loads `conf/proxy.yaml`; pass a
path to use a different file:

```bash
# Auto-load conf/proxy.yaml
krakenwaf --external-proxy-conf

# Or point at a specific file
krakenwaf --external-proxy-conf /etc/krakenwaf/proxy.yaml
```

`conf/proxy.yaml` mirrors the proxy flags one-to-one:

```yaml
listen : 127.0.0.1:443
upstream : https://127.0.0.1:8080 # host defined by the operator
upstream-timeout-secs: # empty -> WAF default (15 s)
upstream-ca: # empty -> trust public CAs only; PEM path to trust a private upstream CA
allow-private-upstream: false # disabled
debug-proxy-dev: false # true -> persist diagnostic proxy JSONL under logs/proxy_errors_dev/
internal-header-name: # empty -> internal header disabled
real-ip-header: X-Forwarded-For
trusted-proxy-cidrs: 127.0.0.1/32
sni-map: ./rules/tls/sni_map.csv # default
no-tls: false # TLS enabled
header-protection-injection: ./rules/headers_http/relax.headers
blockmsg: ./alert/blockalert.html # empty -> no custom block page
```

> **Fronting a TLS backend with a private/internal CA?** Set `upstream-ca` (or
> `--upstream-ca`) to the CA's PEM. KrakenWaf's upstream client trusts the public
> webpki roots by default; the supplied CA is *added* to them (full verification
> is still enforced), so a backend presenting a private-PKI certificate is
> verified instead of rejected with a 502.

`debug-proxy-dev` controls noisy developer diagnostics for proxy parsing errors,
such as malformed `Forwarded:` values from trusted proxies. When `false`, only
critical proxy failures are persisted. When `true`, diagnostic events are
written as JSONL to `logs/proxy_errors_dev/proxy_errors.jsonl`; see
[`docs/proxy_diagnostics.md`](docs/proxy_diagnostics.md).

**Parsing & precedence**

- One `key: value` per line; the value may contain colons (e.g. a URL). The
  parser splits on the **first** colon only.
- A `#` at the start of a line, or preceded by a space, starts a comment — the
  rest of the line is ignored. A `#` inside a value (no leading space) is kept.
- An **empty value** means *keep the WAF default* — it never overrides. An empty
  `internal-header-name` leaves the internal header disabled; an empty
  `upstream-timeout-secs` keeps the built-in 15 s default.
- Resolution order (highest first): an explicitly-passed CLI flag → the value in
  `conf/proxy.yaml` → the built-in default.
- The file is **validated at startup** (fail-fast): `listen` must be a socket
  address, `upstream` an `http(s)` URL, each `trusted-proxy-cidrs` entry a CIDR,
  and the header-name fields valid HTTP tokens. A malformed value aborts boot
  with a descriptive error.

> **Connection & body-size caps** (`--max-connections`,
> `--connection-timeout-secs`, `--max-body-bytes`,
> `--max-upstream-response-bytes`) are configured in
> [`conf/ratelimit.yaml`](docs/rate_limit.md), not `conf/proxy.yaml`, since they
> belong to the rate-limiting / memory-backpressure context.

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
Prepare a **self-signed dev certificate** (git-ignored — never commit private
keys; production uses CA/ACME-issued certs):
```bash
./scripts/gen-dev-certs.sh
# equivalent to:
#   openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
#     -keyout certs/key.pem -out certs/cert.pem -config rules/tls/localhost.cnf
#   chmod 600 certs/key.pem
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

Restrict `/metrics` to specific IPs by adding `only_addrs` to `rules/allowpaths/lists.yaml`:

```yaml
allow:
  - order: 1
    title: "Health check endpoint"
    log: false
    only_addrs: rules/addr/allowlist/allow_addrs.txt   # localhost only by default
    paths:
      - /metrics
      - /healthz
      - /readyz
      - /livez
```

Edit `rules/addr/allowlist/allow_addrs.txt` to add monitoring subnet IPs (exact,
CIDR, or start–end range). See [docs/allowpaths.md](docs/allowpaths.md) for details.

KrakenWaf fails startup when the observability listener inherits a non-loopback
bind and neither `BEARER_PASSWORD` nor an effective `/metrics` IP allowlist is
configured. Server-side TLS alone is not mTLS and does not satisfy this check.

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
| `--upstream-ca` | — | Path to a PEM certificate/bundle to trust as an **additional** root CA for the TLS upstream. Full chain verification is still enforced — lets KrakenWaf front a backend with a private-PKI / internal-CA cert. Also settable via `upstream-ca` in `conf/proxy.yaml` |
| `--enable-libinjection-sqli` | `false` | Enable libinjection-based SQL injection detection — see [docs/libinjection.md](docs/libinjection.md) |
| `--enable-libinjection-xss` | `false` | Enable libinjection-based XSS detection — see [docs/libinjection.md](docs/libinjection.md) |
| `--enable-vectorscan` | `false` | Enable Vectorscan-based fast multi-pattern matching (requires `vectorscan-engine` feature) |
| `--rate-limit-per-minute` | 240 | Per-IP request budget per 60 s window. Overrides the config file. Default when absent: 240. See [docs/rate_limit.md](docs/rate_limit.md) |
| `--ratelimit-by-file-conf` | auto-discover | Path to a YAML rate-limit config file. Auto-discovered at `conf/ratelimit.yaml` in the working directory. Enables Redis backend, `max_coroutines_per_ip`, and the connection/body-size caps. See [docs/rate_limit.md](docs/rate_limit.md) |
| `--external-proxy-conf` | — / `conf/proxy.yaml` | Load the proxy flags (`--listen`, `--upstream`, `--upstream-timeout-secs`, `--allow-private-upstream`, `--debug-proxy-dev`, `--internal-header-name`, `--real-ip-header`, `--trusted-proxy-cidrs`, `--sni-map`, `--no-tls`, `--header-protection-injection`, `--blockmsg`) from a YAML file. Passed bare it auto-loads `conf/proxy.yaml`; pass a path for a different file. An explicit CLI flag still wins; an empty field keeps the WAF default. See [Proxy configuration file](#-proxy-configuration-file-confproxyyaml) |
| `--debug-proxy-dev` | `false` | Persist diagnostic proxy errors to `logs/proxy_errors_dev/proxy_errors.jsonl`. Critical proxy failures are still saved when disabled; this enables noisy developer events such as malformed forwarding headers. Also settable via `debug-proxy-dev` in `conf/proxy.yaml`. See [docs/proxy_diagnostics.md](docs/proxy_diagnostics.md) |
| `--wal-mode` | `sqlite` | Persistence backend for the local rate-limiter snapshot: `sqlite` (inspectable WAL) or `postcard` (atomic-rename binary, ~10–50× faster). Ignored when using Redis. See [docs/rate_limit.md](docs/rate_limit.md) |
| `--websocket-conf` | auto-discover | Path to a YAML WebSocket control-policy file. Auto-discovered at `conf/websocket.yaml`. Governs `ws://`/`wss://` upgrade limits (allowed paths, per-IP session cap, idle/session timeouts, handshake inspection). See [docs/websocket.md](docs/websocket.md) |
| `--upstream-timeout-secs` | `15` | Timeout in seconds for upstream requests |
| `--connection-timeout-secs` | `30` | Timeout in seconds for a client connection accepted by the WAF. Also configurable via `connection_timeout_secs` in [conf/ratelimit.yaml](docs/rate_limit.md) |
| `--http-header-read-timeout-secs` | `10` | HTTP/1 request-line/header read timeout. Closes incomplete-header Slowloris connections before request-level rate limiting runs. `0` disables (not recommended). Also configurable via `http_header_read_timeout_secs` in [conf/ratelimit.yaml](docs/rate_limit.md) |
| `--max-connections` | RAM-derived | Maximum simultaneous TCP connections accepted by the WAF. When unset, a conservative cap is derived from system RAM (clamped to 64–4096). Also configurable via `max_connections` in [conf/ratelimit.yaml](docs/rate_limit.md) or `rules/cmc/config.yaml` |
| `--max-body-bytes` | `8388608` (8 MiB) | Maximum request body buffered for inspection. Larger bodies are streamed in chunks; this caps the in-memory footprint per request. Also configurable via `max_body_bytes` in [conf/ratelimit.yaml](docs/rate_limit.md) or `rules/cmc/config.yaml` |
| `--max-upstream-response-bytes` | `8388608` (8 MiB) | Ceiling for fully buffered textual upstream responses. Binary media streams without full accumulation; its total-byte cap and optional inspection prefix are configured by `max_streamed_response_bytes` and `response_inspect_prefix_bytes` in `rules/cmc/config.yaml`. Also configurable via `max_upstream_response_bytes` in [conf/ratelimit.yaml](docs/rate_limit.md) |
| `--anomaly-threshold` | `600` | Score-engine block threshold. Detection rules with `score` below this are correlated; when their accumulated `sum_score` within a single inspection view reaches the threshold the request is blocked. Also configurable via `Anomaly_threshold` under `global-options` in [rules/cmc/config.yaml](rules/cmc/config.yaml). See [docs/score_rank.md](docs/score_rank.md) |
| `--max-inspection-ms` | `0` (disabled) | Per-request wall-clock cap on WAF inspection (ms). When set and elapsed, inspection blocks fail-closed with a deadline finding and records a JSONL event under `logs/filter/deadline.jsonl`. `0` disables the deadline. Also configurable via `Max_inspection_ms` under `global-options` in [rules/cmc/config.yaml](rules/cmc/config.yaml) |
| `--body-frame-timeout-secs` | `30` | Per-frame timeout when streaming the request body. If the WAF waits longer than this for a single body chunk it returns 408 and drops the connection. Also configurable via `body_frame_timeout_secs` in [conf/ratelimit.yaml](docs/rate_limit.md) |
| `--max-inflight-body-bytes` | `1073741824` (1 GiB) | Global ceiling on bytes from in-flight request bodies across all clients. When exceeded, new requests receive 503 + `Retry-After: 5`. Also configurable via `max_inflight_body_bytes` in [conf/ratelimit.yaml](docs/rate_limit.md) |
| `--max-per-ip-body-bytes` | `209715200` (200 MiB) | Per-IP ceiling on bytes from in-flight request bodies. Prevents a single client from saturating the global body buffer. Also configurable via `max_per_ip_body_bytes` in [conf/ratelimit.yaml](docs/rate_limit.md) |
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
    country VARCHAR(128) NOT NULL DEFAULT '',
    continent_name VARCHAR(64) NOT NULL DEFAULT '',
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

### 🔎  CMC config — `rules/cmc/config.yaml`

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
  Silent_sql_errors: true       # Response-body DBMS error scrubber (OWASP CRS sql-errors.data, CWE-209)
  Detect_bad_artifacts: true    # Request URI artifact detection (dotfiles, config, /proc, credentials — OWASP CRS restricted-files.data, CWE-538)
  Detect_bots_n_scanners: true  # Scanner/crawler User-Agent blocking — OWASP CRS scanners-user-agents.data, gated by Untrust ≥ 60, CWE-200 Low
  HPP_detect: true              # HTTP Parameter Pollution — duplicated param name (case-insensitive) in query/body, normalizer-decoded, gated by Untrust ≥ 60, CWE-235 Critical
  Open_redirect_n_RFI_detect: true # Open Redirect (CWE-601) + RFI (CWE-98) — hot redirect/inclusion params in query/body, normalizer-decoded, High

# Open Redirect / RFI — optional localized hot-parameter lists (default: English only)
multiple-languages-params: false
custom-languages-params:
  russian: false
  japanese: false
  german: false
  bengali: false
  indonesian: false
  french: false
  arabic_modern: false
  arabic_modern_standard: false
  spanish: false
  chinese_mandarin: false
  chinese: false
  hindi: false
  portuguese: false
```

Set any key to `false` to disable that detector without recompiling.

`NOSQL_injection_detect` blocks when the same URI/body inspection payload contains at least one NoSQL operator/selector marker such as `$gt`, `$where`, `$or`, `$and`, `selector`, `this.password.match`, `&&` or `||`, and at least one suspicious value/control marker such as `true`, `admin`, `pass`, `user`, `null`, `sleep(`, `dropDatabase(`, `%00`, `{}`, `.insert`, `==1`, `== 1`, `]=1`, `] = 1`, or `==` followed by a digit from `1` to `9`.

`XXE_attack_detect` blocks when the same URI/body inspection payload contains at least one XML entity/include marker (`ENTITY` or `xi:include`) and at least one XXE context marker such as `xxe`, `SYSTEM`, `etc/passwd`, `eval`, `exfil`, `xmlns:xi`, `send`, `DOCTYPE`, `soap`, or `file`. UTF-16LE/BE payloads that arrive after URL decoding as NUL-interleaved text are decoded before XXE matching.

`HPP_detect` blocks HTTP Parameter Pollution: the query string and request body are each normalized first (percent-decoding, double/recursive percent-decoding, UTF-16 LE/BE transcoding — all via the global normalizer so every CMC module benefits), the `=` characters are counted on the **normalized** form, and when there are two or more the parameter names are parsed (split on `&`, key = substring before the first `=`). If any name repeats — compared **case-insensitively**, so `email` and `eMail` collide — the request is flagged `Critical` and blocked at `Untrust ≥ 60`. Example: `name=Antonio&email=a@x&age=39&eMail=<bingo>` is blocked (duplicate `email`), while `name=Antonio&email=a@x&age=39` is allowed.

`Open_redirect_n_RFI_detect` inspects redirect/inclusion-prone parameters (query string on `GET`, body on `POST`). A parameter is a candidate when its decoded name matches a "hot" token — `redirect`, `url`, `next`, `dest`, `file`, `include`, `page`, … (substring match, so `homepage` matches `page`), with single-character tokens `u`/`r` matched exactly. The matched value is decoded through the global normalizer and its leading control/whitespace bytes stripped, then: a value starting with `//`, a backslash form, or a scheme (`https:`, `javascript:`, `data:`, …) is blocked as **Open Redirect** (CWE-601); a value starting with a PHP/inclusion wrapper (`php://`, `expect://`, `zip://`, `phar:`, `gopher:`, …) or ending with `?`/`%00` is blocked as **RFI** (CWE-98). Both at **High** severity. Example: `next=https://evil.com` is blocked, `homepage=/test/local` is allowed. Set `multiple-languages-params: true` and enable specific `custom-languages-params` to additionally match localized parameter names (12 languages).

→ Full details: [docs/cmc/open_redirect_rfi_detect.md](docs/cmc/open_redirect_rfi_detect.md) · [docs/cmc/schema.md](docs/cmc/schema.md)

---

### 🔎 Security header profiles — `rules/headers_http/`

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

## 🕒 CI/CD

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


## 🕒 Scheduler and auto update

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

## 🚫 Banning

KrakenWaf 2.31.0 introduces an opt-in **BAN list** that short-circuits
repeat offenders (and confirmed scanners) at the server layer, before
any inspection. Configuration lives in `conf/banning.yaml`:

```yaml
Banning_mode: true
Ban_context:
  security_scanners: true       # one Nikto/sqlmap hit → instant ban
  tolerance_block_count: 3      # 3 blocks (any engine) → ban
  Ban_wait_time: 30m            # asymptotic: 30m, 60m, 90m, …
```

The backend is **hybrid** — Redis/Valkey when the rate-limiter pool is
configured (distributed), SQLite at `logs/db/banning.db` otherwise
(single-node, ACID). Ban duration grows linearly with repeat offenses;
all state is wiped 30 days after the last event.

Full reference (lifecycle, log format, storage schema, operational
caveats, manual-test recipe): **[docs/banning.md](docs/banning.md)**.

## 🌍 GeoIP Enrichment (MaxMind GeoLite2-City)

KrakenWaf enriches every security event with the **country** and **continent**
of the attacker's IP, sourced from the MaxMind GeoLite2-City database.  The
fields appear in the SQLite vulnerability log, the JSONL structured log, and the
raw critical log — enabling per-region attack analysis without additional tooling.

A bundled copy of `db/geo/GeoLite2-City.mmdb` ships with the repository so the
WAF works out of the box.  Because MaxMind releases monthly updates, it is
recommended to refresh it periodically using the built-in updater:

**Setup:**

1. Create a free account at <https://www.maxmind.com/en/> and generate a license key.
2. Provide credentials as **file secrets** (preferred) or env vars — **never
   commit them to YAML** (see [docs/secrets.md](docs/secrets.md)):
   ```bash
   # File secret (preferred): /run/secrets/krakenwaf/MAXMIND_LICENSE_KEY, …
   # Environment variable (fallback):
   export MAXMIND_ACCOUNT_ID='1234567'
   export MAXMIND_LICENSE_KEY='YourLicenseKey'
   ```
3. Run the updater once: `./soldier_update --addr-list maxmind-geo`
4. Restart KrakenWaf to load the new database.

`watch_tower` automatically re-runs `soldier_update --addr-list maxmind-geo` on
the schedule defined by `maxmind-geo.cron` (default: 1st of each month at 18:00).
It inherits the environment, so the variables above must be set when `watch_tower`
starts.  Credential errors are written to `logs/console_local/errors.txt`.

Geo lookup is performed **entirely on-host** — no data leaves the machine at
request time.  When the database file is absent or `active: false` is set, the
WAF operates normally with empty geo fields.

Full reference: **[docs/geoip.md](docs/geoip.md)**.


## Operational notes

- Rate limiting is enforced per-IP by the same **GCRA contract** in both backends: a randomized 64-shard local TAT store with async snapshot persistence, or a distributed Redis TAT updated atomically from Redis `TIME`. Rejections return HTTP 429 with a computed `Retry-After` in every WAF inspection mode. A separate per-IP **concurrency gate** (`max_coroutines_per_ip`) limits simultaneous in-flight requests and uses the same trusted-proxy-resolved client IP.
- SNI CSV accepts an optional fourth column (`true`/`false`) to select the default certificate.
- Send `SIGHUP` to hot-reload rule files without restarting the process.
- KrakenWAF has full TLS support but don't use lib OpenSSL, uses rustls.
- `/metrics` exposes Prometheus text counters and `/__krakenwaf/health` exposes a liveness endpoint.
- **Allow-path IP restriction** (`only_addrs`): add `only_addrs: <path>` to any entry in `rules/allowpaths/lists.yaml` to gate that path by client IP. `rules/addr/allowlist/allow_addrs.txt` ships pre-populated with loopback addresses so observability endpoints are localhost-only by default. Supports exact IPs, CIDR, and start–end ranges. See **[docs/allowpaths.md](docs/allowpaths.md)**.
- **Production hardening** (containers / Kubernetes / systemd): ready-to-adapt, **CIS-Benchmark-aligned** deploy artifacts ship under [`deploy/`](deploy) — a sandboxed systemd unit (`NoNewPrivileges`, `ProtectSystem=strict`, `CAP_NET_BIND_SERVICE`-only, syscall allow-list), a restricted Pod Security Admission namespace with `runAsNonRoot` / `readOnlyRootFilesystem` / `allowPrivilegeEscalation: false` / `capabilities.drop: ["ALL"]` / `seccompProfile: RuntimeDefault` plus default-deny NetworkPolicies, and a distroless non-root container `Containerfile`. All wire in `krakenwaf config validate` as a fail-fast pre-flight. See **[docs/production_hardening.md](docs/production_hardening.md)** (and [docs/admin_commands.md](docs/admin_commands.md) for the validation commands).

 ![MTG nadir kraken](https://github.com/Orangewarrior/KrakenWaf/blob/main/docs/img/krakenWAF.png?raw=true)

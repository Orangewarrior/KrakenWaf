# KrakenWaf v1.2.7

## 🚀 Overview
KrakenWaf is a modern, high-performance Web Application Firewall (WAF) written in Rust.
It is designed for real-world deployments, combining security, performance, and simplicity.

---

## 🧠 Architecture Overview

KrakenWaf is built on:

- **Tokio (async runtime)** → high concurrency, non-blocking I/O
- **Reverse proxy model** → sits in front of your application
- **Streaming inspection pipeline** → analyzes requests in chunks
- **Modular WAF engine** → rule-based + advanced detection engines

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

With libinjection + Vectorscan:
```bash
cargo build --release --features "libinjection-engine vectorscan-engine"
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
dvwa.local,/opt/certs/dvwa.crt,/opt/certs/dvwa.key,false
```

Meaning:
- `hostname` → domain the client will access
- `cert_path` → certificate file for that domain
- `key_path` → private key file for that domain
- `is_default` → `true` means fallback certificate if no SNI match is found

---

## 🌐 Example: Protect WordPress

Backend:
```
https://192.168.0.2/apache/wordpress/blog
```

Run:
```bash
./krakenwaf \
  --listen 0.0.0.0:443 \
  --upstream https://192.168.0.2 \
  --rules-dir ./rules \
  --sni-map ./rules/tls/sni_map.csv \
  --allow-private-upstream \
  --blocklist-ip true \
  --rate-limit-per-minute 180 \
  --upstream-timeout-secs 20 \
  --connection-timeout-secs 30 \
  --max-connections 2048 \
  --internal-header-name x-krakenwaf \
  --blockmsg ./blockpages/blocked.html \
  --verbose
```

Access:
```
https://blog.local/apache/wordpress/blog
```

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

## 🧪 Example: DVWA (Testing attacks)

Backend:
```
http://192.168.0.10/dvwa
```

Run:
```bash
./krakenwaf \
  --listen 0.0.0.0:443 \
  --upstream http://192.168.0.10 \
  --rules-dir ./rules \
  --sni-map ./rules/tls/sni_map.csv \
  --allow-private-upstream \
  --blocklist-ip true \
  --enable-libinjection \
  --enable-vectorscan \
  --blockmsg ./blockpages/blocked.html \
  --verbose
```

Access:
```
https://dvwa.local/dvwa
```

This is useful for validating:
- XSS detection
- SQLi detection
- regex rule hits
- keyword rule hits
- custom block responses
- logging and metrics behavior

---

## 📊 Metrics

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

SQLite:
```
logs/db/vulns_alert.db
```

Inspect the database:
```bash
sqlite3 logs/db/vulns_alert.db \
"SELECT id,title,severity,occurred_at FROM vulnerabilities ORDER BY id DESC LIMIT 10;"
```

---

## ⚙️ CLI Arguments

| Argument | Description |
|-----|------------|
| `--listen` | Bind address and port used by KrakenWaf, for example `0.0.0.0:443` |
| `--upstream` | Backend origin URL, such as `https://192.168.0.2` or `http://127.0.0.1:8080` |
| `--rules-dir` | Root directory containing rule files, blocklists, regex rules, and TLS files |
| `--sni-map` | Path to the TLS SNI CSV file used to map hostnames to certificate and key files |
| `--blocklist-ip` | Enables IP and CIDR blocklist enforcement |
| `--allow-private-upstream` | Allows private or local upstream targets such as RFC1918 addresses |
| `--enable-libinjection` | Enables libinjection-based SQLi/XSS-oriented inspection |
| `--enable-vectorscan` | Enables Vectorscan-based fast multi-pattern matching |
| `--rate-limit-per-minute` | Maximum number of requests allowed per client IP per minute |
| `--upstream-timeout-secs` | Timeout in seconds for upstream requests |
| `--connection-timeout-secs` | Timeout in seconds for client connections accepted by the WAF |
| `--max-connections` | Maximum simultaneous connections the WAF will allow |
| `--internal-header-name` | Optional header added to forwarded requests to mark them as processed by KrakenWaf |
| `--blockmsg` | Path to a custom HTML or text file returned when a request is blocked |
| `--verbose` | Enables more detailed runtime logging |
| `--help` | Shows CLI help and exits |
| `--version` | Prints the current KrakenWaf version and exits |

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
CREATE TABLE IF NOT EXISTS vulnerabilities  (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  CWE TEXT NOT NULL,
  description TEXT NOT NULL,
  reference_url TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  rule_match TEXT NOT NULL,
  rule_line_match TEXT NOT NULL,
  request_payload TEXT NOT NULL
);
```

## Directory layout

```text
KrakenWaf/
├── Cargo.toml
├── certs/
├── logs/
│   ├── db/
│   ├── json/
│   └── raw/
├── rules/
│   ├── Vectorscan/
│   │   └── strings2block.json
│   ├── regex/
│   │   ├── body_regex.json
│   │   ├── header_regex.json
│   │   └── path_regex.json
│   ├── blocklist_ip.txt
│   ├── rules.json
│   └── tls/
│       └── sni_map.csv
├── src/
└── tests/
```

## Main rules format

`rules/rules.json`

```json
{
  "blocked_ip_prefixes": ["10.10.10.", "192.0.2."],
  "uri_keywords": [
    {
      "title": "SQL Injection probe",
      "severity": "critical",
      "cwe": "CWE-89",
      "description": "Detects common UNION SELECT probes in the request target.",
      "url": "https://cwe.mitre.org/data/definitions/89.html",
      "rule_match": "union select"
    }
  ],
  "header_keywords": [],
  "body_keywords": [],
  "allow_paths": ["/health", "/__krakenwaf/health"],
  "body_limits": {
    "/upload": 10485760,
    "/": 1048576
  }
}
```

## Regex format

`rules/regex/body_regex.json`

```json
{
  "rules": [
    {
      "title": "RCE regex",
      "severity": "critical",
      "cwe": "CWE-78",
      "description": "Detects command execution payloads.",
      "url": "https://cwe.mitre.org/data/definitions/78.html",
      "rule_match": "(?i)(cmd(\\.exe)?\\s+/c|powershell\\s+-enc)"
    }
  ]
}
```

The same schema is used for:

- `rules/regex/path_regex.json`
- `rules/regex/header_regex.json`
- `rules/Vectorscan/strings2block.json`
- 
## Notes

- Every public function is documented with Rust doc comments so `cargo doc` can render API documentation.
- Regex rules are compiled once during startup.
- The primary rules format is JSON via `rules/rules.json`.
- Vectorscan and libinjection are runtime-toggleable through CLI flags and compile-time optional through Cargo features.
- The custom block page is optional; when omitted, KrakenWaf returns a plain text fallback block message.


## Operational notes

- Rate limiting now persists snapshots for single-node restarts, but clustered/global enforcement still requires a shared backend such as Redis.
- SNI CSV accepts an optional fourth column (`true`/`false`) to select the default certificate.
- Send `SIGHUP` to hot-reload rule files without restarting the process.
- `/metrics` exposes Prometheus text counters and `/__krakenwaf/health` exposes a liveness endpoint.

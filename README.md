# KrakenWaf 1.2.7

KrakenWaf is a Rust/Tokio TLS-terminating reverse-proxy WAF. Version 1.1 keeps the multi-certificate TLS/SNI support and adds metadata-rich JSON rules, custom block pages, and normalized SQLite storage.

## Highlights

- TLS termination with multi-certificate SNI
- precompiled regex rules loaded from JSON under `rules/regex`
- optional `libinjection-rs` SQLi/XSS detection
- optional Vectorscan literal matching from JSON under `rules/Vectorscan/strings2block.json`
- JSON metadata for normal keyword rules and regex rules: `title`, `severity`, `cwe`, `description`, `url`, `rule_match`
- path allowlisting from JSON rules
- route-specific body limits from JSON rules
- IP rate limiting
- optional exact IP blocklist from `rules/blocklist_ip.txt` controlled with `--blocklist-ip 1|0`
- streaming body inspection for large payloads
- JSON logs under `logs/json`
- raw critical logs under `logs/raw`
- SQLite storage for critical detections in `logs/db/vulns_alert.db`
- optional custom block response page via `--blockmsg /path/to/blockalert.html`

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

## Running

```bash
./target/release/krakenwaf \
  --listen 0.0.0.0:8443 \
  --upstream http://127.0.0.1:8080 \
  --rules-dir ./rules \
  --sni-map ./rules/tls/sni_map.csv \
  --enable-libinjection \
  --enable-vectorscan \
  --blocklist-ip 1 \
  --blockmsg ./alert/blockalert.html
```

## Build notes

Default build keeps optional engines disabled:

```bash
cargo build --release
```

Enable libinjection support:

```bash
cargo build --release --features libinjection-engine
```

Enable Vectorscan support:

```bash
cargo build --release --features vectorscan-engine
```

Enable both:

```bash
cargo build --release --features "libinjection-engine vectorscan-engine"
```

## SQLite schema

KrakenWaf creates the `vulnerabilties` table automatically in `logs/db/vulns_alert.db`:

```sql
CREATE TABLE IF NOT EXISTS vulnerabilties (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  CWE TEXT NOT NULL,
  description TEXT NOT NULL,
  reference_url TEXT NOT NULL,
  "date of ocurrence" TEXT NOT NULL,
  rule_match TEXT NOT NULL,
  rule_line_match TEXT NOT NULL,
  "request_payload" TEXT NOT NULL
);
```

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

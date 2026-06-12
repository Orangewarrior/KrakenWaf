# Observability

KrakenWaf exposes a Prometheus-compatible metrics endpoint and structured JSON logs.

## Metrics endpoint

```
GET /__kwaf/metrics
```

Returns metrics in the [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).

### Global counters

| Metric | Type | Description |
|---|---|---|
| `krakenwaf_requests_inspected_total` | counter | Every request that entered the WAF pipeline |
| `krakenwaf_requests_blocked_total` | counter | Every request (or response) that was blocked |
| `krakenwaf_rate_limit_hits_total` | counter | Requests that hit the per-IP rate limit |
| `krakenwaf_redis_rate_limit_failopen_total` | counter | Requests allowed without a decision because Redis was unavailable (fail-open). **Alert if climbing — rate limiting is not being enforced.** |
| `krakenwaf_redis_rate_limit_failclosed_total` | counter | Requests denied (429) because Redis was unavailable and `redis.fail_open: false` |

### Per-engine/module breakdown

```
# TYPE krakenwaf_module_blocks_total counter
# HELP krakenwaf_module_blocks_total Requests blocked grouped by engine and module.
krakenwaf_module_blocks_total{engine="cmc",module="java_deserialize_detect"} 3
krakenwaf_module_blocks_total{engine="cmc",module="overflow_detect"} 12
krakenwaf_module_blocks_total{engine="cmc",module="sqli_comments_detect"} 7
krakenwaf_module_blocks_total{engine="keyword",module="keyword"} 2
krakenwaf_module_blocks_total{engine="libinjection",module="sqli"} 5
krakenwaf_module_blocks_total{engine="vectorscan",module="vectorscan"} 1
```

The `engine` label corresponds to the detection subsystem:

| `engine` value | Source |
|---|---|
| `cmc` | Custom Module Code — CMC rule modules |
| `libinjection` | libinjection SQLi/XSS C library |
| `vectorscan` | Vectorscan PCRE database |
| `keyword` | Aho-Corasick keyword matcher |
| `regex` | Compiled regex rules |

The `module` label for `engine="cmc"` is the CMC module name as it appears in `rules/cmc/config.yaml` (e.g. `sqli_comments_detect`, `java_deserialize_detect`).

## Grafana dashboard query examples

```promql
# Overall block rate (blocks per second)
rate(krakenwaf_requests_blocked_total[1m])

# Top blocked CMC modules over the last hour
topk(5, sum by (module) (
  increase(krakenwaf_module_blocks_total{engine="cmc"}[1h])
))

# Java deserialisation attack trend
rate(krakenwaf_module_blocks_total{engine="cmc",module="java_deserialize_detect"}[5m])

# Inspection throughput
rate(krakenwaf_requests_inspected_total[1m])
```

## The dedicated observability port (default 4343)

`/metrics` and the health probes are served on a **dedicated observability
listener** (default port `4343`, set via `--metrics-port` or `conf/proxy.yaml`'s
`metrics-port`). The same port also fronts the
[kraken-ui](https://github.com/Orangewarrior/kraken-ui). The channel is
TLS-encrypted (the listener reuses the data-plane certificates; it serves plain
HTTP only when the whole WAF runs with `--no-tls`).

Two **independent** gates protect everything on this port, in this order:

1. **IP allowlist → HTTP 403.** Only source IPs listed in
   `rules/addr/allowlist/allow_addrs_metrics_n_ui.txt` may reach the port. Any
   other source is rejected with `403` *before* the token is examined.
2. **Bearer token → HTTP 401.** A valid `Authorization: Bearer <token>` is
   required on **every** endpoint the port serves (`/metrics`, `/livez`,
   `/readyz`, health, and the kraken-ui surface). A missing or invalid token
   returns `401` with a `WWW-Authenticate: Bearer` challenge.

### Bearer token

The expected token is read from the **`KRAKENWAF_METRICS_TOKEN`** secret using
KrakenWaf's file-first resolution chain — never a CLI flag and never hard-coded:

| Order | Source |
|---|---|
| 1 | `KRAKENWAF_METRICS_TOKEN_FILE` — path to a file holding the token |
| 2 | `/run/secrets/krakenwaf/KRAKENWAF_METRICS_TOKEN` — conventional mount |
| 3 | `KRAKENWAF_METRICS_TOKEN` — plain environment variable (12-factor) |

Generate a strong, **ASCII** token (bearer tokens must be ASCII per RFC 6750),
e.g. `openssl rand -hex 32`. Properties of the gate:

- **Constant-time comparison** — the check does not leak the token via response
  timing.
- **Never logged** — every log line shows the literal `****` in place of the
  token, so it cannot leak to disk, a log shipper, or a crash dump.
- **Disabled when unset** — if no token is provisioned the bearer gate is
  skipped (IP allowlist only) and a startup warning is emitted. Provision the
  secret to enable it.

systemd should supply the token via `LoadCredential=` (see
`deploy/systemd/krakenwaf.service`), which places it on a 0400 tmpfs the service
user can read, with `KRAKENWAF_METRICS_TOKEN_FILE` pointing at it — no plaintext
in `Environment=`.

Scrape it with, for example:

```bash
curl --cacert ca.pem \
  -H "Authorization: Bearer $KRAKENWAF_METRICS_TOKEN" \
  https://waf.internal:4343/metrics
```

Prometheus uses an `authorization` stanza in its scrape config:

```yaml
scrape_configs:
  - job_name: krakenwaf
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/krakenwaf_metrics_token
    static_configs:
      - targets: ["waf.internal:4343"]
```

### IP allowlist (`allow_addrs_metrics_n_ui.txt`)

The allow-paths entry for the observability port is **scoped to that port** with
the `port:` field, so it applies only on the observability listener:

```yaml
allow:
  - order: 2
    title: "Health check and UI endpoint"
    description: "Observability + kraken-ui — restricted to allowed IPs"
    log: false
    port: 4343         # scope this entry to the dedicated observability port
    only_addrs: rules/addr/allowlist/allow_addrs_metrics_n_ui.txt
    paths:
      - /metrics
      - /healthz
      - /readyz
      - /livez
```

The companion file `rules/addr/allowlist/allow_addrs_metrics_n_ui.txt` lists the
allowed source IPs (one per line; exact IP, CIDR, or start–end range):

```
# Loopback only — observability and UI visible from localhost exclusively.
127.0.0.1
```

Requests from unlisted IPs receive **HTTP 403**. The check works behind a load
balancer when `--real-ip-header` and `--trusted-proxy-cidrs` are configured —
KrakenWaf uses the effective client IP for the restriction. Add your Prometheus,
Grafana, and kraken-ui pod/node IPs (or a tight CIDR) here.

### Inline `/metrics` fallback

When `/metrics` is reached on the **data-plane** port (no dedicated listener, or
a request that bypasses it), it stays fail-closed as it has since 2.32.0: with no
IP allowlist configured it is served **only to loopback** (`127.0.0.0/8`, `::1`),
because it reveals operational intelligence. Liveness/readiness endpoints are
unaffected. The bearer-token gate applies to the **dedicated observability port
only**, not to inline data-plane health probes used by load balancers.

See **[docs/allowpaths.md](allowpaths.md)** for the full IP-restriction
feature reference, and **[docs/attack_tool.md](attack_tool.md)** for the
`attack --metrics-only` probe that validates this gate.

---

## Structured JSON logs

KrakenWaf writes structured JSON logs to `logs/json/krakenwaf.jsonl.<date>`. Every detection event includes:

```json
{
  "timestamp": "2026-05-11T12:00:00Z",
  "request_id": "3a7f2e9b1c4d5e6f7a8b9c0d1e2f3a4b",
  "engine": "cmc",
  "rule_id": "00000",
  "title": "CMC Java deserialization attack detection",
  "severity": "Critical",
  "cwe": "CWE-502",
  "ip": "203.0.113.42",
  "method": "POST",
  "uri": "/api/deserialize",
  "rule": "cmc::java_deserialize_detect:signal_a+signal_b",
  "rule_source": "cmc/java_deserialize_detect.rs:generated",
  "mode": "Block"
}
```

The `mode` field reflects the active `--mode` flag so detect-only runs are distinguishable from live blocking.

## SQLite database

Blocked requests are also persisted to `logs/db/vulns_alert.db` for historical queries:

```sql
SELECT engine, title, COUNT(*) as hits
FROM alerts
GROUP BY engine, title
ORDER BY hits DESC
LIMIT 20;
```

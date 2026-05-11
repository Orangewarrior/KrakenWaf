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

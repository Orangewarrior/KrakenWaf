# Detect-Only Mode

Detect-only mode lets KrakenWaf run all inspection engines against live traffic without ever blocking a request. Every detection is logged, metrics are incremented, and a security event is written to the database — but the upstream response is always forwarded to the client.

## When to use it

| Scenario | Recommended mode |
|---|---|
| Tuning new CMC rules against production traffic | `detect-only` |
| Evaluating a new rule set for false-positive rate | `detect-only` |
| Short-term observation with zero business risk | `silent` |
| Full enforcement (default) | `block` |

`detect-only` is stricter than `silent` in intent: it is explicitly designed for *pre-production validation* of rules before switching to `block`. Unlike `silent`, the name in logs is `DetectOnly` so dashboards can distinguish observation runs from permanent bypass decisions.

## Enabling detect-only mode

```bash
cargo run -- \
  --no-tls \
  --mode detect-only \
  --cmc-load ./rules/cmc/config.yaml \
  --listen 0.0.0.0:8080 \
  --upstream http://127.0.0.1:9077
```

## Behaviour matrix

| Engine | `block` | `silent` | `detect-only` |
|---|---|---|---|
| Rate limiter | Block (429) | Allow | Allow |
| IP blocklist | Block (403) | Allow | Allow |
| Keyword rules | Block (403) | Allow | Allow |
| CMC modules | Block (403) | Allow | Allow |
| libinjection | Block (403) | Allow | Allow |
| Vectorscan | Block (403) | Allow | Allow |

In all non-`block` modes every finding is still logged (`request detected` log line, `critical.log`, SQLite `vulns_alert` table) and `krakenwaf_requests_blocked_total` is incremented so Prometheus dashboards reflect true detection counts.

## Switching from detect-only to block

Once you are satisfied with the false-positive rate simply restart KrakenWaf without the `--mode` flag (or with `--mode block`). No rule files need to change.

## Log field

The `mode` field in every structured log event reflects the active mode:

```json
{"mode":"DetectOnly","engine":"cmc","title":"CMC SQLi comment evasion detection",...}
```

Filter detect-only events in Grafana / Loki with `{job="krakenwaf"} | json | mode="DetectOnly"`.

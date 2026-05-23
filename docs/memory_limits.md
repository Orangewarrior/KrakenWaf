# Memory-pressure limits (2.24.0)

KrakenWaf 2.24.0 ships **drastically lower** default buffering caps and
centralises every limit in a single YAML block. The intent is simple: a
fresh install should not turn into a memory-exhaustion DoS for the cost of
a single attacker sending big bodies. Operators with legitimate large-body
workloads opt in by editing one file.

## Where the limits live

Primary location: `rules/cmc/config.yaml`, under the top-level
`memory-limits:` key. A fallback location at `conf/limits.yaml` is also
honoured for sites that prefer keeping CMC and memory configuration in
separate files. When both exist, `rules/cmc/config.yaml` wins.

## Knobs and defaults

| Key                                       | Default     | Purpose                                                                                       |
|-------------------------------------------|-------------|-----------------------------------------------------------------------------------------------|
| `max_request_body_buffered_bytes`         | **8 MiB**   | Cap on the inspected request body. Was 100 MiB in ≤ 2.23.0.                                  |
| `max_response_body_buffered_bytes`        | **8 MiB**   | Cap on the buffered upstream response. Was 100 MiB in ≤ 2.23.0.                              |
| `max_streaming_inspection_window_bytes`   | 256 KiB     | Upper bound on the pattern-overlap window for streaming inspection.                          |
| `max_inflight_body_bytes_global`          | 256 MiB     | Aggregate ceiling across **all** in-flight bodies. Excess requests are rejected with 503.    |
| `max_inflight_body_bytes_per_ip`          | 16 MiB      | Per-IP ceiling so one source cannot monopolise the global pool by opening many connections.  |
| `max_decompress_ratio`                    | 32          | Decompressed / compressed ratio cap. Zip-bomb guard before the absolute cap is exhausted.    |
| `max_connections` (optional)              | RAM-derived | TCP accept ceiling. When omitted KrakenWaf reads `/proc/meminfo` and picks `total_mib / 2`, clamped to `[64, 4096]`. |

## CLI precedence

CLI flags still win when the operator passes a non-zero value:

```text
--max-body-bytes               > memory-limits.max_request_body_buffered_bytes  > 8 MiB
--max-upstream-response-bytes  > memory-limits.max_response_body_buffered_bytes > 8 MiB
--max-connections              > memory-limits.max_connections                  > RAM-derived
```

`0` is the sentinel that means "fall through".

## How to raise the limits

Edit `rules/cmc/config.yaml`:

```yaml
memory-limits:
  max_request_body_buffered_bytes: 67108864   # 64 MiB
  max_response_body_buffered_bytes: 134217728 # 128 MiB
  max_decompress_ratio: 64
```

There is no need to restart for the change to load — the file is read at
process start. (Hot-reload of these specific values is planned for 2.25.0.)

## Related defences

- `src/body_decode.rs`: applies the ratio + absolute caps to gzip / br /
  deflate / zstd request bodies before inspection.
- `src/multipart_extract.rs`: caps to 256 parts and a 70-char boundary
  (RFC 2046).
- `src/waf/rate_limit.rs`: when a shard saturates, **incumbents stay** and
  the new arrival is rejected — limit pressure cannot be used to evict a
  legitimate user.

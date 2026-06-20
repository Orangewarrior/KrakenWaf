# Memory-pressure limits (2.24.0)

KrakenWaf 2.24.0 ships **drastically lower** default buffering caps and
centralises every limit in a single YAML block. The intent is simple: a
fresh install should not turn into a memory-exhaustion DoS for the cost of
a single attacker sending big bodies. Operators with legitimate large-body
workloads opt in by editing one file.

## Where the limits live

Primary location: `conf/filter.yaml`, under the top-level
`memory-limits:` key. A fallback location at `conf/limits.yaml` is also
honoured for sites that prefer keeping CMC and memory configuration in
separate files. When both exist, `conf/filter.yaml` wins.

## Knobs and defaults

| Key                                       | Default     | Purpose                                                                                       |
|-------------------------------------------|-------------|-----------------------------------------------------------------------------------------------|
| `max_request_body_buffered_bytes`         | **8 MiB**   | Cap on the inspected request body. Was 100 MiB in ≤ 2.23.0.                                  |
| `max_response_body_buffered_bytes`        | **8 MiB**   | Cap on textual responses buffered for complete inspection.                                   |
| `max_streamed_response_bytes`             | **1 GiB**   | Total-byte ceiling for streamed binary/media responses; bytes are not accumulated in memory. |
| `response_inspect_prefix_bytes`           | **64 KiB**  | Prefix inspected for generic binary or unknown response types before streaming the remainder. |
| `max_streaming_inspection_window_bytes`   | 256 KiB     | Upper bound on the pattern-overlap window for streaming request inspection.                  |
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

Edit `conf/filter.yaml`:

```yaml
memory-limits:
  max_request_body_buffered_bytes: 67108864   # 64 MiB
  max_response_body_buffered_bytes: 134217728 # 128 MiB
  max_streamed_response_bytes: 2147483648     # 2 GiB
  response_inspect_prefix_bytes: 131072       # 128 KiB
  max_decompress_ratio: 64
```

Restart KrakenWaf after changing these values; they are loaded at process
startup.

## Upstream response modes

KrakenWaf selects a bounded response path from the upstream `Content-Type`:

- `InspectBuffered`: `text/*`, JSON, XML, JavaScript, YAML, GraphQL, and form
  data are buffered up to `max_response_body_buffered_bytes`, inspected as a
  complete body, and may have their headers/body rewritten.
- `StreamOnly`: images, video, audio, fonts, PDF, ZIP/gzip/7z/RAR, and WASM are
  forwarded frame by frame up to `max_streamed_response_bytes`.
- `TeePrefix`: `application/octet-stream`, missing content types, and other
  generic formats retain only `response_inspect_prefix_bytes` for inspection,
  then stream the remainder. The prefix is clamped to the total stream limit.

An advertised `Content-Length` above the selected limit is rejected before
body forwarding. Chunked responses are counted while streaming and the
connection is terminated if the limit is exceeded.

## Related defences

- `src/body_decode.rs`: applies the ratio + absolute caps to gzip / br /
  deflate / zstd request bodies before inspection.
- `src/multipart_extract.rs`: caps to 256 parts and a 70-char boundary
  (RFC 2046).
- `src/waf/rate_limit.rs`: when a shard saturates, **incumbents stay** and
  the new arrival is rejected — limit pressure cannot be used to evict a
  legitimate user.

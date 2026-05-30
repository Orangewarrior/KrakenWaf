# Rate Limiter

KrakenWaf ships with a per-IP rate limiter available in two backends: a
**local GCRA sharded limiter** (single-node, zero dependencies, ~20 ns hot
path) and a **Redis-backed distributed limiter** (multi-node, consistent
enforcement across WAF replicas).

Both backends load their configuration from `conf/ratelimit.yaml` (or an
explicit path via `--ratelimit-by-file-conf`). The config file is
optional — the WAF falls back gracefully to built-in defaults when it is absent.

---

## Quick start

### Single-node (default — local GCRA)

```bash
# 1. Start the WAF — default 240 req/min, auto-discovers conf/ratelimit.yaml
krakenwaf --no-tls --upstream http://127.0.0.1:8080 [...]

# 2. Or override the limit at the CLI
krakenwaf --rate-limit-per-minute 60 [...]

# 3. Or use a config file (see conf/ratelimit.yaml for the full schema)
krakenwaf --ratelimit-by-file-conf conf/ratelimit.yaml [...]
```

### Multi-node (Redis backend)

```bash
# 1. Set credentials in the environment (never in the config file)
export REDIS_PASSWORD="strong-secret-here"

# 2. Edit conf/ratelimit.yaml and uncomment the redis section:
#   redis:
#     url: "rediss://redis.internal:6380/0"
#     pool_size: 4
#     key_prefix: "krakenwaf:rl"
#     window_secs: 60

# 3. Start all WAF replicas pointing at the same conf file
krakenwaf --ratelimit-by-file-conf conf/ratelimit.yaml [...]
```

---

## Configuration file reference

`conf/ratelimit.yaml` is the canonical place to configure all rate-limit
settings. KrakenWaf auto-discovers it in the working directory; use
`--ratelimit-by-file-conf <path>` to supply an alternative path.

```yaml
# Maximum requests per minute per source IP.
# 0 (or absent) = defer to --rate-limit-per-minute CLI flag or default 240.
rate_limit_per_minute: 240

# Maximum simultaneous in-flight connections per source IP.
# Excess connections receive HTTP 429 + Retry-After: 5.
# 0 = disabled.
max_coroutines_per_ip: 64

# Slowloris protection: per-frame timeout (seconds) when streaming the
# request body. 0 disables.
body_frame_timeout_secs: 30

# Anti-Slowloris (TLS accept path): max seconds to wait for a client to
# finish the TLS handshake before dropping the connection. 0 disables
# (not recommended). Only applies in TLS mode. Overridden by
# --tls-handshake-timeout-secs.
tls_handshake_timeout_secs: 10

# Global cap (bytes) on in-flight request body data across all clients.
# Excess requests receive HTTP 503 + Retry-After: 5. 0 disables.
max_inflight_body_bytes: 1073741824   # 1 GiB

# Per-IP cap (bytes) on in-flight request body data. 0 disables.
max_per_ip_body_bytes: 209715200      # 200 MiB

# ── Connection & body-size caps (mirror the matching CLI flags) ──────────────
# Each resolves: CLI flag → this file → rules/cmc/config.yaml memory-limits →
# built-in default. A 0 here means "defer to the next source".

# Maximum simultaneous TCP connections the WAF accepts.
# 0 = derive a conservative cap from system RAM at startup. Overridden by
# --max-connections when > 0.
max_connections: 0

# Timeout (seconds) for a single client connection accepted by the WAF.
# Must be >= 1. Overridden by --connection-timeout-secs. Default: 30.
connection_timeout_secs: 30

# Maximum request body buffered for inspection (bytes).
# 0 = use rules/cmc/config.yaml memory-limits (built-in 8 MiB / 8388608).
# Overridden by --max-body-bytes when > 0.
max_body_bytes: 0

# Hard ceiling on the upstream response body buffered in memory (bytes).
# 0 = use rules/cmc/config.yaml memory-limits (built-in 8 MiB / 8388608).
# Overridden by --max-upstream-response-bytes when > 0.
max_upstream_response_bytes: 0

# Redis backend — uncomment to enable distributed rate limiting.
# redis:
#   url: "rediss://redis.internal:6380/0"   # rediss:// (TLS) mandatory
#   pool_size: 4
#   key_prefix: "krakenwaf:rl"
#   window_secs: 60
#   fail_open: true   # on Redis outage: true=allow (default), false=deny (429)
#   # ca_cert_path: "/etc/ssl/private/redis-ca.pem"   # optional: custom CA
```

### Priority chain

Every CLI flag in the rate-limit family follows the same resolution order:

```
CLI flag                          (--rate-limit-per-minute,
                                   --body-frame-timeout-secs,
                                   --tls-handshake-timeout-secs,
                                   --max-inflight-body-bytes,
                                   --max-per-ip-body-bytes — highest)
        ↓
field in conf/ratelimit.yaml
        ↓
built-in default
```

### Field reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rate_limit_per_minute` | u32 | 240 | Per-IP request budget per 60 s window. `0` defers to CLI flag or default. |
| `max_coroutines_per_ip` | usize | 64 | Maximum in-flight connections per IP. `0` disables. |
| `body_frame_timeout_secs` | u64 | 30 | Per-frame timeout (s) when streaming the request body — anti-Slowloris. `0` disables. Overridden by `--body-frame-timeout-secs`. |
| `tls_handshake_timeout_secs` | u64 | 10 | Max time (s) to wait for a client to finish the TLS handshake before dropping the connection — anti-Slowloris on the accept path. TLS mode only. `0` disables (not recommended). Overridden by `--tls-handshake-timeout-secs`. |
| `max_inflight_body_bytes` | usize | 1073741824 (1 GiB) | Global in-flight body byte cap across all clients. `0` disables. Overridden by `--max-inflight-body-bytes`. |
| `max_per_ip_body_bytes` | usize | 209715200 (200 MiB) | Per-IP in-flight body byte cap. `0` disables. Overridden by `--max-per-ip-body-bytes`. |
| `redis.url` | string | — | Redis endpoint. **Must** use `rediss://` (TLS). |
| `redis.pool_size` | usize | 4 | Number of pooled connections. |
| `redis.key_prefix` | string | `"krakenwaf:rl"` | Namespace prefix — isolates this WAF from other services on the same Redis instance. |
| `redis.window_secs` | u64 | 60 | Rate-limit window length in seconds. |
| `redis.ca_cert_path` | string | — | Path to a PEM CA certificate for private PKI / mTLS. Omit to use the system trust store. |
| `redis.fail_open` | bool | `true` | Behaviour on Redis unavailability: `true` = allow the request (fail-open), `false` = deny with HTTP 429 (fail-closed). Both emit a warning + Prometheus counter. |

---

## Per-IP concurrency limiter

`max_coroutines_per_ip` caps the number of **simultaneous in-flight requests**
accepted from a single source IP. This is distinct from the rate limiter:

| Limiter | Metric | Block response |
|---------|--------|----------------|
| GCRA rate limiter | requests / minute | `HTTP 403` via `Decision::Block` |
| Concurrency cap | simultaneous connections | `HTTP 429 Retry-After: 5` |

The concurrency check fires **before** any WAF inspection or upstream
connection is opened, making it the cheapest possible rejection path.

### Implementation

Each IP gets one `Arc<AtomicUsize>` stored in a `DashMap`. On request entry:

```
counter = ip_connections[client_ip]     # lazy-created on first request
prev    = counter.fetch_add(1)          # atomic, no lock

if prev >= max_coroutines_per_ip:
    counter.fetch_sub(1)                 # undo increment
    return HTTP 429

_conn_guard = ConnGuard(counter)        # RAII: decrements on drop
```

`ConnGuard` ensures the counter is decremented even if the handler panics.
There are no per-request heap allocations on the hot path for existing IPs.

### Choosing a value

| Scenario | Suggested value |
|----------|----------------|
| Public API with well-behaved clients | 32–64 |
| Aggressive scan mitigation | 4–8 |
| Disabled (benchmark / development) | 0 |

---

## Local backend — GCRA (Generic Cell Rate Algorithm)

The default backend requires no external dependencies and achieves
**~20–30 ns per admission** on the hot path via lock-free atomic operations.

### Algorithm

Each client is represented by **one `AtomicU64`** — the **TAT** (Theoretical
Arrival Time) in nanoseconds since the Unix epoch.

```
emission_interval  = window_ns / limit       (nanoseconds between conforming requests)
delay_tolerance    = window_ns               (exact burst of `limit` allowed at once)

on each request at `now`:
  new_tat = max(old_tat, now) + emission_interval
  if (new_tat − now) ≤ delay_tolerance  →  ALLOW  (CAS old_tat → new_tat)
  else                                  →  BLOCK  (TAT unchanged)
```

The CAS loop is **completely lock-free** for already-tracked IPs. A write-lock
is acquired only once when a new IP is first seen.

> **Why `tolerance = window` (not `window − emission`)?**
> The textbook formula with `tolerance = window − emission` caps a same-instant
> burst at `limit − 1`. KrakenWaf uses `tolerance = window` so that
> `--rate-limit-per-minute 240` admits exactly 240 requests in a burst, not 239.
> Sustained-rate behaviour is unchanged because it is governed by
> `emission_interval`, not by `tolerance`.

### Sharding

The IP → TAT map is split across **64 shards**, each guarded by an independent
`parking_lot::RwLock<AHashMap<u64, Arc<AtomicU64>>>`.

```
hot path  (existing IP):
    read-lock shard (~10 ns) → lookup → Arc::clone → unlock
    CAS on AtomicU64 (~5 ns, typically 1 iteration)
    Total ≈ 20–30 ns / request, regardless of map size

cold path (new IP):
    read-lock → miss → write-lock → double-check insert → unlock
    Executed exactly once per unique IP
```

At 10 k RPS with 16 workers, expected lock contention is below 2 %.
Each shard caps at `MAX_PER_SHARD = 4 096` entries; on overflow an expired or
least-recently-active entry is evicted. Capacity: **64 × 4 096 = 262 144**
unique IPs simultaneously tracked.

A background task sweeps drained TATs every 30 s and persists the snapshot
every 60 s.

### Stable hashing — FNV-1a

```rust
const OFFSET: u64 = 14_695_981_039_346_656_037;
const PRIME:  u64 = 1_099_511_628_211;
ip.bytes().fold(OFFSET, |h, b| (h ^ b as u64).wrapping_mul(PRIME))
```

FNV-1a is deterministic and seed-free, so `hash_ip("203.0.113.7")` returns the
same `u64` across restarts — which is what makes SQLite re-hydration correct.

### Persistence — `--wal-mode`

The TAT map is snapshotted to disk every 60 s and re-hydrated on startup so a
brief process restart does not grant blocked clients a fresh budget.

| `--wal-mode` | File | Format | Notes |
|-------------|------|--------|-------|
| `sqlite` *(default)* | `tmp_cache/rate_limit_state.db` | SQLite WAL | Inspectable with `sqlite3`; incremental upserts. |
| `bincode` | `tmp_cache/rate_limit_state.bin` | Atomic-rename flat binary | ~10–50× faster; opaque. |

#### SQLite schema

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;

CREATE TABLE rate_counters (
    ip_hash  INTEGER PRIMARY KEY,  -- FNV-1a hash of the IP
    tat_ns   INTEGER NOT NULL      -- TAT in nanoseconds since Unix epoch
);
```

#### Bincode layout

```
[8 bytes magic: "KWAFRL01"][bincode Vec<(u64 ip_hash, u64 tat_ns)>]
```

Writes go to `rate_limit_state.bin.tmp`, `fsync`, then atomic `rename(2)` — a
crash cannot corrupt the live file.

---

## Redis backend

When the `redis:` section is present in `conf/ratelimit.yaml`, KrakenWaf
replaces the local GCRA limiter with a Redis-backed counter. All WAF instances
pointing at the same Redis server share the counter, giving consistent
enforcement across horizontal replicas.

### How it works

A single **atomic Lua script** runs server-side on every admission check:

```lua
local n = redis.call('INCR', KEYS[1])       -- atomic increment
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])    -- set TTL on first write
end
if n > tonumber(ARGV[1]) then
  return 0                                   -- denied
end
return 1                                     -- allowed
```

`KEYS[1]` = `{key_prefix}:{client_ip}` (e.g. `krakenwaf:rl:1.2.3.4`)
`ARGV[1]` = `rate_limit_per_minute`
`ARGV[2]` = `window_secs`

Using `EVAL` (Lua) guarantees atomicity — the increment and TTL set are a
single Redis transaction. There is no MULTI/EXEC overhead and no TOCTOU window.

### Fail-open policy

If Redis is unavailable (network error, timeout, reconnect in progress),
the check returns `true` (allow) and emits a `tracing::warn!` log line. This
means a Redis outage degrades rate limiting to "off" rather than blocking all
traffic. Design your alerting to detect elevated `rate_limit_check_failed`
log events in production.

### Key lifecycle

Keys expire automatically via the `EXPIRE` set on first increment. There is no
background cleanup task in KrakenWaf; Redis handles TTL expiry natively.

---

## CIS Redis Benchmark hardening

KrakenWaf enforces the following CIS Redis Benchmark controls for every
Redis connection:

### 1. Encrypted transport (TLS mandatory)

The URL **must** use `rediss://` (note the double `s`). Any other scheme is
rejected at startup with a clear error message:

```
Error: Redis URL must use rediss:// (TLS) per CIS Benchmark — got: redis://...
```

The TLS connector is built from the system root store by default. For
environments with a private PKI, provide a custom CA certificate:

```yaml
redis:
  url: "rediss://redis.internal:6380/0"
  ca_cert_path: "/etc/ssl/private/my-ca.pem"
```

### 2. Credentials via file secrets (env-var fallback)

**Never store passwords in `conf/ratelimit.yaml`.** Credentials are loaded
file-first, then from environment variables — see
[docs/secrets.md](secrets.md) for the full resolution order.

| Secret | Purpose | File (preferred) | Env (fallback) |
|--------|---------|------------------|----------------|
| `REDIS_PASSWORD` | `AUTH` password (Redis `requirepass`) | `/run/secrets/krakenwaf/REDIS_PASSWORD` | `REDIS_PASSWORD` |
| `REDIS_USERNAME` | ACL username (Redis 6+ `ACL AUTH`) — optional | `/run/secrets/krakenwaf/REDIS_USERNAME` | `REDIS_USERNAME` |

KrakenWaf reads these at startup and injects them into the connection
configuration. The values never appear in log output or error messages.

In Docker / Kubernetes, prefer mounting them as files on the conventional path
(`/run/secrets/krakenwaf/<NAME>`), which KrakenWaf picks up with no further
config. The environment-variable form below still works:

```yaml
# Kubernetes example
env:
  - name: REDIS_PASSWORD
    valueFrom:
      secretKeyRef:
        name: redis-credentials
        key: password
```

```bash
# Docker example
docker run \
  -e REDIS_PASSWORD="$(cat /run/secrets/redis_password)" \
  krakenwaf ...
```

### 3. Least-privilege Redis ACL (recommended)

Create a dedicated Redis user with the minimum permissions needed:

```redis
ACL SETUSER krakenwaf on >[strong-password] ~krakenwaf:rl:* &* +EVAL +EVALSHA +INFO +PING
```

This grants only `EVAL` (for the Lua script), `EVALSHA`, `INFO`, and `PING` —
no administrative commands, no access to other keyspaces.

### 4. Namespace isolation

Use a unique `key_prefix` per WAF deployment when multiple services share a
Redis instance:

```yaml
redis:
  key_prefix: "prod-waf:rl"        # production
```

```yaml
redis:
  key_prefix: "staging-waf:rl"     # staging
```

---

## CLI flags reference

| Flag | Default | Description |
|------|---------|-------------|
| `--rate-limit-per-minute <N>` | (see below) | Per-IP request budget per 60 s window. Overrides the config file. Default when unset: 240. |
| `--ratelimit-by-file-conf <path>` | auto-discover | Path to `ratelimit.yaml`. Auto-discovered at `conf/ratelimit.yaml` in the working directory. |
| `--wal-mode <sqlite\|bincode>` | `sqlite` | Persistence backend for the local GCRA snapshot (ignored when using Redis). |

### Precedence matrix

```
Scenario                               Effective limit
─────────────────────────────────────────────────────
No flag, no file, no redis:            240 (built-in default)
File with rate_limit_per_minute: 120   120 (from file)
--rate-limit-per-minute 60 + file:120  60  (CLI wins)
redis: section in file                 Redis backend, rate from same priority chain
```

---

## Compile-time tunables (local backend only)

| Constant | Value | Meaning |
|----------|-------|---------|
| `NUM_SHARDS` | `64` | Must be power of two (`SHARD_MASK = NUM_SHARDS − 1`). |
| `MAX_PER_SHARD` | `4 096` | Eviction threshold; capacity = 64 × 4096 = 262 144 IPs. |
| `SWEEP_INTERVAL` | `30 s` | Background sweeper frequency. |
| `PERSIST_INTERVAL` | `60 s` | Snapshot flush frequency. |
| `MAX_DB_BYTES` | `32 MiB` | SQLite snapshot guard — wiped on startup if exceeded. |

These are at the top of `src/waf/rate_limit.rs`.

---

## Operational notes

- Rate-limit hits increment the `rate_limit_hits_total` Prometheus counter
  exported at `/metrics`.
- Real client IP extraction (when behind a proxy) is controlled by
  `--real-ip-header` and `--trusted-proxy-cidrs` — see
  [real-ip-header-and-trusted-proxy-cidrs.md](real-ip-header-and-trusted-proxy-cidrs.md).
- `tmp_cache/` holds only rate-limiter snapshot files. Deleting it while the
  WAF is stopped is safe and simply forfeits in-progress TATs.
- Switching `--wal-mode` between `sqlite` and `bincode` ignores the other
  format's snapshot file and starts fresh — no silent corruption.
- With the Redis backend, deleting a key in Redis (e.g. `DEL krakenwaf:rl:1.2.3.4`)
  immediately resets that IP's counter.

---

## Architecture diagram

```
                       ┌─────────────────────────────────────────┐
                       │             KrakenWaf process            │
                       │                                          │
request ──────────────►│  server::handle()                        │
                       │       │                                  │
                       │       ▼  (if max_coroutines_per_ip > 0)  │
                       │  ConnGuard gate ─── over cap? ──► 429    │
                       │       │                                  │
                       │       ▼                                  │
                       │  proxy.handle() → inspect_early()        │
                       │       │                                  │
                       │       ▼                                  │
                       │  RateLimiter::check(ip)                  │
                       │       │                                  │
                       │  ┌────┴────────────────────────┐         │
                       │  │ Local GCRA    │ Redis Lua   │         │
                       │  │ (64 shards)   │ (EVAL)      │         │
                       │  │ ~20 ns / req  │ ~1 RTT      │         │
                       │  └──────────────┴─────────────-┘         │
                       │       │ denied? ──────────────► 403      │
                       │       │                                  │
                       │       ▼  (further WAF inspection)        │
                       └─────────────────────────────────────────┘
```

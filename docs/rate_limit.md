# Rate Limiter

KrakenWaf ships with a per-IP, single-node rate limiter that survives process
restarts via an on-disk snapshot. It is designed to admit tens of thousands of
requests per second on a single host with negligible contention.

---

## Algorithm — GCRA (Generic Cell Rate Algorithm)

GCRA represents each client by **one `AtomicU64`**: the **TAT** (Theoretical
Arrival Time), in nanoseconds since the Unix epoch.

```
emission_interval  = window / limit
delay_tolerance    = window           (burst = exactly `limit` requests)

on each request at `now`:
  new_tat = max(old_tat, now) + emission_interval
  if (new_tat - now) ≤ delay_tolerance  →  ALLOW (CAS old_tat → new_tat)
  else                                  →  BLOCK (TAT unchanged)
```

The admission check is a **lock-free CAS loop**. No mutex is held on the hot
path for IPs that are already tracked. Compared to a token-bucket built around
`tokio::Mutex<HashMap>`, GCRA gives identical semantics with one atomic
read-modify-write per request.

### Why `delay_tolerance = window` and not `window − emission`

The textbook GCRA formula uses `tolerance = window − emission`, which
mathematically caps a same-instant burst at **`limit − 1`** requests. KrakenWaf
sets `tolerance = window` so an operator who configures `--rate-limit-per-minute
240` actually gets 240 admissions in a single instant, not 239. The
sustained-rate behaviour is unchanged because it depends on `emission_interval`,
not on `tolerance`.

---

## Sharding

The IP → TAT map is split across **64 shards**, each guarded by an independent
`parking_lot::RwLock<AHashMap<u64, Arc<AtomicU64>>>`.

```
hot path  (existing IP):
    read-lock shard (~10 ns) → lookup → Arc::clone → unlock
    CAS on AtomicU64 (~5 ns, 1 iteration in practice)
    Total ≈ 20–30 ns per request, regardless of map size

cold path (first time we see this IP):
    read-lock → miss → write-lock → double-check → insert → unlock
    Executed exactly once per unique IP
```

At ~10 k rps with 16 worker threads, expected lock contention is below 2 %.
Each shard caps at `MAX_PER_SHARD = 4 096` entries → 64 × 4 096 = **262 144**
unique IPs tracked simultaneously; once a shard fills, an expired or
least-recently-active entry is evicted.

A background sweeper task runs every 30 s and drops entries whose TAT has
fully drained, freeing memory on long-tail IPs.

---

## Stable hashing — FNV-1a

`hash_ip()` uses **FNV-1a (64-bit)**: deterministic, no random seed.

```rust
const OFFSET: u64 = 14_695_981_039_346_656_037;
const PRIME:  u64 = 1_099_511_628_211;
ip.bytes().fold(OFFSET, |h, b| (h ^ b as u64).wrapping_mul(PRIME))
```

This guarantees `hash_ip("203.0.113.7")` returns the same `u64` across process
restarts, which is what makes snapshot re-hydration correct: the persisted
`(ip_hash, tat_ns)` pairs land in the same shard they came from. (The internal
`AHashMap` still uses `ahash` for bucket placement — that's an
implementation detail that has no external effect.)

Resistance to hash flooding is irrelevant here: real IP addresses cannot be
chosen by an attacker to collide on a specific shard.

---

## Persistence — `--wal-mode`

The TAT map is snapshotted to disk every 60 s and re-hydrated on startup so a
brief restart does not give blocked clients a fresh budget. Two backends are
selectable at process start:

| `--wal-mode` | File | Format | Notes |
|--------------|------|--------|-------|
| `sqlite` *(default)* | `tmp_cache/rate_limit_state.db` | SQLite WAL | Inspectable with `sqlite3 cli`; supports incremental updates. |
| `bincode`            | `tmp_cache/rate_limit_state.bin` | Flat binary, atomic rename | Roughly 10–50× faster snapshot/load. Opaque. |

### SQLite (`--wal-mode sqlite`)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE rate_counters (
    ip_hash  INTEGER PRIMARY KEY,  -- FNV-1a(ip)
    tat_ns   INTEGER NOT NULL      -- nanoseconds since Unix epoch
);
```

WAL mode lets the snapshot writer and any external readers run concurrently
without blocking the WAF hot path. Each persist tick runs as a single
transaction with one upsert per tracked IP plus a `DELETE WHERE tat_ns < cutoff`
to evict drained entries.

**When to pick this:** you want to inspect the state with `sqlite3` for
debugging, or you anticipate sharing the file with an external tool.

### Bincode (`--wal-mode bincode`)

```
file layout:
  [8 bytes magic = "KWAFRL01"][bincode-serialised Vec<(u64, u64)>]
```

Each persist tick takes the in-memory snapshot, filters out drained entries,
serialises the whole vector, writes to `rate_limit_state.bin.tmp`, calls
`fsync`, and atomically renames over the live file. There are no transactions
or row-level updates — the entire state is rewritten on every tick.

For this workload (bulk snapshot, bulk re-hydrate, no queries) bincode is
significantly faster: in micro-benchmarks the snapshot round-trip is one to
two orders of magnitude cheaper than the SQLite path. Crash safety is
identical: an interrupted write leaves the previous file untouched until the
`rename(2)` succeeds.

**When to pick this:** you want the cheapest possible persistence overhead and
do not need external inspection.

### Switching modes

The two backends use **different filenames**, so switching `--wal-mode` simply
ignores the snapshot left by the other format and starts fresh. There is no
silent corruption from reading the wrong format. To migrate state you would
have to start once in the old mode, drain the rate state, and then switch.

---

## CLI arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--rate-limit-per-minute <N>` | `240` | Maximum admissions per client IP per 60 s window. The GCRA `emission_interval` is derived as `60 s / N`. |
| `--wal-mode <sqlite\|bincode>` | `sqlite` | Persistence backend for the snapshot. See table above. |

Snapshot path is fixed at `<cwd>/tmp_cache/rate_limit_state.{db,bin}` — the
directory is created automatically on startup.

---

## Tunables (compile-time)

| Constant | Value | Meaning |
|----------|-------|---------|
| `NUM_SHARDS`        | `64`        | Must be a power of two — `SHARD_MASK = NUM_SHARDS − 1`. |
| `MAX_PER_SHARD`     | `4 096`     | Eviction threshold. 64 × 4096 = 262 144 unique IPs. |
| `SWEEP_INTERVAL`    | `30 s`      | How often the background sweeper drops drained entries. |
| `PERSIST_INTERVAL`  | `60 s`      | How often the snapshot is flushed to disk. |
| `MAX_DB_BYTES`      | `32 MiB`    | If the SQLite snapshot grows beyond this, it is wiped on startup (defensive guard against corruption / runaway growth). |

These are defined at the top of `src/waf/rate_limit.rs`.

---

## Operational notes

- Rate limiting is **per-IP and per-process** — clustered enforcement still
  requires a shared backend such as Redis, which is out of scope for the
  single-node design.
- Real client IP extraction (when the WAF sits behind a proxy) is controlled
  by `--real-ip-header` and `--trusted-proxy-cidrs`; see
  [docs/real-ip-header-and-trusted-proxy-cidrs.md](real-ip-header-and-trusted-proxy-cidrs.md).
- The `tmp_cache/` directory only contains rate-limiter state; deleting it
  while the WAF is stopped is safe and simply forfeits in-flight TATs.
- Rate-limit hits are exported as Prometheus counters via `/metrics`.

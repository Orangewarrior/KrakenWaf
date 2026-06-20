
//! Rate-limiter backends for `KrakenWaf`.
//!
//! ## Architecture
//!
//! [`RateLimiter`] is a public enum with two variants:
//!
//! * **`Local`** — GCRA-sharded in-process limiter (default, zero dependencies).
//! * **`Redis`** — Distributed GCRA backed by Redis server time; suitable for
//!   multi-node deployments where state must be shared across WAF instances.
//!
//! ## Local / GCRA
//!
//! Each client is represented by **one `AtomicU64`** — the TAT (Theoretical
//! Arrival Time) in nanoseconds from the Unix epoch.
//!
//! ```text
//! emission_interval  = ceil(window_ns / limit)   (ns between conforming requests)
//! delay_tolerance    = emission_interval * limit (exact burst of `limit` allowed)
//!
//! On arrival at `now`:
//!   new_tat = max(old_tat, now) + emission_interval
//!   if (new_tat − now) ≤ delay_tolerance  →  ALLOW  (CAS old_tat → new_tat)
//!   else                                  →  BLOCK  (old_tat unchanged)
//! ```
//!
//! The CAS loop is **fully lock-free** for already-tracked IPs. A write-lock on
//! the shard is acquired only once when inserting a new IP.
//!
//! 64 shards → expected contention at 10 k RPS with 16 workers ≈ 2 %.
//! Hot path: read-lock + `Arc::clone` (~10 ns) + CAS (~5 ns) ≈ 20–30 ns/req.
//!
//! ## Redis / distributed
//!
//! An atomic Lua script reads Redis `TIME`, checks and updates the per-IP TAT,
//! and sets a precise TTL — no MULTI/EXEC round-trips and no replica clock
//! skew. On unavailability the limiter applies the
//! configured fail mode (`redis.fail_open`, default **fail-open** = allow the
//! request) and emits a `tracing::warn!` plus a Prometheus counter
//! (`krakenwaf_redis_rate_limit_failopen_total` /
//! `krakenwaf_redis_rate_limit_failclosed_total`).
//!
//! Security (CIS Redis Benchmark):
//! * URL must use `rediss://` (TLS mandatory).
//! * Credentials are loaded **file-first** (`REDIS_PASSWORD_FILE` or
//!   `/run/secrets/krakenwaf/REDIS_PASSWORD`) with a fallback to the
//!   `REDIS_PASSWORD` / `REDIS_USERNAME` environment variables — see
//!   [`crate::secrets`].
//! * Custom CA certificate supported for private PKI / mTLS deployments.
//!
//! ## Persistence (local only)
//!
//! Two back-ends selectable at runtime via [`PersistenceMode`]:
//!
//! * `Sqlite` — WAL journal, inspectable via `sqlite3`.
//! * `Postcard` — atomic-rename flat file, 10-50× faster. Encoded with the
//!   [`postcard`] crate.

use ahash::{AHashMap, RandomState};
use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection};
use std::{
    array,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use fred::clients::Pool as FredPool;
use tokio::time::interval;
use tracing::warn;

use crate::metrics::WafMetrics;

// ── Public API ────────────────────────────────────────────────────────────────

/// Selects the persistence back-end for the local GCRA rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceMode {
    Sqlite,
    /// Flat binary snapshot encoded with `postcard` using atomic rename.
    Postcard,
}

/// Rate-limiter backend. Both variants implement the same GCRA contract.
pub enum RateLimiter {
    Local(Arc<LocalRateLimiter>),
    Redis(Arc<RedisRateLimiter>),
}

/// Typed admission result shared by the local and Redis GCRA backends.
///
/// Keeping the retry delay in the domain result lets HTTP adapters emit an
/// accurate `Retry-After` header without coupling the rate limiter to Hyper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allow,
    Deny {
        retry_after: Duration,
        reason: RateLimitDenyReason,
    },
}

impl RateLimitDecision {
    #[must_use]
    pub const fn is_allowed(self) -> bool { matches!(self, Self::Allow) }

    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        match self {
            Self::Allow => None,
            Self::Deny { retry_after, .. } => Some(retry_after),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDenyReason {
    LimitExceeded,
    BackendUnavailable,
    CapacityExhausted,
}

impl RateLimiter {
    /// Construct a local GCRA rate limiter with optional state persistence.
    ///
    /// # Errors
    /// Returns an error if the persistence backend cannot be opened or initialised.
    pub fn new(
        limit: u32,
        window: Duration,
        snapshot_path: &Path,
        mode: PersistenceMode,
    ) -> Result<Self> {
        anyhow::ensure!(limit > 0, "rate limit must be greater than zero");
        anyhow::ensure!(!window.is_zero(), "rate-limit window must be greater than zero");
        Ok(Self::Local(Arc::new(LocalRateLimiter::new(
            limit,
            window,
            snapshot_path,
            mode,
        )?)))
    }

    /// Construct a Redis-backed distributed rate limiter.
    ///
    /// `url` **must** use `rediss://` (TLS, CIS Benchmark requirement).
    /// Credentials are loaded file-first (`REDIS_PASSWORD_FILE` /
    /// `/run/secrets/krakenwaf/REDIS_PASSWORD`) with an env-var fallback.
    /// `fail_open` selects the behaviour when Redis is unreachable; `metrics`,
    /// when supplied, records each fail-open/closed event.
    ///
    /// # Errors
    /// Returns an error if the URL is not `rediss://`, or if the connection pool
    /// cannot be initialised (e.g. Redis unreachable at startup).
    #[allow(clippy::too_many_arguments)]
    pub async fn new_redis(
        url: &str,
        limit: u32,
        window_secs: u64,
        key_prefix: &str,
        pool_size: usize,
        ca_cert_path: Option<&str>,
        fail_open: bool,
        metrics: Option<Arc<WafMetrics>>,
    ) -> Result<Self> {
        Ok(Self::Redis(Arc::new(
            RedisRateLimiter::new(
                url, limit, window_secs, key_prefix, pool_size, ca_cert_path, fail_open, metrics,
            )
            .await?,
        )))
    }

    /// Like [`new_redis`] but skips the TLS requirement — intended exclusively
    /// for integration tests against a local `redis-server` without TLS.
    ///
    /// # Errors
    /// Returns an error if the Redis connection pool cannot be initialised.
    #[allow(dead_code)]
    pub async fn new_redis_for_test(
        url: &str,
        limit: u32,
        window_secs: u64,
        key_prefix: &str,
    ) -> Result<Self> {
        Ok(Self::Redis(Arc::new(
            RedisRateLimiter::new_inner(
                url, limit, window_secs, key_prefix, 2, None, false, true, None,
            )
            .await?,
        )))
    }

    /// Spawn background sweep + persistence tasks (local mode only; Redis
    /// manages its own TTLs server-side).
    pub fn spawn_persistence_task(self: Arc<Self>) {
        if let Self::Local(inner) = self.as_ref() {
            inner.clone().spawn_persistence_task();
        }
    }

    /// Returns `true` if the request from `ip` is within the rate limit.
    #[allow(dead_code)]
    pub async fn check(&self, ip: &str) -> bool {
        self.decide(ip).await.is_allowed()
    }

    /// Return the complete admission decision, including an accurate retry
    /// delay for rejected requests.
    pub async fn decide(&self, ip: &str) -> RateLimitDecision {
        match self {
            Self::Local(inner) => inner.decide(ip),
            Self::Redis(inner) => inner.decide(ip).await,
        }
    }

    /// Flush in-memory state to the persistence back-end (local mode only).
    ///
    /// # Errors
    /// Returns an error if the persistence backend fails to write the snapshot.
    #[allow(dead_code)]
    pub fn persist(&self) -> Result<()> {
        match self {
            Self::Local(inner) => inner.persist(),
            Self::Redis(_) => Ok(()),
        }
    }

    /// Persist local state without blocking a Tokio worker. Redis owns its
    /// durability and returns immediately.
    ///
    /// # Errors
    ///
    /// Returns an error when the blocking task cannot be joined or the
    /// configured snapshot backend cannot persist the state.
    pub async fn persist_async(&self) -> Result<()> {
        let Self::Local(inner) = self else { return Ok(()) };
        let inner = inner.clone();
        tokio::task::spawn_blocking(move || inner.persist())
            .await
            .context("rate-limiter persistence task panicked")?
    }

    /// Expose a clone of the underlying Redis pool when this limiter is
    /// Redis-backed. Returns `None` for local-mode limiters. Used by the
    /// `BanManager` so a single `fred::Pool` serves both subsystems.
    #[must_use]
    pub fn redis_pool(&self) -> Option<fred::clients::Pool> {
        match self {
            Self::Redis(inner) => Some(inner.pool.clone()),
            Self::Local(_) => None,
        }
    }
}

// ── Tunables ─────────────────────────────────────────────────────────────────

const NUM_SHARDS: usize = 64;
const SHARD_MASK: usize = NUM_SHARDS - 1;
const MAX_PER_SHARD: usize = 4_096;
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const PERSIST_INTERVAL: Duration = Duration::from_mins(1);
const MAX_DB_BYTES: u64 = 32 * 1024 * 1024;
const MAX_POSTCARD_BYTES: u64 = 32 * 1024 * 1024;

// ── GCRA core (lock-free) ─────────────────────────────────────────────────────

#[inline]
fn gcra_decide(
    tat: &AtomicU64,
    now_ns: u64,
    emit_ns: u64,
    tolerance_ns: u64,
) -> RateLimitDecision {
    loop {
        let old_tat = tat.load(Ordering::Acquire);
        let new_tat = old_tat.max(now_ns).saturating_add(emit_ns);
        if new_tat.saturating_sub(now_ns) > tolerance_ns {
            let eligible_at = new_tat.saturating_sub(tolerance_ns);
            return RateLimitDecision::Deny {
                retry_after: Duration::from_nanos(eligible_at.saturating_sub(now_ns).max(1)),
                reason: RateLimitDenyReason::LimitExceeded,
            };
        }
        match tat.compare_exchange_weak(old_tat, new_tat, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return RateLimitDecision::Allow,
            Err(_) => core::hint::spin_loop(),
        }
    }
}

// ── Shard ─────────────────────────────────────────────────────────────────────

struct Shard {
    rw: RwLock<AHashMap<u64, Arc<AtomicU64>>>,
    next_opportunistic_sweep_ns: AtomicU64,
}

impl Shard {
    fn new() -> Self {
        Self {
            rw: RwLock::new(AHashMap::with_capacity(64)),
            next_opportunistic_sweep_ns: AtomicU64::new(0),
        }
    }

    fn decide(
        &self,
        key: u64,
        now_ns: u64,
        emit_ns: u64,
        tolerance_ns: u64,
    ) -> RateLimitDecision {
        {
            let map = self.rw.read();
            if let Some(cell) = map.get(&key) {
                let cell = cell.clone();
                drop(map);
                return gcra_decide(&cell, now_ns, emit_ns, tolerance_ns);
            }
        }
        let fresh = Arc::new(AtomicU64::new(0));
        {
            let mut map = self.rw.write();
            if let Some(existing) = map.get(&key) {
                let cell = existing.clone();
                drop(map);
                return gcra_decide(&cell, now_ns, emit_ns, tolerance_ns);
            }
            if map.len() >= MAX_PER_SHARD {
                // Admission control: scan drained TATs at most once per sweep
                // interval. Repeating an O(n) retain under this write lock for
                // every new flooding address would itself be a CPU/lock DoS.
                // If all slots are live, reject the newcomer with a typed
                // capacity decision and preserve the incumbent working set.
                let sweep_due = self
                    .next_opportunistic_sweep_ns
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |deadline| {
                        (now_ns >= deadline).then(|| {
                            now_ns.saturating_add(
                                u64::try_from(SWEEP_INTERVAL.as_nanos()).unwrap_or(u64::MAX),
                            )
                        })
                    })
                    .is_ok();
                let evicted_expired = sweep_due && try_evict_expired(&mut map, now_ns);
                if !evicted_expired && map.len() >= MAX_PER_SHARD {
                    return RateLimitDecision::Deny {
                        retry_after: SWEEP_INTERVAL,
                        reason: RateLimitDenyReason::CapacityExhausted,
                    };
                }
            }
            map.insert(key, fresh.clone());
        }
        gcra_decide(&fresh, now_ns, emit_ns, tolerance_ns)
    }

    fn sweep(&self, now_ns: u64) {
        let mut map = self.rw.write();
        map.retain(|_, cell| cell.load(Ordering::Relaxed) > now_ns);
    }

    fn snapshot(&self) -> Vec<(u64, u64)> {
        let map = self.rw.read();
        map.iter()
            .map(|(&k, cell)| (k, cell.load(Ordering::Relaxed)))
            .collect()
    }
}

/// Sweep expired counters out of `map` in a single pass. Returns whether
/// at least one slot was freed. Used by admission control (2.24.0) to
/// give incumbent traffic priority over flooding IPs.
fn try_evict_expired(
    map: &mut AHashMap<u64, Arc<AtomicU64>>,
    now_ns: u64,
) -> bool {
    let before = map.len();
    map.retain(|_, cell| cell.load(Ordering::Relaxed) > now_ns);
    map.len() < before
}

// ── Persistence backend ───────────────────────────────────────────────────────

enum Backend {
    Sqlite(Connection),
    Postcard(PathBuf),
}

/// Magic prefix for the postcard snapshot. Unknown formats are ignored rather
/// than decoded with the wrong schema.
const POSTCARD_MAGIC: &[u8; 8] = b"KWAFRL02";

impl Backend {
    fn open(mode: PersistenceMode, path: &Path) -> Result<Self> {
        match mode {
            PersistenceMode::Sqlite => Ok(Backend::Sqlite(
                open_db(path).context("failed to open rate-limiter SQLite database")?,
            )),
            PersistenceMode::Postcard => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Ok(Backend::Postcard(path.to_path_buf()))
            }
        }
    }

    fn load(&self, cutoff: u64) -> Result<Vec<(u64, u64)>> {
        match self {
            Backend::Sqlite(conn) => {
                let mut stmt = conn
                    .prepare("SELECT ip_hash, tat_ns FROM rate_counters WHERE tat_ns >= ?1")?;
                #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
                let rows: rusqlite::Result<Vec<(u64, u64)>> = stmt
                    .query_map(params![cutoff as i64], |row| {
                        Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
                    })?
                    .collect();
                Ok(rows.context("failed to decode rate-limiter SQLite snapshot")?)
            }
            Backend::Postcard(path) => {
                if !path.exists() {
                    return Ok(Vec::new());
                }
                let size = std::fs::metadata(path)?.len();
                anyhow::ensure!(
                    size <= MAX_POSTCARD_BYTES,
                    "postcard rate-limiter snapshot '{}' is {size} bytes; limit is {MAX_POSTCARD_BYTES}",
                    path.display()
                );
                let mut buf = Vec::new();
                File::open(path)?.read_to_end(&mut buf)?;
                if buf.len() < POSTCARD_MAGIC.len() || &buf[..POSTCARD_MAGIC.len()] != POSTCARD_MAGIC
                {
                    warn!(target: "krakenwaf", path = %path.display(),
                        "postcard rate-limiter snapshot magic mismatch; ignoring");
                    return Ok(Vec::new());
                }
                let items: Vec<(u64, u64)> =
                    match postcard::from_bytes(&buf[POSTCARD_MAGIC.len()..]) {
                        Ok(items) => items,
                        Err(e) => {
                            warn!(target: "krakenwaf", path = %path.display(), error = %e,
                                "postcard rate-limiter snapshot decode failed; ignoring");
                            Vec::new()
                        }
                    };
                Ok(items.into_iter().filter(|(_, tat)| *tat >= cutoff).collect())
            }
        }
    }

    fn save(&self, items: &[(u64, u64)], cutoff: u64) -> Result<()> {
        match self {
            Backend::Sqlite(conn) => with_transaction(conn, |c| {
                #[allow(clippy::cast_possible_wrap)]
                for (key, tat_ns) in items {
                    c.execute(
                        "INSERT INTO rate_counters (ip_hash, tat_ns) VALUES (?1, ?2)
                         ON CONFLICT(ip_hash) DO UPDATE SET tat_ns = excluded.tat_ns",
                        params![*key as i64, *tat_ns as i64],
                    )?;
                }
                #[allow(clippy::cast_possible_wrap)]
                c.execute(
                    "DELETE FROM rate_counters WHERE tat_ns < ?1",
                    params![cutoff as i64],
                )?;
                Ok(())
            }),
            Backend::Postcard(path) => {
                let live: Vec<(u64, u64)> =
                    items.iter().copied().filter(|(_, tat)| *tat >= cutoff).collect();
                let payload = postcard::to_allocvec(&live)?;
                let tmp = path.with_extension("tmp");
                {
                    let mut f = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&tmp)?;
                    f.write_all(POSTCARD_MAGIC)?;
                    f.write_all(&payload)?;
                    f.sync_all()?;
                }
                std::fs::rename(&tmp, path)?;
                #[cfg(unix)]
                if let Some(parent) = path.parent() {
                    File::open(parent)?.sync_all()?;
                }
                Ok(())
            }
        }
    }
}

// ── LocalRateLimiter (GCRA) ───────────────────────────────────────────────────

pub struct LocalRateLimiter {
    shards: Arc<[Shard; NUM_SHARDS]>,
    shard_hasher: RandomState,
    emit_ns: u64,
    tolerance_ns: u64,
    db: Arc<Mutex<Backend>>,
    tasks_started: AtomicBool,
}

impl LocalRateLimiter {
    fn new(
        limit: u32,
        window: Duration,
        snapshot_path: &Path,
        mode: PersistenceMode,
    ) -> Result<Self> {
        let window_ns = u64::try_from(window.as_nanos()).unwrap_or(u64::MAX);
        let emit_ns = window_ns.div_ceil(u64::from(limit));
        anyhow::ensure!(emit_ns > 0, "rate-limit emission interval underflowed");
        let tolerance_ns = emit_ns.saturating_mul(u64::from(limit));
        let shards: Arc<[Shard; NUM_SHARDS]> = Arc::new(array::from_fn(|_| Shard::new()));
        let shard_hasher = RandomState::new();
        let backend = Backend::open(mode, snapshot_path)?;
        let now = now_ns();
        let maximum_valid_tat = now.saturating_add(tolerance_ns);
        for (key, persisted_tat) in backend.load(now)? {
            // A valid GCRA TAT can never be further ahead than the burst
            // tolerance. Clamp snapshots after a wall-clock rollback, config
            // change, or manual/corrupt database edit.
            let tat = persisted_tat.min(maximum_valid_tat);
            let idx = shard_index(&shard_hasher, key);
            let mut map = shards[idx].rw.write();
            if map.len() < MAX_PER_SHARD {
                map.insert(key, Arc::new(AtomicU64::new(tat)));
            } else {
                warn!(target: "krakenwaf", shard = idx, "rate-limiter snapshot entry dropped because shard capacity was reached");
            }
        }
        Ok(Self {
            shards,
            shard_hasher,
            emit_ns,
            tolerance_ns,
            db: Arc::new(Mutex::new(backend)),
            tasks_started: AtomicBool::new(false),
        })
    }

    fn spawn_persistence_task(self: Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        if self.tasks_started.swap(true, Ordering::AcqRel) {
            return;
        }

        let sweeper = self.clone();
        handle.spawn(async move {
            let mut ticker = interval(SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                let now = now_ns();
                for shard in sweeper.shards.iter() {
                    shard.sweep(now);
                }
            }
        });

        let persister = self;
        handle.spawn(async move {
            let mut ticker = interval(PERSIST_INTERVAL);
            loop {
                ticker.tick().await;
                let current = persister.clone();
                match tokio::task::spawn_blocking(move || current.persist()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!(target: "krakenwaf", error = %e, "rate-limiter persist failed"),
                    Err(e) => warn!(target: "krakenwaf", error = %e, "rate-limiter persistence task panicked"),
                }
            }
        });
    }

    fn decide(&self, ip: &str) -> RateLimitDecision {
        let key = hash_ip(ip);
        let idx = shard_index(&self.shard_hasher, key);
        self.shards[idx].decide(key, now_ns(), self.emit_ns, self.tolerance_ns)
    }

    fn persist(&self) -> Result<()> {
        let mut items = Vec::with_capacity(NUM_SHARDS * 64);
        for shard in self.shards.iter() {
            items.extend(shard.snapshot());
        }
        let cutoff = now_ns();
        let backend = self.db.lock();
        backend.save(&items, cutoff)
    }
}

#[inline]
fn shard_index(hasher: &RandomState, key: u64) -> usize {
    usize::try_from(hasher.hash_one(key) & u64::try_from(SHARD_MASK).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

// ── RedisRateLimiter ──────────────────────────────────────────────────────────

/// Distributed GCRA admission using Redis as the authoritative clock and TAT
/// store. The script returns `{allowed, retry_after_us}`.
///
/// Redis Lua numbers are exact for the current epoch in microseconds (well
/// below 2^53). `TIME` avoids clock skew between WAF replicas.
const REDIS_GCRA_LUA: &str = r"
local emission_us = tonumber(ARGV[1])
local tolerance_us = tonumber(ARGV[2])
local redis_time = redis.call('TIME')
local now_us = tonumber(redis_time[1]) * 1000000 + tonumber(redis_time[2])
local tat = tonumber(redis.call('GET', KEYS[1])) or now_us
if tat < now_us then
  tat = now_us
end

local new_tat = tat + emission_us
if new_tat - now_us > tolerance_us then
  local eligible_at = new_tat - tolerance_us
  return {0, math.max(1, math.ceil(eligible_at - now_us))}
end

local ttl_ms = math.max(1, math.ceil((new_tat - now_us) / 1000))
redis.call('SET', KEYS[1], string.format('%.0f', new_tat), 'PX', ttl_ms)
return {1, 0}
";

pub struct RedisRateLimiter {
    pool: FredPool,
    key_prefix: String,
    emit_us: u64,
    tolerance_us: u64,
    /// Per-call timeout for `EVAL` operations. Bounds the worst-case latency the
    /// WAF can spend waiting on a hung Redis (network blip, GC stall) before
    /// applying the fail mode. Keeps tail latency under control on heavy load.
    op_timeout: Duration,
    /// Behaviour on Redis unavailability: `true` allows the request
    /// (fail-open), `false` denies it with 429 (fail-closed).
    fail_open: bool,
    /// Optional metrics sink so each fail-open/closed event is observable on
    /// the `/metrics` endpoint.
    metrics: Option<Arc<WafMetrics>>,
}

impl RedisRateLimiter {
    /// Production constructor: enforces `rediss://` (TLS) and injects
    /// credentials loaded file-first (see [`crate::secrets`]) with an env-var
    /// fallback.
    #[allow(clippy::too_many_arguments)]
    async fn new(
        url: &str,
        limit: u32,
        window_secs: u64,
        key_prefix: &str,
        pool_size: usize,
        ca_cert_path: Option<&str>,
        fail_open: bool,
        metrics: Option<Arc<WafMetrics>>,
    ) -> Result<Self> {
        anyhow::ensure!(
            url.starts_with("rediss://"),
            "Redis URL must use rediss:// (TLS) per CIS Benchmark — got: {url}"
        );
        let parsed = url::Url::parse(url).context("invalid Redis URL")?;
        anyhow::ensure!(
            parsed.username().is_empty() && parsed.password().is_none(),
            "Redis URL must not contain credentials; use REDIS_USERNAME/REDIS_PASSWORD secrets"
        );
        Self::new_inner(
            url, limit, window_secs, key_prefix, pool_size, ca_cert_path, true, fail_open, metrics,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_inner(
        url: &str,
        limit: u32,
        window_secs: u64,
        key_prefix: &str,
        pool_size: usize,
        ca_cert_path: Option<&str>,
        inject_credentials: bool,
        fail_open: bool,
        metrics: Option<Arc<WafMetrics>>,
    ) -> Result<Self> {
        use fred::prelude::*;
        use fred::types::config::TlsConnector;

        anyhow::ensure!(limit > 0, "Redis rate limit must be greater than zero");
        anyhow::ensure!(window_secs > 0, "Redis rate-limit window must be greater than zero");
        anyhow::ensure!(pool_size > 0, "Redis pool_size must be greater than zero");
        anyhow::ensure!(!key_prefix.trim().is_empty(), "Redis key_prefix must not be empty");
        let window_us = window_secs
            .checked_mul(1_000_000)
            .context("Redis rate-limit window is too large")?;
        let emit_us = window_us.div_ceil(u64::from(limit));
        let tolerance_us = emit_us
            .checked_mul(u64::from(limit))
            .context("Redis GCRA tolerance overflow")?;

        let mut config = Config::from_url(url).context("invalid Redis URL")?;

        if inject_credentials {
            // File-first secrets (see `crate::secrets`): `REDIS_PASSWORD_FILE` /
            // `/run/secrets/krakenwaf/REDIS_PASSWORD`, then the env var. Keeps
            // the AUTH password out of `/proc/<pid>/environ` and crash dumps.
            if let Some(pwd) = crate::secrets::load_secret("REDIS_PASSWORD") {
                config.password = Some(pwd);
            }
            if let Some(user) = crate::secrets::load_secret("REDIS_USERNAME") {
                config.username = Some(user);
            }
        }

        // Apply TLS connector — default system trust store, or custom CA.
        // rediss:// enables TLS in fred; we also set it explicitly here.
        if inject_credentials || url.starts_with("rediss://") {
            let connector = if let Some(ca_path) = ca_cert_path {
                build_custom_ca_connector(ca_path)?
            } else {
                TlsConnector::default_rustls()
                    .context("failed to build default TLS connector for Redis")?
            };
            // TlsConfig::from(connector) uses the From<C: Into<TlsConnector>> impl.
            config.tls = Some(connector.into());
        }

        let pool = Builder::from_config(config)
            .build_pool(pool_size)
            .context("failed to build Redis connection pool")?;

        // Bound how long startup can spend waiting for Redis; without this the
        // process can hang silently when Redis is misconfigured / unreachable.
        tokio::time::timeout(Duration::from_secs(10), pool.init())
            .await
            .context("Redis pool init timed out after 10s")?
            .context("failed to connect to Redis")?;

        Ok(Self {
            pool,
            key_prefix: key_prefix.to_string(),
            emit_us,
            tolerance_us,
            // 150 ms is comfortably above p99 of a healthy intra-DC Redis call
            // (typically &lt; 5 ms) yet tight enough that a degraded Redis cannot
            // dominate WAF tail latency under load. Tunable later if needed.
            op_timeout: Duration::from_millis(150),
            fail_open,
            metrics,
        })
    }


    async fn decide(&self, ip: &str) -> RateLimitDecision {
        use fred::prelude::*;

        let ip_key = canonical_rate_limit_ip_key(ip);
        let key = format!("{}:{ip_key}", self.key_prefix);
        // Wrap the EVAL in a per-call timeout: a hung Redis (network blip, GC
        // pause, evictions) must not stall the WAF request path. On error or
        // timeout we apply the configured fail mode (`fail_open`) and record it
        // so a Redis outage silently disabling rate limiting is observable.
        let eval_fut = self.pool.eval::<Vec<i64>, _, _, _>(
            REDIS_GCRA_LUA,
            vec![key],
            vec![
                i64::try_from(self.emit_us).unwrap_or(i64::MAX),
                i64::try_from(self.tolerance_us).unwrap_or(i64::MAX),
            ],
        );

        match tokio::time::timeout(self.op_timeout, eval_fut).await {
            Ok(Ok(result)) if result.first() == Some(&1) => RateLimitDecision::Allow,
            Ok(Ok(result)) if result.first() == Some(&0) => {
                let retry_us = result.get(1).copied().unwrap_or(1).max(1);
                RateLimitDecision::Deny {
                    retry_after: Duration::from_micros(u64::try_from(retry_us).unwrap_or(1)),
                    reason: RateLimitDenyReason::LimitExceeded,
                }
            }
            Ok(Ok(result)) => self.on_unavailable(
                ip,
                format_args!("GCRA script returned an invalid response: {result:?}"),
            ),
            Ok(Err(err)) => self.on_unavailable(ip, format_args!("check failed: {err}")),
            Err(_elapsed) => self.on_unavailable(
                ip,
                format_args!(
                    "EVAL exceeded per-call timeout of {}ms",
                    u64::try_from(self.op_timeout.as_millis()).unwrap_or(u64::MAX)
                ),
            ),
        }
    }

    /// Apply the configured fail mode when Redis is unavailable: record the
    /// event in metrics, warn, and return the allow/deny decision.
    fn on_unavailable(
        &self,
        ip: &str,
        reason: std::fmt::Arguments<'_>,
    ) -> RateLimitDecision {
        if let Some(metrics) = &self.metrics {
            metrics.inc_redis_rate_limit_fail(self.fail_open);
        }
        warn!(
            target: "krakenwaf",
            ip,
            fail_open = self.fail_open,
            reason = %reason,
            "Redis rate-limiter unavailable; applying fail mode (fail_open={})",
            self.fail_open
        );
        if self.fail_open {
            RateLimitDecision::Allow
        } else {
            RateLimitDecision::Deny {
                retry_after: Duration::from_secs(1),
                reason: RateLimitDenyReason::BackendUnavailable,
            }
        }
    }
}

// ── TLS helpers ───────────────────────────────────────────────────────────────

fn build_custom_ca_connector(ca_path: &str) -> Result<fred::types::config::TlsConnector> {
    use rustls::{ClientConfig, RootCertStore};
    use rustls_pki_types::{pem::PemObject, CertificateDer};

    let pem = std::fs::read(ca_path)
        .with_context(|| format!("failed to read Redis CA cert '{ca_path}'"))?;

    let mut roots = RootCertStore::empty();
    let mut certificate_count = 0usize;
    for cert in CertificateDer::pem_slice_iter(&pem) {
        roots.add(cert.context("invalid PEM certificate in Redis CA file")?)?;
        certificate_count += 1;
    }
    anyhow::ensure!(certificate_count > 0, "Redis CA file '{ca_path}' contains no certificates");

    // From<RustlsClientConfig> for TlsConnector wraps it in
    // TlsConnector::Rustls(RustlsConnector::from(Arc::new(config))).
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(fred::types::config::TlsConnector::from(client_config))
}

// ── SQLite helpers ────────────────────────────────────────────────────────────

fn open_db(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let sqlite_files = [
        path.to_path_buf(),
        sqlite_sidecar(path, "-wal"),
        sqlite_sidecar(path, "-shm"),
    ];
    let size = sqlite_files
        .iter()
        .filter_map(|file| std::fs::metadata(file).ok())
        .fold(0u64, |total, metadata| total.saturating_add(metadata.len()));
    if size > MAX_DB_BYTES {
            warn!(
                target: "krakenwaf",
                size, limit = MAX_DB_BYTES, path = %path.display(),
                "rate-limiter DB exceeds limit; starting clean"
            );
            for file in &sqlite_files {
                let _ = std::fs::remove_file(file);
            }
        }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous  = NORMAL;
         PRAGMA busy_timeout = 5000;",
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS rate_counters (
             ip_hash  INTEGER PRIMARY KEY,
             tat_ns   INTEGER NOT NULL
         );",
    )?;
    Ok(conn)
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn with_transaction(conn: &Connection, f: impl FnOnce(&Connection) -> Result<()>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    match f(conn) {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// FNV-1a (64-bit) over the canonical IP representation so different
/// textual encodings of the same address share a counter.
///
/// Before 2.24.0 the limiter folded the raw string bytes: `"192.168.1.1"`,
/// `"192.168.001.001"`, and `"::ffff:1.2.3.4"` all received independent
/// counters even though they resolve to the same host. An attacker simply
/// alternated forms across requests to bypass the per-IP limit.
///
/// Parsing failures fall back to the legacy string-hash to preserve
/// behaviour for non-IP keys (test fixtures pass synthetic identifiers).
#[inline]
fn hash_ip(ip: &str) -> u64 {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut h: u64 = OFFSET;
    if let Some(canonical) = canonical_rate_limit_ip(ip) {
        match canonical {
            IpAddr::V4(v4) => {
                for b in v4.octets() {
                    h = (h ^ u64::from(b)).wrapping_mul(PRIME);
                }
            }
            IpAddr::V6(v6) => {
                for b in v6.octets() {
                    h = (h ^ u64::from(b)).wrapping_mul(PRIME);
                }
            }
        }
        return h;
    }
    ip.bytes().fold(OFFSET, |h, b| (h ^ u64::from(b)).wrapping_mul(PRIME))
}

fn canonical_rate_limit_ip(input: &str) -> Option<IpAddr> {
    match input.trim().parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)),
        Ok(ip @ IpAddr::V4(_)) => Some(ip),
        Err(_) => None,
    }
}

fn canonical_rate_limit_ip_key(input: &str) -> String {
    canonical_rate_limit_ip(input).map_or_else(|| input.trim().to_string(), |ip| ip.to_string())
}

/// Monotonic clock anchor — captured once at startup. The rate-limiter hot
/// path computes "ns since this anchor" using [`Instant`], which is
/// guaranteed monotonic and immune to NTP skew. We retain a wall-clock
/// offset so persisted snapshots can be written/read in epoch form.
static MONO_ANCHOR: std::sync::LazyLock<(Instant, u64)> = std::sync::LazyLock::new(|| {
    let epoch_ns = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since_epoch) => u64::try_from(since_epoch.as_nanos()).unwrap_or(0),
        // Wall clock is before the Unix epoch; anchor at 0.
        Err(_) => 0,
    };
    (Instant::now(), epoch_ns)
});

/// Returns "wall-clock-equivalent" nanoseconds derived from a monotonic
/// clock so a request issued during NTP negative-step does not unwind the
/// limiter's TAT into the past (which would re-enable a previously-blocked
/// flood). The output is **monotonic** within a single process: the same
/// invariant the GCRA loop assumes. Compared to the pre-2.24.0
/// `SystemTime::now()` implementation, this is ~3× cheaper and never
/// allocates.
#[inline]
fn now_ns() -> u64 {
    let (anchor, epoch_ns) = *MONO_ANCHOR;
    let elapsed = u64::try_from(anchor.elapsed().as_nanos()).unwrap_or(u64::MAX);
    epoch_ns.saturating_add(elapsed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_limiter(limit: u32, window_secs: u64) -> RateLimiter {
        let window_ns = window_secs * 1_000_000_000;
        let emit_ns = window_ns.div_ceil(u64::from(limit));
        let tolerance_ns = emit_ns * u64::from(limit);
        let conn = Connection::open_in_memory().expect("sqlite in-memory");
        conn.execute_batch(
            "CREATE TABLE rate_counters (ip_hash INTEGER PRIMARY KEY, tat_ns INTEGER NOT NULL);",
        )
        .expect("create test table");
        RateLimiter::Local(Arc::new(LocalRateLimiter {
            shards: Arc::new(array::from_fn(|_| Shard::new())),
            shard_hasher: RandomState::new(),
            emit_ns,
            tolerance_ns,
            db: Arc::new(Mutex::new(Backend::Sqlite(conn))),
            tasks_started: AtomicBool::new(false),
        }))
    }

    #[test]
    fn gcra_allows_exact_burst_then_returns_retry_delay() {
        let limit = 5u32;
        let window_ns = 1_000_000_000u64;
        let emit_ns = window_ns / u64::from(limit);
        let tolerance_ns = window_ns;
        let tat = AtomicU64::new(0);
        let now = now_ns();
        for _ in 0..limit {
            assert_eq!(
                gcra_decide(&tat, now, emit_ns, tolerance_ns),
                RateLimitDecision::Allow
            );
        }
        assert_eq!(
            gcra_decide(&tat, now, emit_ns, tolerance_ns),
            RateLimitDecision::Deny {
                retry_after: Duration::from_nanos(emit_ns),
                reason: RateLimitDenyReason::LimitExceeded,
            }
        );
    }

    #[test]
    fn gcra_recovers_after_window() {
        let limit = 3u32;
        let window_ns = 1_000_000_000u64;
        let emit_ns = window_ns / u64::from(limit);
        let tolerance_ns = window_ns;
        let tat = AtomicU64::new(0);
        let now = now_ns();
        for _ in 0..limit {
            assert!(gcra_decide(&tat, now, emit_ns, tolerance_ns).is_allowed());
        }
        assert!(!gcra_decide(&tat, now, emit_ns, tolerance_ns).is_allowed());
        let later = now + window_ns + 1;
        assert!(gcra_decide(&tat, later, emit_ns, tolerance_ns).is_allowed());
    }

    #[test]
    fn drained_tat_is_evicted_without_an_extra_window() {
        let now = 10_000;
        let mut map = AHashMap::new();
        map.insert(1, Arc::new(AtomicU64::new(now)));
        map.insert(2, Arc::new(AtomicU64::new(now + 1)));
        assert!(try_evict_expired(&mut map, now));
        assert!(!map.contains_key(&1));
        assert!(map.contains_key(&2));
    }

    #[test]
    fn local_constructor_rejects_zero_limit_and_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rate.bin");
        assert!(RateLimiter::new(0, Duration::from_secs(1), &path, PersistenceMode::Postcard)
            .is_err());
        assert!(RateLimiter::new(1, Duration::ZERO, &path, PersistenceMode::Postcard).is_err());
    }

    #[test]
    fn hash_ip_is_stable() {
        assert_eq!(hash_ip("192.168.1.1"), hash_ip("192.168.1.1"));
        assert_ne!(hash_ip("192.168.1.1"), hash_ip("192.168.1.2"));
    }

    #[test]
    fn hash_ip_canonicalises_textual_forms() {
        // IPv4-mapped IPv6 must hash identically to its IPv4 form.
        assert_eq!(hash_ip("::ffff:1.2.3.4"), hash_ip("1.2.3.4"));
        // Different textual notations of the same v6 address must collide.
        assert_eq!(hash_ip("2001:db8::1"), hash_ip("2001:0db8:0000:0000:0000:0000:0000:0001"));
        // Distinct addresses must not collide.
        assert_ne!(hash_ip("10.0.0.1"), hash_ip("10.0.0.2"));
    }

    #[test]
    fn redis_key_ip_canonicalises_textual_forms() {
        assert_eq!(canonical_rate_limit_ip_key("::ffff:1.2.3.4"), "1.2.3.4");
        assert_eq!(
            canonical_rate_limit_ip_key("2001:0db8:0000:0000:0000:0000:0000:0001"),
            "2001:db8::1"
        );
        assert_eq!(
            canonical_rate_limit_ip_key(" synthetic-client "),
            "synthetic-client"
        );
    }

    #[test]
    fn redis_script_uses_server_time_and_tat_state() {
        assert!(REDIS_GCRA_LUA.contains("redis.call('TIME')"));
        assert!(REDIS_GCRA_LUA.contains("redis.call('GET', KEYS[1])"));
        assert!(REDIS_GCRA_LUA.contains("string.format('%.0f', new_tat)"));
        assert!(!REDIS_GCRA_LUA.contains("INCR"));
    }

    #[test]
    fn monotonic_now_ns_never_goes_backwards() {
        let a = now_ns();
        let b = now_ns();
        assert!(b >= a, "now_ns must be monotonic");
    }

    #[test]
    fn shard_routing_is_consistent_within_process() {
        let ip = "10.0.0.99";
        let key = hash_ip(ip);
        let hasher = RandomState::new();
        assert_eq!(shard_index(&hasher, key), shard_index(&hasher, hash_ip(ip)));
    }

    #[tokio::test]
    async fn check_denies_after_limit() {
        let rl = make_limiter(3, 60);
        let ip = "192.0.2.1";
        assert!(rl.check(ip).await);
        assert!(rl.check(ip).await);
        assert!(rl.check(ip).await);
        assert!(!rl.check(ip).await, "4th request must be denied");
    }

    #[tokio::test]
    async fn different_ips_have_independent_budgets() {
        let rl = make_limiter(1, 60);
        assert!(rl.check("10.0.0.1").await);
        assert!(!rl.check("10.0.0.1").await);
        assert!(rl.check("10.0.0.2").await, "different IP should not be affected");
    }

    #[tokio::test]
    async fn persistence_snapshot_succeeds() {
        let rl = make_limiter(10, 60);
        for _ in 0..5 {
            rl.check("10.1.1.1").await;
        }
        rl.persist().expect("persist must succeed");
    }

    #[tokio::test]
    async fn async_persistence_flushes_without_blocking_runtime_worker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rate.bin");
        let limiter = RateLimiter::new(
            2,
            Duration::from_mins(1),
            &path,
            PersistenceMode::Postcard,
        )
        .expect("limiter");
        assert!(limiter.check("192.0.2.55").await);
        limiter.persist_async().await.expect("async persist");
        assert!(path.exists());
        assert!(std::fs::metadata(path).expect("metadata").len() > POSTCARD_MAGIC.len() as u64);
    }

    #[tokio::test]
    async fn postcard_round_trip_rehydrates_tats() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rl.bin");
        {
            let rl = RateLimiter::new(5, Duration::from_mins(1), &path, PersistenceMode::Postcard)
                .expect("create limiter (postcard)");
            for _ in 0..4 {
                assert!(rl.check("203.0.113.7").await);
            }
            rl.persist().expect("persist postcard");
        }
        let rl = RateLimiter::new(5, Duration::from_mins(1), &path, PersistenceMode::Postcard)
            .expect("recreate limiter (postcard)");
        assert!(rl.check("203.0.113.7").await, "5th request must pass");
        assert!(!rl.check("203.0.113.7").await, "6th request must be blocked");
    }

    // ── Redis tests (skipped when redis-server is not on PATH) ────────────────
    //
    // Each test spawns its own short-lived `redis-server` on an **OS-allocated**
    // ephemeral port so dozens of cargo-test processes can run in parallel
    // without colliding on fixed ports (16379/16380/16381 was racy under load —
    // 50 parallel test processes ⇒ only one wins the bind, the rest fail with
    // ECONNREFUSED). The readiness probe polls with PING until the server
    // replies so we never depend on a hard-coded `sleep` to mask startup jitter.

    struct RedisGuard {
        child: std::process::Child,
        pub port: u16,
    }
    impl Drop for RedisGuard {
        fn drop(&mut self) {
            self.child.kill().ok();
            self.child.wait().ok();
        }
    }

    /// Reserves a free TCP port from the OS and returns it. The listener is
    /// dropped before returning so the port becomes available to the child
    /// `redis-server` immediately. A small race window exists (another process
    /// could grab the port) but in practice that's vanishingly rare and the
    /// caller retries on failure.
    fn pick_free_port() -> std::io::Result<u16> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    /// Block until the child Redis answers PING, or give up after `deadline`.
    /// Avoids the cargo-cult `sleep(400ms)` that breaks under heavy load.
    async fn wait_until_redis_ready(port: u16, deadline: std::time::Instant) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while std::time::Instant::now() < deadline {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                if stream.write_all(b"PING\r\n").await.is_ok() {
                    let mut buf = [0u8; 16];
                    if let Ok(Ok(n)) = tokio::time::timeout(
                        Duration::from_millis(250),
                        stream.read(&mut buf),
                    )
                    .await
                    {
                        if n > 0 && buf.starts_with(b"+PONG") {
                            return true;
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// Spawn an isolated `redis-server` on an OS-allocated port. Retries port
    /// selection up to 5 times to defeat the rare port-bind race.
    async fn try_spawn_test_redis() -> Option<RedisGuard> {
        let bin = which::which("redis-server").ok()?;
        for _ in 0..5 {
            let Ok(port) = pick_free_port() else { continue };
            let Ok(child) = std::process::Command::new(&bin)
                .args([
                    "--port", &port.to_string(),
                    "--save", "",
                    "--loglevel", "warning",
                    // Bind only to loopback so we never expose the test server.
                    "--bind", "127.0.0.1",
                    // Tight maxmemory keeps each ephemeral instance light.
                    "--maxmemory", "32mb",
                    "--maxmemory-policy", "allkeys-lru",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            else {
                continue;
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            if wait_until_redis_ready(port, deadline).await {
                return Some(RedisGuard { child, port });
            }
            // Server did not become ready in time — kill and retry on a new port.
            let mut child = child;
            child.kill().ok();
            child.wait().ok();
        }
        None
    }

    #[tokio::test]
    async fn redis_allows_within_limit() {
        let Some(guard) = try_spawn_test_redis().await else { return };
        let url = format!("redis://127.0.0.1:{}", guard.port);
        let rl = RateLimiter::new_redis_for_test(&url, 3, 60, "kwtest1")
            .await
            .expect("connect to test Redis");
        assert!(rl.check("1.2.3.4").await);
        assert!(rl.check("1.2.3.4").await);
        assert!(rl.check("1.2.3.4").await);
        assert!(!rl.check("1.2.3.4").await, "4th must be denied");
    }

    #[tokio::test]
    async fn redis_constructor_rejects_zero_values() {
        let result = RateLimiter::new_redis_for_test("redis://127.0.0.1:1", 0, 60, "kwtest")
            .await;
        assert!(result.is_err());
        let result = RateLimiter::new_redis_for_test("redis://127.0.0.1:1", 1, 0, "kwtest")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn redis_ips_are_independent() {
        let Some(guard) = try_spawn_test_redis().await else { return };
        let url = format!("redis://127.0.0.1:{}", guard.port);
        let rl = RateLimiter::new_redis_for_test(&url, 2, 60, "kwtest2")
            .await
            .expect("connect to test Redis");
        assert!(rl.check("10.0.0.1").await);
        assert!(rl.check("10.0.0.1").await);
        assert!(!rl.check("10.0.0.1").await, "3rd for 10.0.0.1 must be denied");
        assert!(rl.check("10.0.0.2").await, "different IP must not be affected");
    }

    #[tokio::test]
    async fn redis_window_resets() {
        let Some(guard) = try_spawn_test_redis().await else { return };
        let url = format!("redis://127.0.0.1:{}", guard.port);
        let rl = RateLimiter::new_redis_for_test(&url, 2, 2, "kwtest3")
            .await
            .expect("connect to test Redis");
        assert!(rl.check("5.5.5.5").await);
        assert!(rl.check("5.5.5.5").await);
        assert!(!rl.check("5.5.5.5").await, "3rd must be denied");
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(rl.check("5.5.5.5").await, "window reset — first request must pass again");
    }

    #[tokio::test]
    async fn redis_gcra_refills_one_request_per_emission_interval() {
        let Some(guard) = try_spawn_test_redis().await else { return };
        let url = format!("redis://127.0.0.1:{}", guard.port);
        let rl = RateLimiter::new_redis_for_test(&url, 2, 2, "kwtest-gcra-refill")
            .await
            .expect("connect to test Redis");
        assert!(rl.check("6.6.6.6").await);
        assert!(rl.check("6.6.6.6").await);
        let denied = rl.decide("6.6.6.6").await;
        assert!(!denied.is_allowed());
        assert!(denied.retry_after().is_some_and(|delay| delay <= Duration::from_secs(1)));
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(
            rl.check("6.6.6.6").await,
            "GCRA must refill before the original fixed window expires"
        );
    }
}

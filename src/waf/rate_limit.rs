
//! Rate-limiter backends for `KrakenWaf`.
//!
//! ## Architecture
//!
//! [`RateLimiter`] is a public enum with two variants:
//!
//! * **`Local`** — GCRA-sharded in-process limiter (default, zero dependencies).
//! * **`Redis`** — Distributed counter backed by Redis; suitable for multi-node
//!   deployments where state must be shared across WAF instances.
//!
//! ## Local / GCRA
//!
//! Each client is represented by **one `AtomicU64`** — the TAT (Theoretical
//! Arrival Time) in nanoseconds from the Unix epoch.
//!
//! ```text
//! emission_interval  = window_ns / limit         (ns between conforming requests)
//! delay_tolerance    = window_ns                 (exact burst of `limit` allowed)
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
//! An atomic Lua script (`INCR` + conditional `EXPIRE`) runs server-side —
//! no MULTI/EXEC round-trips. On unavailability the limiter **fails open**
//! (request is allowed) and emits a `tracing::warn!`.
//!
//! Security (CIS Redis Benchmark):
//! * URL must use `rediss://` (TLS mandatory).
//! * Credentials are read from `REDIS_PASSWORD` / `REDIS_USERNAME` env vars.
//! * Custom CA certificate supported for private PKI / mTLS deployments.
//!
//! ## Persistence (local only)
//!
//! Two back-ends selectable at runtime via [`PersistenceMode`]:
//!
//! * `Sqlite` — WAL journal, inspectable via `sqlite3`.
//! * `Bincode` — atomic-rename flat file, 10-50× faster.

use ahash::AHashMap;
use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection};
use std::{
    array,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use fred::clients::Pool as FredPool;
use tokio::time::interval;
use tracing::warn;

// ── Public API ────────────────────────────────────────────────────────────────

/// Selects the persistence back-end for the local GCRA rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceMode {
    Sqlite,
    Bincode,
}

/// Rate-limiter backend. Use [`RateLimiter::new`] for the local GCRA limiter or
/// [`RateLimiter::new_redis`] for the Redis-backed distributed limiter.
pub enum RateLimiter {
    Local(Arc<LocalRateLimiter>),
    Redis(Arc<RedisRateLimiter>),
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
    /// Credentials are read from `REDIS_PASSWORD` and `REDIS_USERNAME` env vars.
    ///
    /// # Errors
    /// Returns an error if the URL is not `rediss://`, or if the connection pool
    /// cannot be initialised (e.g. Redis unreachable at startup).
    pub async fn new_redis(
        url: &str,
        limit: u32,
        window_secs: u64,
        key_prefix: &str,
        pool_size: usize,
        ca_cert_path: Option<&str>,
    ) -> Result<Self> {
        Ok(Self::Redis(Arc::new(
            RedisRateLimiter::new(url, limit, window_secs, key_prefix, pool_size, ca_cert_path)
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
            RedisRateLimiter::new_inner(url, limit, window_secs, key_prefix, 2, None, false)
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
    pub async fn check(&self, ip: &str) -> bool {
        match self {
            Self::Local(inner) => inner.check(ip).await,
            Self::Redis(inner) => inner.check(ip).await,
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
const SHARD_MASK: u64 = NUM_SHARDS as u64 - 1;
const MAX_PER_SHARD: usize = 4_096;
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const PERSIST_INTERVAL: Duration = Duration::from_mins(1);
const MAX_DB_BYTES: u64 = 32 * 1024 * 1024;

// ── GCRA core (lock-free) ─────────────────────────────────────────────────────

#[inline]
fn gcra_check(tat: &AtomicU64, now_ns: u64, emit_ns: u64, tolerance_ns: u64) -> bool {
    loop {
        let old_tat = tat.load(Ordering::Acquire);
        let new_tat = old_tat.max(now_ns).saturating_add(emit_ns);
        if new_tat.saturating_sub(now_ns) > tolerance_ns {
            return false;
        }
        match tat.compare_exchange_weak(old_tat, new_tat, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(_) => core::hint::spin_loop(),
        }
    }
}

// ── Shard ─────────────────────────────────────────────────────────────────────

struct Shard {
    rw: RwLock<AHashMap<u64, Arc<AtomicU64>>>,
}

impl Shard {
    fn new() -> Self {
        Self { rw: RwLock::new(AHashMap::with_capacity(64)) }
    }

    fn check(&self, key: u64, now_ns: u64, emit_ns: u64, tolerance_ns: u64) -> bool {
        {
            let map = self.rw.read();
            if let Some(cell) = map.get(&key) {
                let cell = cell.clone();
                drop(map);
                return gcra_check(&cell, now_ns, emit_ns, tolerance_ns);
            }
        }
        let fresh = Arc::new(AtomicU64::new(0));
        {
            let mut map = self.rw.write();
            if let Some(existing) = map.get(&key) {
                let cell = existing.clone();
                drop(map);
                return gcra_check(&cell, now_ns, emit_ns, tolerance_ns);
            }
            if map.len() >= MAX_PER_SHARD {
                // Admission control (2.24.0): under DDoS the shard fills with
                // attacker IPs in a few seconds. Evicting an incumbent — even
                // an "expired" one — favours the attacker because the new
                // arrival is the one stalling legitimate traffic. First try a
                // cheap, opportunistic expired-entry sweep; if every slot is
                // still live, drop the *new* request rather than disturb the
                // working set. A dropped-from-shard request is treated as a
                // denial: we return `false` so the proxy emits 429 just like
                // a normal rate-limit miss.
                let evicted_expired = try_evict_expired(&mut map, now_ns, tolerance_ns);
                if !evicted_expired && map.len() >= MAX_PER_SHARD {
                    return false;
                }
            }
            map.insert(key, fresh.clone());
        }
        gcra_check(&fresh, now_ns, emit_ns, tolerance_ns)
    }

    fn sweep(&self, now_ns: u64, tolerance_ns: u64) {
        let mut map = self.rw.write();
        map.retain(|_, cell| cell.load(Ordering::Relaxed).saturating_add(tolerance_ns) >= now_ns);
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
    tolerance_ns: u64,
) -> bool {
    let before = map.len();
    map.retain(|_, cell| cell.load(Ordering::Relaxed).saturating_add(tolerance_ns) >= now_ns);
    map.len() < before
}

// ── Persistence backend ───────────────────────────────────────────────────────

enum Backend {
    Sqlite(Connection),
    Bincode(PathBuf),
}

const BINCODE_MAGIC: &[u8; 8] = b"KWAFRL01";

impl Backend {
    fn open(mode: PersistenceMode, path: &Path) -> Result<Self> {
        match mode {
            PersistenceMode::Sqlite => Ok(Backend::Sqlite(
                open_db(path).context("failed to open rate-limiter SQLite database")?,
            )),
            PersistenceMode::Bincode => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Ok(Backend::Bincode(path.to_path_buf()))
            }
        }
    }

    fn load(&self, cutoff: u64) -> Result<Vec<(u64, u64)>> {
        match self {
            Backend::Sqlite(conn) => {
                let mut stmt = conn
                    .prepare("SELECT ip_hash, tat_ns FROM rate_counters WHERE tat_ns >= ?1")?;
                #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
                let rows = stmt
                    .query_map(params![cutoff as i64], |row| {
                        Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
                    })?
                    .flatten()
                    .collect();
                Ok(rows)
            }
            Backend::Bincode(path) => {
                if !path.exists() {
                    return Ok(Vec::new());
                }
                let mut buf = Vec::new();
                File::open(path)?.read_to_end(&mut buf)?;
                if buf.len() < BINCODE_MAGIC.len() || &buf[..BINCODE_MAGIC.len()] != BINCODE_MAGIC {
                    warn!(target: "krakenwaf", path = %path.display(),
                        "bincode rate-limiter snapshot magic mismatch; ignoring");
                    return Ok(Vec::new());
                }
                let items: Vec<(u64, u64)> =
                    bincode::deserialize(&buf[BINCODE_MAGIC.len()..]).unwrap_or_default();
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
            Backend::Bincode(path) => {
                let live: Vec<(u64, u64)> =
                    items.iter().copied().filter(|(_, tat)| *tat >= cutoff).collect();
                let payload = bincode::serialize(&live)?;
                let tmp = path.with_extension("tmp");
                {
                    let mut f = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&tmp)?;
                    f.write_all(BINCODE_MAGIC)?;
                    f.write_all(&payload)?;
                    f.sync_all()?;
                }
                std::fs::rename(&tmp, path)?;
                Ok(())
            }
        }
    }
}

// ── LocalRateLimiter (GCRA) ───────────────────────────────────────────────────

pub struct LocalRateLimiter {
    shards: Arc<[Shard; NUM_SHARDS]>,
    emit_ns: u64,
    tolerance_ns: u64,
    db: Arc<Mutex<Backend>>,
}

impl LocalRateLimiter {
    fn new(
        limit: u32,
        window: Duration,
        snapshot_path: &Path,
        mode: PersistenceMode,
    ) -> Result<Self> {
        let window_ns = u64::try_from(window.as_nanos()).unwrap_or(u64::MAX);
        let emit_ns = window_ns / u64::from(limit.max(1));
        let tolerance_ns = window_ns;
        let shards: Arc<[Shard; NUM_SHARDS]> = Arc::new(array::from_fn(|_| Shard::new()));
        let backend = Backend::open(mode, snapshot_path)?;
        let now = now_ns();
        let cutoff = now.saturating_sub(tolerance_ns);
        for (key, tat) in backend.load(cutoff)? {
            let idx = (key & SHARD_MASK) as usize;
            shards[idx].rw.write().insert(key, Arc::new(AtomicU64::new(tat)));
        }
        Ok(Self { shards, emit_ns, tolerance_ns, db: Arc::new(Mutex::new(backend)) })
    }

    fn spawn_persistence_task(self: Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };

        let sweeper = self.clone();
        handle.spawn(async move {
            let mut ticker = interval(SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                let now = now_ns();
                let tol = sweeper.tolerance_ns;
                for shard in sweeper.shards.iter() {
                    shard.sweep(now, tol);
                }
            }
        });

        let persister = self;
        handle.spawn(async move {
            let mut ticker = interval(PERSIST_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) = persister.persist() {
                    warn!(target: "krakenwaf", error = %e, "rate-limiter persist failed");
                }
            }
        });
    }

    #[allow(clippy::unused_async)]
    async fn check(&self, ip: &str) -> bool {
        let key = hash_ip(ip);
        let idx = (key & SHARD_MASK) as usize;
        self.shards[idx].check(key, now_ns(), self.emit_ns, self.tolerance_ns)
    }

    fn persist(&self) -> Result<()> {
        let mut items = Vec::with_capacity(NUM_SHARDS * 64);
        for shard in self.shards.iter() {
            items.extend(shard.snapshot());
        }
        let cutoff = now_ns().saturating_sub(self.tolerance_ns);
        let backend = self.db.lock();
        backend.save(&items, cutoff)
    }
}

// ── RedisRateLimiter ──────────────────────────────────────────────────────────

/// Atomic Lua script: INCR key, set TTL on first write, return 1=allow / 0=deny.
const INCR_WITH_TTL_LUA: &str = r"
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
if n > tonumber(ARGV[1]) then
  return 0
end
return 1
";

pub struct RedisRateLimiter {
    pool: FredPool,
    key_prefix: String,
    max_requests: u32,
    window_secs: u64,
    /// Per-call timeout for `EVAL` operations. Bounds the worst-case latency the
    /// WAF can spend waiting on a hung Redis (network blip, GC stall) before
    /// failing open. Keeps tail latency under control on heavy load.
    op_timeout: Duration,
}

impl RedisRateLimiter {
    /// Production constructor: enforces `rediss://` (TLS) and injects
    /// credentials from `REDIS_PASSWORD` / `REDIS_USERNAME` env vars.
    async fn new(
        url: &str,
        limit: u32,
        window_secs: u64,
        key_prefix: &str,
        pool_size: usize,
        ca_cert_path: Option<&str>,
    ) -> Result<Self> {
        anyhow::ensure!(
            url.starts_with("rediss://"),
            "Redis URL must use rediss:// (TLS) per CIS Benchmark — got: {url}"
        );
        Self::new_inner(url, limit, window_secs, key_prefix, pool_size, ca_cert_path, true).await
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
    ) -> Result<Self> {
        use fred::prelude::*;
        use fred::types::config::TlsConnector;

        let mut config = Config::from_url(url).context("invalid Redis URL")?;

        if inject_credentials {
            if let Ok(pwd) = std::env::var("REDIS_PASSWORD") {
                if !pwd.is_empty() {
                    config.password = Some(pwd);
                }
            }
            if let Ok(user) = std::env::var("REDIS_USERNAME") {
                if !user.is_empty() {
                    config.username = Some(user);
                }
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

        let pool_size = pool_size.max(1);
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
            max_requests: limit,
            window_secs,
            // 150 ms is comfortably above p99 of a healthy intra-DC Redis call
            // (typically &lt; 5 ms) yet tight enough that a degraded Redis cannot
            // dominate WAF tail latency under load. Tunable later if needed.
            op_timeout: Duration::from_millis(150),
        })
    }


    async fn check(&self, ip: &str) -> bool {
        use fred::prelude::*;

        let key = format!("{}:{}", self.key_prefix, ip);
        // Wrap the EVAL in a per-call timeout: a hung Redis (network blip, GC
        // pause, evictions) must not stall the WAF request path. On timeout we
        // fail open — denying availability is worse than missing one count.
        let eval_fut = self.pool.eval::<i64, _, _, _>(
            INCR_WITH_TTL_LUA,
            vec![key],
            vec![i64::from(self.max_requests), self.window_secs.cast_signed()],
        );

        match tokio::time::timeout(self.op_timeout, eval_fut).await {
            Ok(Ok(1)) => true,
            Ok(Ok(_)) => false,
            Ok(Err(err)) => {
                warn!(
                    target: "krakenwaf",
                    error = %err,
                    ip,
                    "Redis rate-limit check failed; failing open"
                );
                true
            }
            Err(_elapsed) => {
                warn!(
                    target: "krakenwaf",
                    timeout_ms = u64::try_from(self.op_timeout.as_millis()).unwrap_or(u64::MAX),
                    ip,
                    "Redis rate-limit EVAL exceeded per-call timeout; failing open"
                );
                true
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
    for cert in CertificateDer::pem_slice_iter(&pem) {
        roots.add(cert.context("invalid PEM certificate in Redis CA file")?)?;
    }

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
    if path.exists() {
        let size = std::fs::metadata(path).map_or(0, |m| m.len());
        if size > MAX_DB_BYTES {
            warn!(
                target: "krakenwaf",
                size, limit = MAX_DB_BYTES, path = %path.display(),
                "rate-limiter DB exceeds limit; starting clean"
            );
            let _ = std::fs::remove_file(path);
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
    if let Ok(parsed) = ip.parse::<IpAddr>() {
        let canonical = match parsed {
            // IPv4-mapped IPv6 (`::ffff:a.b.c.d`) collapses to its IPv4 form.
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            other => other,
        };
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

/// Monotonic clock anchor — captured once at startup. The rate-limiter hot
/// path computes "ns since this anchor" using [`Instant`], which is
/// guaranteed monotonic and immune to NTP skew. We retain a wall-clock
/// offset so persisted snapshots can be written/read in epoch form.
static MONO_ANCHOR: Lazy<(Instant, u64)> = Lazy::new(|| {
    let epoch_ns = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    )
    .unwrap_or(0);
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
        let emit_ns = window_ns / u64::from(limit.max(1));
        let tolerance_ns = window_ns;
        let conn = Connection::open_in_memory().expect("sqlite in-memory");
        conn.execute_batch(
            "CREATE TABLE rate_counters (ip_hash INTEGER PRIMARY KEY, tat_ns INTEGER NOT NULL);",
        )
        .expect("create test table");
        RateLimiter::Local(Arc::new(LocalRateLimiter {
            shards: Arc::new(array::from_fn(|_| Shard::new())),
            emit_ns,
            tolerance_ns,
            db: Arc::new(Mutex::new(Backend::Sqlite(conn))),
        }))
    }

    #[test]
    fn gcra_permite_ate_o_limite() {
        let limit = 5u32;
        let window_ns = 1_000_000_000u64;
        let emit_ns = window_ns / u64::from(limit);
        let tolerance_ns = window_ns;
        let tat = AtomicU64::new(0);
        let now = now_ns();
        for _ in 0..limit {
            assert!(gcra_check(&tat, now, emit_ns, tolerance_ns), "should allow");
        }
        assert!(!gcra_check(&tat, now, emit_ns, tolerance_ns), "should block");
    }

    #[test]
    fn gcra_recupera_apos_janela() {
        let limit = 3u32;
        let window_ns = 1_000_000_000u64;
        let emit_ns = window_ns / u64::from(limit);
        let tolerance_ns = window_ns;
        let tat = AtomicU64::new(0);
        let now = now_ns();
        for _ in 0..limit {
            assert!(gcra_check(&tat, now, emit_ns, tolerance_ns));
        }
        assert!(!gcra_check(&tat, now, emit_ns, tolerance_ns));
        let later = now + window_ns + 1;
        assert!(gcra_check(&tat, later, emit_ns, tolerance_ns));
    }

    #[test]
    fn hash_ip_e_estavel() {
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
    fn monotonic_now_ns_never_goes_backwards() {
        let a = now_ns();
        let b = now_ns();
        assert!(b >= a, "now_ns must be monotonic");
    }

    #[test]
    fn shard_routing_consistente() {
        let ip = "10.0.0.99";
        let key = hash_ip(ip);
        assert_eq!((key & SHARD_MASK) as usize, (hash_ip(ip) & SHARD_MASK) as usize);
    }

    #[tokio::test]
    async fn check_bloqueia_apos_limite() {
        let rl = make_limiter(3, 60);
        let ip = "192.0.2.1";
        assert!(rl.check(ip).await);
        assert!(rl.check(ip).await);
        assert!(rl.check(ip).await);
        assert!(!rl.check(ip).await, "4th request must be denied");
    }

    #[tokio::test]
    async fn ips_diferentes_sao_independentes() {
        let rl = make_limiter(1, 60);
        assert!(rl.check("10.0.0.1").await);
        assert!(!rl.check("10.0.0.1").await);
        assert!(rl.check("10.0.0.2").await, "different IP should not be affected");
    }

    #[tokio::test]
    async fn persist_e_snapshot_funcionam() {
        let rl = make_limiter(10, 60);
        for _ in 0..5 {
            rl.check("10.1.1.1").await;
        }
        rl.persist().expect("persist must succeed");
    }

    #[tokio::test]
    async fn bincode_round_trip_rehidrata_tats() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rl.bin");
        {
            let rl = RateLimiter::new(5, Duration::from_mins(1), &path, PersistenceMode::Bincode)
                .expect("create limiter (bincode)");
            for _ in 0..4 {
                assert!(rl.check("203.0.113.7").await);
            }
            rl.persist().expect("persist bincode");
        }
        let rl = RateLimiter::new(5, Duration::from_mins(1), &path, PersistenceMode::Bincode)
            .expect("recreate limiter (bincode)");
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
}

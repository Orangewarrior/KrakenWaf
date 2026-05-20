
use anyhow::Result;
use fred::{
    interfaces::{ClientLike, LuaInterface},
    prelude::{Builder, Config, Pool},
    types::config::{TlsConfig, TlsConnector},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{fs, sync::Mutex, time::interval};
use tracing::{info, warn};

use crate::ratelimit_config::RateLimitConfig;

const DEFAULT_MAX_TRACKED_IPS: usize = 100_000;
const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);
const PERSIST_INTERVAL: Duration = Duration::from_secs(30);

/// Atomic INCR + conditional EXPIRE in a single Lua round-trip.
/// This prevents the INCR/EXPIRE race (key remains without TTL if the
/// process crashes between the two commands).
const INCR_WITH_TTL_LUA: &str = r#"
local n = redis.call("INCR", KEYS[1])
if n == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return n
"#;

// ─── public enum ──────────────────────────────────────────────────────────────

/// Rate limiter that dispatches to either a local in-memory backend or a
/// distributed Redis backend, depending on configuration.
pub enum RateLimiter {
    Local(LocalRateLimiter),
    Redis(RedisRateLimiter),
}

impl RateLimiter {
    /// Build from configuration, falling back to local when Redis is disabled
    /// or when the Redis connection cannot be established.
    pub async fn from_config(
        config: &RateLimitConfig,
        cli_limit: u32,
        snapshot_path: PathBuf,
    ) -> Result<Self> {
        if config.redis.enabled {
            match RedisRateLimiter::new(&config.redis, cli_limit).await {
                Ok(r) => {
                    info!(target: "krakenwaf", "distributed rate limiter: Redis backend active");
                    return Ok(Self::Redis(r));
                }
                Err(err) => {
                    warn!(
                        target: "krakenwaf",
                        error = %err,
                        "Redis rate limiter init failed — falling back to local in-memory limiter"
                    );
                }
            }
        }
        Ok(Self::Local(LocalRateLimiter::new(
            cli_limit,
            Duration::from_secs(60),
            snapshot_path,
            config.local.max_tracked_ips,
        )?))
    }

    pub async fn check(&self, ip: &str) -> bool {
        match self {
            Self::Local(l) => l.check(ip).await,
            Self::Redis(r) => r.check(ip).await,
        }
    }

    pub async fn persist(&self) -> Result<()> {
        match self {
            Self::Local(l) => l.persist().await,
            // Redis handles its own persistence via TTLs; no snapshot needed.
            Self::Redis(_) => Ok(()),
        }
    }

    pub fn spawn_persistence_task(self: Arc<Self>) {
        if matches!(self.as_ref(), Self::Local(_)) {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let sweeper = self.clone();
                handle.spawn(async move {
                    let mut ticker = interval(SWEEP_INTERVAL);
                    loop {
                        ticker.tick().await;
                        if let Self::Local(l) = sweeper.as_ref() {
                            l.sweep_expired().await;
                        }
                    }
                });

                let persister = self;
                handle.spawn(async move {
                    let mut ticker = interval(PERSIST_INTERVAL);
                    loop {
                        ticker.tick().await;
                        if let Self::Local(l) = persister.as_ref() {
                            if let Err(err) = l.persist().await {
                                warn!(target: "krakenwaf", error=%err, "rate limiter snapshot write failed");
                            }
                        }
                    }
                });
            }
        }
        // Redis backend: sweeping and persistence are handled by Redis TTLs.
    }
}

// ─── local backend ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Counter {
    count: u32,
    started_at_epoch_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCounter {
    ip: String,
    count: u32,
    started_at_epoch_secs: u64,
}

pub struct LocalRateLimiter {
    limit: u32,
    window: Duration,
    counters: Mutex<HashMap<String, Counter>>,
    snapshot_path: PathBuf,
    max_tracked_ips: usize,
}

impl LocalRateLimiter {
    pub fn new(
        limit: u32,
        window: Duration,
        snapshot_path: PathBuf,
        max_tracked_ips: usize,
    ) -> Result<Self> {
        let counters = tokio::task::block_in_place(|| load_snapshot(&snapshot_path));
        Ok(Self { limit, window, counters: Mutex::new(counters), snapshot_path, max_tracked_ips })
    }

    pub async fn check(&self, ip: &str) -> bool {
        let mut map = self.counters.lock().await;
        let now = epoch_secs();
        let window_secs = self.window.as_secs();

        if map.len() >= self.max_tracked_ips && !map.contains_key(ip) {
            evict_one(&mut map, now, window_secs);
        }

        let entry = map.entry(ip.to_string()).or_insert(Counter {
            count: 0,
            started_at_epoch_secs: now,
        });

        if now.saturating_sub(entry.started_at_epoch_secs) >= window_secs {
            entry.count = 0;
            entry.started_at_epoch_secs = now;
        }

        entry.count = entry.count.saturating_add(1);
        entry.count <= self.limit
    }

    async fn sweep_expired(&self) {
        let now = epoch_secs();
        let window_secs = self.window.as_secs();
        let mut map = self.counters.lock().await;
        map.retain(|_, v| now.saturating_sub(v.started_at_epoch_secs) < window_secs);
    }

    pub async fn persist(&self) -> Result<()> {
        let rows: Vec<PersistedCounter> = {
            let map = self.counters.lock().await;
            map.iter()
                .map(|(ip, c)| PersistedCounter {
                    ip: ip.clone(),
                    count: c.count,
                    started_at_epoch_secs: c.started_at_epoch_secs,
                })
                .collect()
        };
        if let Some(parent) = self.snapshot_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let payload = serde_json::to_vec_pretty(&rows)?;
        let tmp = self.snapshot_path.with_extension("json.tmp");
        fs::write(&tmp, &payload).await?;
        fs::rename(&tmp, &self.snapshot_path).await?;
        Ok(())
    }
}

// ─── redis backend ────────────────────────────────────────────────────────────

/// Distributed rate limiter backed by Redis.
///
/// # Security
/// * **TLS mandatory** — only `rediss://` URLs are accepted (CIS Redis Benchmark § 3).
/// * **Credentials via env vars** — `REDIS_PASSWORD` / `REDIS_USERNAME` only;
///   never hardcoded or loaded from the config file.
/// * **Peer cert verification** — always enabled (system or custom CA).
/// * **Key namespacing** — `key_prefix` prevents collision with other tenants.
/// * **Atomic Lua script** — prevents the INCR/EXPIRE race condition.
/// * **Fail-open** — a Redis outage allows requests through (logged as warning)
///   to prevent the WAF from becoming a self-inflicted DoS.
pub struct RedisRateLimiter {
    pool: Pool,
    key_prefix: String,
    max_requests: u32,
    window_secs: i64,
}

impl RedisRateLimiter {
    pub async fn new(
        config: &crate::ratelimit_config::RedisConfig,
        cli_limit: u32,
    ) -> Result<Self> {
        // CIS Redis Benchmark: enforce encrypted transport.
        anyhow::ensure!(
            config.url.starts_with("rediss://"),
            "Redis URL must use rediss:// (TLS required per CIS Redis Benchmark). \
             Plain redis:// connections are not permitted."
        );

        // Credentials via environment variables only — never from the config file.
        let password = std::env::var("REDIS_PASSWORD").ok().filter(|s| !s.is_empty());
        let username = std::env::var("REDIS_USERNAME").ok().filter(|s| !s.is_empty());

        let mut fred_config = Config::from_url(&config.url)
            .map_err(|e| anyhow::anyhow!("invalid Redis URL: {e}"))?;

        fred_config.password = password;
        fred_config.username = username;

        // Build TLS connector: custom CA or system trust store.
        let tls_connector = if config.tls.ca_cert_path.is_empty() {
            TlsConnector::default_rustls()
                .map_err(|e| anyhow::anyhow!("failed to build default TLS connector: {e}"))?
        } else {
            build_custom_ca_connector(&config.tls.ca_cert_path)?
        };
        fred_config.tls = Some(TlsConfig::from(tls_connector));

        let pool = Builder::from_config(fred_config)
            .build_pool(config.pool_size)
            .map_err(|e| anyhow::anyhow!("failed to build Redis pool: {e}"))?;

        let _connection_task = pool.init().await
            .map_err(|e| anyhow::anyhow!("Redis connect failed: {e}"))?;

        let max_requests = if config.max_requests > 0 { config.max_requests } else { cli_limit };
        let window_secs = if config.window_secs > 0 { config.window_secs as i64 } else { 60 };

        Ok(Self { pool, key_prefix: config.key_prefix.clone(), max_requests, window_secs })
    }

    pub async fn check(&self, ip: &str) -> bool {
        let key = format!("{}{}", self.key_prefix, ip);
        let result: Result<i64, fred::error::Error> = self.pool.eval(
            INCR_WITH_TTL_LUA,
            vec![key],
            vec![self.window_secs.to_string()],
        ).await;

        match result {
            Ok(count) => count <= i64::from(self.max_requests),
            Err(err) => {
                // Fail open: a Redis outage must not become a self-inflicted DoS.
                warn!(
                    target: "krakenwaf",
                    error = %err,
                    "Redis rate limit check failed — allowing request (fail-open)"
                );
                true
            }
        }
    }
}

/// Builds a rustls TLS connector using a custom PEM-encoded CA certificate bundle.
///
/// Uses `rustls_pki_types::pem` for PEM parsing — avoids depending on the
/// unmaintained `rustls-pemfile` crate (RUSTSEC-2025-0134).
fn build_custom_ca_connector(ca_cert_path: &str) -> Result<TlsConnector> {
    use fred::rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
    use rustls_pki_types::{pem::PemObject, CertificateDer};

    let pem_bytes = std::fs::read(ca_cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read CA cert '{ca_cert_path}': {e}"))?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse certs from '{ca_cert_path}': {e}"))?;

    anyhow::ensure!(!certs.is_empty(), "no valid certificates found in '{ca_cert_path}'");

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store.add(cert)
            .map_err(|e| anyhow::anyhow!("invalid CA cert in '{ca_cert_path}': {e}"))?;
    }

    let tls_config = RustlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(tls_config))
}

// ─── helpers ──────────────────────────────────────────────────────────────────

fn load_snapshot(path: &std::path::Path) -> HashMap<String, Counter> {
    if !path.exists() {
        return HashMap::new();
    }
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(err) => {
            warn!(target: "krakenwaf", error=%err, path=%path.display(), "rate limiter snapshot stat failed");
            return HashMap::new();
        }
    };
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        warn!(
            target: "krakenwaf",
            size = metadata.len(),
            limit = MAX_SNAPSHOT_BYTES,
            path = %path.display(),
            "rate limiter snapshot exceeds size limit; ignoring"
        );
        return HashMap::new();
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            warn!(target: "krakenwaf", error=%err, path=%path.display(), "rate limiter snapshot read failed");
            return HashMap::new();
        }
    };
    let parsed: Vec<PersistedCounter> = serde_json::from_str(&raw).unwrap_or_default();
    parsed
        .into_iter()
        .take(DEFAULT_MAX_TRACKED_IPS)
        .map(|item| {
            (item.ip, Counter {
                count: item.count,
                started_at_epoch_secs: item.started_at_epoch_secs,
            })
        })
        .collect()
}

fn evict_one(map: &mut HashMap<String, Counter>, now: u64, window_secs: u64) {
    let mut oldest_key: Option<String> = None;
    let mut oldest_started: u64 = u64::MAX;
    let mut expired_key: Option<String> = None;

    for (key, value) in map.iter() {
        if now.saturating_sub(value.started_at_epoch_secs) >= window_secs {
            expired_key = Some(key.clone());
            break;
        }
        if value.started_at_epoch_secs < oldest_started {
            oldest_started = value.started_at_epoch_secs;
            oldest_key = Some(key.clone());
        }
    }

    if let Some(k) = expired_key.or(oldest_key) {
        map.remove(&k);
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}


use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

/// Rate limiter configuration loaded from `conf/ratelimit.yaml`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RateLimitConfig {
    /// Per-IP request rate limit (requests/minute). `None` / 0 = use CLI default.
    #[serde(default, deserialize_with = "deser_option_nonzero_u32")]
    pub rate_limit_per_minute: Option<u32>,
    /// Maximum simultaneous in-flight connections per client IP.
    /// 0 = disabled.  Default: 64.
    #[serde(default = "default_max_coroutines_per_ip")]
    pub max_coroutines_per_ip: usize,
    #[serde(default)]
    pub local: LocalConfig,
    #[serde(default)]
    pub redis: RedisConfig,
}

fn default_max_coroutines_per_ip() -> usize { 64 }

/// Deserializes a `u32` from YAML: 0 or absent → `None`; non-zero → `Some(n)`.
fn deser_option_nonzero_u32<'de, D>(d: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let n: u32 = serde::Deserialize::deserialize(d)?;
    Ok(if n == 0 { None } else { Some(n) })
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalConfig {
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self { max_tracked_ips: default_max_tracked_ips() }
    }
}

fn default_max_tracked_ips() -> usize { 100_000 }

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// When false (default) the local in-memory limiter is used exclusively.
    #[serde(default)]
    pub enabled: bool,
    /// Must start with `rediss://` (TLS mandatory per CIS Redis Benchmark).
    /// Credentials must NOT appear here — use `REDIS_PASSWORD` / `REDIS_USERNAME`
    /// environment variables instead.
    #[serde(default = "default_redis_url")]
    pub url: String,
    #[serde(default)]
    pub tls: RedisTlsConfig,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
    /// Override for max requests per window. 0 = use CLI --rate-limit-per-minute.
    #[serde(default)]
    pub max_requests: u32,
    /// Override for window length in seconds. 0 = use default (60 s).
    #[serde(default)]
    pub window_secs: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_redis_url(),
            tls: RedisTlsConfig::default(),
            pool_size: default_pool_size(),
            key_prefix: default_key_prefix(),
            max_requests: 0,
            window_secs: 0,
        }
    }
}

fn default_redis_url() -> String { "rediss://127.0.0.1:6379".to_string() }
fn default_pool_size() -> usize { 8 }
fn default_key_prefix() -> String { "krakenwaf:rl:".to_string() }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RedisTlsConfig {
    /// Path to a PEM-encoded CA bundle for server certificate verification.
    /// Empty = use the system trust store.
    #[serde(default)]
    pub ca_cert_path: String,
}

impl RateLimitConfig {
    /// Load from `{root}/conf/ratelimit.yaml`; returns `Default` when the file is absent.
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_from(&root.join("conf").join("ratelimit.yaml"))
    }

    /// Load from an explicit file path; returns `Default` when the file is absent.
    ///
    /// # Errors
    /// Returns an error when the file exists but cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))
    }
}

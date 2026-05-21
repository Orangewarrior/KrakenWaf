//! Rate-limit configuration loaded from `conf/ratelimit.yaml` (or an explicit
//! path via `--ratelimit-by-file-conf`).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

// ── Top-level config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per minute per source IP.
    /// `None` (or 0 in the file) defers to the CLI flag or the built-in default (240).
    #[serde(default, deserialize_with = "deser_opt_nonzero_u32")]
    pub rate_limit_per_minute: Option<u32>,

    /// Maximum simultaneous in-flight connections per source IP.
    /// 0 disables per-IP concurrency capping. Default: 64.
    #[serde(default = "default_max_coroutines")]
    pub max_coroutines_per_ip: usize,

    /// Redis distributed rate-limiter settings. When present, replaces the
    /// built-in GCRA limiter with a Redis-backed counter.
    #[serde(default)]
    pub redis: Option<RedisConfig>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: None,
            max_coroutines_per_ip: default_max_coroutines(),
            redis: None,
        }
    }
}

impl RateLimitConfig {
    /// Load from `<root>/conf/ratelimit.yaml`; returns `Default` if absent.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_from(&root.join("conf").join("ratelimit.yaml"))
    }

    /// Load from an explicit path; returns `Default` if the file is absent.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse '{}'", path.display()))
    }

    /// Resolve the effective rate limit applying priority order:
    ///   1. Explicit `--rate-limit-per-minute` CLI argument
    ///   2. `rate_limit_per_minute` from this config file
    ///   3. Built-in default: 240 req/min
    #[must_use]
    pub fn effective_rate_limit(&self, cli: Option<u32>) -> u32 {
        cli.or(self.rate_limit_per_minute).unwrap_or(240)
    }
}

// ── Redis section ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Redis endpoint URL. **Must** use `rediss://` (TLS) per CIS Benchmark.
    /// Credentials are injected at runtime from `REDIS_PASSWORD` /
    /// `REDIS_USERNAME` environment variables — never embed them in this field.
    pub url: String,

    /// Number of pooled connections. Default: 4.
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    /// Key namespace prefix. Isolates this WAF from other services sharing
    /// the same Redis instance. Default: `"krakenwaf:rl"`.
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,

    /// Rate-limit window duration in seconds. Default: 60 (per-minute).
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,

    /// Optional path to a PEM-encoded CA certificate for custom / private PKI.
    /// Omit to use the system trust store.
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

// ── Defaults ──────────────────────────────────────────────────────────────────

fn default_max_coroutines() -> usize { 64 }
fn default_pool_size() -> usize { 4 }
fn default_window_secs() -> u64 { 60 }
fn default_key_prefix() -> String { "krakenwaf:rl".to_string() }

/// Deserialise an optional u32 where 0 and the absent case are both `None`.
fn deser_opt_nonzero_u32<'de, D>(d: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<u32>::deserialize(d)? {
        Some(0) | None => Ok(None),
        Some(n) => Ok(Some(n)),
    }
}

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

    /// Per-frame body inactivity timeout (seconds). Slowloris protection —
    /// if the WAF waits longer than this for a single request-body chunk it
    /// returns 408 and drops the connection.
    /// `None` defers to the CLI flag or the built-in default (30 s).
    #[serde(default)]
    pub body_frame_timeout_secs: Option<u64>,

    /// Global memory-backpressure cap on in-flight request body bytes
    /// across all clients. When exceeded the WAF returns HTTP 503 +
    /// `Retry-After: 5`. 0 disables the cap.
    /// `None` defers to the CLI flag or the built-in default (1 GiB).
    #[serde(default)]
    pub max_inflight_body_bytes: Option<usize>,

    /// Per-IP memory-backpressure cap on in-flight request body bytes.
    /// Prevents a single client from saturating the global body buffer.
    /// 0 disables the cap.
    /// `None` defers to the CLI flag or the built-in default (200 MiB).
    #[serde(default)]
    pub max_per_ip_body_bytes: Option<usize>,

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
            body_frame_timeout_secs: None,
            max_inflight_body_bytes: None,
            max_per_ip_body_bytes: None,
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

    /// Resolve the effective body-frame timeout (seconds):
    ///   1. Explicit `--body-frame-timeout-secs` CLI argument
    ///   2. `body_frame_timeout_secs` from this config file
    ///   3. Built-in default: 30 s
    #[must_use]
    pub fn effective_body_frame_timeout_secs(&self, cli: Option<u64>) -> u64 {
        cli.or(self.body_frame_timeout_secs).unwrap_or(30)
    }

    /// Resolve the effective global in-flight body cap (bytes):
    ///   1. Explicit `--max-inflight-body-bytes` CLI argument
    ///   2. `max_inflight_body_bytes` from this config file
    ///   3. Built-in default: 1 GiB (1073741824)
    #[must_use]
    pub fn effective_max_inflight_body_bytes(&self, cli: Option<usize>) -> usize {
        cli.or(self.max_inflight_body_bytes)
            .unwrap_or(1024 * 1024 * 1024)
    }

    /// Resolve the effective per-IP in-flight body cap (bytes):
    ///   1. Explicit `--max-per-ip-body-bytes` CLI argument
    ///   2. `max_per_ip_body_bytes` from this config file
    ///   3. Built-in default: 200 MiB (209715200)
    #[must_use]
    pub fn effective_max_per_ip_body_bytes(&self, cli: Option<usize>) -> usize {
        cli.or(self.max_per_ip_body_bytes)
            .unwrap_or(200 * 1024 * 1024)
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

    /// Behaviour when Redis is unreachable or a rate-limit check times out.
    /// `true` (default) — **fail-open**: the request is allowed and a metric +
    /// warning are emitted (favours availability). `false` — **fail-closed**:
    /// the request is denied with HTTP 429 (favours the rate-limit guarantee).
    /// Choose fail-closed when the limiter is a hard security control and a
    /// Redis outage must not silently disable it.
    #[serde(default = "default_redis_fail_open")]
    pub fail_open: bool,
}

// ── Defaults ──────────────────────────────────────────────────────────────────

fn default_max_coroutines() -> usize { 64 }
fn default_pool_size() -> usize { 4 }
fn default_window_secs() -> u64 { 60 }
fn default_key_prefix() -> String { "krakenwaf:rl".to_string() }
fn default_redis_fail_open() -> bool { true }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_applied_when_absent_from_yaml() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.effective_rate_limit(None), 240);
        assert_eq!(cfg.effective_body_frame_timeout_secs(None), 30);
        assert_eq!(
            cfg.effective_max_inflight_body_bytes(None),
            1024 * 1024 * 1024
        );
        assert_eq!(
            cfg.effective_max_per_ip_body_bytes(None),
            200 * 1024 * 1024
        );
    }

    #[test]
    fn yaml_values_override_built_in_defaults() {
        let yaml = "\
rate_limit_per_minute: 500
body_frame_timeout_secs: 10
max_inflight_body_bytes: 2147483648
max_per_ip_body_bytes: 104857600
";
        let cfg: RateLimitConfig = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(cfg.effective_rate_limit(None), 500);
        assert_eq!(cfg.effective_body_frame_timeout_secs(None), 10);
        assert_eq!(cfg.effective_max_inflight_body_bytes(None), 2_147_483_648);
        assert_eq!(cfg.effective_max_per_ip_body_bytes(None), 104_857_600);
    }

    #[test]
    fn cli_flag_wins_over_yaml_and_default() {
        let yaml = "\
rate_limit_per_minute: 500
body_frame_timeout_secs: 10
max_inflight_body_bytes: 2147483648
max_per_ip_body_bytes: 104857600
";
        let cfg: RateLimitConfig = serde_yaml::from_str(yaml).expect("yaml parses");
        // CLI explicit values override both YAML and built-in defaults.
        assert_eq!(cfg.effective_rate_limit(Some(99)), 99);
        assert_eq!(cfg.effective_body_frame_timeout_secs(Some(7)), 7);
        assert_eq!(cfg.effective_max_inflight_body_bytes(Some(1024)), 1024);
        assert_eq!(cfg.effective_max_per_ip_body_bytes(Some(512)), 512);
    }
}

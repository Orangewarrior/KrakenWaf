//! Rate-limit configuration loaded from `conf/ratelimit.yaml` (or an explicit
//! path via `--ratelimit-by-file-conf`).

use anyhow::{bail, Context, Result};
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

    /// Anti-Slowloris TLS-handshake timeout (seconds). Maximum wall-clock time
    /// the WAF waits for a client to complete the TLS handshake before dropping
    /// the connection. A stalled handshake would otherwise pin a connection
    /// slot (and a `--max-connections` permit) indefinitely, letting a handful
    /// of half-open sockets exhaust capacity. Only applies to TLS mode.
    /// 0 disables the bound (not recommended — removes the anti-DoS guard).
    /// `None` defers to the CLI flag or the built-in default (10 s).
    #[serde(default)]
    pub tls_handshake_timeout_secs: Option<u64>,

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

    /// Maximum simultaneous TCP connections the WAF accepts. `0` in the file
    /// (or absent) is treated as `None`, deferring to `--max-connections`, then
    /// to `rules/cmc/config.yaml :: memory-limits.max_connections`, and finally
    /// to a value derived from system RAM at startup.
    #[serde(default, deserialize_with = "deser_opt_nonzero_usize")]
    pub max_connections: Option<usize>,

    /// Timeout (seconds) for a single client connection accepted by the WAF.
    /// `None` defers to `--connection-timeout-secs`, then to the built-in
    /// default (30 s). Must be `>= 1` when present — `0` would time out every
    /// connection immediately and is rejected by [`RateLimitConfig::validate`].
    #[serde(default)]
    pub connection_timeout_secs: Option<u64>,

    /// Maximum request body the WAF buffers + inspects (bytes). `0`/absent is
    /// `None`, deferring to `--max-body-bytes`, then to
    /// `rules/cmc/config.yaml :: memory-limits.max_request_body_buffered_bytes`
    /// (built-in default 8 MiB).
    #[serde(default, deserialize_with = "deser_opt_nonzero_usize")]
    pub max_body_bytes: Option<usize>,

    /// Hard ceiling on the upstream response body the WAF buffers (bytes).
    /// `0`/absent is `None`, deferring to `--max-upstream-response-bytes`, then
    /// to `rules/cmc/config.yaml :: memory-limits.max_response_body_buffered_bytes`
    /// (built-in default 8 MiB).
    #[serde(default, deserialize_with = "deser_opt_nonzero_usize")]
    pub max_upstream_response_bytes: Option<usize>,

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
            tls_handshake_timeout_secs: None,
            max_inflight_body_bytes: None,
            max_per_ip_body_bytes: None,
            max_connections: None,
            connection_timeout_secs: None,
            max_body_bytes: None,
            max_upstream_response_bytes: None,
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
        let cfg: Self = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse '{}'", path.display()))?;
        cfg.validate()
            .with_context(|| format!("invalid rate-limit config '{}'", path.display()))?;
        Ok(cfg)
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

    /// Resolve the effective TLS-handshake timeout (seconds):
    ///   1. Explicit `--tls-handshake-timeout-secs` CLI argument
    ///   2. `tls_handshake_timeout_secs` from this config file
    ///   3. Built-in default: 10 s (anti-Slowloris guard)
    ///
    /// A value of 0 (from either source) disables the bound — not recommended,
    /// as it lets half-open TLS sockets pin connection slots indefinitely.
    #[must_use]
    pub fn effective_tls_handshake_timeout_secs(&self, cli: Option<u64>) -> u64 {
        cli.or(self.tls_handshake_timeout_secs).unwrap_or(10)
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

    /// Resolve the effective client-connection timeout (seconds):
    ///   1. Explicit `--connection-timeout-secs` CLI argument
    ///   2. `connection_timeout_secs` from this config file
    ///   3. Built-in default: 30 s
    #[must_use]
    pub fn effective_connection_timeout_secs(&self, cli: Option<u64>) -> u64 {
        cli.or(self.connection_timeout_secs).unwrap_or(30)
    }

    /// Resolve the effective `max_connections` cap. Priority:
    ///   1. Explicit `--max-connections` CLI argument (non-zero)
    ///   2. `max_connections` from this config file (non-zero)
    ///   3. `fallback` — supplied by the caller from
    ///      `MemoryLimits::effective_max_connections` (config / RAM-derived).
    #[must_use]
    pub fn effective_max_connections(&self, cli: usize, fallback: usize) -> usize {
        if cli != 0 {
            return cli;
        }
        self.max_connections.filter(|v| *v != 0).unwrap_or(fallback)
    }

    /// Resolve the effective request-body cap (bytes). Priority:
    ///   1. Explicit `--max-body-bytes` CLI argument (non-zero)
    ///   2. `max_body_bytes` from this config file (non-zero)
    ///   3. `fallback` — `memory-limits.max_request_body_buffered_bytes`.
    #[must_use]
    pub fn effective_max_body_bytes(&self, cli: usize, fallback: usize) -> usize {
        if cli != 0 {
            return cli;
        }
        self.max_body_bytes.filter(|v| *v != 0).unwrap_or(fallback)
    }

    /// Resolve the effective upstream-response cap (bytes). Priority:
    ///   1. Explicit `--max-upstream-response-bytes` CLI argument (non-zero)
    ///   2. `max_upstream_response_bytes` from this config file (non-zero)
    ///   3. `fallback` — `memory-limits.max_response_body_buffered_bytes`.
    #[must_use]
    pub fn effective_max_upstream_response_bytes(&self, cli: usize, fallback: usize) -> usize {
        if cli != 0 {
            return cli;
        }
        self.max_upstream_response_bytes
            .filter(|v| *v != 0)
            .unwrap_or(fallback)
    }

    /// Validate the parsed config. Run on load so a malformed file is rejected
    /// at startup rather than producing a silently-broken limiter.
    ///
    /// # Errors
    /// Returns a descriptive error when a populated field holds a value that
    /// would break the limiter (currently: `connection_timeout_secs == 0`).
    pub fn validate(&self) -> Result<()> {
        if let Some(0) = self.connection_timeout_secs {
            bail!(
                "`connection_timeout_secs` must be >= 1 (got 0); 0 would time out \
                 every client connection immediately"
            );
        }
        Ok(())
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

/// Deserialise an optional usize where 0 and the absent case are both `None`.
/// Lets `conf/ratelimit.yaml` ship the byte/connection caps with an explicit
/// `0` sentinel meaning "defer to the CLI flag / memory-limits / built-in".
fn deser_opt_nonzero_usize<'de, D>(d: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<usize>::deserialize(d)? {
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
        assert_eq!(cfg.effective_tls_handshake_timeout_secs(None), 10);
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
tls_handshake_timeout_secs: 7
max_inflight_body_bytes: 2147483648
max_per_ip_body_bytes: 104857600
";
        let cfg: RateLimitConfig = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(cfg.effective_rate_limit(None), 500);
        assert_eq!(cfg.effective_body_frame_timeout_secs(None), 10);
        assert_eq!(cfg.effective_tls_handshake_timeout_secs(None), 7);
        assert_eq!(cfg.effective_max_inflight_body_bytes(None), 2_147_483_648);
        assert_eq!(cfg.effective_max_per_ip_body_bytes(None), 104_857_600);
    }

    #[test]
    fn cli_flag_wins_over_yaml_and_default() {
        let yaml = "\
rate_limit_per_minute: 500
body_frame_timeout_secs: 10
tls_handshake_timeout_secs: 7
max_inflight_body_bytes: 2147483648
max_per_ip_body_bytes: 104857600
";
        let cfg: RateLimitConfig = serde_yaml::from_str(yaml).expect("yaml parses");
        // CLI explicit values override both YAML and built-in defaults.
        assert_eq!(cfg.effective_rate_limit(Some(99)), 99);
        assert_eq!(cfg.effective_body_frame_timeout_secs(Some(7)), 7);
        assert_eq!(cfg.effective_tls_handshake_timeout_secs(Some(20)), 20);
        assert_eq!(cfg.effective_max_inflight_body_bytes(Some(1024)), 1024);
        assert_eq!(cfg.effective_max_per_ip_body_bytes(Some(512)), 512);
    }

    #[test]
    fn new_caps_default_to_fallback_when_absent() {
        let cfg = RateLimitConfig::default();
        // connection timeout: no CLI, no YAML → built-in 30 s.
        assert_eq!(cfg.effective_connection_timeout_secs(None), 30);
        // byte/connection caps: no CLI (0), no YAML → caller-supplied fallback.
        assert_eq!(cfg.effective_max_connections(0, 512), 512);
        assert_eq!(cfg.effective_max_body_bytes(0, 8_388_608), 8_388_608);
        assert_eq!(
            cfg.effective_max_upstream_response_bytes(0, 8_388_608),
            8_388_608
        );
    }

    #[test]
    fn new_caps_zero_sentinel_is_treated_as_absent() {
        // The shipped conf/ratelimit.yaml carries 0 for the byte/connection caps.
        let yaml = "\
max_connections: 0
max_body_bytes: 0
max_upstream_response_bytes: 0
connection_timeout_secs: 30
";
        let cfg: RateLimitConfig = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(cfg.max_connections, None);
        assert_eq!(cfg.max_body_bytes, None);
        assert_eq!(cfg.max_upstream_response_bytes, None);
        // 0 → fallback; 30 from YAML wins over the built-in default.
        assert_eq!(cfg.effective_max_connections(0, 1024), 1024);
        assert_eq!(cfg.effective_max_body_bytes(0, 8_388_608), 8_388_608);
        assert_eq!(cfg.effective_connection_timeout_secs(None), 30);
    }

    #[test]
    fn new_caps_yaml_overrides_fallback_and_cli_overrides_yaml() {
        let yaml = "\
max_connections: 256
connection_timeout_secs: 45
max_body_bytes: 4194304
max_upstream_response_bytes: 2097152
";
        let cfg: RateLimitConfig = serde_yaml::from_str(yaml).expect("yaml parses");
        // YAML wins over the fallback when CLI is unset (0 / None).
        assert_eq!(cfg.effective_max_connections(0, 1024), 256);
        assert_eq!(cfg.effective_connection_timeout_secs(None), 45);
        assert_eq!(cfg.effective_max_body_bytes(0, 8_388_608), 4_194_304);
        assert_eq!(
            cfg.effective_max_upstream_response_bytes(0, 8_388_608),
            2_097_152
        );
        // Explicit CLI wins over YAML.
        assert_eq!(cfg.effective_max_connections(99, 1024), 99);
        assert_eq!(cfg.effective_connection_timeout_secs(Some(5)), 5);
        assert_eq!(cfg.effective_max_body_bytes(123, 8_388_608), 123);
        assert_eq!(
            cfg.effective_max_upstream_response_bytes(456, 8_388_608),
            456
        );
    }

    #[test]
    fn validate_rejects_zero_connection_timeout() {
        let cfg: RateLimitConfig =
            serde_yaml::from_str("connection_timeout_secs: 0").expect("yaml parses");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_default_and_populated() {
        assert!(RateLimitConfig::default().validate().is_ok());
        let cfg: RateLimitConfig =
            serde_yaml::from_str("connection_timeout_secs: 30").expect("yaml parses");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn tls_handshake_timeout_falls_back_to_yaml_then_default() {
        // Absent from YAML → built-in 10 s default.
        let empty: RateLimitConfig =
            serde_yaml::from_str("rate_limit_per_minute: 1").expect("yaml parses");
        assert_eq!(empty.effective_tls_handshake_timeout_secs(None), 10);

        // Present in YAML, no CLI flag → YAML wins over the default.
        let yaml: RateLimitConfig =
            serde_yaml::from_str("tls_handshake_timeout_secs: 25").expect("yaml parses");
        assert_eq!(yaml.effective_tls_handshake_timeout_secs(None), 25);

        // CLI flag overrides the YAML value.
        assert_eq!(yaml.effective_tls_handshake_timeout_secs(Some(3)), 3);

        // 0 is a legitimate (if unsafe) explicit "disable" value and is honoured.
        let disabled: RateLimitConfig =
            serde_yaml::from_str("tls_handshake_timeout_secs: 0").expect("yaml parses");
        assert_eq!(disabled.effective_tls_handshake_timeout_secs(None), 0);
    }
}

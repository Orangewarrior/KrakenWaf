use clap::{ArgAction, Parser, ValueEnum};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WafMode {
    /// Block detected threats (default behaviour).
    Block,
    /// Log detections but never block (observation mode).
    Silent,
    /// Detect-only / shadow mode: run all inspection engines, emit findings and
    /// increment metrics, but always return Allow. Useful for validating new rule
    /// sets against live traffic before enabling blocking.
    DetectOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WalMode {
    /// Persist rate-limiter state in `SQLite` (WAL journal). Slower writes
    /// but supports inspection via `sqlite3 cli` and partial updates.
    Sqlite,
    /// Persist as a flat bincode file (atomic rename). Much faster snapshots
    /// and re-hydration; entire state is rewritten on each persist tick.
    Bincode,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "krakenwaf")]
#[command(author, version, about = "KrakenWaf - TLS-aware Rust WAF inspired by OctopusWAF")]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    #[arg(long, default_value = "0.0.0.0:8443")]
    pub listen: SocketAddr,

    #[arg(long, default_value = "http://127.0.0.1:8080")]
    pub upstream: String,

    #[arg(long, default_value = "./rules")]
    pub rules_dir: String,

    #[arg(long, default_value = "./rules/tls/sni_map.csv")]
    pub sni_map: String,

    #[arg(long, action = ArgAction::SetTrue, hide = true)]
    pub enable_libinjection: bool,

    #[arg(long = "enable-libinjection-sqli", action = ArgAction::SetTrue)]
    pub enable_libinjection_sqli: bool,

    #[arg(long = "enable-libinjection-xss", action = ArgAction::SetTrue)]
    pub enable_libinjection_xss: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    pub enable_vectorscan: bool,

    #[arg(long, default_value_t = false)]
    pub blocklist_ip: bool,

    #[arg(long)]
    pub blockmsg: Option<String>,

    /// Per-IP request rate limit (requests per minute). Overrides the value in
    /// `--ratelimit-by-file-conf` or `conf/ratelimit.yaml`. When absent the
    /// effective limit is taken from the config file or defaults to 240.
    #[arg(long)]
    pub rate_limit_per_minute: Option<u32>,

    /// Path to a rate-limit YAML configuration file. `KrakenWaf` auto-discovers
    /// `conf/ratelimit.yaml` in the working directory; use this flag to supply
    /// an alternative path. The file controls the Redis backend, per-IP
    /// concurrency cap, and the default rate limit.
    #[arg(long = "ratelimit-by-file-conf")]
    pub ratelimit_by_file_conf: Option<String>,

    #[arg(long, default_value_t = 15)]
    pub upstream_timeout_secs: u64,

    #[arg(long, action = ArgAction::SetTrue)]
    pub verbose: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    pub allow_private_upstream: bool,

    #[arg(long, default_value = "")]
    pub internal_header_name: String,

    /// Maximum simultaneous TCP connections the WAF accepts.
    /// 2.24.0: when 0 (the default) KrakenWaf derives a conservative value
    /// from total RAM at startup (≈ 1 connection per 2 MiB, clamped to
    /// [64, 4096]). YAML key: `memory-limits.max_connections`.
    #[arg(long, default_value_t = 0)]
    pub max_connections: usize,

    /// Maximum upstream response body to buffer (bytes).
    /// 2.24.0: default dropped from 100 MiB → 8 MiB. 0 = use the YAML
    /// value `memory-limits.max_response_body_buffered_bytes`.
    #[arg(long, default_value_t = 0)]
    pub max_upstream_response_bytes: usize,

    /// Hard ceiling on the request body size the WAF will inspect (bytes).
    /// 2.24.0: default dropped from 100 MiB → 8 MiB. 0 = use the YAML
    /// value `memory-limits.max_request_body_buffered_bytes`. Per-route
    /// rule limits remain bounded by this value.
    #[arg(long, default_value_t = 0)]
    pub max_body_bytes: usize,

    #[arg(long, default_value_t = 30)]
    pub connection_timeout_secs: u64,

    #[arg(long = "header-protection-injection")]
    pub header_protection_injection: Option<String>,

    #[arg(long = "cmc-load")]
    pub cmc_load: Option<String>,

    #[arg(long = "real-ip-header")]
    pub real_ip_header: Option<String>,

    #[arg(long = "trusted-proxy-cidrs", value_delimiter = ',')]
    pub trusted_proxy_cidrs: Vec<String>,

    /// WAF enforcement mode.
    /// `block` (default) — block matching requests.
    /// `silent` — log detections but never block.
    /// `detect-only` — run all engines, emit findings and metrics, always allow.
    #[arg(long, value_enum, default_value = "block")]
    pub mode: WafMode,

    /// Path to an allow-paths YAML file (e.g. rules/allowpaths/lists.yaml). URIs
    /// matching any entry are passed through without blocking even when a rule fires.
    #[arg(long = "allow-paths")]
    pub allow_paths_file: Option<String>,

    /// Disable TLS and listen on plain HTTP. Useful when TLS termination is handled
    /// by an upstream load balancer, or for integration testing. When set, --sni-map
    /// is ignored.
    #[arg(long = "no-tls", default_value_t = false)]
    pub no_tls: bool,

    /// Persistence backend for the rate-limiter snapshot.
    /// `sqlite` uses WAL journaling (queryable, slower); `bincode` uses a
    /// flat binary file with atomic rename (much faster, opaque format).
    #[arg(long = "wal-mode", value_enum, default_value = "sqlite")]
    pub wal_mode: WalMode,

    /// Anomaly-score block threshold. Rule scores accumulate across all
    /// matches in a single request; when the sum reaches this value the
    /// Detection-engine block threshold (score). Overrides the
    /// `Anomaly_threshold` field under `global-options` in the CMC config
    /// file (`--cmc-load`). When absent the effective value is taken from
    /// the CMC file or defaults to 600.
    #[arg(long = "anomaly-threshold")]
    pub anomaly_threshold: Option<u32>,

    /// Per-request wall-clock cap on WAF inspection (milliseconds).
    /// 0 = unlimited (default). When exceeded the inspection stops and the
    /// request is allowed to proceed with whatever findings were produced.
    /// Overrides the `Max_inspection_ms` field under `global-options` in the
    /// CMC config file (`--cmc-load`). When absent the effective value is
    /// taken from the CMC file or defaults to 0 (disabled).
    #[arg(long = "max-inspection-ms")]
    pub max_inspection_ms: Option<u64>,

    /// Slowloris protection: maximum wall-clock time the WAF waits for a
    /// single body frame before timing out. Overrides the value in
    /// `--ratelimit-by-file-conf` or `conf/ratelimit.yaml`. When absent the
    /// effective value is taken from the config file or defaults to 30 s.
    #[arg(long = "body-frame-timeout-secs")]
    pub body_frame_timeout_secs: Option<u64>,

    /// Global memory-backpressure cap on in-flight request body bytes.
    /// When exceeded the WAF returns HTTP 503 immediately. 0 = disabled.
    /// Overrides the value in `--ratelimit-by-file-conf` or
    /// `conf/ratelimit.yaml`. When absent the effective value is taken from
    /// the config file or defaults to 1 GiB (1073741824).
    #[arg(long = "max-inflight-body-bytes")]
    pub max_inflight_body_bytes: Option<usize>,

    /// Per-IP memory-backpressure cap on in-flight request body bytes.
    /// When exceeded the WAF returns HTTP 503 for that IP. 0 = disabled.
    /// Overrides the value in `--ratelimit-by-file-conf` or
    /// `conf/ratelimit.yaml`. When absent the effective value is taken from
    /// the config file or defaults to 200 MiB (209715200).
    #[arg(long = "max-per-ip-body-bytes")]
    pub max_per_ip_body_bytes: Option<usize>,
}

impl Cli {
    #[must_use] 
    pub fn libinjection_sqli_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_sqli
    }

    #[must_use] 
    pub fn libinjection_xss_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_xss
    }
}

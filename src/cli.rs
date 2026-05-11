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
    /// Persist rate-limiter state in SQLite (WAL journal). Slower writes
    /// but supports inspection via `sqlite3 cli` and partial updates.
    Sqlite,
    /// Persist as a flat bincode file (atomic rename). Much faster snapshots
    /// and re-hydration; entire state is rewritten on each persist tick.
    Bincode,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "krakenwaf")]
#[command(author, version, about = "KrakenWaf - TLS-aware Rust WAF inspired by OctopusWAF")]
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

    #[arg(long, default_value_t = 240)]
    pub rate_limit_per_minute: u32,

    #[arg(long, default_value_t = 15)]
    pub upstream_timeout_secs: u64,

    #[arg(long, action = ArgAction::SetTrue)]
    pub verbose: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    pub allow_private_upstream: bool,

    #[arg(long, default_value = "")]
    pub internal_header_name: String,

    /// Maximum simultaneous TCP connections the WAF accepts. Each connection
    /// holds inspection buffers, so keep this proportional to available memory.
    /// 512 provides solid backpressure; raise for very high-traffic deployments.
    #[arg(long, default_value_t = 512)]
    pub max_connections: usize,

    /// Maximum upstream response body to buffer (bytes). Prevents an upstream returning
    /// an unbounded body from exhausting WAF memory. Default: 100 MiB.
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
    pub max_upstream_response_bytes: usize,

    /// Hard ceiling on the request body size the WAF will inspect (bytes).
    /// Per-route limits configured in rules are further bounded by this value —
    /// no route can exceed it regardless of its rule configuration.
    /// Requests whose bodies exceed this limit are rejected with HTTP 413.
    /// Default: 100 MiB.
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
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
}

impl Cli {
    pub fn libinjection_sqli_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_sqli
    }

    pub fn libinjection_xss_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_xss
    }
}

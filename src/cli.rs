use clap::{ArgAction, Parser, ValueEnum};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WafMode {
    /// Block detected threats (default behaviour).
    Block,
    /// Log detections but never block (observation mode).
    Silent,
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

    /// Per-IP request rate limit (requests per minute).
    /// When --ratelimit-by-file-conf is also given this value acts as a final
    /// override; otherwise 240 is the built-in default.
    #[arg(long)]
    pub rate_limit_per_minute: Option<u32>,

    /// Load all rate-limit settings from a YAML configuration file.
    /// Enables Redis distributed mode, per-IP concurrency cap, and custom window
    /// settings without passing individual CLI flags.  See conf/ratelimit.yaml
    /// for the full schema and documentation.
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

    #[arg(long, default_value_t = 2048)]
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

    /// Timeout in seconds for receiving the complete HTTP request headers.
    /// Defends against Slowloris attacks that send headers one byte at a time.
    #[arg(long, default_value_t = 10)]
    pub header_timeout_secs: u64,

    /// Timeout in seconds for the client to finish sending the request body.
    /// Defends against RUDY (R-U-Dead-Yet) slow-body attacks.
    #[arg(long, default_value_t = 30)]
    pub body_read_timeout_secs: u64,

    /// Maximum wall-clock time for a single request (headers + body + upstream + response).
    /// Prevents any single request from tying up a connection indefinitely.
    #[arg(long, default_value_t = 120)]
    pub request_timeout_secs: u64,

    #[arg(long = "header-protection-injection")]
    pub header_protection_injection: Option<String>,

    #[arg(long = "dfa-load")]
    pub dfa_load: Option<String>,

    #[arg(long = "real-ip-header")]
    pub real_ip_header: Option<String>,

    #[arg(long = "trusted-proxy-cidrs", value_delimiter = ',')]
    pub trusted_proxy_cidrs: Vec<String>,

    /// WAF enforcement mode. `block` (default) blocks matching requests; `silent` logs
    /// detections without blocking, useful for tuning rule sets in production.
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
}

impl Cli {
    pub fn libinjection_sqli_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_sqli
    }

    pub fn libinjection_xss_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_xss
    }

    /// Effective rate limit: CLI flag beats file config, file config beats built-in default (240).
    #[must_use]
    pub fn effective_rate_limit(&self, file_config: Option<u32>) -> u32 {
        self.rate_limit_per_minute
            .or(file_config)
            .unwrap_or(240)
    }
}

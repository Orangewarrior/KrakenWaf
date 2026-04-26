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

    #[arg(long, default_value_t = 2048)]
    pub max_connections: usize,

    /// Maximum upstream response body to buffer (bytes). Prevents an upstream returning
    /// an unbounded body from exhausting WAF memory. Default: 100 MiB.
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
    pub max_upstream_response_bytes: usize,

    #[arg(long, default_value_t = 30)]
    pub connection_timeout_secs: u64,

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

}

impl Cli {
    pub fn libinjection_sqli_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_sqli
    }

    pub fn libinjection_xss_enabled(&self) -> bool {
        self.enable_libinjection || self.enable_libinjection_xss
    }
}

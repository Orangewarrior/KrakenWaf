
use clap::{ArgAction, Parser};
use std::net::SocketAddr;

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

    #[arg(long, action = ArgAction::SetTrue)]
    pub enable_libinjection: bool,

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

    #[arg(long, default_value_t = 30)]
    pub connection_timeout_secs: u64,
}

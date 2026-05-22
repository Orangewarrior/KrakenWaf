
use crate::{
    allowpaths::AllowPathConfig,
    cli::{Cli, WafMode},
    logging::LoggingHandles,
    metrics::WafMetrics,
    proxy::ProxyClient,
    response_headers::ResponseHeaderPolicy,
    storage::SqliteStore,
    waf::WafEngine,
};
use bytes::Bytes;
use dashmap::DashMap;
use std::{
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
};

#[derive(Clone)]
pub struct AppState {
    pub cli: Cli,
    pub waf: Arc<WafEngine>,
    pub proxy: Arc<ProxyClient>,
    pub store: Arc<SqliteStore>,
    pub logging: Arc<LoggingHandles>,
    pub metrics: Arc<WafMetrics>,
    pub rules_dir: PathBuf,
    pub block_response_body: Option<Bytes>,
    pub block_response_content_type: String,
    pub response_header_policy: Arc<ResponseHeaderPolicy>,
    pub mode: WafMode,
    pub allow_path_config: Option<AllowPathConfig>,
    /// Tracks the number of in-flight requests per source IP for per-IP
    /// concurrency limiting. Entries are lazily created on first request.
    pub ip_connections: Arc<DashMap<String, Arc<AtomicUsize>>>,
    /// Maximum simultaneous in-flight requests accepted from a single IP.
    /// 0 disables the per-IP concurrency cap.
    pub max_coroutines_per_ip: usize,
    /// Global in-flight request-body byte counter for memory backpressure.
    pub inflight_body_bytes: Arc<AtomicUsize>,
    /// Hard cap on total in-flight body bytes globally. 0 = disabled.
    pub max_inflight_body_bytes: usize,
    /// Per-IP in-flight body-byte counters. Guards per-IP memory fairness.
    pub ip_body_bytes: Arc<DashMap<String, Arc<AtomicUsize>>>,
    /// Per-IP hard cap on in-flight body bytes. 0 = disabled.
    pub max_per_ip_body_bytes: usize,
    /// Resolved per-frame body inactivity timeout (seconds). Anti-Slowloris.
    /// 0 disables the timeout. Resolved from CLI flag, then YAML, then 30 s.
    pub body_frame_timeout_secs: u64,
}

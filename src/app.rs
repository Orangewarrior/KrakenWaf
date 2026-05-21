
use crate::{
    allowpaths::AllowPathConfig,
    cli::{Cli, WafMode},
    logging::LoggingHandles,
    metrics::WafMetrics,
    network_config::NetworkConfig,
    proxy::ProxyClient,
    response_headers::ResponseHeaderPolicy,
    scoring::ScoringConfig,
    storage::SqliteStore,
    waf::WafEngine,
};
use bytes::Bytes;
use dashmap::DashMap;
use std::{
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
};
use tokio_rustls::TlsAcceptor;

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
    pub network: Arc<NetworkConfig>,
    pub tls_acceptor: Option<Arc<tokio::sync::RwLock<TlsAcceptor>>>,
    pub scoring: Arc<ScoringConfig>,
    /// Per-client-IP in-flight request counter. Used by `max_coroutines_per_ip` enforcement.
    pub ip_connections: Arc<DashMap<String, Arc<AtomicUsize>>>,
    /// 0 = unlimited (feature disabled).
    pub max_coroutines_per_ip: usize,
}

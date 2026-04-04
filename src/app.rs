
use crate::{
    cli::Cli,
    logging::LoggingHandles,
    metrics::WafMetrics,
    proxy::ProxyClient,
    storage::SqliteStore,
    waf::WafEngine,
};
use bytes::Bytes;
use std::path::PathBuf;
use std::sync::Arc;

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
}


use crate::{
    allowpaths::AllowPathConfig,
    banning::BanManager,
    cli::{Cli, WafMode},
    geo::GeoIpReader,
    limits::MemoryLimits,
    logging::LoggingHandles,
    metrics::WafMetrics,
    proxy::ProxyClient,
    response_headers::ResponseHeaderPolicy,
    storage::SqliteStore,
    waf::WafEngine,
    websocket::WebSocketControl,
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
    /// Expected bearer token for the dedicated observability listener. Resolved
    /// once at startup from `BEARER_PASSWORD` (file-first, then env; see
    /// [`crate::secrets::load_secret`]). When `None` the bearer gate is disabled
    /// and observability is protected by the IP allowlist alone. A non-loopback
    /// observability bind without either gate is rejected at startup. Never
    /// logged — only `"****"` is.
    pub metrics_auth_token: Option<Arc<str>>,
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
    /// Resolved client-connection timeout (seconds). Bounds how long a single
    /// accepted connection may stay open. Resolved from `--connection-timeout-secs`,
    /// then `conf/ratelimit.yaml`, then the built-in 30 s default.
    pub connection_timeout_secs: u64,
    /// Resolved TLS-handshake timeout (seconds). Anti-Slowloris guard on the
    /// accept path. 0 disables the bound. Resolved from CLI flag, then YAML,
    /// then 10 s. Only consulted in TLS mode.
    pub tls_handshake_timeout_secs: u64,
    /// Resolved HTTP/1 request-header read timeout. Anti-Slowloris guard after
    /// TCP accept/TLS handshake and before request-level rate limiting.
    /// 0 disables the bound. Resolved from CLI, then YAML, then 10 s.
    pub http_header_read_timeout_secs: u64,
    /// Memory-pressure limits resolved at startup (YAML > CLI > defaults).
    /// Read-only at runtime; reloading requires a process restart. Carries
    /// the 2.29.0 knobs (`max_decompress_ratio`, RAM-derived
    /// `max_connections`, etc) that the older `max_inflight_*` fields above
    /// do not cover.
    pub memory_limits: Arc<MemoryLimits>,
    /// BAN-list manager. Resolved from `conf/banning.yaml` at startup.
    /// When `Banning_mode: false` (or the file is absent) the manager is
    /// inert and every method is a cheap no-op.
    pub ban_manager: Arc<BanManager>,
    /// Optional `GeoIP` reader backed by `db/geo/GeoLite2-City.mmdb`.
    /// `None` when the database file is absent or fails to open.
    pub geo_reader: Option<Arc<GeoIpReader>>,
    /// WebSocket control policy resolved from `conf/websocket.yaml`. When
    /// `enable_ws_control` is false the limits are inert and `ws://` / `wss://`
    /// upgrades are tunneled transparently.
    pub ws_control: Arc<WebSocketControl>,
}

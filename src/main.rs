mod allowpaths;
mod app;
mod banner;
mod banning;
mod body_decode;
mod cli;
mod cmc;
mod error;
mod ffi;
mod geo;
mod limits;
mod logging;
mod metrics;
mod multipart_extract;
mod proxy;
mod ratelimit_config;
mod response_headers;
mod rules;
mod server;
mod storage;
mod tls;
#[allow(dead_code)]
mod update;
mod waf;

use anyhow::{Context, Result};
use app::AppState;
use banning::BanManager;
use bytes::Bytes;
use clap::Parser;
use cli::{Cli, WalMode};
use cmc::{CmcConfig, CmcManagerBuilder};
use dashmap::DashMap;
use limits::MemoryLimits;
use metrics::WafMetrics;
use ratelimit_config::RateLimitConfig;
use response_headers::ResponseHeaderPolicy;
use std::{
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
};
use tracing::{error, info};
use waf::rate_limit::{PersistenceMode, RateLimiter};

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigpipe = signal(SignalKind::pipe()).expect("failed to register SIGPIPE handler");
        tokio::spawn(async move {
            loop {
                sigpipe.recv().await;
            }
        });
    }

    let mut cli = Cli::parse();
    let root_dir = std::env::current_dir()?;

    // ── Memory-pressure limits ───────────────────────────────────────────────
    // Loaded before anything else allocates inspection buffers so subsequent
    // construction can read the resolved values straight off `cli`.
    let memory_limits = Arc::new(MemoryLimits::load(&root_dir)?);
    if cli.max_body_bytes == 0 {
        cli.max_body_bytes = memory_limits.max_request_body_buffered_bytes;
    }
    if cli.max_upstream_response_bytes == 0 {
        cli.max_upstream_response_bytes = memory_limits.max_response_body_buffered_bytes;
    }
    if cli.max_connections == 0 {
        cli.max_connections = memory_limits.effective_max_connections(None);
    }

    println!("{}", banner::banner());

    let logging = Arc::new(logging::init_logging(&root_dir, cli.verbose)?);
    let response_header_policy = Arc::new(match cli.header_protection_injection.as_deref() {
        Some(path) => ResponseHeaderPolicy::from_file(&PathBuf::from(path))?,
        None => ResponseHeaderPolicy::default(),
    });
    let metrics = Arc::new(WafMetrics::default());
    let rules_root = PathBuf::from(&cli.rules_dir);
    let rules = Arc::new(rules::RuleSet::from_dir(&rules_root)?);
    let cmc_config = match cli.cmc_load.as_deref() {
        Some(path) => CmcConfig::from_file(&PathBuf::from(path))?,
        None => CmcConfig::default(),
    };
    // Resolve detection-engine globals before moving cmc_config into the
    // builder. CLI flag > cmc/config.yaml `global-options` > built-in default.
    let effective_anomaly_threshold =
        cmc_config.effective_anomaly_threshold(cli.anomaly_threshold);
    let effective_max_inspection_ms =
        cmc_config.effective_max_inspection_ms(cli.max_inspection_ms);
    let cmc_manager = Arc::new(
        CmcManagerBuilder::new(cmc_config)
            .vectorscan_enabled(cli.enable_vectorscan)
            .rules_dir(rules_root.clone())
            .build(),
    );
    let store = Arc::new(storage::SqliteStore::new(&root_dir).await?);

    // ── GeoIP reader ─────────────────────────────────────────────────────────
    // Respects conf/update.yaml `maxmind-geo.active`. When false, geo lookup
    // is disabled and country/continent_name are saved as empty strings.
    let geo_reader: Option<Arc<geo::GeoIpReader>> = {
        let update_config_path = root_dir.join(update::DEFAULT_UPDATE_CONFIG);
        let geo_active = update::load_update_config(&update_config_path)
            .map(|c| c.maxmind_geo.active)
            .unwrap_or(true);

        if geo_active {
            let geo_db_path = root_dir.join("db/geo/GeoLite2-City.mmdb");
            if geo_db_path.exists() {
                match geo::GeoIpReader::builder(&geo_db_path).build() {
                    Ok(reader) => {
                        info!(
                            target: "krakenwaf",
                            path = %geo_db_path.display(),
                            "GeoLite2-City database loaded — GeoIP enrichment active"
                        );
                        Some(Arc::new(reader))
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "krakenwaf",
                            path = %geo_db_path.display(),
                            error = %err,
                            "failed to open GeoLite2-City.mmdb; GeoIP enrichment disabled"
                        );
                        None
                    }
                }
            } else {
                info!(
                    target: "krakenwaf",
                    path = %geo_db_path.display(),
                    "GeoLite2-City.mmdb not found; GeoIP enrichment disabled. \
                     Run soldier_update --geo-update after configuring conf/update.yaml."
                );
                None
            }
        } else {
            info!(
                target: "krakenwaf",
                "GeoIP enrichment disabled (maxmind-geo.active: false in conf/update.yaml)"
            );
            None
        }
    };

    // ── Rate-limit configuration ──────────────────────────────────────────────

    let rl_config = match cli.ratelimit_by_file_conf.as_deref() {
        Some(path) => RateLimitConfig::load_from(&PathBuf::from(path))
            .with_context(|| format!("--ratelimit-by-file-conf: failed to load '{path}'"))?,
        None => RateLimitConfig::load(&root_dir)?,
    };
    let effective_limit = rl_config.effective_rate_limit(cli.rate_limit_per_minute);

    let rate_limiter = Arc::new(build_rate_limiter(&cli, &rl_config, effective_limit, &root_dir).await?);

    // ── BAN list manager ──────────────────────────────────────────────────────

    let ban_manager = build_ban_manager(&root_dir, rate_limiter.as_ref())?;

    // ── WAF engine ────────────────────────────────────────────────────────────

    let waf = Arc::new(waf::WafEngineFactory::create(waf::WafEngineConfig {
        rules,
        rate_limiter,
        blocklist_ip_enabled: cli.blocklist_ip,
        libinjection_sqli_enabled: cli.libinjection_sqli_enabled(),
        libinjection_xss_enabled: cli.libinjection_xss_enabled(),
        vectorscan_enabled: cli.enable_vectorscan,
        metrics: metrics.clone(),
        cmc_manager: cmc_manager.clone(),
        anomaly_threshold: effective_anomaly_threshold,
        max_inspection_ms: effective_max_inspection_ms,
    })?);
    let proxy = Arc::new(proxy::ProxyClient::new(
        &cli.upstream,
        cli.upstream_timeout_secs,
        cli.allow_private_upstream,
        Some(cli.internal_header_name.clone()),
    )?);
    let (block_response_body, block_response_content_type) =
        load_block_message(cli.blockmsg.as_deref(), &root_dir)?;

    let allow_path_config = match cli.allow_paths_file.as_deref() {
        Some(path) => Some(
            allowpaths::load_and_validate(&PathBuf::from(path), &root_dir)
                .with_context(|| format!("--allow-paths: failed to load '{path}'"))?,
        ),
        None => None,
    };

    let state = Arc::new(AppState {
        mode: cli.mode,
        allow_path_config,
        cli: cli.clone(),
        waf,
        proxy,
        store,
        logging,
        metrics,
        rules_dir: rules_root.clone(),
        block_response_body,
        block_response_content_type,
        response_header_policy,
        ip_connections: Arc::new(DashMap::new()),
        max_coroutines_per_ip: rl_config.max_coroutines_per_ip,
        inflight_body_bytes: Arc::new(AtomicUsize::new(0)),
        max_inflight_body_bytes: rl_config
            .effective_max_inflight_body_bytes(cli.max_inflight_body_bytes),
        ip_body_bytes: Arc::new(DashMap::new()),
        max_per_ip_body_bytes: rl_config
            .effective_max_per_ip_body_bytes(cli.max_per_ip_body_bytes),
        body_frame_timeout_secs: rl_config
            .effective_body_frame_timeout_secs(cli.body_frame_timeout_secs),
        memory_limits: memory_limits.clone(),
        ban_manager,
        geo_reader,
    });

    // Build TLS store once; clone it for both the SIGHUP handler and the server.
    let tls_store = if cli.no_tls {
        None
    } else {
        Some(tls::TlsConfigStore::new(PathBuf::from(&cli.sni_map))?)
    };

    spawn_rule_reload(state.clone(), tls_store.clone());

    info!(
        target: "krakenwaf",
        libinjection_sqli_enabled = cli.libinjection_sqli_enabled(),
        libinjection_xss_enabled = cli.libinjection_xss_enabled(),
        vectorscan_enabled = cli.enable_vectorscan,
        blocklist_ip_enabled = cli.blocklist_ip,
        cmc_config_loaded = cli.cmc_load.is_some(),
        mode = ?cli.mode,
        allow_paths_file = ?cli.allow_paths_file,
        no_tls = cli.no_tls,
        upstream = %cli.upstream,
        rate_limit_per_minute = effective_limit,
        max_coroutines_per_ip = rl_config.max_coroutines_per_ip,
        redis_backend = rl_config.redis.is_some(),
        max_body_bytes = cli.max_body_bytes,
        max_upstream_response_bytes = cli.max_upstream_response_bytes,
        max_connections = cli.max_connections,
        max_decompress_ratio = memory_limits.max_decompress_ratio,
        "KrakenWaf initialized"
    );

    if cli.no_tls {
        server::run_plain(cli.listen, state).await
    } else {
        let store = tls_store.expect("tls_store is Some when !cli.no_tls");
        server::run(cli.listen, store, state).await
    }
}

/// Build the BAN-list manager. Reuses the rate-limiter's Redis pool when
/// configured (distributed); otherwise opens a local `SQLite` store under
/// `logs/db/banning.db` (single-node, durable).
fn build_ban_manager(
    root_dir: &std::path::Path,
    rate_limiter: &RateLimiter,
) -> Result<Arc<BanManager>> {
    let cfg = banning::BanConfig::load(root_dir)
        .context("failed to load conf/banning.yaml")?;

    if !cfg.enabled {
        info!(target: "krakenwaf", "banning subsystem disabled (Banning_mode: false or conf/banning.yaml absent)");
        return Ok(BanManager::disabled());
    }

    if let Some(pool) = rate_limiter.redis_pool() {
        info!(
            target: "krakenwaf",
            tolerance_block_count = cfg.tolerance_block_count,
            ban_wait_secs = cfg.ban_wait_time.as_secs(),
            security_scanners = cfg.security_scanners,
            "banning subsystem initialised (Redis backend, sharing rate-limiter pool)"
        );
        Ok(BanManager::new_redis(cfg, pool, "krakenwaf:ban"))
    } else {
        info!(
            target: "krakenwaf",
            tolerance_block_count = cfg.tolerance_block_count,
            ban_wait_secs = cfg.ban_wait_time.as_secs(),
            security_scanners = cfg.security_scanners,
            "banning subsystem initialised (SQLite backend at logs/db/banning.db)"
        );
        BanManager::new_sqlite(cfg, root_dir)
            .context("failed to initialise SQLite ban store")
    }
}

/// Build the rate limiter: Redis if configured, otherwise local GCRA.
async fn build_rate_limiter(
    cli: &Cli,
    rl_config: &RateLimitConfig,
    effective_limit: u32,
    root_dir: &std::path::Path,
) -> Result<RateLimiter> {
    if let Some(redis_cfg) = &rl_config.redis {
        info!(target: "krakenwaf", url = %redis_cfg.url, "using Redis rate-limiter backend");
        return RateLimiter::new_redis(
            &redis_cfg.url,
            effective_limit,
            redis_cfg.window_secs,
            &redis_cfg.key_prefix,
            redis_cfg.pool_size,
            redis_cfg.ca_cert_path.as_deref(),
        )
        .await
        .context("failed to initialise Redis rate-limiter");
    }

    let snapshot_path = rate_limit_snapshot_path(root_dir, cli.wal_mode);
    let persistence = match cli.wal_mode {
        WalMode::Sqlite => PersistenceMode::Sqlite,
        WalMode::Bincode => PersistenceMode::Bincode,
    };
    RateLimiter::new(effective_limit, std::time::Duration::from_secs(60), &snapshot_path, persistence)
        .context("failed to initialise local GCRA rate-limiter")
}

fn spawn_rule_reload(state: Arc<AppState>, tls_store: Option<tls::TlsConfigStore>) {
    #[cfg(unix)]
    {
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(sig) => sig,
                Err(err) => {
                    error!(target: "krakenwaf", "failed to register SIGHUP handler: {err}");
                    return;
                }
            };
            while sighup.recv().await.is_some() {
                match state.waf.reload_from_dir(&state.rules_dir).await {
                    Ok(()) => info!(target: "krakenwaf", "rules hot-reloaded successfully"),
                    Err(err) => error!(target: "krakenwaf", "rule reload failed: {err:#}"),
                }
                // Hot-reload TLS certificates if a TLS store is active.
                if let Some(ref store) = tls_store {
                    match store.reload() {
                        Ok(()) => info!(target: "krakenwaf", "TLS certificates hot-reloaded"),
                        Err(err) => error!(target: "krakenwaf", "TLS cert reload failed: {err:#}"),
                    }
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = (state, tls_store);
    }
}

fn rate_limit_snapshot_path(root: &std::path::Path, mode: WalMode) -> PathBuf {
    let dir = root.join("tmp_cache");
    match mode {
        WalMode::Sqlite => dir.join("rate_limit_state.db"),
        WalMode::Bincode => dir.join("rate_limit_state.bin"),
    }
}

fn load_block_message(path: Option<&str>, root: &std::path::Path) -> Result<(Option<Bytes>, String)> {
    match path {
        Some(raw) => {
            let canonical = std::fs::canonicalize(raw)
                .with_context(|| format!("--blockmsg: cannot resolve path '{raw}'"))?;
            anyhow::ensure!(
                canonical.starts_with(root),
                "--blockmsg path '{}' is outside the allowed root '{}'; \
                 place the file inside the KrakenWaf working directory",
                canonical.display(),
                root.display()
            );
            let content = std::fs::read(&canonical)?;
            let ext = canonical
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let content_type = match ext.as_str() {
                "html" | "htm" => "text/html; charset=utf-8",
                "json" => "application/json",
                _ => "text/plain; charset=utf-8",
            };
            Ok((Some(Bytes::from(content)), content_type.to_string()))
        }
        None => Ok((None, "text/plain; charset=utf-8".to_string())),
    }
}

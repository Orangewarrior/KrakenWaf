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
mod proxy_config;
mod ratelimit_config;
mod response_headers;
mod rorschach;
mod rule_management;
mod rules;
mod secrets;
mod server;
mod storage;
mod subcommands;
mod tls;
#[allow(dead_code)]
mod update;
mod waf;
mod websocket;

use anyhow::{Context, Result};
use app::AppState;
use banning::BanManager;
use bytes::Bytes;
use clap::Parser;
use cli::{Cli, WalMode};
use cmc::{CmcConfig, CmcController};
use dashmap::DashMap;
use limits::MemoryLimits;
use metrics::WafMetrics;
use ratelimit_config::RateLimitConfig;
use response_headers::ResponseHeaderPolicy;
use std::{
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
};
use tracing::{error, info, warn};
use waf::rate_limit::{PersistenceMode, RateLimiter};

/// Built-in fallback port for the dedicated observability listener, used when
/// neither `--metrics-port` nor `conf/proxy.yaml`'s `metrics-port` supplies one.
const DEFAULT_METRICS_PORT: u16 = 4343;

/// Built-in fallback port for the dedicated rule-management control-plane
/// listener, used when neither `--rule-management-port` nor
/// `conf/proxy.yaml`'s `rule_management_port` supplies one.
const DEFAULT_RULE_MANAGEMENT_PORT: u16 = 4342;

/// Secret name for the observability bearer token. Resolved file-first
/// (`BEARER_PASSWORD_FILE` → `/run/secrets/krakenwaf/BEARER_PASSWORD`
/// → the `BEARER_PASSWORD` env var) so credentials are never hard-coded.
/// systemd should provision it via `LoadCredential=` (see `deploy/systemd`).
const BEARER_PASSWORD_SECRET: &str = "BEARER_PASSWORD";

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

    // ── Administrative sub-commands (config/rules validate, config dump) ──────
    // When a sub-command is present we run it and exit without starting any
    // listener. Used for fail-fast pre-flight checks in CI / Kubernetes init
    // containers and for redacted effective-config dumps in production support.
    if let Some(command) = cli.command.clone() {
        // Print a concise error chain (no Rust backtrace) and exit non-zero so
        // the sub-commands behave like a well-mannered CLI / CI gate.
        if let Err(err) = subcommands::run(command, &cli, &root_dir) {
            eprintln!("{err:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    // ── Proxy configuration file (--external-proxy-conf) ──────────────────────
    // Overlay conf/proxy.yaml onto the proxy-related CLI flags *before* anything
    // reads them, so the resolved values flow through the rest of startup
    // (listener, upstream, TLS store, block page, response headers). An
    // explicitly-passed flag still wins; an empty YAML field keeps the WAF's
    // built-in default for that knob.
    let external_proxy_conf = cli.external_proxy_conf.clone();
    if let Some(path) = external_proxy_conf.as_deref() {
        let proxy_cfg = proxy_config::ProxyConfig::load_from(&PathBuf::from(path))
            .with_context(|| format!("--external-proxy-conf: failed to load '{path}'"))?;
        proxy_cfg.merge_into(&mut cli, &|flag| proxy_config::cli_flag_present(flag));
    }

    // ── Memory-pressure + connection limits ──────────────────────────────────
    // The rate-limit config is loaded here (not later) because the connection
    // and body-byte caps now resolve through it. Priority for each cap:
    // explicit CLI flag → conf/ratelimit.yaml → memory-limits
    // (rules/cmc/config.yaml) → built-in default. Resolved before anything
    // allocates inspection buffers so construction reads the values off `cli`.
    let memory_limits = Arc::new(MemoryLimits::load(&root_dir)?);
    let rl_config = match cli.ratelimit_by_file_conf.as_deref() {
        Some(path) => RateLimitConfig::load_from(&PathBuf::from(path))
            .with_context(|| format!("--ratelimit-by-file-conf: failed to load '{path}'"))?,
        None => RateLimitConfig::load(&root_dir)?,
    };
    cli.max_body_bytes = rl_config.effective_max_body_bytes(
        cli.max_body_bytes,
        memory_limits.max_request_body_buffered_bytes,
    );
    cli.max_upstream_response_bytes = rl_config.effective_max_upstream_response_bytes(
        cli.max_upstream_response_bytes,
        memory_limits.max_response_body_buffered_bytes,
    );
    cli.max_connections = rl_config.effective_max_connections(
        cli.max_connections,
        memory_limits.effective_max_connections(None),
    );

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
    // Wrap the CMC manager in a controller so the rule-management control plane
    // can toggle modules in real time (atomic hot-swap of the live manager).
    let cmc_manager = Arc::new(CmcController::new(
        cmc_config,
        cli.enable_vectorscan,
        Some(rules_root.clone()),
    ));
    let store = Arc::new(storage::SqliteStore::new(&root_dir).await?);

    // ── GeoIP reader ─────────────────────────────────────────────────────────
    // Respects conf/update.yaml `maxmind-geo.active`. When false, geo lookup
    // is disabled and country/continent_name are saved as empty strings.
    let geo_reader: Option<Arc<geo::GeoIpReader>> = {
        let update_config_path = root_dir.join(update::DEFAULT_UPDATE_CONFIG);
        let geo_active = update::load_update_config(&update_config_path)
            .map_or(true, |c| c.maxmind_geo.active);

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
    // `rl_config` was loaded earlier (it also drives the connection/body-byte
    // caps); here we only derive the per-minute request budget from it.
    let effective_limit = rl_config.effective_rate_limit(cli.rate_limit_per_minute);

    let rate_limiter =
        Arc::new(build_rate_limiter(&cli, &rl_config, effective_limit, &root_dir, &metrics).await?);

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
        cli.upstream_ca.as_deref(),
    )?);
    let (block_response_body, block_response_content_type) =
        load_block_message(cli.blockmsg.as_deref(), &root_dir)?;

    // ── WebSocket control policy ──────────────────────────────────────────────
    // Loaded every start from conf/websocket.yaml (or --websocket-conf). Default
    // ships enabled with conservative limits; enable_ws_control: false makes it
    // a transparent tunnel.
    let ws_config = match cli.websocket_conf.as_deref() {
        Some(path) => websocket::WebSocketConfig::load_from(&PathBuf::from(path))
            .with_context(|| format!("--websocket-conf: failed to load '{path}'"))?,
        None => websocket::WebSocketConfig::load(&root_dir)?,
    };
    let ws_control = Arc::new(websocket::WebSocketControl::new(ws_config));

    let allow_path_config = match cli.allow_paths_file.as_deref() {
        Some(path) => Some(
            allowpaths::load_and_validate(&PathBuf::from(path), &root_dir)
                .with_context(|| format!("--allow-paths: failed to load '{path}'"))?,
        ),
        None => None,
    };

    // Resolve the observability bearer token (file-first, env fallback) so the
    // dedicated metrics/UI port can require `Authorization: Bearer <token>`.
    // When absent the bearer gate stays disabled (IP allowlist only). Startup
    // validation below rejects a non-loopback bind if no allowlist is active.
    let metrics_auth_token: Option<Arc<str>> =
        secrets::load_secret(BEARER_PASSWORD_SECRET).map(Arc::from);
    if metrics_auth_token.is_some() {
        info!(
            target: "krakenwaf",
            "observability bearer-token gate ENABLED (Authorization: Bearer required on the metrics/UI port)"
        );
    } else {
        warn!(
            target: "krakenwaf",
            secret = BEARER_PASSWORD_SECRET,
            "observability bearer-token gate DISABLED: no token provisioned; the metrics/UI port \
             requires an IP allowlist when bound beyond loopback. Set {BEARER_PASSWORD_SECRET} \
             (file or env) to enable bearer authentication"
        );
    }

    // ── Rorschach rule-management control plane ───────────────────────────────
    // Resolve the even/odd Rorschach secrets (file-first, env fallback). When
    // neither is provisioned the control plane stays disabled. A
    // provisioned-but-invalid secret, or an empty/invalid IP allowlist, is a
    // fatal startup error (fail-closed) — the WAF does not run.
    let rule_management = build_rule_management_gate(&cli, &rules_root)?;
    if rule_management.is_some() {
        info!(
            target: "krakenwaf",
            "rule-management control plane ENABLED (Rorschach bearer token + IP allowlist)"
        );
    } else {
        info!(
            target: "krakenwaf",
            secret_even = rorschach::SECRET_EVEN_NAME,
            secret_odd = rorschach::SECRET_ODD_NAME,
            "rule-management control plane DISABLED: Rorschach secrets not provisioned; set both \
             secrets (file or env) to enable real-time CMC rule management"
        );
    }

    // Parse + validate the trusted-proxy CIDRs once, after proxy.yaml has been
    // overlaid onto the CLI. A malformed entry is a hard startup error here
    // rather than a value silently dropped on every request.
    let trusted_proxy_nets = Arc::new(
        proxy::parse_trusted_proxy_cidrs(&cli.trusted_proxy_cidrs)
            .context("--trusted-proxy-cidrs / proxy.yaml trusted_proxy_cidrs is invalid")?,
    );

    let state = Arc::new(AppState {
        mode: cli.mode,
        allow_path_config,
        trusted_proxy_nets,
        metrics_auth_token,
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
        connection_timeout_secs: rl_config
            .effective_connection_timeout_secs(cli.connection_timeout_secs),
        tls_handshake_timeout_secs: rl_config
            .effective_tls_handshake_timeout_secs(cli.tls_handshake_timeout_secs),
        http_header_read_timeout_secs: rl_config
            .effective_http_header_read_timeout_secs(cli.http_header_read_timeout_secs),
        memory_limits: memory_limits.clone(),
        ban_manager,
        geo_reader,
        ws_control,
        rule_management,
    });

    // Resolve and validate the observability bind before opening any listener
    // or spawning background reload tasks. Non-loopback exposure is fail-closed
    // unless bearer authentication or an explicit IP allowlist is active.
    let metrics_port = cli.metrics_port.unwrap_or_else(|| {
        proxy_config::ProxyConfig::load_from(&root_dir.join("conf/proxy.yaml"))
            .ok()
            .and_then(|cfg| cfg.metrics_port)
            .unwrap_or(DEFAULT_METRICS_PORT)
    });
    let metrics_addr = std::net::SocketAddr::new(cli.listen.ip(), metrics_port);
    let rules_snapshot = state.waf.rules_snapshot();
    server::validate_observability_exposure(
        metrics_addr,
        state.metrics_auth_token.is_some(),
        state.allow_path_config.as_ref(),
        &rules_snapshot,
    )?;

    // Build TLS store once; clone it for both the SIGHUP handler and the server.
    let tls_store = if cli.no_tls {
        None
    } else {
        Some(tls::TlsConfigStore::new(PathBuf::from(&cli.sni_map))?)
    };

    spawn_rule_reload(state.clone(), tls_store.clone());
    // Reap idle per-IP counter entries so the concurrency/body-byte maps cannot
    // grow without bound under source-IP rotation (e.g. an IPv6 /64 flood).
    server::spawn_ip_map_janitor(state.clone());

    // ── Observability listener (/metrics + health probes) ─────────────────────
    // Metrics moved off the reverse-proxy port onto a dedicated listener so the
    // Prometheus surface can be firewalled/routed in isolation. Port resolution:
    // --metrics-port → conf/proxy.yaml `metrics-port` → built-in default. It
    // binds the same IP as --listen and, in TLS mode, reuses the listener's TLS
    // store (same certs); under --no-tls it serves plain HTTP.
    if metrics_addr == cli.listen {
        warn!(
            target: "krakenwaf",
            %metrics_addr,
            "metrics-port equals the proxy listen port; observability stays inline on the \
             main port and no separate listener is started"
        );
    } else {
        let obs_state = state.clone();
        if cli.no_tls {
            tokio::spawn(async move {
                if let Err(err) = server::run_metrics_plain(metrics_addr, obs_state).await {
                    error!(target: "krakenwaf", %metrics_addr, "observability listener failed: {err:#}");
                }
            });
        } else {
            let obs_store = tls_store
                .clone()
                .expect("tls_store is Some when !cli.no_tls");
            tokio::spawn(async move {
                if let Err(err) = server::run_metrics(metrics_addr, obs_store, obs_state).await {
                    error!(target: "krakenwaf", %metrics_addr, "observability listener failed: {err:#}");
                }
            });
        }
    }

    // ── Rule-management control-plane listener ────────────────────────────────
    // Started only when the Rorschach control plane is enabled. Mirrors the
    // observability listener: binds the same IP as --listen on a separate port
    // (--rule-management-port → conf/proxy.yaml `rule_management_port` → 4342),
    // reusing the listener TLS certs (plain HTTP under --no-tls). Protected by
    // the IP allowlist (403) and the Rorschach bearer token (401).
    if state.rule_management.is_some() {
        let rm_port = cli.rule_management_port.unwrap_or_else(|| {
            proxy_config::ProxyConfig::load_from(&root_dir.join("conf/proxy.yaml"))
                .ok()
                .and_then(|cfg| cfg.rule_management_port)
                .unwrap_or(DEFAULT_RULE_MANAGEMENT_PORT)
        });
        let rm_addr = std::net::SocketAddr::new(cli.listen.ip(), rm_port);
        if rm_addr == cli.listen || rm_addr == metrics_addr {
            warn!(
                target: "krakenwaf",
                %rm_addr,
                "rule_management_port collides with the proxy listen or metrics port; \
                 the rule-management listener was not started — choose a distinct port"
            );
        } else {
            rule_management::spawn_nonce_janitor(&state);
            let rm_state = state.clone();
            if cli.no_tls {
                tokio::spawn(async move {
                    if let Err(err) = rule_management::run_plain(rm_addr, rm_state).await {
                        error!(target: "krakenwaf", %rm_addr, "rule-management listener failed: {err:#}");
                    }
                });
            } else {
                let rm_store = tls_store
                    .clone()
                    .expect("tls_store is Some when !cli.no_tls");
                tokio::spawn(async move {
                    if let Err(err) = rule_management::run(rm_addr, rm_store, rm_state).await {
                        error!(target: "krakenwaf", %rm_addr, "rule-management listener failed: {err:#}");
                    }
                });
            }
            info!(target: "krakenwaf", %rm_addr, no_tls = cli.no_tls, "rule-management listener bound");
        }
    }

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
        metrics_listen = %metrics_addr,
        rate_limit_per_minute = effective_limit,
        max_coroutines_per_ip = rl_config.max_coroutines_per_ip,
        redis_backend = rl_config.redis.is_some(),
        max_body_bytes = cli.max_body_bytes,
        max_upstream_response_bytes = cli.max_upstream_response_bytes,
        max_connections = cli.max_connections,
        max_decompress_ratio = memory_limits.max_decompress_ratio,
        connection_timeout_secs = state.connection_timeout_secs,
        tls_handshake_timeout_secs = state.tls_handshake_timeout_secs,
        http_header_read_timeout_secs = state.http_header_read_timeout_secs,
        external_proxy_conf = external_proxy_conf.is_some(),
        ws_control_enabled = state.ws_control.enabled(),
        ws_max_connections_per_ip = state.ws_control.config().max_connections_per_ip,
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
    metrics: &Arc<WafMetrics>,
) -> Result<RateLimiter> {
    if let Some(redis_cfg) = &rl_config.redis {
        info!(
            target: "krakenwaf",
            url = %redis_cfg.url,
            fail_open = redis_cfg.fail_open,
            "using Redis rate-limiter backend"
        );
        return RateLimiter::new_redis(
            &redis_cfg.url,
            effective_limit,
            redis_cfg.window_secs,
            &redis_cfg.key_prefix,
            redis_cfg.pool_size,
            redis_cfg.ca_cert_path.as_deref(),
            redis_cfg.fail_open,
            Some(metrics.clone()),
        )
        .await
        .context("failed to initialise Redis rate-limiter");
    }

    let snapshot_path = rate_limit_snapshot_path(root_dir, cli.wal_mode);
    let persistence = match cli.wal_mode {
        WalMode::Sqlite => PersistenceMode::Sqlite,
        WalMode::Postcard => PersistenceMode::Postcard,
    };
    RateLimiter::new(effective_limit, std::time::Duration::from_mins(1), &snapshot_path, persistence)
        .context("failed to initialise local GCRA rate-limiter")
}

/// Resolve the rule-management control-plane access gate.
///
/// Returns `Ok(None)` when neither Rorschach secret is provisioned (feature
/// off). Returns an error — aborting startup, fail-closed — when a secret is
/// provisioned but invalid, only one secret is set, or the IP allowlist is
/// missing/empty/invalid.
fn build_rule_management_gate(
    cli: &Cli,
    rules_root: &std::path::Path,
) -> Result<Option<Arc<rule_management::RuleManagementGate>>> {
    use rorschach::SecretsConfig;

    let secrets = match rorschach::load_secrets().map_err(|e| anyhow::anyhow!(e))? {
        SecretsConfig::Disabled => return Ok(None),
        SecretsConfig::Enabled(secrets) => secrets,
    };

    let allowlist_path = match cli.rule_management_allowlist.as_deref() {
        Some(path) => PathBuf::from(path),
        None => rule_management::default_allowlist_path(rules_root),
    };
    let allowlist = rule_management::load_allowlist(&allowlist_path)
        .context("rule-management IP allowlist failed validation; the control plane cannot start")?;

    let validator = rorschach::RorschachValidator::new(secrets);
    Ok(Some(Arc::new(rule_management::RuleManagementGate {
        validator,
        allowlist,
    })))
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
        WalMode::Postcard => dir.join("rate_limit_state.bin"),
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

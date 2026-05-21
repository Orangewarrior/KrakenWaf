
mod allowpaths;
mod app;
mod banner;
mod cli;
mod error;
mod dfa;
mod ffi;
mod logging;
mod metrics;
mod network_config;
mod proxy;
mod ratelimit_config;
mod response_headers;
mod rules;
mod scoring;
mod server;
mod storage;
mod tls;
mod waf;

use anyhow::{Context, Result};

use app::AppState;
use bytes::Bytes;
use clap::Parser;
use cli::Cli;
use dfa::{DfaConfig, DfaManagerBuilder};
use metrics::WafMetrics;
use network_config::NetworkConfig;
use ratelimit_config::RateLimitConfig;
use response_headers::ResponseHeaderPolicy;
use std::{path::PathBuf, sync::Arc};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default().expect("failed to install rustls CryptoProvider");
    let cli = Cli::parse();
    let root_dir = std::env::current_dir()?;
    let network_config = Arc::new(NetworkConfig::load(&root_dir)?);
    let scoring_config = Arc::new(scoring::ScoringConfig::load(&root_dir)?);
    let rl_config = match cli.ratelimit_by_file_conf.as_deref() {
        Some(path) => RateLimitConfig::load_from(&std::path::PathBuf::from(path))
            .with_context(|| format!("--ratelimit-by-file-conf: failed to load '{path}'"))?,
        None => RateLimitConfig::load(&root_dir)?,
    };
    let effective_rate_limit = cli.effective_rate_limit(rl_config.rate_limit_per_minute);

    println!("{}", banner::banner());

    let logging = Arc::new(logging::init_logging(&root_dir, cli.verbose)?);
    let response_header_policy = Arc::new(match cli.header_protection_injection.as_deref() {
        Some(path) => ResponseHeaderPolicy::from_file(&PathBuf::from(path))?,
        None => ResponseHeaderPolicy::default(),
    });
    let metrics = Arc::new(WafMetrics::default());
    let rules_root = PathBuf::from(&cli.rules_dir);
    let rules = Arc::new(rules::RuleSet::from_dir(&rules_root)?);
    let dfa_config = match cli.dfa_load.as_deref() {
        Some(path) => DfaConfig::from_file(&PathBuf::from(path))?,
        None => DfaConfig::default(),
    };
    let dfa_manager = Arc::new(DfaManagerBuilder::new(dfa_config).build());
    let store = Arc::new(storage::SqliteStore::new(&root_dir).await?);
    let waf = Arc::new(waf::WafEngine::new(
        rules,
        &rl_config,
        effective_rate_limit,
        cli.blocklist_ip,
        cli.libinjection_sqli_enabled(),
        cli.libinjection_xss_enabled(),
        cli.enable_vectorscan,
        root_dir.join("logs").join("db").join("rate_limit_state.json"),
        metrics.clone(),
        dfa_manager.clone(),
    ).await?);
    let proxy = Arc::new(proxy::ProxyClient::new(
        &cli.upstream,
        cli.upstream_timeout_secs,
        cli.allow_private_upstream,
        Some(cli.internal_header_name.clone()),
    )?);
    let (block_response_body, block_response_content_type) = load_block_message(cli.blockmsg.as_deref(), &root_dir)?;

    let allow_path_config = match cli.allow_paths_file.as_deref() {
        Some(path) => Some(allowpaths::load_and_validate(&PathBuf::from(path))
            .with_context(|| format!("--allow-paths: failed to load '{path}'"))?),
        None => None,
    };

    let tls_acceptor_shared = if cli.no_tls {
        None
    } else {
        let tls_config = tls::build_tls_config(PathBuf::from(&cli.sni_map).as_path())?;
        Some(Arc::new(tokio::sync::RwLock::new(TlsAcceptor::from(tls_config))))
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
        network: network_config.clone(),
        tls_acceptor: tls_acceptor_shared.clone(),
        scoring: scoring_config,
        ip_connections: Arc::new(dashmap::DashMap::new()),
        max_coroutines_per_ip: rl_config.max_coroutines_per_ip,
    });

    spawn_rule_reload(state.clone());

    info!(target: "krakenwaf", libinjection_sqli_enabled=cli.libinjection_sqli_enabled(), libinjection_xss_enabled=cli.libinjection_xss_enabled(), vectorscan_enabled=cli.enable_vectorscan, blocklist_ip_enabled=cli.blocklist_ip, dfa_config_loaded=cli.dfa_load.is_some(), mode=?cli.mode, allow_paths_file=?cli.allow_paths_file, no_tls=cli.no_tls, upstream=%cli.upstream, "KrakenWaf initialized");

    if cli.no_tls {
        server::run_plain(cli.listen, state.clone(), shutdown_signal()).await?;
    } else {
        let shared = tls_acceptor_shared.expect("tls_acceptor_shared is Some when !cli.no_tls");
        server::run(cli.listen, shared, state.clone(), shutdown_signal()).await?;
    }

    // Graceful drain: flush rate-limit snapshot and SQLite event queue.
    state.waf.persist_rate_limit().await;
    state.store.flush().await;
    info!(target: "krakenwaf", "KrakenWaf shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;
    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = sigterm.recv() => { tracing::info!(target: "krakenwaf", "received SIGTERM, shutting down"); }
            _ = signal::ctrl_c() => { tracing::info!(target: "krakenwaf", "received SIGINT, shutting down"); }
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await.expect("failed to listen for ctrl-c");
        tracing::info!(target: "krakenwaf", "received SIGINT, shutting down");
    }
}

fn spawn_rule_reload(state: Arc<AppState>) {
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
                    Ok(_) => info!(target: "krakenwaf", "rules hot-reloaded successfully"),
                    Err(err) => error!(target: "krakenwaf", "rule reload failed: {err:#}"),
                }

                // Reload TLS certs if we have a shared acceptor
                if let Some(ref shared_acceptor) = state.tls_acceptor {
                    match tls::build_tls_config(PathBuf::from(&state.cli.sni_map).as_path()) {
                        Ok(new_cfg) => {
                            *shared_acceptor.write().await = TlsAcceptor::from(new_cfg);
                            info!(target: "krakenwaf", "TLS certificates hot-reloaded");
                        }
                        Err(err) => error!(target: "krakenwaf", "TLS cert reload failed: {err:#}"),
                    }
                }
            }
        });
    }
}

fn load_block_message(path: Option<&str>, root: &std::path::Path) -> Result<(Option<Bytes>, String)> {
    match path {
        Some(raw) => {
            // Canonicalize to resolve symlinks and `../` components, then verify the
            // resulting path stays inside the process working directory. Prevents
            // `--blockmsg /etc/shadow` or `--blockmsg ../../secret` from reading
            // arbitrary files even when the CLI is driven by a compromised operator.
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
            let ext = canonical.extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let content_type = match ext.as_str()
            {
                "html" | "htm" => "text/html; charset=utf-8",
                "json" => "application/json",
                _ => "text/plain; charset=utf-8",
            };
            Ok((Some(Bytes::from(content)), content_type.to_string()))
        }
        None => Ok((None, "text/plain; charset=utf-8".to_string())),
    }
}


mod app;
mod banner;
mod cli;
mod error;
mod logging;
mod metrics;
mod proxy;
mod rules;
mod server;
mod storage;
mod tls;
mod waf;

use anyhow::Result;
use app::AppState;
use bytes::Bytes;
use clap::Parser;
use cli::Cli;
use metrics::WafMetrics;
use std::{path::PathBuf, sync::Arc};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default().expect("failed to install rustls CryptoProvider");
    let cli = Cli::parse();
    let root_dir = std::env::current_dir()?;

    println!("{}", banner::banner());

    let logging = Arc::new(logging::init_logging(&root_dir, cli.verbose)?);
    let metrics = Arc::new(WafMetrics::default());
    let rules_root = PathBuf::from(&cli.rules_dir);
    let rules = Arc::new(rules::RuleSet::from_dir(&rules_root)?);
    let store = Arc::new(storage::SqliteStore::new(&root_dir).await?);
    let waf = Arc::new(waf::WafEngine::new(
        rules,
        cli.rate_limit_per_minute,
        cli.blocklist_ip,
        cli.enable_libinjection,
        cli.enable_vectorscan,
        root_dir.join("logs").join("db").join("rate_limit_state.json"),
        metrics.clone(),
    )?);
    let proxy = Arc::new(proxy::ProxyClient::new(
        &cli.upstream,
        cli.upstream_timeout_secs,
        cli.allow_private_upstream,
        Some(cli.internal_header_name.clone()),
    )?);
    let (block_response_body, block_response_content_type) = load_block_message(cli.blockmsg.as_deref())?;

    let state = Arc::new(AppState {
        cli: cli.clone(),
        waf,
        proxy,
        store,
        logging,
        metrics,
        rules_dir: rules_root.clone(),
        block_response_body,
        block_response_content_type,
    });

    spawn_rule_reload(state.clone());

    let tls_config = tls::build_tls_config(PathBuf::from(&cli.sni_map).as_path())?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    info!(target: "krakenwaf", libinjection_enabled=cli.enable_libinjection, vectorscan_enabled=cli.enable_vectorscan, blocklist_ip_enabled=cli.blocklist_ip, upstream=%cli.upstream, "KrakenWaf initialized");

    server::run(cli.listen, tls_acceptor, state).await
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
            }
        });
    }
}

fn load_block_message(path: Option<&str>) -> Result<(Option<Bytes>, String)> {
    match path {
        Some(path) => {
            let content = std::fs::read(path)?;
            let content_type = match std::path::Path::new(path)
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
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

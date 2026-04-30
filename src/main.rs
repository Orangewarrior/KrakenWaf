
mod allowpaths;
mod app;
mod banner;
mod cli;
mod error;
mod dfa;
mod ffi;
mod logging;
mod metrics;
mod proxy;
mod response_headers;
mod rules;
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
use response_headers::ResponseHeaderPolicy;
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
        cli.rate_limit_per_minute,
        cli.blocklist_ip,
        cli.libinjection_sqli_enabled(),
        cli.libinjection_xss_enabled(),
        cli.enable_vectorscan,
        root_dir.join("logs").join("db").join("rate_limit_state.json"),
        metrics.clone(),
        dfa_manager.clone(),
    )?);
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
    });

    spawn_rule_reload(state.clone());

    info!(target: "krakenwaf", libinjection_sqli_enabled=cli.libinjection_sqli_enabled(), libinjection_xss_enabled=cli.libinjection_xss_enabled(), vectorscan_enabled=cli.enable_vectorscan, blocklist_ip_enabled=cli.blocklist_ip, dfa_config_loaded=cli.dfa_load.is_some(), mode=?cli.mode, allow_paths_file=?cli.allow_paths_file, no_tls=cli.no_tls, upstream=%cli.upstream, "KrakenWaf initialized");

    if cli.no_tls {
        server::run_plain(cli.listen, state).await
    } else {
        let tls_config = tls::build_tls_config(PathBuf::from(&cli.sni_map).as_path())?;
        let tls_acceptor = TlsAcceptor::from(tls_config);
        server::run(cli.listen, tls_acceptor, state).await
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

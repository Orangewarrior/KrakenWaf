use clap::Parser;
use krakenwaf::update::{
    default_config_path, load_update_config, log_update_action, log_update_error,
    update_addr_list_from_config_with_reporter, update_kraken_waf_with_config,
    StderrUpdateReporter,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "soldier_update")]
#[command(about = "Isolated KrakenWaf updater")]
struct Cli {
    #[arg(long = "kraken-update")]
    kraken_update: bool,

    /// Address-list or `GeoIP` database to update.
    /// Valid values: spamhaus, blocklist, firehol, maxmind-geo
    #[arg(long = "addr-list")]
    addr_list: Option<String>,

    #[arg(long, default_value = ".")]
    repo_root: PathBuf,

    #[arg(long, default_value = "conf/update.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let reporter = StderrUpdateReporter;
    let config = if cli.config.as_os_str().is_empty() {
        default_config_path()
    } else {
        cli.config
    };

    // Resolve the action/target up front so every code path — including the
    // "no action selected" error — is journalled to logs/updates/lastupdate.jsonl.
    let (action, target): (&str, String) = if cli.kraken_update {
        ("kraken-update", "repository".to_string())
    } else if let Some(addr_list) = cli.addr_list.as_deref() {
        ("addr-list", addr_list.to_string())
    } else {
        log_update_action(
            &cli.repo_root,
            "noop",
            "none",
            "error",
            "no action selected: pass --kraken-update or --addr-list",
        );
        anyhow::bail!("use --kraken-update or --addr-list <spamhaus|blocklist|firehol|maxmind-geo>")
    };

    // Record the start of the action before any network/git work begins.
    log_update_action(
        &cli.repo_root,
        action,
        &target,
        "started",
        &format!(
            "config={}, repo_root={}",
            config.display(),
            cli.repo_root.display()
        ),
    );

    let result = if cli.kraken_update {
        eprintln!(
            "[soldier_update] updating KrakenWaf checkout at {}",
            cli.repo_root.display()
        );
        let update_config = load_update_config(&config)?;
        update_kraken_waf_with_config(&cli.repo_root, &update_config.kraken_waf)
    } else {
        eprintln!(
            "[soldier_update] updating addr-list '{target}' using config {}",
            config.display()
        );
        update_addr_list_from_config_with_reporter(&cli.repo_root, &config, &target, &reporter)
            .await
    };

    // Record the outcome of the action.
    match &result {
        Ok(()) => log_update_action(&cli.repo_root, action, &target, "success", "completed"),
        Err(err) => {
            log_update_action(
                &cli.repo_root,
                action,
                &target,
                "error",
                &format!("{err:#}"),
            );
            log_update_error(&cli.repo_root, err);
        }
    }

    result
}

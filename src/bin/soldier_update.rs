use clap::Parser;
use krakenwaf::update::{
    StderrUpdateReporter, default_config_path, log_update_error,
    update_addr_list_from_config_with_reporter, update_kraken_waf,
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

    let result = if cli.kraken_update {
        eprintln!(
            "[soldier_update] updating KrakenWaf checkout at {}",
            cli.repo_root.display()
        );
        update_kraken_waf(&cli.repo_root)
    } else if let Some(addr_list) = cli.addr_list.as_deref() {
        eprintln!(
            "[soldier_update] updating addr-list '{addr_list}' using config {}",
            config.display()
        );
        update_addr_list_from_config_with_reporter(&cli.repo_root, &config, addr_list, &reporter)
            .await
    } else {
        anyhow::bail!("use --kraken-update or --addr-list <spamhaus|blocklist|firehol|maxmind-geo>")
    };

    if let Err(err) = &result {
        log_update_error(&cli.repo_root, err);
    }

    result
}

use clap::Parser;
use krakenwaf::update::{
    default_config_path, log_update_error, update_addr_list_from_config,
    update_kraken_waf, update_maxmind_geo_from_config,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "soldier_update")]
#[command(about = "Isolated KrakenWaf updater")]
struct Cli {
    #[arg(long = "kraken-update")]
    kraken_update: bool,

    #[arg(long = "addr-list")]
    addr_list: Option<String>,

    /// Download and extract the MaxMind GeoLite2-City database to db/geo/.
    /// Requires account_id and key configured in conf/update.yaml.
    #[arg(long = "geo-update")]
    geo_update: bool,

    #[arg(long, default_value = ".")]
    repo_root: PathBuf,

    #[arg(long, default_value = "conf/update.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = if cli.config.as_os_str().is_empty() {
        default_config_path()
    } else {
        cli.config
    };

    let result = if cli.kraken_update {
        update_kraken_waf(&cli.repo_root)
    } else if let Some(addr_list) = cli.addr_list.as_deref() {
        update_addr_list_from_config(&cli.repo_root, &config, addr_list).await
    } else if cli.geo_update {
        update_maxmind_geo_from_config(&cli.repo_root, &config).await
    } else {
        anyhow::bail!(
            "use --kraken-update, --addr-list <spamhaus|blocklist|firehol>, or --geo-update"
        )
    };

    if let Err(err) = &result {
        log_update_error(&cli.repo_root, err);
    }

    result
}

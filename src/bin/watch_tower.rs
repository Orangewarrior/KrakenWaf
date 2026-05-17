use clap::Parser;
use krakenwaf::update::{default_config_path, run_watch_tower};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "watch_tower")]
#[command(about = "KrakenWaf update scheduler")]
struct Cli {
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
    run_watch_tower(cli.repo_root, config).await
}

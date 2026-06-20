use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::{Datelike, Local, Timelike};
use hickory_resolver::{
    config::{LookupIpStrategy, ResolveHosts, ResolverConfig},
    name_server::TokioConnectionProvider,
    ResolveError, Resolver, TokioResolver,
};
use reqwest::{dns, Client};
use serde::Deserialize;
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write as _,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};
use url::Url;

pub const DEFAULT_UPDATE_CONFIG: &str = "conf/update.yaml";
const ADDR_RULES_DIR: &str = "rules/addr";
const ERROR_LOG: &str = "logs/console_local/errors.txt";
/// Structured, append-only journal of every update action (one JSON object per
/// line). Mirrors `logs/console_local/errors.txt` but in machine-readable JSONL
/// so dashboards / `jq` can track what the updater did and when.
const UPDATE_ACTION_LOG: &str = "logs/updates/lastupdate.jsonl";
const ADDR_LIST_DOWNLOAD_TIMEOUT: Duration = Duration::from_mins(5);
const GEO_DB_DIR: &str = "db/geo";
const GEO_DB_FILE: &str = "GeoLite2-City.mmdb";
const DOWNLOAD_PROGRESS_MIN_INTERVAL: Duration = Duration::from_secs(1);
const DOWNLOAD_PROGRESS_MIN_BYTES: u64 = 5 * 1024 * 1024;

/// Hard ceiling on a single address-list download (Firehol / Spamhaus /
/// blocklist text files). Real lists are a few MB at most; this bounds memory
/// if a mirror is compromised or MITM'd and streams an unbounded body or lies
/// about `Content-Length`.
const MAX_ADDR_LIST_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Hard ceiling on the `MaxMind` GeoLite2-City archive download. The City DB is
/// ~70 MB uncompressed; the gzip is smaller. Generous but bounded.
const MAX_GEO_DB_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// Hard ceiling on a single tar entry unpacked from the `GeoLite2` archive — a
/// decompression-bomb guard equivalent to the one the request-body path
/// already applies (`body_decode`); the updater must not be the weak link.
const MAX_GEO_DB_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;

static QUAD9_DOT_DNS_RESOLVER: LazyLock<Arc<Quad9DotDnsResolver>> =
    LazyLock::new(|| Arc::new(Quad9DotDnsResolver::new()));

#[derive(Clone)]
struct Quad9DotDnsResolver {
    resolver: Arc<TokioResolver>,
}

impl Quad9DotDnsResolver {
    fn new() -> Self {
        let mut builder = Resolver::builder_with_config(
            ResolverConfig::quad9_tls(),
            TokioConnectionProvider::default(),
        );
        let opts = builder.options_mut();
        opts.validate = true;
        opts.edns0 = true;
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;

        Self {
            resolver: Arc::new(builder.build()),
        }
    }

    async fn lookup_ip(&self, host: &str) -> std::result::Result<Vec<IpAddr>, ResolveError> {
        let lookup = self.resolver.lookup_ip(host).await?;
        Ok(lookup.into_iter().collect())
    }
}

impl dns::Resolve for Quad9DotDnsResolver {
    fn resolve(&self, name: dns::Name) -> dns::Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let addrs = resolver
                .lookup_ip(name.as_str())
                .await?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect::<Vec<_>>();
            Ok(Box::new(addrs.into_iter()) as dns::Addrs)
        })
    }
}

fn quad9_dot_dns_resolver() -> Arc<Quad9DotDnsResolver> {
    Arc::clone(&QUAD9_DOT_DNS_RESOLVER)
}

fn update_http_client() -> Result<Client> {
    Ok(Client::builder()
        .use_rustls_tls()
        .dns_resolver(quad9_dot_dns_resolver())
        .timeout(ADDR_LIST_DOWNLOAD_TIMEOUT)
        .build()?)
}

#[derive(Debug, Clone, Copy)]
pub enum UpdateEvent<'a> {
    Step {
        message: &'a str,
    },
    DownloadStarted {
        url: &'a Url,
        destination: Option<&'a Path>,
    },
    DownloadProgress {
        url: &'a Url,
        downloaded: u64,
        total: Option<u64>,
    },
    DownloadFinished {
        url: &'a Url,
        bytes: u64,
    },
    FileSaved {
        path: &'a Path,
        bytes: u64,
    },
}

pub trait UpdateReporter {
    fn report(&self, event: UpdateEvent<'_>);
}

#[derive(Debug, Default)]
pub struct NoopUpdateReporter;

impl UpdateReporter for NoopUpdateReporter {
    fn report(&self, _event: UpdateEvent<'_>) {}
}

#[derive(Debug, Default)]
pub struct StderrUpdateReporter;

impl UpdateReporter for StderrUpdateReporter {
    fn report(&self, event: UpdateEvent<'_>) {
        match event {
            UpdateEvent::Step { message } => eprintln!("[soldier_update] {message}"),
            UpdateEvent::DownloadStarted { url, destination } => {
                if let Some(destination) = destination {
                    eprintln!(
                        "[soldier_update] downloading {url} -> {}",
                        destination.display()
                    );
                } else {
                    eprintln!("[soldier_update] downloading {url}");
                }
            }
            UpdateEvent::DownloadProgress {
                url: _,
                downloaded,
                total,
            } => {
                if let Some(total) = total {
                    let pct = percent_tenths(downloaded, total);
                    eprintln!(
                        "[soldier_update] downloaded {} / {} ({}.{:01}%)",
                        human_bytes(downloaded),
                        human_bytes(total),
                        pct / 10,
                        pct % 10
                    );
                } else {
                    eprintln!("[soldier_update] downloaded {}", human_bytes(downloaded));
                }
            }
            UpdateEvent::DownloadFinished { url: _, bytes } => {
                eprintln!("[soldier_update] download finished: {}", human_bytes(bytes));
            }
            UpdateEvent::FileSaved { path, bytes } => {
                eprintln!(
                    "[soldier_update] saved {} ({})",
                    path.display(),
                    human_bytes(bytes)
                );
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpdateConfig {
    #[serde(rename = "KrakenWaf", default)]
    pub kraken_waf: KrakenWafUpdateConfig,
    #[serde(default)]
    pub blocklist: AddrListUpdateConfig,
    #[serde(default)]
    pub firehol: AddrListUpdateConfig,
    #[serde(default)]
    pub spamhaus: SpamhausUpdateConfig,
    #[serde(rename = "maxmind-geo", default)]
    pub maxmind_geo: MaxmindGeoConfig,
}

/// Configuration for the `MaxMind` GeoLite2-City auto-update.
///
/// Credentials are read from the environment variables `MAXMIND_ACCOUNT_ID`
/// and `MAXMIND_LICENSE_KEY` — never stored in YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct MaxmindGeoConfig {
    #[serde(default)]
    pub title: String,
    /// Set to `false` to disable periodic `GeoIP` DB updates without removing
    /// the rest of the configuration.
    #[serde(default = "default_geo_active")]
    pub active: bool,
    /// Download URLs. Typically one entry pointing to the GeoLite2-City tar.gz.
    #[serde(default)]
    pub url_file: UrlFileList,
    /// Cron expression controlling update frequency (default: 1st of each month at 18:00).
    #[serde(default = "default_geo_cron")]
    pub cron: String,
}

impl Default for MaxmindGeoConfig {
    fn default() -> Self {
        Self {
            title: String::new(),
            active: default_geo_active(),
            url_file: UrlFileList::default(),
            cron: default_geo_cron(),
        }
    }
}

fn default_geo_active() -> bool {
    true
}

fn default_geo_cron() -> String {
    "0 18 1 * *".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct KrakenWafUpdateConfig {
    #[serde(default = "default_kraken_cron")]
    pub cron: String,
}

impl Default for KrakenWafUpdateConfig {
    fn default() -> Self {
        Self {
            cron: default_kraken_cron(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpamhausUpdateConfig {
    #[serde(default = "default_spamhaus_title")]
    pub title: String,
    #[serde(rename = "DQS-key", default)]
    pub dqs_key: bool,
    #[serde(default)]
    pub lists: AddrListsConfig,
    #[serde(default = "default_spamhaus_cron")]
    pub cron: String,
    #[serde(default = "default_spamhaus_zones")]
    pub zones: Vec<String>,
    /// Seconds a *positive* (listed) DQS result is cached before a fresh
    /// DNS-over-TLS lookup is performed. Bounds the per-request lookup cost so a
    /// flood of requests from the same IP does not become a DNS-over-TLS amplification denial of service.
    #[serde(rename = "DQS-cache-ttl-secs", default = "default_dqs_cache_ttl_secs")]
    pub dqs_cache_ttl_secs: u64,
    /// Seconds a *negative* (not-listed) DQS result is cached. Kept shorter than
    /// the positive TTL so a newly-listed IP starts being blocked sooner.
    #[serde(
        rename = "DQS-cache-negative-ttl-secs",
        default = "default_dqs_cache_negative_ttl_secs"
    )]
    pub dqs_cache_negative_ttl_secs: u64,
}

impl Default for SpamhausUpdateConfig {
    fn default() -> Self {
        Self {
            title: default_spamhaus_title(),
            dqs_key: false,
            lists: AddrListsConfig::default(),
            cron: default_spamhaus_cron(),
            zones: default_spamhaus_zones(),
            dqs_cache_ttl_secs: default_dqs_cache_ttl_secs(),
            dqs_cache_negative_ttl_secs: default_dqs_cache_negative_ttl_secs(),
        }
    }
}

/// Default positive (listed) DQS cache TTL: one hour.
const fn default_dqs_cache_ttl_secs() -> u64 {
    3600
}

/// Default negative (not-listed) DQS cache TTL: five minutes.
const fn default_dqs_cache_negative_ttl_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddrListUpdateConfig {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub lists: AddrListsConfig,
    #[serde(default = "default_addr_list_cron")]
    pub cron: String,
}

impl Default for AddrListUpdateConfig {
    fn default() -> Self {
        Self {
            title: String::new(),
            lists: AddrListsConfig::default(),
            cron: default_addr_list_cron(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AddrListsConfig {
    #[serde(default)]
    pub url_file: UrlFileList,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum UrlFileList {
    One(String),
    Many(Vec<String>),
}

impl Default for UrlFileList {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl UrlFileList {
    #[must_use]
    pub fn values(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpamhausDqsMatch {
    pub zone: String,
    pub query: String,
    pub response: IpAddr,
}

fn default_kraken_cron() -> String {
    "0 18 */15 * *".to_string()
}

fn default_spamhaus_cron() -> String {
    "0 12 */3 * *".to_string()
}

fn default_addr_list_cron() -> String {
    "0 12 */3 * *".to_string()
}

fn default_spamhaus_title() -> String {
    "Spamhaus site".to_string()
}

fn default_spamhaus_zones() -> Vec<String> {
    ["sbl", "xbl", "authbl"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
}

#[must_use]
pub fn default_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_UPDATE_CONFIG)
}

/// Load update configuration. Missing config is treated as defaults so the
/// updater remains usable before an operator customizes `conf/update.yaml`.
///
/// # Errors
/// Returns an error if the file cannot be read or the YAML cannot be parsed.
pub fn load_update_config(path: &Path) -> Result<UpdateConfig> {
    if !path.exists() {
        return Ok(UpdateConfig::default());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read update config {}", path.display()))?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse update config {}", path.display()))
}

/// Update the local `KrakenWaf` checkout from the upstream `main` branch.
///
/// # Errors
/// Returns an error if `git pull --ff-only` cannot be executed or exits with a
/// failing status.
pub fn update_kraken_waf(repo_root: &Path) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("pull")
        .arg("--ff-only")
        .arg("https://github.com/Orangewarrior/KrakenWaf")
        .arg("main")
        .status()
        .context("failed to execute git pull for KrakenWaf update")?;

    if !status.success() {
        anyhow::bail!("git pull failed with status {status}");
    }

    Ok(())
}

/// Load an address-list update section from YAML and execute it.
///
/// # Errors
/// Returns an error if the config is invalid, the named list is unknown, a
/// configured list download fails, DQS is enabled without a key, or DQS
/// validation fails.
pub async fn update_addr_list_from_config(
    repo_root: &Path,
    config_path: &Path,
    list_name: &str,
) -> Result<()> {
    let config = load_update_config(config_path)?;
    update_addr_list_with_reporter(repo_root, &config, list_name, &NoopUpdateReporter).await
}

/// Load an address-list update section from YAML and execute it with status reporting.
///
/// # Errors
/// Returns an error if the config is invalid, the named list is unknown, a
/// configured list download fails, DQS is enabled without a key, or DQS
/// validation fails.
pub async fn update_addr_list_from_config_with_reporter(
    repo_root: &Path,
    config_path: &Path,
    list_name: &str,
    reporter: &dyn UpdateReporter,
) -> Result<()> {
    reporter.report(UpdateEvent::Step {
        message: "loading update configuration",
    });
    let config = load_update_config(config_path)?;
    update_addr_list_with_reporter(repo_root, &config, list_name, reporter).await
}

/// Download an address-list section and validate Spamhaus DQS when enabled.
///
/// # Errors
/// Returns an error if the named list is unknown, a configured list download
/// fails, DQS is enabled without `SPAMHAUS_DQS_KEY`, or DQS validation/write
/// fails.
pub async fn update_addr_list(
    repo_root: &Path,
    config: &UpdateConfig,
    list_name: &str,
) -> Result<()> {
    update_addr_list_with_reporter(repo_root, config, list_name, &NoopUpdateReporter).await
}

/// Download an address-list section and validate Spamhaus DQS when enabled,
/// reporting status to the supplied reporter.
///
/// # Errors
/// Returns an error if the named list is unknown, a configured list download
/// fails, DQS is enabled without `SPAMHAUS_DQS_KEY`, or DQS validation/write
/// fails.
pub async fn update_addr_list_with_reporter(
    repo_root: &Path,
    config: &UpdateConfig,
    list_name: &str,
    reporter: &dyn UpdateReporter,
) -> Result<()> {
    match list_name {
        "spamhaus" => update_spamhaus_with_reporter(repo_root, config, reporter).await,
        "blocklist" => {
            let title = title_or_default(&config.blocklist.title, "Blocklist site");
            let list_urls = config.blocklist.lists.url_file.values();
            if list_urls.is_empty() {
                let err = anyhow::anyhow!("blocklist.lists.url_file has no URLs configured");
                log_update_error(repo_root, &err);
                return Err(err);
            }
            download_addr_list_url_files_with_reporter(
                repo_root,
                "blocklist",
                &title,
                &list_urls,
                reporter,
            )
            .await
            .inspect_err(|err| log_update_error(repo_root, err))
        }
        "firehol" => {
            let title = title_or_default(&config.firehol.title, "Firehol");
            let list_urls = config.firehol.lists.url_file.values();
            if list_urls.is_empty() {
                let err = anyhow::anyhow!("firehol.lists.url_file has no URLs configured");
                log_update_error(repo_root, &err);
                return Err(err);
            }
            download_addr_list_url_files_with_reporter(
                repo_root, "firehol", &title, &list_urls, reporter,
            )
            .await
            .inspect_err(|err| log_update_error(repo_root, err))
        }
        "maxmind-geo" => update_maxmind_geo_with_reporter(repo_root, config, reporter)
            .await
            .inspect_err(|err| log_update_error(repo_root, err)),
        other => {
            let err = anyhow::anyhow!("unknown addr list: {other}");
            log_update_error(repo_root, &err);
            Err(err)
        }
    }
}

/// Download Spamhaus URL lists and validate DQS zones when enabled.
///
/// # Errors
/// Returns an error if a configured list download fails, DQS is enabled without
/// `SPAMHAUS_DQS_KEY`, or DQS validation/write fails.
pub async fn update_spamhaus(repo_root: &Path, config: &UpdateConfig) -> Result<()> {
    update_spamhaus_with_reporter(repo_root, config, &NoopUpdateReporter).await
}

/// Download Spamhaus URL lists and validate DQS zones when enabled, reporting
/// status to the supplied reporter.
///
/// # Errors
/// Returns an error if a configured list download fails, DQS is enabled without
/// `SPAMHAUS_DQS_KEY`, or DQS validation/write fails.
pub async fn update_spamhaus_with_reporter(
    repo_root: &Path,
    config: &UpdateConfig,
    reporter: &dyn UpdateReporter,
) -> Result<()> {
    let title = title_or_default(&config.spamhaus.title, "Spamhaus site");
    let list_urls = config.spamhaus.lists.url_file.values();
    if !list_urls.is_empty() {
        download_addr_list_url_files_with_reporter(
            repo_root, "spamhaus", &title, &list_urls, reporter,
        )
        .await
        .inspect_err(|err| {
            log_update_error(repo_root, err);
        })?;
    }

    if !config.spamhaus.dqs_key {
        if list_urls.is_empty() {
            let err = anyhow::anyhow!(
                "Spamhaus DQS-key is disabled and no spamhaus.lists.url_file entries are configured"
            );
            log_update_error(repo_root, &err);
            return Err(err);
        }
        reporter.report(UpdateEvent::Step {
            message: "Spamhaus DQS validation disabled; URL file update complete",
        });
        return Ok(());
    }

    // File-first secret: SPAMHAUS_DQS_KEY_FILE, then
    // /run/secrets/krakenwaf/SPAMHAUS_DQS_KEY, then the SPAMHAUS_DQS_KEY env var.
    let Some(token) = crate::secrets::load_secret("SPAMHAUS_DQS_KEY") else {
        let err = anyhow::anyhow!(
            "SPAMHAUS_DQS_KEY is not set — provide it via a file secret \
             (SPAMHAUS_DQS_KEY_FILE or /run/secrets/krakenwaf/SPAMHAUS_DQS_KEY) \
             or the SPAMHAUS_DQS_KEY environment variable"
        );
        log_update_error(repo_root, &err);
        return Err(err);
    };

    reporter.report(UpdateEvent::Step {
        message: "validating Spamhaus DQS zones",
    });
    validate_spamhaus_dqs_zones(repo_root, &token, &config.spamhaus.zones)
        .await
        .inspect_err(|err| {
            log_update_error(repo_root, err);
        })
}

/// Download configured text lists into `rules/addr/<list_name>`.
///
/// # Errors
/// Returns an error if the HTTP client cannot be built, a URL is invalid, a
/// download returns a non-2xx status, or a file cannot be written.
pub async fn download_addr_list_url_files(
    repo_root: &Path,
    list_name: &str,
    title: &str,
    urls: &[String],
) -> Result<()> {
    download_addr_list_url_files_with_reporter(
        repo_root,
        list_name,
        title,
        urls,
        &NoopUpdateReporter,
    )
    .await
}

/// Download configured text lists into `rules/addr/<list_name>`, reporting
/// progress and final output files to the supplied reporter.
///
/// # Errors
/// Returns an error if the HTTP client cannot be built, a URL is invalid, a
/// download returns a non-2xx status, the body is not UTF-8 text, or a file
/// cannot be written.
pub async fn download_addr_list_url_files_with_reporter(
    repo_root: &Path,
    list_name: &str,
    title: &str,
    urls: &[String],
    reporter: &dyn UpdateReporter,
) -> Result<()> {
    if urls.is_empty() {
        return Ok(());
    }

    let out_dir = safe_addr_list_output_dir(repo_root, list_name)?;
    reporter.report(UpdateEvent::Step {
        message: "address-list output directory ready",
    });
    let client = update_http_client()?;
    reporter.report(UpdateEvent::Step {
        message: "DNS resolver ready: Quad9 DNS-over-TLS with DNSSEC validation",
    });

    for raw_url in urls {
        let url =
            Url::parse(raw_url).with_context(|| format!("invalid address list URL: {raw_url}"))?;
        let file_name = output_file_name_for_url(list_name, &url)?;
        let destination = out_dir.join(&file_name);
        let bytes = download_url_bytes(
            &client,
            &url,
            Some(destination.as_path()),
            reporter,
            "address list",
            MAX_ADDR_LIST_DOWNLOAD_BYTES,
        )
        .await?;
        let body = String::from_utf8(bytes.to_vec())
            .with_context(|| format!("address list {url} is not valid UTF-8 text"))?;
        let content = with_addr_list_metadata(title, &url, &body);
        fs::write(&destination, content.as_bytes())
            .with_context(|| format!("failed to write address list {file_name}"))?;
        reporter.report(UpdateEvent::FileSaved {
            path: &destination,
            bytes: content.len() as u64,
        });
    }

    Ok(())
}

fn safe_addr_list_output_dir(repo_root: &Path, list_name: &str) -> Result<PathBuf> {
    if list_name.contains("..")
        || list_name.contains('/')
        || list_name.contains('\\')
        || list_name.is_empty()
    {
        anyhow::bail!("invalid address list name: {list_name}");
    }

    let rules_addr_dir = repo_root.join(ADDR_RULES_DIR);
    fs::create_dir_all(&rules_addr_dir).with_context(|| {
        format!(
            "failed to create address rules dir {}",
            rules_addr_dir.display()
        )
    })?;
    let out_dir = rules_addr_dir.join(list_name);
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create address list dir {}", out_dir.display()))?;

    let rules_addr_canonical = rules_addr_dir.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize address rules dir {}",
            rules_addr_dir.display()
        )
    })?;
    let out_canonical = out_dir.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize address list dir {}",
            out_dir.display()
        )
    })?;
    if !out_canonical.starts_with(&rules_addr_canonical) {
        anyhow::bail!(
            "address list dir {} resolved outside {} — possible symlink attack",
            out_canonical.display(),
            rules_addr_canonical.display()
        );
    }

    Ok(out_canonical)
}

/// Download configured Spamhaus text lists into `rules/addr/spamhaus`.
///
/// # Errors
/// Returns an error if the HTTP client cannot be built, a URL is invalid, a
/// download returns a non-2xx status, or a file cannot be written.
pub async fn download_spamhaus_url_files(repo_root: &Path, urls: &[String]) -> Result<()> {
    download_addr_list_url_files(repo_root, "spamhaus", "Spamhaus site", urls).await
}

/// Resolve the local output filename for a configured list URL.
///
/// # Errors
/// Returns an error if the URL path does not contain a usable filename.
pub fn output_file_name_for_url(list_name: &str, url: &Url) -> Result<String> {
    let Some(last_segment) = url
        .path_segments()
        .and_then(Iterator::last)
        .filter(|segment| !segment.is_empty())
    else {
        anyhow::bail!("address list URL has no file name: {url}");
    };

    let lower_url = url.as_str().to_ascii_lowercase();
    if list_name == "spamhaus"
        && (lower_url.contains("/drop/") || last_segment.eq_ignore_ascii_case("drop.lasso"))
    {
        return Ok("DROP.txt".to_string());
    }

    let sanitized = last_segment
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '.' | '-' | '_'))
        .collect::<String>();
    if sanitized.is_empty() {
        anyhow::bail!("address list URL has unusable file name: {url}");
    }
    Ok(sanitized)
}

fn title_or_default(title: &str, default: &str) -> String {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn with_addr_list_metadata(title: &str, url: &Url, body: &str) -> String {
    format!(
        "# krakenwaf-title: {}\n# krakenwaf-source-url: {}\n{}",
        title.replace(['\r', '\n'], " "),
        url,
        body
    )
}

async fn download_url_bytes(
    client: &Client,
    url: &Url,
    destination: Option<&Path>,
    reporter: &dyn UpdateReporter,
    label: &str,
    max_bytes: u64,
) -> Result<Bytes> {
    download_url_bytes_with_request(
        client.get(url.clone()),
        url,
        destination,
        reporter,
        label,
        max_bytes,
    )
    .await
}

async fn download_url_bytes_with_request(
    request: reqwest::RequestBuilder,
    url: &Url,
    destination: Option<&Path>,
    reporter: &dyn UpdateReporter,
    label: &str,
    max_bytes: u64,
) -> Result<Bytes> {
    reporter.report(UpdateEvent::DownloadStarted { url, destination });
    let mut response = request
        .send()
        .await
        .with_context(|| format!("{label} download request failed: {url}"))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "{label} download failed from {} with HTTP {}",
            url,
            response.status()
        );
    }

    let total = response.content_length();
    // Reject up-front when the server advertises a body larger than the ceiling,
    // so a hostile `Content-Length` cannot drive a huge pre-allocation.
    if let Some(total) = total {
        anyhow::ensure!(
            total <= max_bytes,
            "{label} from {url} advertises Content-Length {total} > ceiling {max_bytes} bytes; refusing"
        );
    }
    // Cap the pre-allocation at the ceiling regardless of the advertised length.
    let prealloc = total
        .and_then(|len| usize::try_from(len).ok())
        .unwrap_or(0)
        .min(usize::try_from(max_bytes).unwrap_or(usize::MAX));
    let mut body = Vec::with_capacity(prealloc);
    let mut downloaded = 0_u64;
    let mut last_report = Instant::now();
    let mut last_reported_bytes = 0_u64;

    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed to read {label} response body from {url}"))?
    {
        downloaded += chunk.len() as u64;
        // Streaming guard: a chunked / Content-Length-less response cannot grow
        // the buffer past the ceiling.
        anyhow::ensure!(
            downloaded <= max_bytes,
            "{label} download from {url} exceeded the {max_bytes}-byte ceiling and was aborted \
             (possible compromised mirror or misconfiguration)"
        );
        body.extend_from_slice(&chunk);
        let enough_time = last_report.elapsed() >= DOWNLOAD_PROGRESS_MIN_INTERVAL;
        let enough_bytes =
            downloaded.saturating_sub(last_reported_bytes) >= DOWNLOAD_PROGRESS_MIN_BYTES;
        if enough_time || enough_bytes {
            reporter.report(UpdateEvent::DownloadProgress {
                url,
                downloaded,
                total,
            });
            last_report = Instant::now();
            last_reported_bytes = downloaded;
        }
    }

    reporter.report(UpdateEvent::DownloadProgress {
        url,
        downloaded,
        total,
    });
    reporter.report(UpdateEvent::DownloadFinished {
        url,
        bytes: downloaded,
    });
    Ok(Bytes::from(body))
}

fn percent_tenths(downloaded: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((u128::from(downloaded) * 1000) / u128::from(total))
        .min(1000)
        .try_into()
        .unwrap_or(1000)
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut divisor = 1_u64;
    let mut unit = 0_usize;
    while bytes / divisor >= 1024 && unit + 1 < UNITS.len() {
        divisor = divisor.saturating_mul(1024);
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        let whole = bytes / divisor;
        let fraction = ((bytes % divisor) * 100) / divisor;
        format!("{whole}.{fraction:02} {}", UNITS[unit])
    }
}

#[must_use]
pub fn spamhaus_dqs_zones() -> Vec<String> {
    default_spamhaus_zones()
}

/// Validate configured Spamhaus DQS zones and write local audit marker files.
///
/// # Errors
/// Returns an error if the output directory cannot be created, a DQS query
/// fails, or an audit marker file cannot be written.
pub async fn validate_spamhaus_dqs_zones(
    repo_root: &Path,
    token: &str,
    zones: &[String],
) -> Result<()> {
    let out_dir = safe_addr_list_output_dir(repo_root, "spamhaus")?;
    let zones = normalized_dqs_zones(zones);

    for zone in zones {
        let Some(response) = query_spamhaus_dqs("127.0.0.2", token, &zone).await? else {
            anyhow::bail!("Spamhaus DQS zone {zone} did not list the 127.0.0.2 test address");
        };
        let content = format!(
            "# Spamhaus DQS DNS zone marker\n# zone={zone}\n# test_ip=127.0.0.2\n# response={}\n# This is not a downloaded IP list. KrakenWaf queries this DQS zone at runtime.\n",
            response.response
        );
        fs::write(
            out_dir.join(format!("{}.txt", zone.to_ascii_uppercase())),
            content,
        )
        .with_context(|| format!("failed to write Spamhaus DQS marker for {zone}"))?;
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledSoldierJob {
    pub args: Vec<String>,
}

/// Return the updater commands due for the supplied cron time tuple.
///
/// # Errors
/// Returns an error when any configured cron expression is invalid.
pub fn scheduled_soldier_jobs_for_values(
    config: &UpdateConfig,
    minute: u32,
    hour: u32,
    day: u32,
    month: u32,
    weekday: u32,
) -> Result<Vec<ScheduledSoldierJob>> {
    let mut jobs = Vec::new();

    if CronSchedule::parse(&config.kraken_waf.cron)?
        .matches_values(minute, hour, day, month, weekday)
    {
        jobs.push(ScheduledSoldierJob {
            args: vec!["--kraken-update".to_string()],
        });
    }
    if CronSchedule::parse(&config.blocklist.cron)?
        .matches_values(minute, hour, day, month, weekday)
    {
        jobs.push(ScheduledSoldierJob {
            args: vec!["--addr-list".to_string(), "blocklist".to_string()],
        });
    }
    if CronSchedule::parse(&config.firehol.cron)?.matches_values(minute, hour, day, month, weekday)
    {
        jobs.push(ScheduledSoldierJob {
            args: vec!["--addr-list".to_string(), "firehol".to_string()],
        });
    }
    if CronSchedule::parse(&config.spamhaus.cron)?.matches_values(minute, hour, day, month, weekday)
    {
        jobs.push(ScheduledSoldierJob {
            args: vec!["--addr-list".to_string(), "spamhaus".to_string()],
        });
    }
    if config.maxmind_geo.active
        && CronSchedule::parse(&config.maxmind_geo.cron)?
            .matches_values(minute, hour, day, month, weekday)
    {
        jobs.push(ScheduledSoldierJob {
            args: vec!["--addr-list".to_string(), "maxmind-geo".to_string()],
        });
    }

    Ok(jobs)
}

/// Load update configuration and trigger a `MaxMind` `GeoIP` database refresh.
///
/// # Errors
/// Returns an error when the config cannot be loaded, credentials are missing,
/// the download fails, or the archive cannot be extracted.
pub async fn update_maxmind_geo_from_config(repo_root: &Path, config_path: &Path) -> Result<()> {
    let config = load_update_config(config_path)?;
    update_maxmind_geo_with_reporter(repo_root, &config, &NoopUpdateReporter).await
}

/// Load update configuration and trigger a `MaxMind` `GeoIP` database refresh
/// with status reporting.
///
/// # Errors
/// Returns an error when the config cannot be loaded, credentials are missing,
/// the download fails, or the archive cannot be extracted.
pub async fn update_maxmind_geo_from_config_with_reporter(
    repo_root: &Path,
    config_path: &Path,
    reporter: &dyn UpdateReporter,
) -> Result<()> {
    reporter.report(UpdateEvent::Step {
        message: "loading update configuration",
    });
    let config = load_update_config(config_path)?;
    update_maxmind_geo_with_reporter(repo_root, &config, reporter).await
}

/// Download and extract the `MaxMind` GeoLite2-City database to `db/geo/`.
///
/// Credentials are read from the `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY`
/// environment variables.  The archive is extracted atomically (write to `.tmp`,
/// then rename) so the WAF never sees a partially-written database.
///
/// # Errors
/// Returns an error when `active` is false, env var credentials are missing,
/// the HTTP request fails, or the `.mmdb` file is not found in the archive.
pub async fn update_maxmind_geo(repo_root: &Path, config: &UpdateConfig) -> Result<()> {
    update_maxmind_geo_with_reporter(repo_root, config, &NoopUpdateReporter).await
}

/// Download and extract the `MaxMind` GeoLite2-City database to `db/geo/`,
/// reporting download progress and the final `.mmdb` path.
///
/// # Errors
/// Returns an error when `active` is false, env var credentials are missing,
/// the HTTP request fails, or the `.mmdb` file is not found in the archive.
pub async fn update_maxmind_geo_with_reporter(
    repo_root: &Path,
    config: &UpdateConfig,
    reporter: &dyn UpdateReporter,
) -> Result<()> {
    let cfg = &config.maxmind_geo;

    if !cfg.active {
        reporter.report(UpdateEvent::Step {
            message: "maxmind-geo is disabled; no download needed",
        });
        return Ok(());
    }

    // File-first secrets (see `crate::secrets`): `<NAME>_FILE`, then
    // `/run/secrets/krakenwaf/<NAME>`, then the plain env var. `load_secret`
    // already trims surrounding whitespace and treats empty as absent.
    // `load_secret` treats empty as absent, so `Some` already guarantees a
    // non-empty credential — bind both with a single `let else`.
    let (Some(account_id), Some(key)) = (
        crate::secrets::load_secret("MAXMIND_ACCOUNT_ID"),
        crate::secrets::load_secret("MAXMIND_LICENSE_KEY"),
    ) else {
        anyhow::bail!(
            "maxmind-geo: MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY must be set. Provide them \
             as file secrets (/run/secrets/krakenwaf/<NAME> or <NAME>_FILE) or environment \
             variables. Register at https://www.maxmind.com/en/ to obtain free credentials."
        );
    };

    let urls = cfg.url_file.values();
    if urls.is_empty() {
        anyhow::bail!("maxmind-geo: url_file has no download URLs configured");
    }

    let out_dir = repo_root.join(GEO_DB_DIR);
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create GeoIP DB directory {}", out_dir.display()))?;
    reporter.report(UpdateEvent::Step {
        message: "GeoIP output directory ready",
    });

    let client = update_http_client()?;
    reporter.report(UpdateEvent::Step {
        message: "DNS resolver ready: Quad9 DNS-over-TLS with DNSSEC validation",
    });

    for raw_url in &urls {
        download_and_extract_mmdb(repo_root, &client, &account_id, &key, raw_url, reporter).await?;
    }

    Ok(())
}

async fn download_and_extract_mmdb(
    repo_root: &Path,
    client: &Client,
    account_id: &str,
    key: &str,
    url: &str,
    reporter: &dyn UpdateReporter,
) -> Result<()> {
    let parsed = Url::parse(url).with_context(|| format!("invalid MaxMind download URL: {url}"))?;
    let destination = repo_root.join(GEO_DB_DIR).join(GEO_DB_FILE);
    let bytes = download_url_bytes_with_request(
        client.get(parsed.clone()).basic_auth(account_id, Some(key)),
        &parsed,
        Some(destination.as_path()),
        reporter,
        "MaxMind DB",
        MAX_GEO_DB_DOWNLOAD_BYTES,
    )
    .await?;

    reporter.report(UpdateEvent::Step {
        message: "extracting GeoLite2-City.mmdb from downloaded archive",
    });
    let final_path = extract_mmdb_from_targz(repo_root, &bytes).with_context(|| {
        format!("failed to extract {GEO_DB_FILE} from archive downloaded from {url}")
    })?;
    let size = match fs::metadata(&final_path) {
        Ok(metadata) => metadata.len(),
        Err(_) => 0,
    };
    reporter.report(UpdateEvent::FileSaved {
        path: &final_path,
        bytes: size,
    });
    Ok(())
}

/// Reject tar entry paths that could escape the intended output directory:
/// any `..` component, an absolute root (`/`), or a Windows drive/UNC prefix.
/// Plain relative paths (including nested subdirectories) are considered safe.
fn tar_entry_path_is_safe(path: &Path) -> bool {
    !path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    })
}

fn extract_mmdb_from_targz(repo_root: &Path, data: &[u8]) -> Result<PathBuf> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let gz = GzDecoder::new(std::io::Cursor::new(data));
    let mut archive = Archive::new(gz);

    let out_dir = repo_root.join(GEO_DB_DIR);

    for entry in archive
        .entries()
        .context("failed to iterate tar archive entries")?
    {
        let mut entry = entry.context("failed to read tar entry")?;
        let path = entry.path().context("failed to get tar entry path")?;

        // Defence-in-depth against tar path traversal (zip-slip): a malicious
        // archive could ship an entry named `GeoLite2-City.mmdb` whose path
        // contains `..` or an absolute prefix to escape `out_dir`. We only ever
        // unpack to a fixed temp file we control, but reject suspicious paths
        // outright so the intent is explicit and audit-friendly.
        if !tar_entry_path_is_safe(&path) {
            anyhow::bail!(
                "refusing tar entry with traversal/absolute path: {}",
                path.display()
            );
        }

        if path.file_name() == Some(OsStr::new(GEO_DB_FILE)) {
            // Write to a temporary file first, then rename atomically so the
            // WAF never sees a partially-written database.
            let tmp_path = out_dir.join(format!("{GEO_DB_FILE}.tmp"));
            // Bounded copy instead of `entry.unpack`: a malicious archive could
            // gzip-compress a tiny tar that declares (or streams) a multi-GiB
            // entry. Cap the bytes written and abort past the ceiling so the
            // updater cannot be OOM'd by a decompression bomb.
            {
                let mut out_file = fs::File::create(&tmp_path)
                    .with_context(|| format!("failed to create {}", tmp_path.display()))?;
                let mut capped =
                    std::io::Read::take(&mut entry, MAX_GEO_DB_UNPACKED_BYTES + 1);
                let written = std::io::copy(&mut capped, &mut out_file)
                    .context("failed to unpack GeoLite2-City.mmdb")?;
                if written > MAX_GEO_DB_UNPACKED_BYTES {
                    drop(out_file);
                    let _ = fs::remove_file(&tmp_path);
                    anyhow::bail!(
                        "GeoLite2-City.mmdb entry exceeded the {MAX_GEO_DB_UNPACKED_BYTES}-byte \
                         unpack ceiling; refusing (possible decompression bomb)"
                    );
                }
                out_file
                    .sync_all()
                    .context("failed to flush unpacked GeoLite2-City.mmdb")?;
            }
            let final_path = out_dir.join(GEO_DB_FILE);
            fs::rename(&tmp_path, &final_path).with_context(|| {
                format!(
                    "failed to rename {} → {}",
                    tmp_path.display(),
                    final_path.display()
                )
            })?;
            return Ok(final_path);
        }
    }

    anyhow::bail!("{GEO_DB_FILE} not found inside the downloaded archive")
}

/// Query a Spamhaus DQS zone for a single IP address.
///
/// # Errors
/// Returns an error if the IP is invalid or DNS resolution fails unexpectedly.
pub async fn query_spamhaus_dqs(
    ip: &str,
    token: &str,
    zone: &str,
) -> Result<Option<SpamhausDqsMatch>> {
    let ip = ip
        .parse::<IpAddr>()
        .with_context(|| format!("invalid IP address for Spamhaus DQS lookup: {ip}"))?;
    let query = build_spamhaus_dqs_query(ip, token, zone)
        .with_context(|| format!("unsupported Spamhaus DQS IP address: {ip}"))?;

    let resolver = quad9_dot_dns_resolver();
    let lookup = timeout(Duration::from_secs(5), resolver.lookup_ip(&query)).await;
    let addrs = match lookup {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(err)) if dns_not_listed(&err) => return Ok(None),
        Ok(Err(err)) => {
            return Err(err).with_context(|| format!("Spamhaus DQS lookup failed for {query}"));
        }
        Err(_) => anyhow::bail!("Spamhaus DQS lookup timed out for {query}"),
    };

    Ok(addrs.first().map(|addr| SpamhausDqsMatch {
        zone: zone.to_ascii_lowercase(),
        query,
        response: *addr,
    }))
}

#[must_use]
pub fn build_spamhaus_dqs_query(ip: IpAddr, token: &str, zone: &str) -> Option<String> {
    let reversed = match ip {
        IpAddr::V4(v4) => v4
            .octets()
            .into_iter()
            .rev()
            .map(|octet| octet.to_string())
            .collect::<Vec<_>>()
            .join("."),
        IpAddr::V6(v6) => v6
            .octets()
            .into_iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .rev()
            .map(|nibble| format!("{nibble:x}"))
            .collect::<Vec<_>>()
            .join("."),
    };
    let token = token.trim();
    let zone = zone.trim().to_ascii_lowercase();
    (!token.is_empty() && is_supported_dqs_zone(&zone))
        .then(|| format!("{reversed}.{token}.{zone}.dq.spamhaus.net"))
}

#[must_use]
pub fn normalized_dqs_zones(zones: &[String]) -> Vec<String> {
    let mut out = zones
        .iter()
        .map(|zone| zone.trim().to_ascii_lowercase())
        .filter(|zone| is_supported_dqs_zone(zone))
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    if out.is_empty() {
        return default_spamhaus_zones();
    }
    out
}

fn is_supported_dqs_zone(zone: &str) -> bool {
    matches!(zone, "sbl" | "xbl" | "authbl")
}

fn dns_not_listed(err: &ResolveError) -> bool {
    err.is_nx_domain() || err.is_no_records_found()
}

pub fn log_update_error(repo_root: &Path, err: &anyhow::Error) {
    let path = repo_root.join(ERROR_LOG);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{} {err:#}", chrono::Utc::now().to_rfc3339());
    }
}

/// Append a structured JSON record describing a single update action to
/// `logs/updates/lastupdate.jsonl`.
///
/// Every line is a self-contained JSON object so the journal can be tailed or
/// parsed with `jq` without a surrounding array. Covers *all* update resources
/// — the `KrakenWaf` repository checkout (`kraken-update`) as well as every
/// address-list / `GeoIP` refresh — so a single file answers "what did the
/// updater do, to what, and did it succeed?".
///
/// This is best-effort observability: a failure to create the directory or open
/// the file is swallowed so logging never aborts an in-progress update.
///
/// * `action` — the update verb, e.g. `"kraken-update"` or `"addr-list"`.
/// * `target` — the resource the action touched, e.g. `"repository"`,
///   `"spamhaus"`, `"maxmind-geo"`.
/// * `status` — `"started"`, `"success"`, or `"error"`.
/// * `detail` — free-form human context (config path, error message, …).
pub fn log_update_action(
    repo_root: &Path,
    action: &str,
    target: &str,
    status: &str,
    detail: &str,
) {
    let path = repo_root.join(UPDATE_ACTION_LOG);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let record = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "action": action,
        "target": target,
        "status": status,
        "detail": detail,
    });
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{record}");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronSchedule {
    minute: CronField,
    hour: CronField,
    day: CronField,
    month: CronField,
    weekday: CronField,
}

impl CronSchedule {
    /// Parse a five-field cron expression.
    ///
    /// # Errors
    /// Returns an error when the expression does not have five fields or any
    /// field is outside the supported numeric range.
    pub fn parse(value: &str) -> Result<Self> {
        let parts = value.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 5 {
            anyhow::bail!("cron expression must have 5 fields: {value}");
        }
        Ok(Self {
            minute: CronField::parse(parts[0], 0, 59)?,
            hour: CronField::parse(parts[1], 0, 23)?,
            day: CronField::parse(parts[2], 1, 31)?,
            month: CronField::parse(parts[3], 1, 12)?,
            weekday: CronField::parse(parts[4], 0, 6)?,
        })
    }

    #[must_use]
    pub fn matches_now(&self) -> bool {
        let now = Local::now();
        self.matches_values(
            now.minute(),
            now.hour(),
            now.day(),
            now.month(),
            now.weekday().num_days_from_sunday(),
        )
    }

    #[must_use]
    pub fn matches_values(
        &self,
        minute: u32,
        hour: u32,
        day: u32,
        month: u32,
        weekday: u32,
    ) -> bool {
        self.minute.matches(minute)
            && self.hour.matches(hour)
            && self.day.matches(day)
            && self.month.matches(month)
            && self.weekday.matches(weekday)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CronField {
    Any,
    Exact(u32),
    Step { start: u32, step: u32 },
}

impl CronField {
    fn parse(value: &str, min: u32, max: u32) -> Result<Self> {
        if value == "*" {
            return Ok(Self::Any);
        }
        if let Some(step) = value.strip_prefix("*/") {
            let step = step.parse::<u32>()?;
            if step == 0 {
                anyhow::bail!("cron step cannot be zero");
            }
            return Ok(Self::Step { start: min, step });
        }
        let exact = value.parse::<u32>()?;
        if exact < min || exact > max {
            anyhow::bail!("cron field {exact} outside {min}..={max}");
        }
        Ok(Self::Exact(exact))
    }

    fn matches(&self, value: u32) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => value == *expected,
            Self::Step { start, step } => value >= *start && (value - *start).is_multiple_of(*step),
        }
    }
}

/// Run the update scheduler forever.
///
/// # Errors
/// Returns an error if the config cannot be loaded/parsed or a scheduled
/// updater command fails.
pub async fn run_watch_tower(repo_root: PathBuf, config_path: PathBuf) -> Result<()> {
    let mut last_minute: Option<String> = None;

    loop {
        let minute_key = Local::now().format("%Y-%m-%dT%H:%M").to_string();
        if last_minute.as_deref() != Some(&minute_key) {
            let config = load_update_config(&config_path)?;
            let now = Local::now();
            for job in scheduled_soldier_jobs_for_values(
                &config,
                now.minute(),
                now.hour(),
                now.day(),
                now.month(),
                now.weekday().num_days_from_sunday(),
            )? {
                run_soldier_args(
                    &repo_root,
                    &job.args.iter().map(String::as_str).collect::<Vec<_>>(),
                )?;
            }
            last_minute = Some(minute_key);
        }

        sleep(Duration::from_secs(30)).await;
    }
}

fn run_soldier_args(repo_root: &Path, args: &[&str]) -> Result<()> {
    let current = std::env::current_exe()?;
    let soldier = current.parent().map_or_else(
        || PathBuf::from("soldier_update"),
        |dir| dir.join("soldier_update"),
    );
    let status = Command::new(soldier)
        .current_dir(repo_root)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute soldier_update {}", args.join(" ")))?;

    if !status.success() {
        anyhow::bail!(
            "soldier_update {} failed with status {status}",
            args.join(" ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod traversal_tests {
    use super::tar_entry_path_is_safe;
    use std::path::Path;

    #[test]
    fn accepts_plain_and_nested_relative_paths() {
        assert!(tar_entry_path_is_safe(Path::new("GeoLite2-City.mmdb")));
        assert!(tar_entry_path_is_safe(Path::new(
            "GeoLite2-City_20260101/GeoLite2-City.mmdb"
        )));
    }

    #[test]
    fn rejects_parent_dir_traversal() {
        assert!(!tar_entry_path_is_safe(Path::new("../GeoLite2-City.mmdb")));
        assert!(!tar_entry_path_is_safe(Path::new(
            "a/../../etc/GeoLite2-City.mmdb"
        )));
    }

    #[test]
    fn rejects_absolute_paths() {
        assert!(!tar_entry_path_is_safe(Path::new("/etc/GeoLite2-City.mmdb")));
    }
}

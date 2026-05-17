use anyhow::{Context, Result};
use chrono::{Datelike, Local, Timelike};
use reqwest::Client;
use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio::{
    net::lookup_host,
    time::{sleep, timeout},
};
use url::Url;

const DEFAULT_UPDATE_CONFIG: &str = "conf/update.yaml";
const ADDR_RULES_DIR: &str = "rules/addr";
const ERROR_LOG: &str = "logs/console_local/errors.txt";
const ADDR_LIST_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

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
}

impl Default for SpamhausUpdateConfig {
    fn default() -> Self {
        Self {
            title: default_spamhaus_title(),
            dqs_key: false,
            lists: AddrListsConfig::default(),
            cron: default_spamhaus_cron(),
            zones: default_spamhaus_zones(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AddrListUpdateConfig {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub lists: AddrListsConfig,
    #[serde(default = "default_addr_list_cron")]
    pub cron: String,
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

#[derive(Debug, Clone)]
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
    update_addr_list(repo_root, &config, list_name).await
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
    match list_name {
        "spamhaus" => update_spamhaus(repo_root, config).await,
        "blocklist" => {
            let title = title_or_default(&config.blocklist.title, "Blocklist site");
            let list_urls = config.blocklist.lists.url_file.values();
            if list_urls.is_empty() {
                let err = anyhow::anyhow!("blocklist.lists.url_file has no URLs configured");
                log_update_error(repo_root, &err);
                return Err(err);
            }
            download_addr_list_url_files(repo_root, "blocklist", &title, &list_urls)
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
            download_addr_list_url_files(repo_root, "firehol", &title, &list_urls)
                .await
                .inspect_err(|err| log_update_error(repo_root, err))
        }
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
    let title = title_or_default(&config.spamhaus.title, "Spamhaus site");
    let list_urls = config.spamhaus.lists.url_file.values();
    if !list_urls.is_empty() {
        download_addr_list_url_files(repo_root, "spamhaus", &title, &list_urls)
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
        return Ok(());
    }

    let token = match std::env::var("SPAMHAUS_DQS_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            let err = anyhow::anyhow!("SPAMHAUS_DQS_KEY environment variable is missing");
            log_update_error(repo_root, &err);
            return Err(err);
        }
    };

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
    if urls.is_empty() {
        return Ok(());
    }

    let out_dir = safe_addr_list_output_dir(repo_root, list_name)?;
    let client = Client::builder()
        .use_rustls_tls()
        .timeout(ADDR_LIST_DOWNLOAD_TIMEOUT)
        .build()?;

    for raw_url in urls {
        let url =
            Url::parse(raw_url).with_context(|| format!("invalid address list URL: {raw_url}"))?;
        let response = client
            .get(url.clone())
            .send()
            .await
            .with_context(|| format!("failed to download address list {url}"))?;
        if !response.status().is_success() {
            anyhow::bail!(
                "address list download failed from {} with HTTP {}",
                url,
                response.status()
            );
        }

        let body = response
            .text()
            .await
            .with_context(|| format!("failed to read address list {url}"))?;
        let file_name = output_file_name_for_url(list_name, &url)?;
        let content = with_addr_list_metadata(title, &url, &body);
        fs::write(out_dir.join(&file_name), content)
            .with_context(|| format!("failed to write address list {file_name}"))?;
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

    Ok(jobs)
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

    let lookup_target = query.clone();
    let lookup = timeout(
        Duration::from_secs(3),
        lookup_host((lookup_target.as_str(), 0)),
    )
    .await;
    let addrs = match lookup {
        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
        Ok(Err(err)) if dns_not_listed(&err) => return Ok(None),
        Ok(Err(err)) => {
            return Err(err).with_context(|| format!("Spamhaus DQS lookup failed for {query}"));
        }
        Err(_) => anyhow::bail!("Spamhaus DQS lookup timed out for {query}"),
    };

    Ok(addrs.first().map(|addr| SpamhausDqsMatch {
        zone: zone.to_ascii_lowercase(),
        query,
        response: addr.ip(),
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
            .flat_map(|byte| [byte & 0x0f, byte >> 4])
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

fn dns_not_listed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::Other
    )
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

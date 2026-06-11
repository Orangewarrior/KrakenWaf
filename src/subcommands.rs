//! Administrative sub-commands: `krakenwaf config validate`,
//! `krakenwaf config dump [--redact]`, and `krakenwaf rules validate`.
//!
//! These run a single task and exit; they never start the proxy listener. They
//! give operators a fail-fast pre-flight check (CI, Kubernetes init containers,
//! support) over the configuration files and rule set the WAF would load, and a
//! redacted dump of the effective configuration for sharing without leaking
//! secrets.

use crate::{
    cli::{Cli, Commands, ConfigAction, RulesAction},
    proxy_config::ProxyConfig,
    ratelimit_config::RateLimitConfig,
    rules::RuleSet,
    websocket::WebSocketConfig,
};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Entry point invoked from `main` when a sub-command is present.
///
/// # Errors
/// Returns an error (non-zero exit) when validation fails or a requested file
/// cannot be loaded.
pub fn run(command: Commands, cli: &Cli, root: &Path) -> Result<()> {
    match command {
        Commands::Config { action } => match action {
            ConfigAction::Validate => config_validate(cli, root),
            ConfigAction::Dump { redact } => config_dump(cli, root, redact),
        },
        Commands::Rules { action } => match action {
            RulesAction::Validate => rules_validate(cli),
        },
    }
}

/// Resolve an effective config path: the explicit CLI override when present,
/// otherwise the conventional `conf/<name>` under the working directory.
fn resolved_path(explicit: Option<&str>, root: &Path, default_rel: &str) -> PathBuf {
    explicit.map_or_else(|| root.join(default_rel), PathBuf::from)
}

// ── config validate ──────────────────────────────────────────────────────────

fn config_validate(cli: &Cli, root: &Path) -> Result<()> {
    let mut failures = 0usize;

    // proxy.yaml — only validated when present (explicit flag OR the default
    // file exists). An explicitly-requested path that is missing is an error.
    let proxy_path = resolved_path(cli.external_proxy_conf.as_deref(), root, "conf/proxy.yaml");
    if cli.external_proxy_conf.is_some() || proxy_path.exists() {
        report("proxy", &proxy_path, ProxyConfig::load_from(&proxy_path).map(|_| ()), &mut failures);
    } else {
        skipped("proxy", &proxy_path);
    }

    // ratelimit.yaml — loader is lenient (absent ⇒ defaults), but validate() runs.
    let rl_path = resolved_path(cli.ratelimit_by_file_conf.as_deref(), root, "conf/ratelimit.yaml");
    report("ratelimit", &rl_path, RateLimitConfig::load_from(&rl_path).map(|_| ()), &mut failures);

    // websocket.yaml — same lenient-load + validate contract.
    let ws_path = resolved_path(cli.websocket_conf.as_deref(), root, "conf/websocket.yaml");
    report("websocket", &ws_path, WebSocketConfig::load_from(&ws_path).map(|_| ()), &mut failures);

    // banning.yaml — loaded relative to root by its own loader.
    report("banning", &root.join("conf/banning.yaml"),
        crate::banning::BanConfig::load(root).map(|_| ()), &mut failures);

    // update.yaml — only when present.
    let update_path = root.join(crate::update::DEFAULT_UPDATE_CONFIG);
    if update_path.exists() {
        report("update", &update_path,
            crate::update::load_update_config(&update_path).map(|_| ()), &mut failures);
    } else {
        skipped("update", &update_path);
    }

    // CMC config — only when --cmc-load was supplied.
    if let Some(cmc_path) = cli.cmc_load.as_deref() {
        let path = PathBuf::from(cmc_path);
        report("cmc", &path,
            crate::cmc::CmcConfig::from_file(&path).map(|_| ()), &mut failures);
    }

    if failures == 0 {
        println!("\nconfig validate: OK — all configuration files are valid");
        Ok(())
    } else {
        anyhow::bail!("config validate: {failures} configuration file(s) failed validation")
    }
}

fn report(name: &str, path: &Path, result: Result<()>, failures: &mut usize) {
    match result {
        Ok(()) => println!("  ✓ {name:<10} {}", path.display()),
        Err(err) => {
            *failures += 1;
            println!("  ✗ {name:<10} {}\n      {err:#}", path.display());
        }
    }
}

fn skipped(name: &str, path: &Path) {
    println!("  - {name:<10} {} (absent — using built-in defaults)", path.display());
}

// ── config dump ──────────────────────────────────────────────────────────────

const REDACTED: &str = "***REDACTED***";

fn config_dump(cli: &Cli, root: &Path, redact: bool) -> Result<()> {
    let proxy_path = resolved_path(cli.external_proxy_conf.as_deref(), root, "conf/proxy.yaml");
    let proxy = if proxy_path.exists() {
        ProxyConfig::load_from(&proxy_path).unwrap_or_default()
    } else {
        ProxyConfig::default()
    };

    let rl_path = resolved_path(cli.ratelimit_by_file_conf.as_deref(), root, "conf/ratelimit.yaml");
    let ratelimit = RateLimitConfig::load_from(&rl_path).unwrap_or_default();

    let ws_path = resolved_path(cli.websocket_conf.as_deref(), root, "conf/websocket.yaml");
    let websocket = WebSocketConfig::load_from(&ws_path).unwrap_or_default();

    // Serialize each section to a YAML value so secret-bearing fields can be
    // masked in-place before printing.
    let mut proxy_val = serde_yaml::to_value(&proxy).context("serialize proxy config")?;
    let mut rl_val = serde_yaml::to_value(&ratelimit).context("serialize ratelimit config")?;
    let ws_val = serde_yaml::to_value(&websocket).context("serialize websocket config")?;

    if redact {
        redact_url_field(&mut proxy_val, "upstream");
        if let serde_yaml::Value::Mapping(map) = &mut rl_val {
            if let Some(redis) = map.get_mut(serde_yaml::Value::String("redis".into())) {
                redact_url_field(redis, "url");
            }
        }
    }

    let mut root_map = serde_yaml::Mapping::new();
    root_map.insert("proxy".into(), proxy_val);
    root_map.insert("ratelimit".into(), rl_val);
    root_map.insert("websocket".into(), ws_val);

    // Resolved effective values that depend on CLI precedence — handy at a glance.
    let mut effective = serde_yaml::Mapping::new();
    effective.insert(
        "rate_limit_per_minute".into(),
        ratelimit.effective_rate_limit(cli.rate_limit_per_minute).into(),
    );
    effective.insert(
        "ws_control_enabled".into(),
        websocket.enable_ws_control.into(),
    );
    root_map.insert("effective".into(), serde_yaml::Value::Mapping(effective));

    // Secret presence — never the value itself. Helps debug "is the password
    // wired up?" without printing it.
    let mut secrets = serde_yaml::Mapping::new();
    for name in ["REDIS_PASSWORD", "REDIS_USERNAME", "MAXMIND_LICENSE_KEY"] {
        let present = crate::secrets::load_secret(name).is_some();
        let val = if !present {
            "<unset>"
        } else if redact {
            REDACTED
        } else {
            "<set via file/env>"
        };
        secrets.insert(name.into(), val.into());
    }
    root_map.insert("secrets".into(), serde_yaml::Value::Mapping(secrets));

    let doc = serde_yaml::Value::Mapping(root_map);
    let rendered = serde_yaml::to_string(&doc).context("render effective config as YAML")?;
    println!("# KrakenWaf effective configuration{}",
        if redact { " (secrets redacted)" } else { "" });
    print!("{rendered}");
    Ok(())
}

/// Mask the userinfo (`user:pass@`) of a URL-valued field so credentials
/// embedded in a connection string never appear in the dump. The host / path
/// are preserved so the topology stays legible.
fn redact_url_field(value: &mut serde_yaml::Value, field: &str) {
    let serde_yaml::Value::Mapping(map) = value else { return };
    let key = serde_yaml::Value::String(field.to_string());
    if let Some(serde_yaml::Value::String(url)) = map.get_mut(&key) {
        if let Some(redacted) = redact_url_userinfo(url) {
            *url = redacted;
        }
    }
}

/// Return a copy of `url` with any `user:pass@` segment replaced by `REDACTED@`,
/// or `None` when the URL carries no userinfo (left untouched).
fn redact_url_userinfo(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let (authority, tail) = match rest.split_once('/') {
        Some((auth, path)) => (auth, Some(path)),
        None => (rest, None),
    };
    let at = authority.rfind('@')?;
    let hostport = &authority[at + 1..];
    let mut out = format!("{scheme}://{REDACTED}@{hostport}");
    if let Some(path) = tail {
        out.push('/');
        out.push_str(path);
    }
    Some(out)
}

// ── rules validate ───────────────────────────────────────────────────────────

fn rules_validate(cli: &Cli) -> Result<()> {
    let rules_dir = PathBuf::from(&cli.rules_dir);
    println!("rules validate: loading from {}", rules_dir.display());
    let ruleset = RuleSet::from_dir(&rules_dir)
        .with_context(|| format!("failed to load rule set from {}", rules_dir.display()))?;

    println!("  ✓ rule set parsed successfully");
    println!("      uri_keywords          {}", ruleset.uri_keywords.len());
    println!("      header_keywords       {}", ruleset.header_keywords.len());
    println!("      body_keywords         {}", ruleset.body_keywords.len());
    println!("      path_regex            {}", ruleset.path_regex.len());
    println!("      blocked_ips           {}", ruleset.blocked_ips.len());
    println!("      blocked_ip_prefixes   {}", ruleset.blocked_ip_prefixes.len());
    println!("      allowed_ips           {}", ruleset.allowed_ips.len());

    let total = ruleset.uri_keywords.len()
        + ruleset.header_keywords.len()
        + ruleset.body_keywords.len()
        + ruleset.path_regex.len();
    if total == 0 {
        println!(
            "  ! warning: no request-matching rules loaded — the WAF would start \
             but report NOT READY on /readyz"
        );
    }

    // Validate the CMC config too when one is configured.
    if let Some(cmc_path) = cli.cmc_load.as_deref() {
        crate::cmc::CmcConfig::from_file(&PathBuf::from(cmc_path))
            .with_context(|| format!("failed to load CMC config from {cmc_path}"))?;
        println!("  ✓ cmc config valid    {cmc_path}");
    }

    println!("\nrules validate: OK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_url_userinfo() {
        assert_eq!(
            redact_url_userinfo("rediss://admin:s3cr3t@redis.internal:6380/0").as_deref(),
            Some("rediss://***REDACTED***@redis.internal:6380/0")
        );
        assert_eq!(
            redact_url_userinfo("rediss://admin:p@host:6380").as_deref(),
            Some("rediss://***REDACTED***@host:6380")
        );
    }

    #[test]
    fn url_without_userinfo_is_untouched() {
        assert_eq!(redact_url_userinfo("https://backend.internal:8080/app"), None);
        assert_eq!(redact_url_userinfo("not-a-url"), None);
    }
}

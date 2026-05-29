//! Configuration loader + validator for `conf/banning.yaml`.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::{fs, path::Path, time::Duration};

/// Root structure of `conf/banning.yaml`.
///
/// Field names accept the operator-friendly capitalisation used in the
/// example YAML (`Banning_mode`, `Ban_context`, `Ban_wait_time`). The
/// snake-case lowercase forms are also accepted for tooling that may
/// normalise YAML keys.
#[derive(Debug, Clone, Deserialize)]
pub struct BanConfigFile {
    #[serde(alias = "banning_mode")]
    #[serde(rename = "Banning_mode", default)]
    pub banning_mode: bool,

    #[serde(alias = "ban_context")]
    #[serde(rename = "Ban_context", default)]
    pub ban_context: BanContextFile,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BanContextFile {
    #[serde(default)]
    pub security_scanners: bool,

    #[serde(default, alias = "tolerance block count")]
    pub tolerance_block_count: Option<u32>,

    #[serde(default, alias = "ban_wait_time", rename = "Ban_wait_time")]
    pub ban_wait_time: Option<String>,
}

/// Validated, ready-to-use banning configuration.
///
/// Built via [`BanConfig::from_file`] which guarantees:
/// * `tolerance_block_count >= 1` when banning is enabled
/// * `ban_wait_time` parses as a non-zero `humantime` duration
#[derive(Debug, Clone)]
pub struct BanConfig {
    pub enabled: bool,
    pub security_scanners: bool,
    pub tolerance_block_count: u32,
    pub ban_wait_time: Duration,
}

impl BanConfig {
    /// All-disabled config — used when `conf/banning.yaml` is absent or
    /// `Banning_mode: false`.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            security_scanners: false,
            tolerance_block_count: u32::MAX,
            ban_wait_time: Duration::from_secs(0),
        }
    }

    /// Load + validate from `<root>/conf/banning.yaml`. Returns
    /// [`BanConfig::disabled`] when the file is absent.
    ///
    /// # Errors
    /// Returns an error if the file exists but is malformed, or if the
    /// validator finds a missing/invalid field while `Banning_mode: true`.
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_from(&root.join("conf").join("banning.yaml"))
    }

    /// Load + validate from an explicit path. Returns
    /// [`BanConfig::disabled`] when the file is absent.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read, parsed, or
    /// validated.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::disabled());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        let parsed: BanConfigFile = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse YAML '{}'", path.display()))?;
        Self::validate(parsed)
            .with_context(|| format!("invalid banning config '{}'", path.display()))
    }

    /// Validate a parsed [`BanConfigFile`] in isolation. Exposed so unit
    /// tests can exercise edge cases without touching the filesystem.
    ///
    /// # Errors
    /// Returns a descriptive error when any required field is missing or
    /// invalid for the requested mode.
    pub fn validate(file: BanConfigFile) -> Result<Self> {
        if !file.banning_mode {
            return Ok(Self::disabled());
        }

        let tolerance = file
            .ban_context
            .tolerance_block_count
            .ok_or_else(|| anyhow!("`Ban_context.tolerance_block_count` is required when Banning_mode is true"))?;

        if tolerance == 0 {
            bail!("`Ban_context.tolerance_block_count` must be >= 1 (got 0)");
        }

        let raw_wait = file
            .ban_context
            .ban_wait_time
            .ok_or_else(|| anyhow!("`Ban_context.Ban_wait_time` is required when Banning_mode is true"))?;

        let wait = humantime::parse_duration(raw_wait.trim())
            .with_context(|| format!("`Ban_context.Ban_wait_time`: cannot parse '{raw_wait}' as a duration (expected forms: 30s, 30m, 2h, 1h30m, 1d)"))?;

        if wait.is_zero() {
            bail!("`Ban_context.Ban_wait_time` must be > 0 (got '{raw_wait}')");
        }

        Ok(Self {
            enabled: true,
            security_scanners: file.ban_context.security_scanners,
            tolerance_block_count: tolerance,
            ban_wait_time: wait,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<BanConfig> {
        let file: BanConfigFile = serde_yaml::from_str(yaml)?;
        BanConfig::validate(file)
    }

    #[test]
    fn disabled_when_banning_mode_false() {
        let cfg = parse("Banning_mode: false\n").expect("ok");
        assert!(!cfg.enabled);
    }

    #[test]
    fn parses_canonical_example() {
        let yaml = "Banning_mode: true\nBan_context:\n  security_scanners: true\n  tolerance_block_count: 3\n  Ban_wait_time: 30m\n";
        let cfg = parse(yaml).expect("ok");
        assert!(cfg.enabled);
        assert!(cfg.security_scanners);
        assert_eq!(cfg.tolerance_block_count, 3);
        assert_eq!(cfg.ban_wait_time, Duration::from_mins(30));
    }

    #[test]
    fn accepts_aliased_with_spaces() {
        let yaml = "Banning_mode: true\nBan_context:\n  security_scanners: false\n  \"tolerance block count\": 5\n  ban_wait_time: 2h\n";
        let cfg = parse(yaml).expect("ok");
        assert_eq!(cfg.tolerance_block_count, 5);
        assert_eq!(cfg.ban_wait_time, Duration::from_hours(2));
    }

    #[test]
    fn rejects_zero_tolerance() {
        let yaml = "Banning_mode: true\nBan_context:\n  tolerance_block_count: 0\n  Ban_wait_time: 30m\n";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn rejects_missing_tolerance_when_enabled() {
        let yaml = "Banning_mode: true\nBan_context:\n  Ban_wait_time: 30m\n";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn rejects_missing_wait_when_enabled() {
        let yaml = "Banning_mode: true\nBan_context:\n  tolerance_block_count: 3\n";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn rejects_zero_wait() {
        let yaml = "Banning_mode: true\nBan_context:\n  tolerance_block_count: 3\n  Ban_wait_time: 0s\n";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn rejects_malformed_wait() {
        let yaml = "Banning_mode: true\nBan_context:\n  tolerance_block_count: 3\n  Ban_wait_time: forever\n";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn compound_duration_works() {
        let yaml = "Banning_mode: true\nBan_context:\n  tolerance_block_count: 1\n  Ban_wait_time: 1h30m\n";
        let cfg = parse(yaml).expect("ok");
        assert_eq!(cfg.ban_wait_time, Duration::from_mins(90));
    }

    #[test]
    fn disabled_constructor_is_inert() {
        let cfg = BanConfig::disabled();
        assert!(!cfg.enabled);
        assert!(!cfg.security_scanners);
        assert_eq!(cfg.tolerance_block_count, u32::MAX);
        assert_eq!(cfg.ban_wait_time, Duration::ZERO);
    }

    #[test]
    fn missing_file_returns_disabled() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = BanConfig::load_from(&tmp.path().join("does_not_exist.yaml")).expect("ok");
        assert!(!cfg.enabled);
    }

    #[test]
    fn loads_from_filesystem() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("banning.yaml");
        std::fs::write(
            &path,
            "Banning_mode: true\nBan_context:\n  security_scanners: true\n  tolerance_block_count: 7\n  Ban_wait_time: 45s\n",
        )
        .expect("write");
        let cfg = BanConfig::load_from(&path).expect("ok");
        assert!(cfg.enabled);
        assert!(cfg.security_scanners);
        assert_eq!(cfg.tolerance_block_count, 7);
        assert_eq!(cfg.ban_wait_time, Duration::from_secs(45));
    }
}

//! Filter-engine configuration loaded from `conf/filter.yaml`.
//!
//! The file owns the CMC module table, memory limits, and top-level engine
//! switches. Explicit command-line arguments take precedence over values read
//! from the file.

use crate::{cli::Cli, cmc::CmcConfig};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const DEFAULT_FILTER_CONFIG: &str = "conf/filter.yaml";

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
struct FilterSwitches {
    #[serde(rename = "libinjection-sqli")]
    libinjection_sqli: bool,
    #[serde(rename = "libinjection-xss")]
    libinjection_xss: bool,
    vectorscan: bool,
    #[serde(rename = "cmc-modules")]
    cmc_modules: bool,
    #[serde(rename = "redact-mask-filter")]
    redact_mask_filter: bool,
    #[serde(rename = "rules-dir")]
    rules_dir: String,
    allowpaths: String,
    verbose: bool,
}

impl Default for FilterSwitches {
    fn default() -> Self {
        Self {
            libinjection_sqli: true,
            libinjection_xss: true,
            vectorscan: true,
            cmc_modules: true,
            redact_mask_filter: true,
            rules_dir: "./rules".to_string(),
            // The shipped file declares the path explicitly. Keeping the
            // parser fallback empty preserves compatibility with older custom
            // CMC-only files while still validating every configured path.
            allowpaths: String::new(),
            verbose: true,
        }
    }
}

impl FilterSwitches {
    fn compatibility_defaults() -> Self {
        Self {
            libinjection_sqli: false,
            libinjection_xss: false,
            vectorscan: false,
            cmc_modules: true,
            redact_mask_filter: true,
            rules_dir: "./rules".to_string(),
            allowpaths: String::new(),
            verbose: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub cmc: CmcConfig,
    switches: FilterSwitches,
    pub source: PathBuf,
}

impl FilterConfig {
    pub fn merge_into_cli(&self, cli: &mut Cli, is_explicit: &dyn Fn(&str) -> bool) {
        if !is_explicit("enable-libinjection") && !is_explicit("enable-libinjection-sqli") {
            cli.enable_libinjection_sqli = self.switches.libinjection_sqli;
        }
        if !is_explicit("enable-libinjection") && !is_explicit("enable-libinjection-xss") {
            cli.enable_libinjection_xss = self.switches.libinjection_xss;
        }
        if !is_explicit("enable-vectorscan") {
            cli.enable_vectorscan = self.switches.vectorscan;
        }
        if !is_explicit("rules-dir") {
            cli.rules_dir.clone_from(&self.switches.rules_dir);
        }
        if !is_explicit("allow-paths") && !self.switches.allowpaths.is_empty() {
            cli.allow_paths_file = Some(self.switches.allowpaths.clone());
        }
        if !is_explicit("verbose") {
            cli.verbose = self.switches.verbose;
        }
    }

    #[must_use]
    pub fn cmc_config(&self) -> CmcConfig {
        let mut config = self.cmc.clone();
        if !self.switches.cmc_modules {
            config.disable_all_modules();
        }
        config
    }

    #[must_use]
    pub const fn redact_mask_filter(&self) -> bool {
        self.switches.redact_mask_filter
    }
}

/// Factory for validated filter configurations.
pub struct FilterConfigFactory;

impl FilterConfigFactory {
    /// Build a filter configuration from an explicit path or the conventional
    /// `conf/filter.yaml` path below the process working directory.
    ///
    /// # Errors
    /// Returns an error when an explicit or discovered configuration cannot be
    /// read or parsed as filter and CMC configuration.
    pub fn create(root: &Path, explicit: Option<&str>) -> Result<FilterConfig> {
        let source = explicit.map_or_else(|| root.join(DEFAULT_FILTER_CONFIG), PathBuf::from);
        if explicit.is_none() && !source.exists() {
            return Ok(FilterConfig {
                cmc: CmcConfig::default(),
                switches: FilterSwitches::compatibility_defaults(),
                source,
            });
        }
        let raw = fs::read_to_string(&source)
            .with_context(|| format!("failed to read filter config '{}'", source.display()))?;
        let switches: FilterSwitches = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse filter switches '{}'", source.display()))?;
        let cmc = CmcConfig::from_file(&source)?;
        Ok(FilterConfig {
            cmc,
            switches,
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn factory_loads_switches_and_disables_all_cmc_modules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("filter.yaml");
        fs::write(
            &path,
            "CMC-Rules:\n  SQLi_comments_detect: true\ncmc-modules: false\nredact-mask-filter: false\nlibinjection-sqli: false\nlibinjection-xss: false\nvectorscan: false\nrules-dir: custom-rules\nallowpaths: custom-allowpaths.yaml\nverbose: false\n",
        )
        .expect("write filter config");
        let config = FilterConfigFactory::create(dir.path(), path.to_str()).expect("load config");
        assert!(!config.cmc_config().sqli_comments_detect);

        let mut cli = Cli::try_parse_from(["krakenwaf"]).expect("parse cli");
        config.merge_into_cli(&mut cli, &|_| false);
        assert!(!cli.enable_libinjection_sqli);
        assert!(!cli.enable_libinjection_xss);
        assert!(!cli.enable_vectorscan);
        assert_eq!(cli.rules_dir, "custom-rules");
        assert_eq!(
            cli.allow_paths_file.as_deref(),
            Some("custom-allowpaths.yaml")
        );
        assert!(!cli.verbose);
        assert!(!config.redact_mask_filter());
    }

    #[test]
    fn explicit_cli_values_win_over_filter_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("filter.yaml");
        fs::write(
            &path,
            "rules-dir: from-file\nallowpaths: from-file.yaml\nverbose: false\n",
        )
        .expect("write filter config");
        let config = FilterConfigFactory::create(dir.path(), path.to_str()).expect("load config");
        let mut cli = Cli::try_parse_from([
            "krakenwaf",
            "--rules-dir",
            "from-cli",
            "--allow-paths",
            "from-cli.yaml",
            "--verbose",
        ])
        .expect("parse cli");
        config.merge_into_cli(&mut cli, &|flag| {
            matches!(flag, "rules-dir" | "allow-paths" | "verbose")
        });
        assert_eq!(cli.rules_dir, "from-cli");
        assert_eq!(cli.allow_paths_file.as_deref(), Some("from-cli.yaml"));
        assert!(cli.verbose);
    }

    #[test]
    fn redact_mask_filter_defaults_to_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("filter.yaml");
        fs::write(&path, "CMC-Rules:\n  SQLi_comments_detect: true\n")
            .expect("write filter config");
        let config = FilterConfigFactory::create(dir.path(), path.to_str()).expect("load config");
        assert!(config.redact_mask_filter());
    }
}

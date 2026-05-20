
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

/// Anomaly scoring configuration loaded from `conf/scoring.yaml`.
///
/// Example:
/// ```yaml
/// default_threshold: 10
/// paths:
///   - pattern: "/api/"
///     threshold: 5
///   - pattern: "/admin/"
///     threshold: 3
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScoringConfig {
    /// Score threshold applied when no path pattern matches.
    #[serde(default = "default_threshold")]
    pub default_threshold: u32,

    /// Per-path threshold overrides. Matched in order; first match wins.
    #[serde(default)]
    pub paths: Vec<PathThreshold>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathThreshold {
    /// URI path prefix (e.g. "/api/", "/admin/").
    pub pattern: String,
    pub threshold: u32,
}

fn default_threshold() -> u32 { 10 }

impl ScoringConfig {
    /// Load from `conf/scoring.yaml` relative to `root`. Returns defaults if absent.
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join("conf").join("scoring.yaml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))
    }

    /// Returns the effective threshold for the given URI path.
    pub fn threshold_for(&self, path: &str) -> u32 {
        self.paths
            .iter()
            .find(|p| path.starts_with(&p.pattern))
            .map_or(self.default_threshold, |p| p.threshold)
    }
}

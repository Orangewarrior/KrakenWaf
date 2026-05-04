use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct AllowPathEntry {
    pub order: u32,
    pub title: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    #[serde(default)]
    pub log: bool,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AllowPathConfig {
    pub entries: Vec<AllowPathEntry>,
}

impl AllowPathConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read allow-paths file {}", path.display()))?;
        Self::from_str(&content, path)
    }

    fn from_str(content: &str, path: &Path) -> Result<Self> {
        #[derive(Deserialize)]
        struct Root {
            #[serde(default)]
            allow: Vec<AllowPathEntry>,
        }

        let root: Root = serde_yml::from_str(content)
            .with_context(|| format!("failed to parse allow-paths YAML {}", path.display()))?;

        let mut entries = root.allow;
        entries.sort_by_key(|e| e.order);
        Ok(Self { entries })
    }

    /// Returns true if the given URI path matches any allow-path entry.
    pub fn is_allowed(&self, uri_path: &str) -> Option<&AllowPathEntry> {
        let normalized = crate::rules::normalize_url_path(uri_path);
        self.entries.iter().find(|entry| {
            entry.paths.iter().any(|p| {
                let allowed = crate::rules::normalize_url_path(p);
                normalized == allowed || normalized.starts_with(&format!("{}/", allowed))
            })
        })
    }
}

/// Validate and load an allow-paths YAML file, returning a descriptive error on failure.
pub fn load_and_validate(path: &Path) -> Result<AllowPathConfig> {
    let config = AllowPathConfig::from_file(path)?;
    for entry in &config.entries {
        if entry.title.trim().is_empty() {
            anyhow::bail!("allow-paths entry with order={} has an empty title", entry.order);
        }
        if entry.paths.is_empty() {
            anyhow::bail!("allow-paths entry '{}' (order={}) has no paths listed", entry.title, entry.order);
        }
    }
    Ok(config)
}

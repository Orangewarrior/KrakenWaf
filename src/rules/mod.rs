
mod loader;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, path::{Component, Path}};

pub use loader::load_rules_from_dir;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        };
        f.write_str(value)
    }
}

/// Fully loaded rule set used by KrakenWaf.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub blocked_ips: Vec<String>,
    pub blocked_ip_prefixes: Vec<String>,
    pub uri_keywords: Vec<DetectionRule>,
    pub header_keywords: Vec<DetectionRule>,
    pub body_keywords: Vec<DetectionRule>,
    pub allow_paths: Vec<String>,
    pub body_limits: HashMap<String, usize>,
    pub path_regex: Vec<CompiledDetectionRule>,
    pub body_regex: Vec<CompiledDetectionRule>,
    pub header_regex: Vec<CompiledDetectionRule>,
    pub vectorscan_keywords: Vec<DetectionRule>,
}

/// Generic metadata-backed rule loaded from external JSON files.
#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub title: String,
    pub severity: Severity,
    pub cwe: String,
    pub description: String,
    pub reference_url: String,
    pub rule_match: String,
    pub source: String,
    pub line: usize,
}

/// A compiled regex rule with its metadata.
#[derive(Debug, Clone)]
pub struct CompiledDetectionRule {
    pub meta: DetectionRule,
    pub compiled: Regex,
}

impl RuleSet {
    pub fn from_dir(root: &Path) -> Result<Self> {
        load_rules_from_dir(root)
    }

    pub fn body_limit_for_path(&self, path: &str) -> usize {
        let normalized = normalize_url_path(path);
        self.body_limits
            .iter()
            .find(|(prefix, _)| normalized.starts_with(&normalize_url_path(prefix)))
            .map(|(_, limit)| *limit)
            .unwrap_or(1024 * 1024)
    }

    pub fn is_allowlisted(&self, path: &str) -> bool {
        let normalized = normalize_url_path(path);
        self.allow_paths
            .iter()
            .map(|p| normalize_url_path(p))
            .any(|allowed| normalized == allowed || normalized.starts_with(&(allowed + "/")))
    }
}

pub fn normalize_url_path(path: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
    // On Linux, std::path::Path treats `\` as a regular character, not a separator.
    // Without this replacement, `foo\..\bar` would be a single Normal component
    // and the `..` would never be popped, opening a Windows-style traversal bypass.
    let with_fwd: String;
    let to_parse: &str = if decoded.contains('\\') {
        with_fwd = decoded.replace('\\', "/");
        &with_fwd
    } else {
        decoded.as_ref()
    };
    let mut out = Vec::new();

    for component in Path::new(to_parse).components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Normal(value) => out.push(value.to_string_lossy().to_string()),
            Component::Prefix(_) => {}
        }
    }

    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

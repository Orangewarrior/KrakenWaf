
mod loader;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, path::{Component, Path}};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum HttpAction {
    #[default]
    Request,
    Response,
}

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
    /// Exact IPs blocked from all access (from rules/addr/blocklist.txt).
    pub blocked_ips: Vec<String>,
    /// CIDR ranges blocked (from rules.json:blocked_ip_prefixes — kept for compat).
    pub blocked_ip_prefixes: Vec<String>,
    /// IPs allowed to access /metrics and /__krakenwaf/health (from rules/addr/allowlist.txt).
    pub allowed_ips: Vec<String>,
    /// Scanner/crawler user-agent substrings (from rules/user_agents/scanners.txt).
    pub scanner_agents: Vec<String>,
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
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cwe: String,
    pub description: String,
    pub reference_url: String,
    pub rule_match: String,
    pub source: String,
    pub line: usize,
    pub http_action: HttpAction,
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

    /// Returns true if the client IP is in rules/addr/allowlist.txt (may access health/metrics).
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.allowed_ips.is_empty() {
            return true; // No allowlist configured → all IPs may access health/metrics.
        }
        self.allowed_ips.iter().any(|entry| {
            if let Ok(net) = entry.parse::<ipnet::IpNet>() {
                if let Ok(client) = ip.parse::<std::net::IpAddr>() {
                    return net.contains(&client);
                }
            }
            entry.trim() == ip.trim()
        })
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
            Component::RootDir | Component::CurDir => {}
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

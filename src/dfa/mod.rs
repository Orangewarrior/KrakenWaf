use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};
use tracing::warn;

mod esi_injection_detect;
mod overflow_detect;
mod sqli_comments_detect;
mod ssi_injection_detect;
mod ssti_detect;

use crate::rules::Severity;
use crate::waf::Finding;
use chrono::Utc;

pub use esi_injection_detect::EsiInjectionDfaBuilder;
pub use overflow_detect::OverflowDfaBuilder;
pub use sqli_comments_detect::SqliCommentsDfaBuilder;
pub use ssi_injection_detect::SsiInjectionDfaBuilder;
pub use ssti_detect::SstiDfaBuilder;

#[derive(Debug, Clone, Default)]
pub struct DfaConfig {
    pub sqli_comments_detect: bool,
    pub overflow_detect: bool,
    pub ssti_detect: bool,
    pub ssi_injection_detect: bool,
    pub esi_injection_detect: bool,
}

impl DfaConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read DFA config {}", path.display()))?;
        parse_lenient_yaml(&content)
            .with_context(|| format!("failed to parse DFA config {}", path.display()))
    }
}

#[derive(Debug, Default)]
pub struct DfaManagerBuilder {
    config: DfaConfig,
}

impl DfaManagerBuilder {
    pub fn new(config: DfaConfig) -> Self { Self { config } }

    pub fn build(self) -> DfaManager {
        DfaManager {
            sqli_comments: self.config.sqli_comments_detect.then(|| SqliCommentsDfaBuilder::new().threshold(2).build()),
            overflow: self.config.overflow_detect.then(|| OverflowDfaBuilder::new().threshold(10).build()),
            ssti: self.config.ssti_detect.then(|| SstiDfaBuilder::new().build()),
            ssi: self.config.ssi_injection_detect.then(|| SsiInjectionDfaBuilder::new().build()),
            esi: self.config.esi_injection_detect.then(|| EsiInjectionDfaBuilder::new().build()),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct DfaManager {
    sqli_comments: Option<sqli_comments_detect::SqliCommentsDfa>,
    overflow: Option<overflow_detect::OverflowDfa>,
    ssti: Option<ssti_detect::SstiDfa>,
    ssi: Option<ssi_injection_detect::SsiInjectionDfa>,
    esi: Option<esi_injection_detect::EsiInjectionDfa>,
}

impl DfaManager {
    pub fn inspect(&self, input: &str) -> Option<Finding> {
        if let Some(detector) = &self.sqli_comments {
            let total = detector.count_matches(input);
            if detector.matches(input) {
                return Some(finding(
                    "DFA SQLi comment evasion detection",
                    Severity::High,
                    "CWE-89",
                    &format!("Detected repeated SQL block comments often used to obfuscate injection payloads. Total comments found: {total}."),
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    format!("dfa::sqli_comments_detect:comments-total={total}"),
                    "dfa/sqli_comments_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.overflow {
            if let Some((ch, total)) = detector.detect_run(input) {
                return Some(finding(
                    "DFA repeated-character overflow detection",
                    Severity::Medium,
                    "CWE-400",
                    &format!("Detected a repeated-character run of length {total}, which may indicate overflow, flooding or parser abuse. Character: {:?}.", ch),
                    "https://cwe.mitre.org/data/definitions/400.html",
                    format!("dfa::overflow_detect:repeated-char={} count={total}", ch.escape_default()),
                    "dfa/overflow_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.ssti {
            if let Some(rule) = detector.detect(input) {
                return Some(finding(
                    "DFA SSTI detection",
                    Severity::High,
                    "CWE-1336",
                    &format!("Detected SSTI payload pattern {} using a dedicated DFA module.", rule.id()),
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    format!("dfa::ssti_detect:{}:{}", rule.id(), rule.pattern()),
                    "dfa/ssti_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.ssi {
            if let Some(keyword) = detector.detect(input) {
                return Some(finding(
                    "DFA SSI injection detection",
                    Severity::High,
                    "CWE-97",
                    "Detected a server-side include directive pattern in attacker-controlled input.",
                    "https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection",
                    format!("dfa::ssi_injection_detect:{keyword}"),
                    "dfa/ssi_injection_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.esi {
            if let Some(keyword) = detector.detect(input) {
                return Some(finding(
                    "DFA ESI injection detection",
                    Severity::High,
                    "CWE-94",
                    "Detected an Edge Side Include directive pattern in attacker-controlled input.",
                    "https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection",
                    format!("dfa::esi_injection_detect:{keyword}"),
                    "dfa/esi_injection_detect.rs:generated",
                    input,
                ));
            }
        }

        None
    }
}

fn finding(title: &str, severity: Severity, cwe: &str, description: &str, reference_url: &str, rule_match: String, rule_line_match: &str, input: &str) -> Finding {
    Finding {
        rule_id: "00000".to_string(),
        title: title.to_string(),
        severity,
        cwe: cwe.to_string(),
        description: description.to_string(),
        reference_url: reference_url.to_string(),
        rule_match,
        rule_line_match: rule_line_match.to_string(),
        request_payload: input.chars().take(2048).collect(),
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn parse_lenient_yaml(content: &str) -> Result<DfaConfig> {
    // Accept both integer (0/1) and YAML-boolean (true/false) values so that
    // `SSTI_detect: true` enables the engine instead of silently coercing to 0.
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum BoolOrInt {
        Bool(bool),
        Int(i64),
    }
    impl From<BoolOrInt> for i64 {
        fn from(v: BoolOrInt) -> i64 {
            match v {
                BoolOrInt::Bool(b) => b as i64,
                BoolOrInt::Int(n) => n,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct StrictCfg {
        #[serde(rename = "DFA-Rules")]
        dfa_rules: Option<BTreeMap<String, BoolOrInt>>,
    }

    if let Ok(strict) = serde_yaml::from_str::<StrictCfg>(content) {
        if let Some(map) = strict.dfa_rules {
            let int_map: BTreeMap<String, i64> = map.into_iter().map(|(k, v)| (k, v.into())).collect();
            return Ok(from_map(&int_map));
        }
    }

    let mut map = BTreeMap::new();
    let mut saw_candidate = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" || trimmed.eq_ignore_ascii_case("DFA-Rules") || trimmed.eq_ignore_ascii_case("DFA-Rules:") {
            continue;
        }
        let normalized = trimmed.replace('=', ":");
        if let Some((k, v)) = normalized.split_once(':') {
            saw_candidate = true;
            let key = k.trim().to_string();
            let raw = v.trim();
            let value = if raw.eq_ignore_ascii_case("true") {
                1i64
            } else if raw.eq_ignore_ascii_case("false") {
                0i64
            } else if let Ok(n) = raw.parse::<i64>() {
                n
            } else {
                warn!(
                    target: "krakenwaf",
                    key = %key,
                    raw_value = %raw,
                    "DFA config: unrecognised value, treating as disabled (expected 0/1 or true/false)"
                );
                0i64
            };
            map.insert(key, value);
        }
    }
    if map.is_empty() && saw_candidate {
        warn!(target: "krakenwaf", "DFA YAML fallback parser did not recover any valid rules; all DFA engines will remain disabled");
    } else if map.is_empty() {
        warn!(target: "krakenwaf", "DFA config parsed to an empty rule map; all DFA engines are disabled");
    }
    Ok(from_map(&map))
}

fn from_map(map: &BTreeMap<String, i64>) -> DfaConfig {
    let enabled = |name: &str| map.get(name).copied().unwrap_or(0) == 1;
    DfaConfig {
        sqli_comments_detect: enabled("SQLi_comments_detect"),
        overflow_detect: enabled("Overflow_detect"),
        ssti_detect: enabled("SSTI_detect"),
        ssi_injection_detect: enabled("SSI_injection_detect"),
        esi_injection_detect: enabled("ESI_injection_detect"),
    }
}

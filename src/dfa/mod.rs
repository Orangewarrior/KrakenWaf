use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};
use tracing::warn;

mod anti_exposed_backup;
mod anti_passwd_leak;
mod crlf_injection_detect;
mod esi_injection_detect;
mod java_deserialize_detect;
mod nosql_injection_detect;
mod overflow_detect;
mod request_smuggling_detect;
mod sqli_comments_detect;
mod ssi_injection_detect;
mod ssti_detect;
mod xxe_attack_detect;

use crate::rules::Severity;
use crate::waf::Finding;
use chrono::Utc;

pub use anti_exposed_backup::AntiExposedBackupDfaBuilder;
pub use anti_passwd_leak::AntiPasswdLeakDfaBuilder;
pub use crlf_injection_detect::CrlfInjectionDfaBuilder;
pub use java_deserialize_detect::JavaDeserializeDfaBuilder;
pub use esi_injection_detect::EsiInjectionDfaBuilder;
pub use nosql_injection_detect::NoSqlInjectionDfaBuilder;
pub use overflow_detect::OverflowDfaBuilder;
pub use request_smuggling_detect::RequestSmugglingDfaBuilder;
pub use sqli_comments_detect::SqliCommentsDfaBuilder;
pub use ssi_injection_detect::SsiInjectionDfaBuilder;
pub use ssti_detect::SstiDfaBuilder;
pub use xxe_attack_detect::XxeAttackDfaBuilder;

#[derive(Debug, Clone)]
pub struct DfaConfig {
    pub sqli_comments_detect: bool,
    pub overflow_detect: bool,
    pub ssti_detect: bool,
    pub ssi_injection_detect: bool,
    pub esi_injection_detect: bool,
    pub crlf_injection_detect: bool,
    pub request_smuggling_detect: bool,
    pub nosql_injection_detect: bool,
    pub xxe_attack_detect: bool,
    pub anti_exposed_backup: bool,
    pub anti_passwd_leak_detect: bool,
    pub java_deserialize_detect: bool,
    /// Global paranoia level (0–100). Controls the 2-signal block threshold
    /// and the 1-signal informative-log threshold in `java_deserialize_detect`.
    /// Default: 60.
    pub untrust_level: u8,
}

impl Default for DfaConfig {
    fn default() -> Self {
        Self {
            sqli_comments_detect: false,
            overflow_detect: false,
            ssti_detect: false,
            ssi_injection_detect: false,
            esi_injection_detect: false,
            crlf_injection_detect: false,
            request_smuggling_detect: false,
            nosql_injection_detect: false,
            xxe_attack_detect: false,
            anti_exposed_backup: false,
            anti_passwd_leak_detect: false,
            java_deserialize_detect: false,
            untrust_level: 60,
        }
    }
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
    vectorscan_enabled: bool,
}

impl DfaManagerBuilder {
    pub fn new(config: DfaConfig) -> Self {
        Self {
            config,
            vectorscan_enabled: false,
        }
    }

    pub fn vectorscan_enabled(mut self, enabled: bool) -> Self {
        self.vectorscan_enabled = enabled;
        self
    }

    pub fn build(self) -> DfaManager {
        DfaManager {
            sqli_comments: self
                .config
                .sqli_comments_detect
                .then(|| SqliCommentsDfaBuilder::new().threshold(2).build()),
            overflow: self
                .config
                .overflow_detect
                .then(|| OverflowDfaBuilder::new().threshold(10).build()),
            ssti: self
                .config
                .ssti_detect
                .then(|| SstiDfaBuilder::new().build()),
            ssi: self
                .config
                .ssi_injection_detect
                .then(|| SsiInjectionDfaBuilder::new().build()),
            esi: self
                .config
                .esi_injection_detect
                .then(|| EsiInjectionDfaBuilder::new().build()),
            crlf: self
                .config
                .crlf_injection_detect
                .then(|| CrlfInjectionDfaBuilder::new().build()),
            request_smuggling: self
                .config
                .request_smuggling_detect
                .then(|| RequestSmugglingDfaBuilder::new().build()),
            nosql_injection: self.config.nosql_injection_detect.then(|| {
                NoSqlInjectionDfaBuilder::new()
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            xxe_attack: self.config.xxe_attack_detect.then(|| {
                XxeAttackDfaBuilder::new()
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            anti_exposed_backup: self.config.anti_exposed_backup.then(|| {
                AntiExposedBackupDfaBuilder::new()
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            anti_passwd_leak: self.config.anti_passwd_leak_detect.then(|| {
                AntiPasswdLeakDfaBuilder::new()
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            java_deserialize: self.config.java_deserialize_detect.then(|| {
                JavaDeserializeDfaBuilder::new()
                    .untrust_level(self.config.untrust_level)
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
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
    crlf: Option<crlf_injection_detect::CrlfInjectionDfa>,
    request_smuggling: Option<request_smuggling_detect::RequestSmugglingDfa>,
    nosql_injection: Option<nosql_injection_detect::NoSqlInjectionDfa>,
    xxe_attack: Option<xxe_attack_detect::XxeAttackDfa>,
    anti_exposed_backup: Option<anti_exposed_backup::AntiExposedBackupDfa>,
    anti_passwd_leak: Option<anti_passwd_leak::AntiPasswdLeakDfa>,
    java_deserialize: Option<java_deserialize_detect::JavaDeserializeDfa>,
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
            if let Some(shellcode) = detector.detect_shellcode(input) {
                return Some(finding(
                    "DFA shellcode opcode detection",
                    Severity::High,
                    "CWE-94",
                    &format!(
                        "Detected {} shellcode-like opcode sequence using the overflow DFA module. Pattern: {}. Score: {}.",
                        shellcode.arch().as_str(),
                        shellcode.pattern(),
                        shellcode.score()
                    ),
                    "https://owasp.org/www-community/attacks/Buffer_overflow_attack",
                    format!(
                        "dfa::overflow_detect:shellcode:{}:{} score={}",
                        shellcode.arch().as_str(),
                        shellcode.pattern(),
                        shellcode.score()
                    ),
                    "dfa/overflow_detect.rs:generated",
                    input,
                ));
            }

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
                    &format!(
                        "Detected SSTI payload pattern {} using a dedicated DFA module.",
                        rule.id()
                    ),
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

        if let Some(detector) = &self.crlf {
            if let Some(matched) = detector.detect(input) {
                return Some(finding(
                    "DFA CRLF injection detection",
                    Severity::High,
                    "CWE-93",
                    "Detected a CRLF injection or HTTP response-splitting payload pattern in attacker-controlled input.",
                    "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                    format!("dfa::crlf_injection_detect:{}", matched.pattern()),
                    "dfa/crlf_injection_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.request_smuggling {
            if let Some(matched) = detector.detect(input) {
                return Some(finding(
                    "DFA request smuggling detection",
                    Severity::High,
                    "CWE-444",
                    "Detected an HTTP request smuggling payload pattern in attacker-controlled input.",
                    "https://portswigger.net/web-security/request-smuggling",
                    format!("dfa::request_smuggling_detect:{}", matched.pattern()),
                    "dfa/request_smuggling_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.nosql_injection {
            if let Some(matched) = detector.detect(input) {
                return Some(finding(
                    "DFA NoSQL injection detection",
                    Severity::High,
                    "CWE-943",
                    "Detected a NoSQL injection payload with at least one operator or selector marker and at least one suspicious value or control-flow marker.",
                    "https://owasp.org/www-community/attacks/Testing_for_NoSQL_injection",
                    format!(
                        "dfa::nosql_injection_detect:list_A={} list_B={}",
                        matched.list_a(),
                        matched.list_b()
                    ),
                    "dfa/nosql_injection_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.xxe_attack {
            if let Some(matched) = detector.detect(input) {
                return Some(finding(
                    "DFA XXE attack detection",
                    Severity::High,
                    "CWE-611",
                    "Detected an XXE payload with at least one XML entity/include marker and at least one suspicious external entity, SOAP, file, exfiltration, or DOCTYPE marker.",
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    format!(
                        "dfa::xxe_attack_detect:list_A={} list_B={} decoded_utf16={}",
                        matched.list_a(),
                        matched.list_b(),
                        matched.decoded_utf16()
                    ),
                    "dfa/xxe_attack_detect.rs:generated",
                    input,
                ));
            }
        }

        None
    }

    /// Inspect the request URI path. Called from `inspect_early()` so that
    /// method-gated detectors (e.g. `anti_exposed_backup`) have access to the
    /// original method and path before the full payload is assembled.
    pub fn inspect_uri(&self, method: &str, path: &str) -> Option<Finding> {
        if let Some(detector) = &self.anti_exposed_backup {
            if let Some(matched) = detector.detect(method, path) {
                return Some(finding(
                    "DFA exposed backup/temp file detection",
                    Severity::High,
                    "CWE-538",
                    &format!(
                        "Blocked {} request for a backup, temporary, or configuration-leak file. \
                         URI path ends with '{}', a known sensitive file extension that should \
                         never be publicly accessible.",
                        method,
                        matched.suffix()
                    ),
                    "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_References",
                    format!("dfa::anti_exposed_backup:suffix={}", matched.suffix()),
                    "dfa/anti_exposed_backup.rs:generated",
                    &format!("{method} {path}"),
                ));
            }
        }

        None
    }

    /// Inspect the upstream response body for sensitive data leaks.
    /// Called from `inspect_response()` after the full response body is buffered.
    pub fn inspect_response_body(&self, body: &str) -> Option<Finding> {
        if let Some(detector) = &self.anti_passwd_leak {
            if let Some(matched) = detector.detect(body) {
                let (kind_label, cwe) = match matched.kind() {
                    anti_passwd_leak::LeakKind::Passwd => ("passwd", "CWE-538"),
                    anti_passwd_leak::LeakKind::Shadow => ("shadow", "CWE-538"),
                };
                return Some(finding(
                    "DFA passwd/shadow file leak detection",
                    Severity::Critical,
                    cwe,
                    &format!(
                        "Blocked a response body that contains {count} distinct /etc/{kind} \
                         structural tokens ('{a}' and '{b}'), indicating the upstream may be \
                         leaking a Unix password or shadow file to an attacker.",
                        count = matched.match_count(),
                        kind = kind_label,
                        a = matched.token_a(),
                        b = matched.token_b(),
                    ),
                    "https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure",
                    format!(
                        "dfa::anti_passwd_leak:{kind_label}:token_a={a} token_b={b} count={c}",
                        a = matched.token_a(),
                        b = matched.token_b(),
                        c = matched.match_count(),
                    ),
                    "dfa/anti_passwd_leak.rs:generated",
                    &body.chars().take(256).collect::<String>(),
                ));
            }
        }

        None
    }

    /// Inspect a request or response for Java deserialization attack signals.
    ///
    /// `text`      — the combined text representation (headers + body, UTF-8 lossy).
    /// `raw_bytes` — the raw body bytes used for binary magic detection.
    ///
    /// Returns `Some(Finding)` when the detector fires a blocking decision.
    /// Silent / informative log cases emit a `tracing::warn!` but return `None`.
    pub fn inspect_java_deser(&self, text: &str, raw_bytes: &[u8]) -> Option<Finding> {
        use java_deserialize_detect::JavaDeserDecision;

        let detector = self.java_deserialize.as_ref()?;
        match detector.detect(text, raw_bytes) {
            JavaDeserDecision::Block(m) => Some(finding(
                "DFA Java deserialization attack detection",
                Severity::Critical,
                "CWE-502",
                &format!(
                    "Detected Java deserialization attack payload. \
                     {count} distinct signals fired ({signals}). Evidence: {ev}.",
                    count = m.signal_count(),
                    signals = m.signals_fired(),
                    ev = m.evidence(),
                ),
                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                format!(
                    "dfa::java_deserialize_detect:signals={signals} evidence={ev}",
                    signals = m.signals_fired(),
                    ev = m.evidence(),
                ),
                "dfa/java_deserialize_detect.rs:generated",
                &text.chars().take(256).collect::<String>(),
            )),
            JavaDeserDecision::SuspiciousHigh(m) => {
                warn!(
                    target: "krakenwaf",
                    signals = %m.signals_fired(),
                    evidence = %m.evidence(),
                    signal_count = m.signal_count(),
                    "java_deserialize_detect: 2 signals but untrust_level < 60 — suspicious-high, not blocking"
                );
                None
            }
            JavaDeserDecision::SuspiciousLow(m) => {
                warn!(
                    target: "krakenwaf",
                    signals = %m.signals_fired(),
                    evidence = %m.evidence(),
                    signal_count = m.signal_count(),
                    "java_deserialize_detect: 1 signal with untrust_level > 80 — suspicious-low, not blocking"
                );
                None
            }
            JavaDeserDecision::Clean => None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    title: &str,
    severity: Severity,
    cwe: &str,
    description: &str,
    reference_url: &str,
    rule_match: String,
    rule_line_match: &str,
    input: &str,
) -> Finding {
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
        #[serde(rename = "global-options")]
        global_options: Option<BTreeMap<String, serde_yaml::Value>>,
    }

    if let Ok(strict) = serde_yaml::from_str::<StrictCfg>(content) {
        let untrust_level = strict
            .global_options
            .as_ref()
            .and_then(|m| m.get("Untrust"))
            .and_then(|v| match v {
                serde_yaml::Value::Number(n) => n.as_u64().map(|n| n.min(100) as u8),
                _ => None,
            })
            .unwrap_or(60);

        if let Some(map) = strict.dfa_rules {
            let int_map: BTreeMap<String, i64> =
                map.into_iter().map(|(k, v)| (k, v.into())).collect();
            let mut cfg = from_map(&int_map);
            cfg.untrust_level = untrust_level;
            return Ok(cfg);
        }
    }

    // Lenient line-by-line fallback for non-standard / legacy config formats.
    let mut map = BTreeMap::new();
    let mut saw_candidate = false;
    let mut untrust_level: u8 = 60;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed == "---"
            || trimmed.eq_ignore_ascii_case("DFA-Rules")
            || trimmed.eq_ignore_ascii_case("DFA-Rules:")
            || trimmed.eq_ignore_ascii_case("global-options")
            || trimmed.eq_ignore_ascii_case("global-options:")
        {
            continue;
        }
        let normalized = trimmed.replace('=', ":");
        if let Some((k, v)) = normalized.split_once(':') {
            let key = k.trim().to_string();
            let raw = v.trim();

            // Handle Untrust as a global integer option.
            if key == "Untrust" {
                if let Ok(n) = raw.parse::<u8>() {
                    untrust_level = n.min(100);
                }
                continue;
            }

            saw_candidate = true;
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
    let mut cfg = from_map(&map);
    cfg.untrust_level = untrust_level;
    Ok(cfg)
}

fn from_map(map: &BTreeMap<String, i64>) -> DfaConfig {
    let enabled = |name: &str| map.get(name).copied().unwrap_or(0) == 1;
    DfaConfig {
        sqli_comments_detect: enabled("SQLi_comments_detect"),
        overflow_detect: enabled("Overflow_detect"),
        ssti_detect: enabled("SSTI_detect"),
        ssi_injection_detect: enabled("SSI_injection_detect"),
        esi_injection_detect: enabled("ESI_injection_detect"),
        crlf_injection_detect: enabled("CRLF_injection_detect"),
        request_smuggling_detect: enabled("Request_Smuggling_detect"),
        nosql_injection_detect: enabled("NOSQL_injection_detect"),
        xxe_attack_detect: enabled("XXE_attack_detect"),
        anti_exposed_backup: enabled("Anti_exposed_backup"),
        anti_passwd_leak_detect: enabled("Anti_passwd_leak"),
        java_deserialize_detect: enabled("Java_deserialize_detect"),
        untrust_level: 60, // overwritten by caller when global-options is parsed
    }
}

#[cfg(test)]
mod tests {
    use super::parse_lenient_yaml;

    #[test]
    fn parses_crlf_injection_detect_config_key() {
        let crlf = parse_lenient_yaml(
            r#"
DFA-Rules:
  CRLF_injection_detect: true
"#,
        )
        .expect("parse CRLF key");
        assert!(crlf.crlf_injection_detect);
    }

    #[test]
    fn parses_request_smuggling_detect_config_key() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  Request_Smuggling_detect: true
"#,
        )
        .expect("parse request smuggling key");
        assert!(cfg.request_smuggling_detect);
    }

    #[test]
    fn parses_nosql_injection_detect_config_key() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  NOSQL_injection_detect: true
"#,
        )
        .expect("parse NoSQL injection key");
        assert!(cfg.nosql_injection_detect);
    }

    #[test]
    fn parses_xxe_attack_detect_config_key() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  XXE_attack_detect: true
"#,
        )
        .expect("parse XXE attack key");
        assert!(cfg.xxe_attack_detect);
    }

    #[test]
    fn parses_anti_exposed_backup_config_key() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  Anti_exposed_backup: true
"#,
        )
        .expect("parse Anti_exposed_backup key");
        assert!(cfg.anti_exposed_backup);
    }

    #[test]
    fn anti_exposed_backup_disabled_by_default() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  SQLi_comments_detect: true
"#,
        )
        .expect("parse minimal config");
        assert!(!cfg.anti_exposed_backup);
    }

    #[test]
    fn parses_anti_passwd_leak_config_key() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  Anti_passwd_leak: true
"#,
        )
        .expect("parse Anti_passwd_leak key");
        assert!(cfg.anti_passwd_leak_detect);
    }

    #[test]
    fn anti_passwd_leak_disabled_by_default() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  SQLi_comments_detect: true
"#,
        )
        .expect("parse minimal config");
        assert!(!cfg.anti_passwd_leak_detect);
    }

    #[test]
    fn parses_java_deserialize_detect_config_key() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  Java_deserialize_detect: true
"#,
        )
        .expect("parse Java_deserialize_detect key");
        assert!(cfg.java_deserialize_detect);
    }

    #[test]
    fn java_deserialize_detect_disabled_by_default() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  SQLi_comments_detect: true
"#,
        )
        .expect("parse minimal config");
        assert!(!cfg.java_deserialize_detect);
    }

    #[test]
    fn parses_global_options_untrust_level() {
        let cfg = parse_lenient_yaml(
            r#"
global-options:
  Untrust: 75
DFA-Rules:
  Java_deserialize_detect: true
"#,
        )
        .expect("parse global-options Untrust");
        assert_eq!(cfg.untrust_level, 75);
        assert!(cfg.java_deserialize_detect);
    }

    #[test]
    fn untrust_level_defaults_to_60() {
        let cfg = parse_lenient_yaml(
            r#"
DFA-Rules:
  Java_deserialize_detect: true
"#,
        )
        .expect("parse without global-options");
        assert_eq!(cfg.untrust_level, 60);
    }

    #[test]
    fn untrust_level_clamped_to_100() {
        let cfg = parse_lenient_yaml(
            r#"
global-options:
  Untrust: 150
DFA-Rules:
  Java_deserialize_detect: true
"#,
        )
        .expect("parse clamped Untrust");
        assert_eq!(cfg.untrust_level, 100);
    }
}

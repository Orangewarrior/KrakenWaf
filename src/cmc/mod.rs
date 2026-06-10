use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use tracing::warn;

mod anti_exposed_backup;
mod anti_passwd_leak;
mod crlf_injection_detect;
pub mod detect_bad_artifacts;
pub mod detect_bots_n_scanners;
pub mod detect_db_errors;
mod esi_injection_detect;
mod hpp_detect;
mod java_deserialize_detect;
mod nosql_injection_detect;
mod open_redirect_rfi_detect;
mod overflow_detect;
mod request_smuggling_detect;
pub mod silent_sql_errors;
mod sqli_comments_detect;
mod ssi_injection_detect;
mod ssti_detect;
mod xxe_attack_detect;

use crate::rules::Severity;
use crate::waf::Finding;
use chrono::Utc;

/// Decision emitted by CMC response-body inspection.
///
/// * `Block` — WAF returns a 403 and logs the event to all outputs.
/// * `Monitor` — log the event to all outputs but forward the upstream
///   response unchanged.
/// * `SilentReplace` — forward a **modified** response body where the matched
///   substring has been scrubbed; the finding is logged with low severity.
///   Used by `silent_sql_errors` when `untrust_level < 80`.
#[derive(Debug, Clone)]
pub enum CmcResponseDecision {
    Block(Finding),
    Monitor(Finding),
    SilentReplace {
        finding: Finding,
        body: bytes::Bytes,
    },
}

pub use anti_exposed_backup::AntiExposedBackupCmcBuilder;
pub use anti_passwd_leak::AntiPasswdLeakCmcBuilder;
pub use crlf_injection_detect::CrlfInjectionCmcBuilder;
pub use esi_injection_detect::EsiInjectionCmcBuilder;
pub use hpp_detect::HppDetectorBuilder;
pub use java_deserialize_detect::JavaDeserializeCmcBuilder;
pub use nosql_injection_detect::NoSqlInjectionCmcBuilder;
pub use open_redirect_rfi_detect::{
    LangParams, OpenRedirectRfiDetectorBuilder,
};
pub use overflow_detect::OverflowCmcBuilder;
pub use request_smuggling_detect::RequestSmugglingCmcBuilder;
pub use sqli_comments_detect::SqliCommentsCmcBuilder;
pub use ssi_injection_detect::SsiInjectionCmcBuilder;
pub use ssti_detect::SstiCmcBuilder;
pub use xxe_attack_detect::XxeAttackCmcBuilder;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct CmcConfig {
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
    /// Detect HTTP Parameter Pollution (the same parameter name appearing 2+
    /// times) independently in the query string and the request body. A clear
    /// duplicate is reported at `Critical` severity so the existing untrust
    /// scoring blocks the request at the `>= 60` threshold.
    pub hpp_detect: bool,
    /// Detect Open Redirect and Remote/Local File Inclusion attacks by
    /// inspecting redirect/inclusion-prone request parameters (query string on
    /// `GET`, body on `POST`). When a hot parameter's value resolves to an
    /// external/scheme-relative URL it is reported as Open Redirect; a PHP
    /// wrapper / inclusion scheme or a trailing `?`/`%00` marker is reported as
    /// RFI. Both block at High severity.
    pub open_redirect_n_rfi_detect: bool,
    /// Optional localized hot-parameter lists used in addition to the English
    /// base list by `open_redirect_n_rfi_detect`. Driven by the
    /// `multiple-languages-params` / `custom-languages-params` config block.
    pub multi_lang_params: LangParams,
    /// Scan upstream response bodies for DB error fingerprints.
    pub detect_db_errors: bool,
    /// Scrub or block upstream responses leaking OWASP CRS DBMS error
    /// fingerprints. Action depends on `untrust_level`: ≥ 80 blocks, otherwise
    /// the matched substring is replaced with a single space and the response
    /// is forwarded.
    pub silent_sql_errors: bool,
    /// Block requests targeting sensitive file artifacts (dotfiles, config files,
    /// /proc entries, credentials). Based on OWASP CRS `restricted-files.data`.
    /// Action depends on `untrust_level`: ≥ 60 blocks, otherwise logs only.
    pub detect_bad_artifacts: bool,
    /// Block requests whose `User-Agent` matches a known scanner / crawler /
    /// offensive-tooling substring loaded from `rules/user_agents/scanners.txt`
    /// (OWASP CRS `scanners-user-agents.data`).
    /// Action depends on `untrust_level`: ≥ 60 blocks (Low severity), < 60
    /// logs silently.
    pub detect_bots_n_scanners: bool,
    /// Global paranoia level (0–100). Controls the 2-signal block threshold
    /// and the 1-signal informative-log threshold in `java_deserialize_detect`.
    /// At ≥ 60, `detect_db_errors` blocks matching responses; below 60 it logs only.
    /// At ≥ 60, `detect_bad_artifacts` blocks matching requests; below 60 it logs only.
    /// At ≥ 80, `silent_sql_errors` blocks; below 80 it scrubs + low-severity log.
    /// Default: 60.
    pub untrust_level: u8,
    /// Detection-engine block threshold (score). Rules with `score >= threshold`
    /// block on their own; lower-scored rules accumulate inside a single
    /// inspection view until their sum reaches `threshold`.
    /// `None` defers to the CLI flag `--anomaly-threshold` or the built-in
    /// default of 600.
    pub anomaly_threshold: Option<u32>,
    /// Per-request wall-clock cap on WAF inspection (milliseconds). When
    /// `Some(n > 0)` and the deadline elapses, inspection stops scanning
    /// additional views and the request proceeds with whatever findings
    /// were produced so far. `Some(0)` or `None` disables the deadline.
    /// `None` defers to the CLI flag `--max-inspection-ms` or the built-in
    /// default of 0 (disabled).
    pub max_inspection_ms: Option<u64>,
}

impl CmcConfig {
    /// Resolve the effective `anomaly_threshold`:
    ///   1. Explicit `--anomaly-threshold` CLI argument
    ///   2. `Anomaly_threshold` from the CMC config file
    ///   3. Built-in default: 600
    #[must_use]
    pub fn effective_anomaly_threshold(&self, cli: Option<u32>) -> u32 {
        cli.or(self.anomaly_threshold).unwrap_or(600)
    }

    /// Resolve the effective `max_inspection_ms`:
    ///   1. Explicit `--max-inspection-ms` CLI argument
    ///   2. `Max_inspection_ms` from the CMC config file
    ///   3. Built-in default: 0 (disabled)
    #[must_use]
    pub fn effective_max_inspection_ms(&self, cli: Option<u64>) -> u64 {
        cli.or(self.max_inspection_ms).unwrap_or(0)
    }
}

impl Default for CmcConfig {
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
            hpp_detect: false,
            open_redirect_n_rfi_detect: false,
            multi_lang_params: LangParams::default(),
            detect_db_errors: false,
            silent_sql_errors: false,
            detect_bad_artifacts: false,
            detect_bots_n_scanners: false,
            untrust_level: 60,
            anomaly_threshold: None,
            max_inspection_ms: None,
        }
    }
}

impl CmcConfig {
    /// # Errors
    /// Returns an error if the file cannot be read or contains invalid YAML.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read CMC config {}", path.display()))?;
        parse_lenient_yaml(&content)
            .with_context(|| format!("failed to parse CMC config {}", path.display()))
    }
}

#[derive(Debug, Default)]
pub struct CmcManagerBuilder {
    config: CmcConfig,
    vectorscan_enabled: bool,
    /// Root directory used to resolve the DB-error pattern file
    /// (`<rules_dir>/error_msgs/sql_errors.txt`).
    rules_dir: Option<PathBuf>,
}

impl CmcManagerBuilder {
    #[must_use]
    pub fn new(config: CmcConfig) -> Self {
        Self {
            config,
            vectorscan_enabled: false,
            rules_dir: None,
        }
    }

    #[must_use]
    pub fn vectorscan_enabled(mut self, enabled: bool) -> Self {
        self.vectorscan_enabled = enabled;
        self
    }

    #[must_use]
    pub fn rules_dir(mut self, dir: PathBuf) -> Self {
        self.rules_dir = Some(dir);
        self
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn build(self) -> CmcManager {
        CmcManager {
            sqli_comments: self
                .config
                .sqli_comments_detect
                .then(|| SqliCommentsCmcBuilder::new().threshold(2).build()),
            overflow: self
                .config
                .overflow_detect
                .then(|| OverflowCmcBuilder::new().threshold(10).build()),
            ssti: self
                .config
                .ssti_detect
                .then(|| SstiCmcBuilder::new().build()),
            ssi: self
                .config
                .ssi_injection_detect
                .then(|| SsiInjectionCmcBuilder::new().build()),
            esi: self
                .config
                .esi_injection_detect
                .then(|| EsiInjectionCmcBuilder::new().build()),
            crlf: self
                .config
                .crlf_injection_detect
                .then(|| CrlfInjectionCmcBuilder::new().build()),
            request_smuggling: self
                .config
                .request_smuggling_detect
                .then(|| RequestSmugglingCmcBuilder::new().build()),
            nosql_injection: self.config.nosql_injection_detect.then(|| {
                NoSqlInjectionCmcBuilder::new()
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            xxe_attack: self.config.xxe_attack_detect.then(|| {
                XxeAttackCmcBuilder::new()
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            anti_exposed_backup: self.config.anti_exposed_backup.then(|| {
                AntiExposedBackupCmcBuilder::new()
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            anti_passwd_leak: self.config.anti_passwd_leak_detect.then(|| {
                AntiPasswdLeakCmcBuilder::new()
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            java_deserialize: self.config.java_deserialize_detect.then(|| {
                JavaDeserializeCmcBuilder::new()
                    .untrust_level(self.config.untrust_level)
                    .vectorscan_enabled(self.vectorscan_enabled)
                    .build()
            }),
            hpp_detect: self
                .config
                .hpp_detect
                .then(|| HppDetectorBuilder::new().build()),
            open_redirect_rfi: self.config.open_redirect_n_rfi_detect.then(|| {
                OpenRedirectRfiDetectorBuilder::new()
                    .lang_params(self.config.multi_lang_params)
                    .build()
            }),
            detect_db_errors: if self.config.detect_db_errors {
                if let Some(ref dir) = self.rules_dir {
                    let path = dir.join("error_msgs/sql_errors.txt");
                    match detect_db_errors::DbErrorDetector::from_file(
                        &path,
                        self.vectorscan_enabled,
                    ) {
                        Ok(d) => {
                            tracing::info!(
                                target: "krakenwaf",
                                patterns = d.pattern_count(),
                                path = %path.display(),
                                "detect_db_errors: loaded DB error patterns"
                            );
                            Some(d)
                        }
                        Err(e) => {
                            warn!(
                                target: "krakenwaf",
                                error = %e,
                                path = %path.display(),
                                "detect_db_errors: failed to load patterns — module disabled"
                            );
                            None
                        }
                    }
                } else {
                    warn!(
                        target: "krakenwaf",
                        "detect_db_errors: enabled in config but no rules_dir supplied — module disabled"
                    );
                    None
                }
            } else {
                None
            },
            silent_sql_errors: if self.config.silent_sql_errors {
                if let Some(ref dir) = self.rules_dir {
                    let path = dir.join("error_msgs/sql_errors_static.txt");
                    match silent_sql_errors::SilentSqlErrorsDetector::from_file(
                        &path,
                        self.vectorscan_enabled,
                    ) {
                        Ok(d) => {
                            tracing::info!(
                                target: "krakenwaf",
                                patterns = d.pattern_count(),
                                path = %path.display(),
                                "silent_sql_errors: loaded static DBMS error fingerprints"
                            );
                            Some(d)
                        }
                        Err(e) => {
                            warn!(
                                target: "krakenwaf",
                                error = %e,
                                path = %path.display(),
                                "silent_sql_errors: failed to load patterns — module disabled"
                            );
                            None
                        }
                    }
                } else {
                    warn!(
                        target: "krakenwaf",
                        "silent_sql_errors: enabled in config but no rules_dir supplied — module disabled"
                    );
                    None
                }
            } else {
                None
            },
            detect_bad_artifacts: if self.config.detect_bad_artifacts {
                if let Some(ref dir) = self.rules_dir {
                    let path = dir.join("artifacts/file_pitfalls.txt");
                    match detect_bad_artifacts::BadArtifactsDetector::from_file(
                        &path,
                        self.vectorscan_enabled,
                    ) {
                        Ok(d) => {
                            tracing::info!(
                                target: "krakenwaf",
                                patterns = d.pattern_count(),
                                path = %path.display(),
                                "detect_bad_artifacts: loaded artifact patterns"
                            );
                            Some(d)
                        }
                        Err(e) => {
                            warn!(target: "krakenwaf", error = %e, path = %path.display(),
                                "detect_bad_artifacts: failed to load patterns — module disabled");
                            None
                        }
                    }
                } else {
                    warn!(target: "krakenwaf", "detect_bad_artifacts: enabled in config but no rules_dir supplied — module disabled");
                    None
                }
            } else {
                None
            },
            detect_bots_n_scanners: if self.config.detect_bots_n_scanners {
                if let Some(ref dir) = self.rules_dir {
                    let path = dir.join("user_agents/scanners.txt");
                    match detect_bots_n_scanners::DetectBotsNScannersCmc::from_file(
                        &path,
                        self.vectorscan_enabled,
                    ) {
                        Ok(d) => {
                            tracing::info!(
                                target: "krakenwaf",
                                patterns = d.pattern_count(),
                                path = %path.display(),
                                "detect_bots_n_scanners: loaded scanner user-agent patterns"
                            );
                            Some(d)
                        }
                        Err(e) => {
                            warn!(target: "krakenwaf", error = %e, path = %path.display(),
                                "detect_bots_n_scanners: failed to load patterns — module disabled");
                            None
                        }
                    }
                } else {
                    warn!(target: "krakenwaf", "detect_bots_n_scanners: enabled in config but no rules_dir supplied — module disabled");
                    None
                }
            } else {
                None
            },
            untrust_level: self.config.untrust_level,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CmcManager {
    sqli_comments: Option<sqli_comments_detect::SqliCommentsCmc>,
    overflow: Option<overflow_detect::OverflowCmc>,
    ssti: Option<ssti_detect::SstiCmc>,
    ssi: Option<ssi_injection_detect::SsiInjectionCmc>,
    esi: Option<esi_injection_detect::EsiInjectionCmc>,
    crlf: Option<crlf_injection_detect::CrlfInjectionCmc>,
    request_smuggling: Option<request_smuggling_detect::RequestSmugglingCmc>,
    nosql_injection: Option<nosql_injection_detect::NoSqlInjectionCmc>,
    xxe_attack: Option<xxe_attack_detect::XxeAttackCmc>,
    anti_exposed_backup: Option<anti_exposed_backup::AntiExposedBackupCmc>,
    anti_passwd_leak: Option<anti_passwd_leak::AntiPasswdLeakCmc>,
    java_deserialize: Option<java_deserialize_detect::JavaDeserializeCmc>,
    hpp_detect: Option<hpp_detect::HppDetector>,
    open_redirect_rfi: Option<open_redirect_rfi_detect::OpenRedirectRfiDetector>,
    detect_db_errors: Option<detect_db_errors::DbErrorDetector>,
    silent_sql_errors: Option<silent_sql_errors::SilentSqlErrorsDetector>,
    detect_bad_artifacts: Option<detect_bad_artifacts::BadArtifactsDetector>,
    detect_bots_n_scanners: Option<detect_bots_n_scanners::DetectBotsNScannersCmc>,
    untrust_level: u8,
}

impl Default for CmcManager {
    fn default() -> Self {
        Self {
            sqli_comments: None,
            overflow: None,
            ssti: None,
            ssi: None,
            esi: None,
            crlf: None,
            request_smuggling: None,
            nosql_injection: None,
            xxe_attack: None,
            anti_exposed_backup: None,
            anti_passwd_leak: None,
            java_deserialize: None,
            hpp_detect: None,
            open_redirect_rfi: None,
            detect_db_errors: None,
            silent_sql_errors: None,
            detect_bad_artifacts: None,
            detect_bots_n_scanners: None,
            untrust_level: 60,
        }
    }
}

impl CmcManager {
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn inspect(&self, input: &str) -> Option<Finding> {
        if let Some(detector) = &self.sqli_comments {
            let total = detector.count_matches(input);
            if detector.matches(input) {
                return Some(finding(
                    "CMC SQLi comment evasion detection",
                    Severity::High,
                    "CWE-89",
                    &format!("Detected repeated SQL block comments often used to obfuscate injection payloads. Total comments found: {total}."),
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    format!("cmc::sqli_comments_detect:comments-total={total}"),
                    "cmc/sqli_comments_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.overflow {
            if let Some(shellcode) = detector.detect_shellcode(input) {
                return Some(finding(
                    "CMC shellcode opcode detection",
                    Severity::High,
                    "CWE-94",
                    &format!(
                        "Detected {} shellcode-like opcode sequence using the overflow CMC module. Pattern: {}. Score: {}.",
                        shellcode.arch().as_str(),
                        shellcode.pattern(),
                        shellcode.score()
                    ),
                    "https://owasp.org/www-community/attacks/Buffer_overflow_attack",
                    format!(
                        "cmc::overflow_detect:shellcode:{}:{} score={}",
                        shellcode.arch().as_str(),
                        shellcode.pattern(),
                        shellcode.score()
                    ),
                    "cmc/overflow_detect.rs:generated",
                    input,
                ));
            }

            if let Some((ch, total)) = detector.detect_run(input) {
                return Some(finding(
                    "CMC repeated-character overflow detection",
                    Severity::Medium,
                    "CWE-400",
                    &format!("Detected a repeated-character run of length {total}, which may indicate overflow, flooding or parser abuse. Character: {ch:?}."),
                    "https://cwe.mitre.org/data/definitions/400.html",
                    format!("cmc::overflow_detect:repeated-char={} count={total}", ch.escape_default()),
                    "cmc/overflow_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.ssti {
            if let Some(rule) = detector.detect(input) {
                return Some(finding(
                    "CMC SSTI detection",
                    Severity::High,
                    "CWE-1336",
                    &format!(
                        "Detected SSTI payload pattern {} using a dedicated CMC module.",
                        rule.id()
                    ),
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    format!("cmc::ssti_detect:{}:{}", rule.id(), rule.pattern()),
                    "cmc/ssti_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.ssi {
            if let Some(keyword) = detector.detect(input) {
                return Some(finding(
                    "CMC SSI injection detection",
                    Severity::High,
                    "CWE-97",
                    "Detected a server-side include directive pattern in attacker-controlled input.",
                    "https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection",
                    format!("cmc::ssi_injection_detect:{keyword}"),
                    "cmc/ssi_injection_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.esi {
            if let Some(keyword) = detector.detect(input) {
                return Some(finding(
                    "CMC ESI injection detection",
                    Severity::High,
                    "CWE-94",
                    "Detected an Edge Side Include directive pattern in attacker-controlled input.",
                    "https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection",
                    format!("cmc::esi_injection_detect:{keyword}"),
                    "cmc/esi_injection_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.crlf {
            if let Some(matched) = detector.detect(input) {
                return Some(finding(
                    "CMC CRLF injection detection",
                    Severity::High,
                    "CWE-93",
                    "Detected a CRLF injection or HTTP response-splitting payload pattern in attacker-controlled input.",
                    "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                    format!("cmc::crlf_injection_detect:{}", matched.pattern()),
                    "cmc/crlf_injection_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.request_smuggling {
            if let Some(matched) = detector.detect(input) {
                return Some(finding(
                    "CMC request smuggling detection",
                    Severity::High,
                    "CWE-444",
                    "Detected an HTTP request smuggling payload pattern in attacker-controlled input.",
                    "https://portswigger.net/web-security/request-smuggling",
                    format!("cmc::request_smuggling_detect:{}", matched.pattern()),
                    "cmc/request_smuggling_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.nosql_injection {
            if let Some(matched) = detector.detect(input) {
                return Some(finding(
                    "CMC NoSQL injection detection",
                    Severity::High,
                    "CWE-943",
                    "Detected a NoSQL injection payload with at least one operator or selector marker and at least one suspicious value or control-flow marker.",
                    "https://owasp.org/www-community/attacks/Testing_for_NoSQL_injection",
                    format!(
                        "cmc::nosql_injection_detect:list_A={} list_B={}",
                        matched.list_a(),
                        matched.list_b()
                    ),
                    "cmc/nosql_injection_detect.rs:generated",
                    input,
                ));
            }
        }

        if let Some(detector) = &self.xxe_attack {
            if let Some(matched) = detector.detect(input) {
                return Some(finding(
                    "CMC XXE attack detection",
                    Severity::High,
                    "CWE-611",
                    "Detected an XXE payload with at least one XML entity/include marker and at least one suspicious external entity, SOAP, file, exfiltration, or DOCTYPE marker.",
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    format!(
                        "cmc::xxe_attack_detect:list_A={} list_B={} decoded_utf16={}",
                        matched.list_a(),
                        matched.list_b(),
                        matched.decoded_utf16()
                    ),
                    "cmc/xxe_attack_detect.rs:generated",
                    input,
                ));
            }
        }

        None
    }

    /// Inspect the request `User-Agent` header value for known scanner /
    /// crawler / offensive-tooling substrings.  Called from `inspect_early()`
    /// before any payload inspection.
    ///
    /// Returns `Some(Finding)` when the module is enabled, a pattern matches,
    /// and the global `untrust_level` is `>= 60` — in which case the WAF
    /// should reply with HTTP 403 and log the event at `Low` severity to
    /// raw, `JSONL` and `SQLite` outputs (treated as a bot/scanner sweep).
    /// When `untrust_level < 60` the match is logged via `tracing::warn!`
    /// and `None` is returned so the request proceeds.
    #[must_use]
    pub fn inspect_user_agent(&self, user_agent: &str) -> Option<Finding> {
        let detector = self.detect_bots_n_scanners.as_ref()?;
        let matched = detector.detect(user_agent)?;
        if self.untrust_level >= 60 {
            return Some(finding(
                "CMC bot/scanner user-agent detection",
                Severity::Low,
                "CWE-200",
                &format!(
                    "Blocked request: User-Agent contains a known scanner/crawler/offensive tooling \
                     substring '{pat}'. Treated as a bot or scanner reconnaissance sweep against the \
                     protected origin.",
                    pat = matched.matched_pattern(),
                ),
                "https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data",
                format!(
                    "cmc::detect_bots_n_scanners:pattern={}",
                    matched.matched_pattern()
                ),
                "cmc/detect_bots_n_scanners.rs:generated",
                user_agent,
            ));
        }
        warn!(
            target: "krakenwaf",
            pattern = %matched.matched_pattern(),
            user_agent = user_agent,
            "detect_bots_n_scanners: untrust_level < 60 — scanner UA match, not blocking"
        );
        None
    }

    /// Inspect the request URI path. Called from `inspect_early()` so that
    /// method-gated detectors (e.g. `anti_exposed_backup`) have access to the
    /// original method and path before the full payload is assembled.
    #[must_use]
    pub fn inspect_uri(&self, method: &str, path: &str) -> Option<Finding> {
        if let Some(detector) = &self.anti_exposed_backup {
            if let Some(matched) =
                detector.detect(method, path) as Option<anti_exposed_backup::AntiExposedBackupMatch>
            {
                return Some(finding(
                    "CMC exposed backup/temp file detection",
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
                    format!("cmc::anti_exposed_backup:suffix={}", matched.suffix()),
                    "cmc/anti_exposed_backup.rs:generated",
                    &format!("{method} {path}"),
                ));
            }
        }

        if let Some(detector) = &self.detect_bad_artifacts {
            if let Some(matched) = detector.scan(path.as_bytes()) {
                if self.untrust_level >= 60 {
                    return Some(finding(
                        "CMC sensitive artifact access detection",
                        Severity::High,
                        "CWE-538",
                        &format!(
                            "Blocked {method} request targeting a sensitive file artifact. \
                             URI path contains '{pat}', a known credential, configuration, \
                             or system file pattern that should never be publicly accessible.",
                            pat = matched.matched_pattern(),
                        ),
                        "https://github.com/coreruleset/coreruleset/blob/main/rules/restricted-files.data",
                        format!("cmc::detect_bad_artifacts:pattern={}", matched.matched_pattern()),
                        "cmc/detect_bad_artifacts.rs:generated",
                        &format!("{method} {path}"),
                    ));
                }
                // untrust < 60: log silently, don't block
                warn!(
                    target: "krakenwaf",
                    pattern = %matched.matched_pattern(),
                    path = path,
                    "detect_bad_artifacts: untrust_level < 60 — artifact match, not blocking"
                );
            }
        }

        None
    }

    /// Inspect the upstream response body for sensitive data leaks and DB error
    /// fingerprints. Called from `inspect_response()` after the full response
    /// body is buffered.
    ///
    /// Returns `Some(CmcResponseDecision::Block(_))` to abort the response,
    /// or `Some(CmcResponseDecision::Monitor(_))` to log without blocking.
    #[must_use]
    pub fn inspect_response_body(&self, body: &str) -> Option<CmcResponseDecision> {
        if let Some(detector) = &self.anti_passwd_leak {
            if let Some(matched) = detector.detect(body) {
                let (kind_label, cwe) = match matched.kind() {
                    anti_passwd_leak::LeakKind::Passwd => ("passwd", "CWE-538"),
                    anti_passwd_leak::LeakKind::Shadow => ("shadow", "CWE-538"),
                };
                return Some(CmcResponseDecision::Block(finding(
                    "CMC passwd/shadow file leak detection",
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
                        "cmc::anti_passwd_leak:{kind_label}:token_a={a} token_b={b} count={c}",
                        a = matched.token_a(),
                        b = matched.token_b(),
                        c = matched.match_count(),
                    ),
                    "cmc/anti_passwd_leak.rs:generated",
                    &body.chars().take(256).collect::<String>(),
                )));
            }
        }

        if let Some(detector) = &self.detect_db_errors {
            if let Some(matched) = detector.detect(body) {
                let f = finding(
                    "CMC DB error-based attack detection",
                    Severity::High,
                    "CWE-209",
                    &format!(
                        "Upstream response body contains a database error message that may \
                         disclose DBMS internals to an attacker, enabling error-based injection \
                         reconnaissance. Matched pattern: '{pat}'.",
                        pat = matched.matched_pattern(),
                    ),
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    format!(
                        "cmc::detect_db_errors:pattern={}",
                        matched.matched_pattern()
                    ),
                    "cmc/detect_db_errors.rs:generated",
                    &body.chars().take(256).collect::<String>(),
                );
                if self.untrust_level >= 60 {
                    return Some(CmcResponseDecision::Block(f));
                }
                return Some(CmcResponseDecision::Monitor(f));
            }
        }

        if let Some(detector) = &self.silent_sql_errors {
            if let Some(m) = detector.scan(body.as_bytes()) {
                let severity = if self.untrust_level >= 80 {
                    Severity::High
                } else {
                    Severity::Low
                };
                let f = finding(
                    "CMC silent SQL error scrubber",
                    severity,
                    "CWE-209",
                    &format!(
                        "Upstream response body leaks a static DBMS error fingerprint that an \
                         error-based SQL injection probe could use to enumerate the backend. \
                         Matched literal: '{pat}'.",
                        pat = m.matched_pattern,
                    ),
                    "https://github.com/coreruleset/coreruleset/blob/main/rules/sql-errors.data",
                    format!("cmc::silent_sql_errors:literal={}", m.matched_pattern),
                    "cmc/silent_sql_errors.rs:generated",
                    &body.chars().take(256).collect::<String>(),
                );
                if self.untrust_level >= 80 {
                    return Some(CmcResponseDecision::Block(f));
                }
                let scrubbed = silent_sql_errors::scrub(body.as_bytes(), &m);
                return Some(CmcResponseDecision::SilentReplace {
                    finding: f,
                    body: bytes::Bytes::from(scrubbed),
                });
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
                "CMC Java deserialization attack detection",
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
                    "cmc::java_deserialize_detect:signals={signals} evidence={ev}",
                    signals = m.signals_fired(),
                    ev = m.evidence(),
                ),
                "cmc/java_deserialize_detect.rs:generated",
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

#[allow(clippy::unnecessary_wraps, clippy::too_many_lines)]
fn parse_lenient_yaml(content: &str) -> Result<CmcConfig> {
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
                BoolOrInt::Bool(b) => i64::from(b),
                BoolOrInt::Int(n) => n,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct StrictCfg {
        #[serde(rename = "CMC-Rules")]
        cmc_rules: Option<BTreeMap<String, BoolOrInt>>,
        #[serde(rename = "global-options")]
        global_options: Option<BTreeMap<String, serde_yaml::Value>>,
        #[serde(rename = "multiple-languages-params")]
        multiple_languages_params: Option<BoolOrInt>,
        #[serde(rename = "custom-languages-params")]
        custom_languages_params: Option<BTreeMap<String, BoolOrInt>>,
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

        let anomaly_threshold = strict
            .global_options
            .as_ref()
            .and_then(|m| m.get("Anomaly_threshold"))
            .and_then(|v| match v {
                serde_yaml::Value::Number(n) => {
                    n.as_u64().map(|n| u32::try_from(n).unwrap_or(u32::MAX))
                }
                _ => None,
            });

        let max_inspection_ms = strict
            .global_options
            .as_ref()
            .and_then(|m| m.get("Max_inspection_ms"))
            .and_then(|v| match v {
                serde_yaml::Value::Number(n) => n.as_u64(),
                _ => None,
            });

        let multi_lang_enabled = matches!(strict.multiple_languages_params, Some(BoolOrInt::Bool(true)))
            || matches!(strict.multiple_languages_params, Some(BoolOrInt::Int(n)) if n == 1);
        let lang_map: Option<BTreeMap<String, i64>> = strict
            .custom_languages_params
            .map(|m| m.into_iter().map(|(k, v)| (k, v.into())).collect());
        let multi_lang_params = lang_params_from(multi_lang_enabled, lang_map.as_ref());

        if let Some(map) = strict.cmc_rules {
            let int_map: BTreeMap<String, i64> =
                map.into_iter().map(|(k, v)| (k, v.into())).collect();
            let mut cfg = from_map(&int_map);
            cfg.untrust_level = untrust_level;
            cfg.anomaly_threshold = anomaly_threshold;
            cfg.max_inspection_ms = max_inspection_ms;
            cfg.multi_lang_params = multi_lang_params;
            return Ok(cfg);
        }
    }

    // Lenient line-by-line fallback for non-standard / legacy config formats.
    let mut map = BTreeMap::new();
    let mut saw_candidate = false;
    let mut untrust_level: u8 = 60;
    let mut anomaly_threshold: Option<u32> = None;
    let mut max_inspection_ms: Option<u64> = None;
    let mut multi_lang_enabled = false;
    let mut lang_flags: BTreeMap<String, i64> = BTreeMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed == "---"
            || trimmed.eq_ignore_ascii_case("CMC-Rules")
            || trimmed.eq_ignore_ascii_case("CMC-Rules:")
            || trimmed.eq_ignore_ascii_case("global-options")
            || trimmed.eq_ignore_ascii_case("global-options:")
            || trimmed.eq_ignore_ascii_case("custom-languages-params")
            || trimmed.eq_ignore_ascii_case("custom-languages-params:")
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

            // Detection-engine globals: anomaly threshold + inspection deadline.
            if key == "Anomaly_threshold" {
                if let Ok(n) = raw.parse::<u32>() {
                    anomaly_threshold = Some(n);
                }
                continue;
            }
            if key == "Max_inspection_ms" {
                if let Ok(n) = raw.parse::<u64>() {
                    max_inspection_ms = Some(n);
                }
                continue;
            }

            // Multi-language hot-parameter block for open_redirect_n_rfi_detect.
            let bool_val = |raw: &str| -> i64 {
                if raw.eq_ignore_ascii_case("true") {
                    1
                } else {
                    raw.parse::<i64>().unwrap_or(0)
                }
            };
            if key.eq_ignore_ascii_case("multiple-languages-params") {
                multi_lang_enabled = bool_val(raw) == 1;
                continue;
            }
            if LANG_KEYS.contains(&key.as_str()) {
                lang_flags.insert(key, bool_val(raw));
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
                    "CMC config: unrecognised value, treating as disabled (expected 0/1 or true/false)"
                );
                0i64
            };
            map.insert(key, value);
        }
    }
    if map.is_empty() && saw_candidate {
        warn!(target: "krakenwaf", "CMC YAML fallback parser did not recover any valid rules; all CMC engines will remain disabled");
    } else if map.is_empty() {
        warn!(target: "krakenwaf", "CMC config parsed to an empty rule map; all CMC engines are disabled");
    }
    let mut cfg = from_map(&map);
    cfg.untrust_level = untrust_level;
    cfg.anomaly_threshold = anomaly_threshold;
    cfg.max_inspection_ms = max_inspection_ms;
    cfg.multi_lang_params = lang_params_from(multi_lang_enabled, Some(&lang_flags));
    Ok(cfg)
}

/// Build a [`LangParams`] from the `multiple-languages-params` master switch and
/// the `custom-languages-params` flag map (`1`/`true` ⇒ enabled). Both the
/// `arabic_modern` and `arabic_modern_standard` keys map to the single Arabic
/// Modern Standard list.
/// Config keys recognised inside the `custom-languages-params` block.
const LANG_KEYS: &[&str] = &[
    "russian",
    "japanese",
    "german",
    "bengali",
    "indonesian",
    "french",
    "arabic_modern",
    "arabic_modern_standard",
    "spanish",
    "chinese_mandarin",
    "chinese",
    "hindi",
];

fn lang_params_from(enabled: bool, map: Option<&BTreeMap<String, i64>>) -> LangParams {
    let mut lp = LangParams {
        enabled,
        ..LangParams::default()
    };
    if let Some(m) = map {
        let on = |k: &str| m.get(k).copied().unwrap_or(0) == 1;
        lp.russian = on("russian");
        lp.japanese = on("japanese");
        lp.german = on("german");
        lp.bengali = on("bengali");
        lp.indonesian = on("indonesian");
        lp.french = on("french");
        lp.arabic_modern_standard = on("arabic_modern") || on("arabic_modern_standard");
        lp.spanish = on("spanish");
        lp.chinese_mandarin = on("chinese_mandarin");
        lp.chinese = on("chinese");
        lp.hindi = on("hindi");
    }
    lp
}

fn from_map(map: &BTreeMap<String, i64>) -> CmcConfig {
    let enabled = |name: &str| map.get(name).copied().unwrap_or(0) == 1;
    CmcConfig {
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
        hpp_detect: enabled("HPP_detect"),
        open_redirect_n_rfi_detect: enabled("Open_redirect_n_RFI_detect"),
        multi_lang_params: LangParams::default(), // overwritten by caller from the language block
        detect_db_errors: enabled("Detect_db_errors"),
        silent_sql_errors: enabled("Silent_sql_errors"),
        detect_bad_artifacts: enabled("Detect_bad_artifacts"),
        detect_bots_n_scanners: enabled("Detect_bots_n_scanners"),
        untrust_level: 60, // overwritten by caller when global-options is parsed
        anomaly_threshold: None, // overwritten by caller when global-options is parsed
        max_inspection_ms: None, // overwritten by caller when global-options is parsed
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_lenient_yaml, CmcConfig};

    #[test]
    fn detection_engine_resolvers_use_defaults_when_yaml_absent() {
        let cfg = CmcConfig::default();
        assert_eq!(cfg.effective_anomaly_threshold(None), 600);
        assert_eq!(cfg.effective_max_inspection_ms(None), 0);
    }

    #[test]
    fn detection_engine_resolvers_pick_up_global_options_from_yaml() {
        let cfg = parse_lenient_yaml(
            r"
global-options:
  Untrust: 60
  Anomaly_threshold: 450
  Max_inspection_ms: 25
CMC-Rules:
  CRLF_injection_detect: true
",
        )
        .expect("parse global-options with detection-engine fields");
        assert_eq!(cfg.effective_anomaly_threshold(None), 450);
        assert_eq!(cfg.effective_max_inspection_ms(None), 25);
    }

    #[test]
    fn detection_engine_cli_flag_overrides_yaml() {
        let cfg = parse_lenient_yaml(
            r"
global-options:
  Anomaly_threshold: 450
  Max_inspection_ms: 25
CMC-Rules:
  CRLF_injection_detect: true
",
        )
        .expect("parse global-options with detection-engine fields");
        // Explicit CLI overrides both YAML and built-in defaults.
        assert_eq!(cfg.effective_anomaly_threshold(Some(700)), 700);
        assert_eq!(cfg.effective_max_inspection_ms(Some(50)), 50);
    }

    #[test]
    fn parses_crlf_injection_detect_config_key() {
        let crlf = parse_lenient_yaml(
            r"
CMC-Rules:
  CRLF_injection_detect: true
",
        )
        .expect("parse CRLF key");
        assert!(crlf.crlf_injection_detect);
    }

    #[test]
    fn parses_request_smuggling_detect_config_key() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  Request_Smuggling_detect: true
",
        )
        .expect("parse request smuggling key");
        assert!(cfg.request_smuggling_detect);
    }

    #[test]
    fn parses_nosql_injection_detect_config_key() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  NOSQL_injection_detect: true
",
        )
        .expect("parse NoSQL injection key");
        assert!(cfg.nosql_injection_detect);
    }

    #[test]
    fn parses_xxe_attack_detect_config_key() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  XXE_attack_detect: true
",
        )
        .expect("parse XXE attack key");
        assert!(cfg.xxe_attack_detect);
    }

    #[test]
    fn parses_anti_exposed_backup_config_key() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  Anti_exposed_backup: true
",
        )
        .expect("parse Anti_exposed_backup key");
        assert!(cfg.anti_exposed_backup);
    }

    #[test]
    fn anti_exposed_backup_disabled_by_default() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  SQLi_comments_detect: true
",
        )
        .expect("parse minimal config");
        assert!(!cfg.anti_exposed_backup);
    }

    #[test]
    fn parses_anti_passwd_leak_config_key() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  Anti_passwd_leak: true
",
        )
        .expect("parse Anti_passwd_leak key");
        assert!(cfg.anti_passwd_leak_detect);
    }

    #[test]
    fn anti_passwd_leak_disabled_by_default() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  SQLi_comments_detect: true
",
        )
        .expect("parse minimal config");
        assert!(!cfg.anti_passwd_leak_detect);
    }

    #[test]
    fn parses_java_deserialize_detect_config_key() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  Java_deserialize_detect: true
",
        )
        .expect("parse Java_deserialize_detect key");
        assert!(cfg.java_deserialize_detect);
    }

    #[test]
    fn java_deserialize_detect_disabled_by_default() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  SQLi_comments_detect: true
",
        )
        .expect("parse minimal config");
        assert!(!cfg.java_deserialize_detect);
    }

    #[test]
    fn parses_global_options_untrust_level() {
        let cfg = parse_lenient_yaml(
            r"
global-options:
  Untrust: 75
CMC-Rules:
  Java_deserialize_detect: true
",
        )
        .expect("parse global-options Untrust");
        assert_eq!(cfg.untrust_level, 75);
        assert!(cfg.java_deserialize_detect);
    }

    #[test]
    fn untrust_level_defaults_to_60() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  Java_deserialize_detect: true
",
        )
        .expect("parse without global-options");
        assert_eq!(cfg.untrust_level, 60);
    }

    #[test]
    fn untrust_level_clamped_to_100() {
        let cfg = parse_lenient_yaml(
            r"
global-options:
  Untrust: 150
CMC-Rules:
  Java_deserialize_detect: true
",
        )
        .expect("parse clamped Untrust");
        assert_eq!(cfg.untrust_level, 100);
    }

    #[test]
    fn parses_detect_db_errors_config_key() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  Detect_db_errors: true
",
        )
        .expect("parse Detect_db_errors key");
        assert!(cfg.detect_db_errors);
    }

    #[test]
    fn detect_db_errors_disabled_by_default() {
        let cfg = parse_lenient_yaml(
            r"
CMC-Rules:
  SQLi_comments_detect: true
",
        )
        .expect("parse minimal config");
        assert!(!cfg.detect_db_errors);
    }

    #[test]
    fn parses_detect_bad_artifacts_config_key() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  Detect_bad_artifacts: true\n").expect("parse");
        assert!(cfg.detect_bad_artifacts);
    }

    #[test]
    fn detect_bad_artifacts_disabled_by_default() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  SQLi_comments_detect: true\n").expect("parse");
        assert!(!cfg.detect_bad_artifacts);
    }

    #[test]
    fn parses_detect_bots_n_scanners_config_key() {
        let cfg =
            parse_lenient_yaml("CMC-Rules:\n  Detect_bots_n_scanners: true\n").expect("parse");
        assert!(cfg.detect_bots_n_scanners);
    }

    #[test]
    fn detect_bots_n_scanners_disabled_by_default() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  SQLi_comments_detect: true\n").expect("parse");
        assert!(!cfg.detect_bots_n_scanners);
    }

    #[test]
    fn detect_bots_n_scanners_explicit_false() {
        let cfg =
            parse_lenient_yaml("CMC-Rules:\n  Detect_bots_n_scanners: false\n").expect("parse");
        assert!(!cfg.detect_bots_n_scanners);
    }

    #[test]
    fn parses_hpp_detect_config_key() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  HPP_detect: true\n").expect("parse");
        assert!(cfg.hpp_detect);
    }

    #[test]
    fn hpp_detect_disabled_by_default() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  SQLi_comments_detect: true\n").expect("parse");
        assert!(!cfg.hpp_detect);
    }

    #[test]
    fn hpp_detect_explicit_false() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  HPP_detect: false\n").expect("parse");
        assert!(!cfg.hpp_detect);
    }

    #[test]
    fn disabled_hpp_manager_is_noop() {
        // When the flag is off the manager must not construct the detector, so
        // even a blatantly polluted query returns no finding.
        let cfg = parse_lenient_yaml("CMC-Rules:\n  HPP_detect: false\n").expect("parse");
        let mgr = super::CmcManagerBuilder::new(cfg).build();
        assert!(mgr.inspect_hpp("a=1&a=2", "").is_none());
    }

    #[test]
    fn enabled_hpp_manager_blocks_duplicate_and_reaches_block() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  HPP_detect: true\n").expect("parse");
        let mgr = super::CmcManagerBuilder::new(cfg).build();
        let finding = mgr
            .inspect_hpp("name=A&email=a@x&age=39&eMail=<bingo>", "")
            .expect("duplicate email must be detected");
        // Critical severity ⇒ the request reaches the Untrust >= 60 block gate.
        assert_eq!(finding.severity, super::Severity::Critical);
    }

    #[test]
    fn enabled_hpp_manager_detects_body_pollution() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  HPP_detect: true\n").expect("parse");
        let mgr = super::CmcManagerBuilder::new(cfg).build();
        assert!(mgr.inspect_hpp("", "user=a&User=b").is_some());
    }

    #[test]
    fn parses_open_redirect_n_rfi_detect_config_key() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  Open_redirect_n_RFI_detect: true\n")
            .expect("parse Open_redirect_n_RFI_detect key");
        assert!(cfg.open_redirect_n_rfi_detect);
    }

    #[test]
    fn open_redirect_n_rfi_detect_disabled_by_default() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  SQLi_comments_detect: true\n").expect("parse");
        assert!(!cfg.open_redirect_n_rfi_detect);
    }

    #[test]
    fn open_redirect_n_rfi_detect_explicit_false() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  Open_redirect_n_RFI_detect: false\n")
            .expect("parse");
        assert!(!cfg.open_redirect_n_rfi_detect);
    }

    #[test]
    fn disabled_open_redirect_manager_is_noop() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  Open_redirect_n_RFI_detect: false\n")
            .expect("parse");
        let mgr = super::CmcManagerBuilder::new(cfg).build();
        assert!(mgr
            .inspect_open_redirect_rfi("next=https://evil.example", "")
            .is_none());
    }

    #[test]
    fn enabled_open_redirect_manager_blocks_query_and_body() {
        let cfg = parse_lenient_yaml("CMC-Rules:\n  Open_redirect_n_RFI_detect: true\n")
            .expect("parse");
        let mgr = super::CmcManagerBuilder::new(cfg).build();
        // GET query string.
        let f = mgr
            .inspect_open_redirect_rfi("book=x&next=//evil.example", "")
            .expect("open redirect in query must be detected");
        assert_eq!(f.severity, super::Severity::High);
        // POST body.
        assert!(mgr
            .inspect_open_redirect_rfi("", "redirect=php://filter/resource=x")
            .is_some());
    }

    #[test]
    fn parses_multiple_languages_params_block() {
        let cfg = parse_lenient_yaml(
            r"
multiple-languages-params: true
custom-languages-params:
  spanish: true
  japanese: true
  russian: false
CMC-Rules:
  Open_redirect_n_RFI_detect: true
",
        )
        .expect("parse language block");
        assert!(cfg.multi_lang_params.enabled);
        assert!(cfg.multi_lang_params.spanish);
        assert!(cfg.multi_lang_params.japanese);
        assert!(!cfg.multi_lang_params.russian);
    }

    #[test]
    fn arabic_modern_alias_maps_to_standard() {
        let cfg = parse_lenient_yaml(
            r"
multiple-languages-params: true
custom-languages-params:
  arabic_modern: true
CMC-Rules:
  Open_redirect_n_RFI_detect: true
",
        )
        .expect("parse arabic alias");
        assert!(cfg.multi_lang_params.arabic_modern_standard);
    }

    #[test]
    fn multi_language_lists_used_only_when_master_switch_on() {
        // Localized param `mostrar` (Spanish) is ignored unless the master
        // switch AND the spanish flag are both on.
        let off = parse_lenient_yaml(
            r"
multiple-languages-params: false
custom-languages-params:
  spanish: true
CMC-Rules:
  Open_redirect_n_RFI_detect: true
",
        )
        .expect("parse");
        let mgr_off = super::CmcManagerBuilder::new(off).build();
        assert!(mgr_off
            .inspect_open_redirect_rfi("mostrar=//evil.example", "")
            .is_none());

        let on = parse_lenient_yaml(
            r"
multiple-languages-params: true
custom-languages-params:
  spanish: true
CMC-Rules:
  Open_redirect_n_RFI_detect: true
",
        )
        .expect("parse");
        let mgr_on = super::CmcManagerBuilder::new(on).build();
        assert!(mgr_on
            .inspect_open_redirect_rfi("mostrar=//evil.example", "")
            .is_some());
    }

    #[test]
    fn shipped_config_parses_and_enables_module() {
        let content = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rules/cmc/config.yaml"
        ))
        .expect("read shipped CMC config");
        let cfg = parse_lenient_yaml(&content).expect("parse shipped config");
        assert!(cfg.open_redirect_n_rfi_detect);
    }
}

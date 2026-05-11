use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::Result;
use chrono::Utc;
use ipnet::IpNet;
#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

use crate::ffi::libinjection;
use crate::rules::{CompiledDetectionRule, DetectionRule, HttpAction, RuleSet, Severity};

use super::finding::{truncate_payload, Finding};
use super::ip_filter::parse_ip_net;

pub(super) const SCORE_BLOCK_THRESHOLD: u32 = 600;

#[derive(Debug, Clone)]
pub(super) struct KeywordMatcher {
    pub(super) ac: AhoCorasick,
    pub(super) rules: Vec<DetectionRule>,
}

/// Compiled matchers split by inspection phase (Request vs Response).
#[derive(Debug, Clone, Default)]
pub(super) struct EngineMatchers {
    pub(super) req_uri: Option<KeywordMatcher>,
    pub(super) req_headers: Option<KeywordMatcher>,
    pub(super) req_body: Option<KeywordMatcher>,
    pub(super) req_scanner_agents: Option<KeywordMatcher>,
    pub(super) resp_headers: Option<KeywordMatcher>,
    pub(super) resp_body: Option<KeywordMatcher>,
    pub(super) blocked_ip_nets: Vec<IpNet>,
    #[cfg(feature = "vectorscan-engine")]
    pub(super) req_vectorscan: Option<VectorscanMatcher>,
    #[cfg(feature = "vectorscan-engine")]
    pub(super) resp_vectorscan: Option<VectorscanMatcher>,
    #[cfg(feature = "vectorscan-engine")]
    pub(super) scanner_vectorscan: Option<VectorscanMatcher>,
}

#[cfg(feature = "vectorscan-engine")]
#[derive(Debug, Clone)]
pub(super) struct VectorscanMatcher {
    pub(super) db: BlockDatabase,
    pub(super) keywords: Vec<DetectionRule>,
}

pub(super) fn build_matchers(rules: &RuleSet, vectorscan_enabled: bool) -> Result<EngineMatchers> {
    #[cfg(not(feature = "vectorscan-engine"))]
    let _ = vectorscan_enabled;

    let req_filter = |r: &&DetectionRule| r.http_action == HttpAction::Request;
    let resp_filter = |r: &&DetectionRule| r.http_action == HttpAction::Response;

    let req_uri_rules: Vec<DetectionRule> = rules
        .uri_keywords
        .iter()
        .filter(req_filter)
        .cloned()
        .collect();
    let req_hdr_rules: Vec<DetectionRule> = rules
        .header_keywords
        .iter()
        .filter(req_filter)
        .cloned()
        .collect();
    let req_body_rules: Vec<DetectionRule> = rules
        .body_keywords
        .iter()
        .filter(req_filter)
        .cloned()
        .collect();
    let resp_hdr_rules: Vec<DetectionRule> = rules
        .header_keywords
        .iter()
        .filter(resp_filter)
        .cloned()
        .collect();
    let resp_body_rules: Vec<DetectionRule> = rules
        .body_keywords
        .iter()
        .filter(resp_filter)
        .cloned()
        .collect();

    let scanner_rules: Vec<DetectionRule> = rules
        .scanner_agents
        .iter()
        .enumerate()
        .map(|(idx, pattern)| DetectionRule {
            id: format!("{:05}", idx + 1),
            title: "Scanner/crawler user-agent detected".to_string(),
            severity: Severity::High,
            cwe: "CWE-200".to_string(),
            description: format!("A known scanning tool user-agent was detected: {}", pattern),
            reference_url:
                "https://owasp.org/www-project-web-security-testing-guide/".to_string(),
            rule_match: pattern.clone(),
            source: "user_agents/scanners.txt".to_string(),
            line: idx + 1,
            http_action: HttpAction::Request,
            score: SCORE_BLOCK_THRESHOLD,
        })
        .collect();

    #[cfg(feature = "vectorscan-engine")]
    let (req_vs_rules, resp_vs_rules): (Vec<_>, Vec<_>) = {
        let req: Vec<DetectionRule> = rules
            .vectorscan_keywords
            .iter()
            .filter(req_filter)
            .cloned()
            .collect();
        let resp: Vec<DetectionRule> = rules
            .vectorscan_keywords
            .iter()
            .filter(resp_filter)
            .cloned()
            .collect();
        (req, resp)
    };

    Ok(EngineMatchers {
        req_uri: build_keyword_matcher(&req_uri_rules)?,
        req_headers: build_keyword_matcher(&req_hdr_rules)?,
        req_body: build_keyword_matcher(&req_body_rules)?,
        req_scanner_agents: build_keyword_matcher(&scanner_rules)?,
        resp_headers: build_keyword_matcher(&resp_hdr_rules)?,
        resp_body: build_keyword_matcher(&resp_body_rules)?,
        blocked_ip_nets: rules
            .blocked_ip_prefixes
            .iter()
            .filter_map(|entry| parse_ip_net(entry))
            .collect(),
        #[cfg(feature = "vectorscan-engine")]
        req_vectorscan: if vectorscan_enabled && !req_vs_rules.is_empty() {
            Some(build_vectorscan_matcher(&req_vs_rules)?)
        } else {
            None
        },
        #[cfg(feature = "vectorscan-engine")]
        resp_vectorscan: if vectorscan_enabled && !resp_vs_rules.is_empty() {
            Some(build_vectorscan_matcher(&resp_vs_rules)?)
        } else {
            None
        },
        #[cfg(feature = "vectorscan-engine")]
        scanner_vectorscan: if vectorscan_enabled && !scanner_rules.is_empty() {
            Some(build_vectorscan_literal_matcher(&scanner_rules)?)
        } else {
            None
        },
    })
}

pub(super) fn build_keyword_matcher(rules: &[DetectionRule]) -> Result<Option<KeywordMatcher>> {
    if rules.is_empty() {
        return Ok(None);
    }
    let patterns = rules
        .iter()
        .map(|rule| rule.rule_match.as_str())
        .collect::<Vec<_>>();
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(patterns)?;
    Ok(Some(KeywordMatcher {
        ac,
        rules: rules.to_vec(),
    }))
}

pub(super) fn keyword_match(
    matcher: Option<&KeywordMatcher>,
    haystack: &str,
    original_payload: &str,
) -> Option<Finding> {
    let matcher = matcher?;
    let mat = matcher.ac.find(haystack)?;
    matcher
        .rules
        .get(mat.pattern().as_usize())
        .map(|rule| super::finding::rule_to_finding(rule, original_payload))
}

pub(super) fn score_allows_block(rule: &DetectionRule, sum_score: &mut u32) -> bool {
    if rule.score >= SCORE_BLOCK_THRESHOLD {
        *sum_score = 0;
        return true;
    }
    *sum_score = sum_score.saturating_add(rule.score);
    if *sum_score >= SCORE_BLOCK_THRESHOLD {
        *sum_score = 0;
        return true;
    }
    false
}

/// Regex match filtered by http_action phase.
pub(super) fn regex_match_phase_scored(
    rules: &[CompiledDetectionRule],
    haystack: &str,
    original_payload: &str,
    phase: &HttpAction,
) -> Option<Finding> {
    let mut sum_score = 0u32;
    rules
        .iter()
        .filter(|r| &r.meta.http_action == phase)
        .filter(|rule| rule.compiled.is_match(haystack))
        .find_map(|rule| {
            score_allows_block(&rule.meta, &mut sum_score)
                .then(|| super::finding::rule_to_finding(&rule.meta, original_payload))
        })
}

pub(super) fn libinjection_match(
    normalized_payload: &[u8],
    original_payload: &str,
    enable_sqli: bool,
    enable_xss: bool,
) -> Option<Finding> {
    if enable_sqli {
        if let Some(hit) = libinjection::detect_sqli(normalized_payload) {
            return Some(Finding {
                rule_id: "00000".to_string(),
                title: "LibInjection SQLi detection".into(),
                severity: Severity::Critical,
                cwe: "CWE-89".into(),
                description: "Vendored C libinjection-compatible engine flagged the payload as probable SQL injection.".into(),
                reference_url: "https://github.com/client9/libinjection".into(),
                rule_match: format!(
                    "libinjection::sqli:{}",
                    hit.fingerprint.unwrap_or_else(|| "match".into())
                ),
                rule_line_match: "runtime:ffi/libinjection".into(),
                request_payload: truncate_payload(original_payload).into_owned(),
                timestamp: Utc::now().to_rfc3339(),
            });
        }
    }
    if enable_xss {
        if let Some(hit) = libinjection::detect_xss(normalized_payload) {
            return Some(Finding {
                rule_id: "00000".to_string(),
                title: "LibInjection XSS detection".into(),
                severity: Severity::High,
                cwe: "CWE-79".into(),
                description: "Vendored C libinjection-compatible engine flagged the payload as probable cross-site scripting.".into(),
                reference_url: "https://github.com/client9/libinjection".into(),
                rule_match: format!(
                    "libinjection::xss:{}",
                    hit.fingerprint.unwrap_or_else(|| "match".into())
                ),
                rule_line_match: "runtime:ffi/libinjection".into(),
                request_payload: truncate_payload(original_payload).into_owned(),
                timestamp: Utc::now().to_rfc3339(),
            });
        }
    }
    None
}

#[cfg(feature = "vectorscan-engine")]
pub(super) fn build_vectorscan_matcher(rules: &[DetectionRule]) -> Result<VectorscanMatcher> {
    if rules.is_empty() {
        anyhow::bail!("vectorscan enabled but no literal rules were loaded");
    }
    let patterns = rules
        .iter()
        .enumerate()
        .map(|(idx, rule)| build_vectorscan_pattern(rule, idx))
        .collect::<Result<Vec<_>>>()?;

    let db = match BlockDatabase::new(patterns) {
        Ok(db) => db,
        Err(err) => {
            if let Some(detailed) = find_vectorscan_rule_error(rules) {
                return Err(detailed);
            }
            return Err(anyhow::anyhow!(
                "failed to compile Vectorscan database from {} rules. Underlying error: {}",
                rules.len(),
                err
            ));
        }
    };
    Ok(VectorscanMatcher {
        db,
        keywords: rules.to_vec(),
    })
}

#[cfg(feature = "vectorscan-engine")]
pub(super) fn build_vectorscan_literal_matcher(
    rules: &[DetectionRule],
) -> Result<VectorscanMatcher> {
    if rules.is_empty() {
        anyhow::bail!("vectorscan enabled but no scanner-agent rules were loaded");
    }
    let escaped_rules: Vec<DetectionRule> = rules
        .iter()
        .map(|r| DetectionRule {
            rule_match: regex_escape_literal(&r.rule_match),
            ..r.clone()
        })
        .collect();
    let patterns = escaped_rules
        .iter()
        .enumerate()
        .map(|(idx, rule)| build_vectorscan_pattern(rule, idx))
        .collect::<Result<Vec<_>>>()?;

    let db = match BlockDatabase::new(patterns) {
        Ok(db) => db,
        Err(err) => {
            if let Some(detailed) = find_vectorscan_rule_error(&escaped_rules) {
                return Err(detailed);
            }
            return Err(anyhow::anyhow!(
                "failed to compile Vectorscan scanner-agent database from {} rules. Underlying error: {}",
                rules.len(),
                err
            ));
        }
    };
    Ok(VectorscanMatcher {
        db,
        keywords: rules.to_vec(),
    })
}

#[cfg(feature = "vectorscan-engine")]
fn regex_escape_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if matches!(
            c,
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan_pattern(rule: &DetectionRule, idx: usize) -> Result<Pattern> {
    let literal = rule.rule_match.trim();
    if literal.is_empty() {
        anyhow::bail!(
            "invalid Vectorscan rule #{} at {}:{} (title: {}). Rule content is empty.",
            idx + 1,
            rule.source,
            rule.line,
            rule.title,
        );
    }
    if literal.as_bytes().contains(&0) {
        anyhow::bail!(
            "invalid Vectorscan rule #{} at {}:{} (title: {}). Rule content contains a NUL byte.",
            idx + 1,
            rule.source,
            rule.line,
            rule.title,
        );
    }
    Ok(Pattern::new(
        literal.as_bytes().to_vec(),
        Flag::CASELESS | Flag::SINGLEMATCH,
        Some(idx as u32),
    ))
}

#[cfg(feature = "vectorscan-engine")]
fn find_vectorscan_rule_error(rules: &[DetectionRule]) -> Option<anyhow::Error> {
    for (idx, rule) in rules.iter().enumerate() {
        let pattern = match build_vectorscan_pattern(rule, idx) {
            Ok(p) => p,
            Err(err) => return Some(err),
        };
        if let Err(err) = BlockDatabase::new(vec![pattern]) {
            return Some(anyhow::anyhow!(
                "failed to compile Vectorscan rule #{} at {}:{} (title: {}). Content: {:?}. Error: {}",
                idx + 1,
                rule.source,
                rule.line,
                rule.title,
                rule.rule_match,
                err
            ));
        }
    }
    None
}

#[cfg(feature = "vectorscan-engine")]
pub(super) fn vectorscan_match_scored(
    matcher: &VectorscanMatcher,
    normalized_haystack: &str,
    original_payload: &str,
) -> Option<Finding> {
    let mut scanner = matcher.db.create_scanner().ok()?;
    let mut matched_indexes: Vec<usize> = Vec::new();
    let _ = scanner.scan(normalized_haystack.as_bytes(), |id, _from, _to, _flags| {
        matched_indexes.push(id as usize);
        Scan::Continue
    });
    matched_indexes.sort_unstable();
    matched_indexes.dedup();

    let mut sum_score = 0u32;
    matched_indexes
        .into_iter()
        .filter_map(|idx| matcher.keywords.get(idx))
        .find_map(|rule| {
            score_allows_block(rule, &mut sum_score)
                .then(|| super::finding::rule_to_finding(rule, original_payload))
        })
}

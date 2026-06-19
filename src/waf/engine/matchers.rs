use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context as _, Result};
use chrono::Utc;
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;
#[cfg(feature = "vectorscan-engine")]
use tracing::warn;
#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

use crate::ffi::libinjection;
use crate::rules::{CompiledDetectionRule, DetectionRule, HttpAction, RuleSet, Severity};

use super::finding::{truncate_payload, Finding};
use super::ip_filter::{canonical_ip, parse_ip_net};

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
    pub(super) resp_headers: Option<KeywordMatcher>,
    pub(super) resp_body: Option<KeywordMatcher>,
    pub(super) blocked_ip_nets: Vec<IpNet>,
    /// Exact-match IP blocklist, canonicalised once at build time. Replaces the
    /// former per-request linear scan + per-entry `canonical_ip` parse over
    /// `rules.blocked_ips`, which was O(n) with an allocation on every request.
    pub(super) blocked_ips_canon: HashSet<IpAddr>,
    #[cfg(feature = "vectorscan-engine")]
    pub(super) req_vectorscan: Option<VectorscanMatcher>,
    #[cfg(feature = "vectorscan-engine")]
    pub(super) resp_vectorscan: Option<VectorscanMatcher>,
}

#[derive(Debug, Clone)]
pub(super) struct RegexDeadline {
    pub(super) rule_id: String,
    pub(super) title: String,
    pub(super) rule_match: String,
    pub(super) rule_line_match: String,
}

#[derive(Debug, Clone)]
pub(super) enum RegexScanResult {
    Match(Finding),
    DeadlineExceeded(RegexDeadline),
    NoMatch,
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
    let blocked_ip_nets = rules
        .blocked_ip_prefixes
        .iter()
        .map(|entry| {
            parse_ip_net(entry).with_context(|| {
                format!("invalid blocked_ip_prefixes entry '{entry}' while building WAF matchers")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let blocked_ips_canon: HashSet<IpAddr> = rules
        .blocked_ips
        .iter()
        .filter_map(|ip| canonical_ip(ip))
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
        resp_headers: build_keyword_matcher(&resp_hdr_rules)?,
        resp_body: build_keyword_matcher(&resp_body_rules)?,
        blocked_ip_nets,
        blocked_ips_canon,
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


/// Returns `true` when the rule's score alone or the accumulated `sum_score`
/// reaches `SCORE_BLOCK_THRESHOLD`. Resets `sum_score` to zero on a block so
/// the next view starts fresh. Kept for vectorscan callers that use the
/// hard-coded default; new code should use [`score_allows_block_threshold`].
#[cfg(feature = "vectorscan-engine")]
pub(super) fn score_allows_block(rule: &DetectionRule, sum_score: &mut u32) -> bool {
    score_allows_block_threshold(rule, sum_score, SCORE_BLOCK_THRESHOLD)
}

/// Configurable-threshold variant used when `--anomaly-threshold` is set.
pub(super) fn score_allows_block_threshold(
    rule: &DetectionRule,
    sum_score: &mut u32,
    threshold: u32,
) -> bool {
    if rule.score >= threshold {
        *sum_score = 0;
        return true;
    }
    *sum_score = sum_score.saturating_add(rule.score);
    if *sum_score >= threshold {
        *sum_score = 0;
        return true;
    }
    false
}

/// Keyword-match variant that accumulates score across **all** non-overlapping
/// hits using `find_iter`, so multiple low-score rules in the same payload can
/// trip the threshold even when no single hit reaches it.
pub(super) fn keyword_match_accumulate(
    matcher: Option<&KeywordMatcher>,
    haystack: &str,
    original_payload: &str,
    threshold: u32,
    sum_score: &mut u32,
) -> Option<Finding> {
    let matcher = matcher?;
    for mat in matcher.ac.find_iter(haystack) {
        let Some(rule) = matcher.rules.get(mat.pattern().as_usize()) else {
            tracing::warn!(
                target: "krakenwaf",
                pattern_index = mat.pattern().as_usize(),
                rule_count = matcher.rules.len(),
                "keyword matcher returned a pattern index without rule metadata; skipping"
            );
            continue;
        };
        if score_allows_block_threshold(rule, sum_score, threshold) {
            return Some(super::finding::rule_to_finding(rule, original_payload));
        }
    }
    None
}

/// Configurable-threshold regex match. The caller threads `sum_score` across
/// inspection views so cross-view score accumulation works correctly.
pub(super) fn regex_match_phase_scored_threshold(
    rules: &[CompiledDetectionRule],
    haystack: &str,
    original_payload: &str,
    phase: &HttpAction,
    threshold: u32,
    sum_score: &mut u32,
) -> Option<Finding> {
    match regex_match_phase_scored_threshold_deadline(
        rules,
        haystack,
        original_payload,
        phase,
        threshold,
        sum_score,
        None,
    ) {
        RegexScanResult::Match(finding) => Some(finding),
        RegexScanResult::DeadlineExceeded(_) | RegexScanResult::NoMatch => None,
    }
}

pub(super) fn regex_match_phase_scored_threshold_deadline(
    rules: &[CompiledDetectionRule],
    haystack: &str,
    original_payload: &str,
    phase: &HttpAction,
    threshold: u32,
    sum_score: &mut u32,
    deadline: Option<Instant>,
) -> RegexScanResult {
    for rule in rules.iter().filter(|r| &r.meta.http_action == phase) {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return RegexScanResult::DeadlineExceeded(regex_deadline(&rule.meta));
        }
        let matched = rule.compiled.is_match(haystack);
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return RegexScanResult::DeadlineExceeded(regex_deadline(&rule.meta));
        }
        if matched && score_allows_block_threshold(&rule.meta, sum_score, threshold) {
            return RegexScanResult::Match(super::finding::rule_to_finding(
                &rule.meta,
                original_payload,
            ));
        }
    }
    RegexScanResult::NoMatch
}

fn regex_deadline(rule: &DetectionRule) -> RegexDeadline {
    RegexDeadline {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        rule_match: rule.rule_match.clone(),
        rule_line_match: format!("{}:{}", rule.source, rule.line),
    }
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
        Some(u32::try_from(idx).expect("pattern index fits in u32")),
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
    let mut scanner = match matcher.db.create_scanner() {
        Ok(scanner) => scanner,
        Err(err) => {
            warn!(
                target: "krakenwaf",
                error = %err,
                "Vectorscan scanner creation failed; skipping Vectorscan match for this payload"
            );
            return None;
        }
    };
    let mut matched_indexes: Vec<usize> = Vec::new();
    if let Err(err) = scanner.scan(normalized_haystack.as_bytes(), |id, _from, _to, _flags| {
        matched_indexes.push(id as usize);
        Scan::Continue
    }) {
        warn!(
            target: "krakenwaf",
            error = %err,
            haystack_len = normalized_haystack.len(),
            "Vectorscan scan failed; skipping Vectorscan match for this payload"
        );
        return None;
    }
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

#[cfg(test)]
mod tests {
    use super::build_matchers;
    use crate::rules::RuleSet;

    #[test]
    fn build_matchers_rejects_invalid_blocked_ip_prefix() {
        let rules = RuleSet {
            blocked_ip_prefixes: vec!["not-a-cidr".to_string()],
            ..RuleSet::default()
        };

        let err = build_matchers(&rules, false).expect_err("invalid CIDR must fail matcher build");
        assert!(
            err.to_string()
                .contains("invalid blocked_ip_prefixes entry"),
            "unexpected error: {err}"
        );
    }
}

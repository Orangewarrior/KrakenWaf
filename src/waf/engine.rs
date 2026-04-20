

/// Maximum number of URL-decode passes to perform when canonicalizing a payload.
/// Bounded to defeat double/triple-encoding evasions while keeping the cost O(n·k).
const MAX_URL_DECODE_PASSES: usize = 4;

fn url_decode_once(input: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => {
                if let (Some(h), Some(l)) = (
                    (input[i + 1] as char).to_digit(16),
                    (input[i + 2] as char).to_digit(16),
                ) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    changed = true;
                    continue;
                }
                out.push(input[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
                changed = true;
            }
            _ => {
                out.push(input[i]);
                i += 1;
            }
        }
    }
    (out, changed)
}

fn url_decode(input: &[u8]) -> Vec<u8> {
    let (mut current, mut changed) = url_decode_once(input);
    let mut passes = 1;
    while changed && passes < MAX_URL_DECODE_PASSES {
        let (next, next_changed) = url_decode_once(&current);
        current = next;
        changed = next_changed;
        passes += 1;
    }
    current
}

use crate::{
    dfa::DfaManager,
    metrics::WafMetrics,
    rules::{CompiledDetectionRule, DetectionRule, RuleSet, Severity},
    waf::rate_limit::RateLimiter,
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::Result;
use chrono::Utc;
use ipnet::IpNet;
use crate::ffi::libinjection;
use parking_lot::RwLock;
use std::{borrow::Cow, net::IpAddr, path::Path, sync::Arc, time::Duration};
use tracing::warn;
#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};
use crate::proxy::format_request_prefix_bytes;

/// Streaming and full-payload inspection context generated per request.
#[derive(Debug, Clone)]
pub struct InspectionContext {
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub path: String,
    pub headers: String,
    pub body_limit: usize,
}

/// Final WAF decision for a specific phase of the inspection pipeline.
#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Block(Finding),
}

/// Normalized structured detection finding.
#[derive(Debug, Clone)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub cwe: String,
    pub description: String,
    pub reference_url: String,
    pub rule_match: String,
    pub rule_line_match: String,
    pub request_payload: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
struct KeywordMatcher {
    ac: AhoCorasick,
    rules: Vec<DetectionRule>,
}

#[derive(Debug, Clone, Default)]
struct EngineMatchers {
    uri: Option<KeywordMatcher>,
    headers: Option<KeywordMatcher>,
    body: Option<KeywordMatcher>,
    blocked_ip_nets: Vec<IpNet>,
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<VectorscanMatcher>,
}

#[cfg(feature = "vectorscan-engine")]
#[derive(Debug, Clone)]
struct VectorscanMatcher {
    db: BlockDatabase,
    keywords: Vec<DetectionRule>,
}

/// Immutable snapshot of rules + their pre-compiled matchers. Held behind a
/// single `Arc` so a hot-reload swaps both atomically — no window where a
/// reader can see new rules paired with stale matchers or vice versa.
struct RulesSnapshot {
    rules: Arc<RuleSet>,
    matchers: EngineMatchers,
}

/// Main KrakenWaf engine containing rules and optional accelerated detectors.
pub struct WafEngine {
    /// Single lock covers both rules and matchers; readers always see a
    /// consistent pair because reload replaces the whole Arc at once.
    snapshot: RwLock<Arc<RulesSnapshot>>,
    rate_limiter: Arc<RateLimiter>,
    blocklist_ip_enabled: bool,
    libinjection_sqli_enabled: bool,
    libinjection_xss_enabled: bool,
    vectorscan_enabled: bool,
    metrics: Arc<WafMetrics>,
    dfa_manager: Arc<DfaManager>,
}

impl WafEngine {
    pub fn new(
        rules: Arc<RuleSet>,
        rate_limit_per_minute: u32,
        blocklist_ip_enabled: bool,
        libinjection_sqli_enabled: bool,
        libinjection_xss_enabled: bool,
        vectorscan_enabled: bool,
        snapshot_path: std::path::PathBuf,
        metrics: Arc<WafMetrics>,
        dfa_manager: Arc<DfaManager>,
    ) -> Result<Self> {
        let rate_limiter = Arc::new(RateLimiter::new(rate_limit_per_minute, Duration::from_secs(60), snapshot_path)?);
        rate_limiter.clone().spawn_persistence_task();
        let matchers = build_matchers(&rules, vectorscan_enabled)?;
        Ok(Self {
            snapshot: RwLock::new(Arc::new(RulesSnapshot { rules, matchers })),
            rate_limiter,
            blocklist_ip_enabled,
            libinjection_sqli_enabled,
            libinjection_xss_enabled,
            vectorscan_enabled,
            metrics,
            dfa_manager,
        })
    }

    pub fn body_limit_for_path(&self, path: &str) -> usize {
        self.snapshot.read().rules.body_limit_for_path(path)
    }

    pub async fn reload_from_dir(&self, root: &Path) -> Result<()> {
        let new_rules = Arc::new(RuleSet::from_dir(root)?);
        let new_matchers = build_matchers(&new_rules, self.vectorscan_enabled)?;
        // Atomic swap: readers see either the old snapshot or the new one,
        // never a mixture of old rules with new matchers (or vice versa).
        *self.snapshot.write() = Arc::new(RulesSnapshot { rules: new_rules, matchers: new_matchers });
        Ok(())
    }

    pub async fn inspect_early(&self, ctx: &InspectionContext) -> Decision {
        self.metrics.inc_inspected();
        let snap = self.snapshot.read().clone();
        let rules = &snap.rules;
        let matchers = &snap.matchers;

        if rules.is_allowlisted(&ctx.path) {
            return Decision::Allow;
        }

        if !self.rate_limiter.check(&ctx.client_ip).await {
            self.metrics.inc_rate_limit_hits();
            return Decision::Block(self.simple_finding(
                "Rate limit exceeded",
                Severity::High,
                "CWE-770",
                "The client exceeded the configured requests-per-minute threshold.",
                "https://cwe.mitre.org/data/definitions/770.html",
                "rate_limiter",
                "window_exceeded",
                format!("{} {}", ctx.method, ctx.uri),
            ));
        }

        if self.blocklist_ip_enabled {
            if let Some(client) = canonical_ip(&ctx.client_ip) {
                if rules.blocked_ips.iter().filter_map(|ip| canonical_ip(ip)).any(|blocked| blocked == client) {
                    return Decision::Block(self.simple_finding(
                        "Blocked source IP",
                        Severity::High,
                        "CWE-693",
                        "The client IP matched an exact entry in rules/blocklist_ip.txt.",
                        "https://cwe.mitre.org/data/definitions/693.html",
                        "blocklist_ip.txt",
                        "exact_match",
                        format!("{} {}", ctx.method, ctx.uri),
                    ));
                }

                if matchers.blocked_ip_nets.iter().any(|net| net.contains(&client)) {
                    return Decision::Block(self.simple_finding(
                        "Blocked IP range",
                        Severity::High,
                        "CWE-693",
                        "The client IP matched a blocked CIDR or normalized legacy IP range before request processing.",
                        "https://cwe.mitre.org/data/definitions/693.html",
                        "rules.json:blocked_ip_prefixes",
                        "cidr_match",
                        format!("{} {}", ctx.method, ctx.uri),
                    ));
                }
            }
        }

let early_request = format_request_prefix_bytes(ctx);
self.inspect_complete_payload_with_context(&early_request, Some(&ctx.method))
    }
    #[allow(dead_code)]
    pub fn inspect_body_chunk(&self, chunk: &[u8]) -> Decision {
        self.inspect_complete_payload(chunk)
    }

    pub fn inspect_complete_payload(&self, payload: &[u8]) -> Decision {
        self.inspect_complete_payload_with_context(payload, None)
    }

    pub fn inspect_complete_payload_with_context(&self, payload: &[u8], _method_hint: Option<&str>) -> Decision {
        let snap = self.snapshot.read().clone();
        let rules = &snap.rules;
        let matchers = &snap.matchers;

        // Always URL-decode the payload (iteratively, bounded). Previously this was gated to
        // GET requests, which let percent-encoded POST bodies bypass keyword/regex matching.
        let normalized_bytes = normalize_request_bytes(payload);
        let original_text = String::from_utf8_lossy(payload);
        let normalized_text = String::from_utf8_lossy(normalized_bytes.as_ref());

        // DFA requires a fully-lowercased input. Every other matcher is already
        // case-insensitive (AhoCorasick → ascii_case_insensitive, Vectorscan → CASELESS,
        // Regex patterns → (?i)), so we avoid one full heap allocation per request by
        // only lowercasing for the DFA check and dropping that copy immediately after.
        {
            let dfa_lower = normalized_text.to_lowercase();
            if let Some(finding) = self.dfa_manager.inspect(&dfa_lower) {
                return Decision::Block(finding);
            }
        }

        if self.libinjection_sqli_enabled || self.libinjection_xss_enabled {
            if let Some(finding) = libinjection_match(
                normalized_bytes.as_ref(),
                original_text.as_ref(),
                self.libinjection_sqli_enabled,
                self.libinjection_xss_enabled,
            ) {
                return Decision::Block(finding);
            }
        }

        if self.vectorscan_enabled {
            #[cfg(feature = "vectorscan-engine")]
            {
                if let Some(matcher) = &matchers.vectorscan {
                    if let Some(finding) = vectorscan_match(matcher, normalized_text.as_ref(), original_text.as_ref()) {
                        return Decision::Block(finding);
                    }
                }
            }
        }

        for view in inspection_views(normalized_text.as_ref()) {
            if let Some(finding) = keyword_match(matchers.uri.as_ref(), view, original_text.as_ref()) {
                return Decision::Block(finding);
            }
            if let Some(finding) = keyword_match(matchers.headers.as_ref(), view, original_text.as_ref()) {
                return Decision::Block(finding);
            }
            if let Some(finding) = keyword_match(matchers.body.as_ref(), view, original_text.as_ref()) {
                return Decision::Block(finding);
            }

            if let Some(finding) = regex_match(&rules.path_regex, view, original_text.as_ref()) {
                return Decision::Block(finding);
            }
            if let Some(finding) = regex_match(&rules.header_regex, view, original_text.as_ref()) {
                return Decision::Block(finding);
            }
            if let Some(finding) = regex_match(&rules.body_regex, view, original_text.as_ref()) {
                return Decision::Block(finding);
            }
        }

        Decision::Allow
    }

    fn simple_finding(
        &self,
        title: &str,
        severity: Severity,
        cwe: &str,
        description: &str,
        reference_url: &str,
        rule_match: impl Into<String>,
        rule_line_match: impl Into<String>,
        request_payload: impl Into<String>,
    ) -> Finding {
        Finding {
            title: title.to_string(),
            severity,
            cwe: cwe.to_string(),
            description: description.to_string(),
            reference_url: reference_url.to_string(),
            rule_match: rule_match.into(),
            rule_line_match: rule_line_match.into(),
            request_payload: request_payload.into(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

fn build_matchers(rules: &RuleSet, vectorscan_enabled: bool) -> Result<EngineMatchers> {
    #[cfg(not(feature = "vectorscan-engine"))]
    let _ = vectorscan_enabled;

    Ok(EngineMatchers {
        uri: build_keyword_matcher(&rules.uri_keywords)?,
        headers: build_keyword_matcher(&rules.header_keywords)?,
        body: build_keyword_matcher(&rules.body_keywords)?,
        blocked_ip_nets: rules.blocked_ip_prefixes.iter().filter_map(|entry| parse_ip_net(entry)).collect(),
        #[cfg(feature = "vectorscan-engine")]
        vectorscan: if vectorscan_enabled {
            Some(build_vectorscan_matcher(&rules.vectorscan_keywords)?)
        } else {
            None
        },
    })
}

fn build_keyword_matcher(rules: &[DetectionRule]) -> Result<Option<KeywordMatcher>> {
    if rules.is_empty() {
        return Ok(None);
    }
    let patterns = rules.iter().map(|rule| rule.rule_match.as_str()).collect::<Vec<_>>();
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(patterns)?;
    Ok(Some(KeywordMatcher { ac, rules: rules.to_vec() }))
}

fn keyword_match(matcher: Option<&KeywordMatcher>, haystack: &str, original_payload: &str) -> Option<Finding> {
    let matcher = matcher?;
    let mat = matcher.ac.find(haystack)?;
    matcher.rules.get(mat.pattern().as_usize()).map(|rule| rule_to_finding(rule, original_payload))
}

fn regex_match(rules: &[CompiledDetectionRule], haystack: &str, original_payload: &str) -> Option<Finding> {
    rules.iter().find_map(|rule| rule.compiled.is_match(haystack).then(|| rule_to_finding(&rule.meta, original_payload)))
}

fn rule_to_finding(rule: &DetectionRule, haystack: &str) -> Finding {
    Finding {
        title: rule.title.clone(),
        severity: rule.severity.clone(),
        cwe: rule.cwe.clone(),
        description: rule.description.clone(),
        reference_url: rule.reference_url.clone(),
        rule_match: rule.rule_match.clone(),
        rule_line_match: format!("{}:{}", rule.source, rule.line),
        request_payload: truncate_payload(haystack).into_owned(),
        timestamp: Utc::now().to_rfc3339(),
    }
}


fn normalize_request_bytes(payload: &[u8]) -> Cow<'_, [u8]> {
    let decoded = url_decode(payload);
    if decoded.as_slice() == payload {
        Cow::Borrowed(payload)
    } else {
        Cow::Owned(decoded)
    }
}


fn inspection_views<'a>(normalized: &'a str) -> Vec<&'a str> {
    let mut views = Vec::with_capacity(8);
    if !normalized.is_empty() {
        views.push(normalized);
    }

    for part in normalized.split(|c| matches!(c, '&' | '\n' | '\r' | '\0')) {
        let trimmed = part.trim();
        if !trimmed.is_empty() && trimmed != normalized {
            views.push(trimmed);
        }
    }

    views
}

fn truncate_payload(value: &str) -> Cow<'_, str> {
    const LIMIT: usize = 2048;
    if value.len() <= LIMIT {
        return Cow::Borrowed(value);
    }
    let mut idx = LIMIT;
    while idx > 0 && !value.is_char_boundary(idx) {
        idx -= 1;
    }
    Cow::Owned(format!("{}…", &value[..idx]))
}

fn canonical_ip(input: &str) -> Option<IpAddr> {
    let trimmed = input.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            other => other,
        });
    }

    let parts = trimmed.split('.').collect::<Vec<_>>();
    if parts.len() == 4 {
        let octets = parts.into_iter().map(|part| part.parse::<u8>()).collect::<Result<Vec<_>, _>>().ok()?;
        return Some(IpAddr::from([octets[0], octets[1], octets[2], octets[3]]));
    }
    None
}

fn parse_ip_net(value: &str) -> Option<IpNet> {
    let trimmed = value.trim();
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Some(net);
    }

    if trimmed.ends_with('.') {
        let parts = trimmed.trim_end_matches('.').split('.').collect::<Vec<_>>();
        let (cidr, expanded_prefix) = match parts.len() {
            1 => (format!("{}.0.0.0/8", parts[0]), 8u8),
            2 => (format!("{}.{}.0.0/16", parts[0], parts[1]), 16),
            3 => (format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]), 24),
            _ => return None,
        };
        let parsed = cidr.parse::<IpNet>().ok();
        if parsed.is_some() {
            // Surface silent CIDR widening so operators see a misconfigured short prefix
            // (e.g. "10." -> 10.0.0.0/8) instead of accidentally blackholing huge ranges.
            warn!(
                target: "krakenwaf",
                input = %trimmed,
                expanded_to = %cidr,
                prefix_bits = expanded_prefix,
                "blocked_ip_prefixes entry expanded from dotted prefix; prefer explicit CIDR notation"
            );
        }
        return parsed;
    }

    canonical_ip(trimmed).map(|ip| match ip {
        IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), 32).ok(),
        IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), 128).ok(),
    })?
}

fn libinjection_match(
    normalized_payload: &[u8],
    original_payload: &str,
    enable_sqli: bool,
    enable_xss: bool,
) -> Option<Finding> {
    if enable_sqli {
        if let Some(hit) = libinjection::detect_sqli(normalized_payload) {
            return Some(Finding {
                title: "LibInjection SQLi detection".into(),
                severity: Severity::Critical,
                cwe: "CWE-89".into(),
                description: "Vendored C libinjection-compatible engine flagged the payload as probable SQL injection.".into(),
                reference_url: "https://github.com/client9/libinjection".into(),
                rule_match: format!("libinjection::sqli:{}", hit.fingerprint.unwrap_or_else(|| "match".into())),
                rule_line_match: "runtime:ffi/libinjection".into(),
                request_payload: truncate_payload(original_payload).into_owned(),
                timestamp: Utc::now().to_rfc3339(),
            });
        }
    }

    if enable_xss {
        if let Some(hit) = libinjection::detect_xss(normalized_payload) {
            return Some(Finding {
                title: "LibInjection XSS detection".into(),
                severity: Severity::High,
                cwe: "CWE-79".into(),
                description: "Vendored C libinjection-compatible engine flagged the payload as probable cross-site scripting.".into(),
                reference_url: "https://github.com/client9/libinjection".into(),
                rule_match: format!("libinjection::xss:{}", hit.fingerprint.unwrap_or_else(|| "match".into())),
                rule_line_match: "runtime:ffi/libinjection".into(),
                request_payload: truncate_payload(original_payload).into_owned(),
                timestamp: Utc::now().to_rfc3339(),
            });
        }
    }

    None
}

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan_matcher(rules: &[DetectionRule]) -> Result<VectorscanMatcher> {
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
                "failed to compile Vectorscan database from {} rules. None of the rules failed in isolation, so the error likely depends on the full set or the active flags. Underlying error: {}",
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
            "invalid Vectorscan rule #{} at {}:{} (title: {}). Rule content is empty. Vectorscan rules in KrakenWaf are pattern strings; if you want a literal match, write the exact text you want to block and escape special characters like ( ) [ ] {{ }} ? + * . | ^ $ when needed.",
            idx + 1,
            rule.source,
            rule.line,
            rule.title,
        );
    }
    if literal.as_bytes().contains(&0) {
        anyhow::bail!(
            "invalid Vectorscan rule #{} at {}:{} (title: {}). Rule content contains a NUL byte, which is not supported here. Rule content: {:?}",
            idx + 1,
            rule.source,
            rule.line,
            rule.title,
            rule.rule_match,
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
            Ok(pattern) => pattern,
            Err(err) => return Some(err),
        };

        if let Err(err) = BlockDatabase::new(vec![pattern]) {
            return Some(anyhow::anyhow!(
                "failed to compile Vectorscan rule #{} at {}:{} (title: {}). Rule content: {:?}. Vectorscan rules in KrakenWaf are compiled with pattern syntax, not JSON regex syntax. If you meant a literal parenthesis or other metacharacter, escape it, for example 'sleep\\('. Underlying error: {}",
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
fn vectorscan_match(matcher: &VectorscanMatcher, normalized_haystack: &str, original_payload: &str) -> Option<Finding> {
    let mut scanner = matcher.db.create_scanner().ok()?;
    let mut matched_index: Option<usize> = None;

    let _ = scanner.scan(normalized_haystack.as_bytes(), |id, _from, _to, _flags| {
        matched_index = Some(id as usize);
        Scan::Terminate
    });

    matched_index
        .and_then(|idx| matcher.keywords.get(idx))
        .map(|rule| rule_to_finding(rule, original_payload))
}

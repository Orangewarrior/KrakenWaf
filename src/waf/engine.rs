
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
    rules::{CompiledDetectionRule, DetectionRule, HttpAction, RuleSet, Severity},
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
    /// Compact UUID v4 (32 lowercase hex chars, no hyphens) generated once per
    /// request and threaded through all log events, SQLite rows, and upstream
    /// headers so that a WAF alert can be correlated with upstream access logs.
    pub request_id: String,
}

/// Context used when inspecting the upstream HTTP response.
#[derive(Debug, Clone)]
pub struct ResponseContext {
    pub status: u16,
    pub headers: String,
    pub body: bytes::Bytes,
}

/// Final WAF decision for a specific phase of the inspection pipeline.
#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Block(Box<Finding>),
}

/// Normalized structured detection finding.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
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

/// Compiled matchers split by inspection phase (Request vs Response).
#[derive(Debug, Clone, Default)]
struct EngineMatchers {
    // Request-phase keyword matchers
    req_uri: Option<KeywordMatcher>,
    req_headers: Option<KeywordMatcher>,
    req_body: Option<KeywordMatcher>,
    // Scanner user-agent matcher (request only)
    req_scanner_agents: Option<KeywordMatcher>,
    // Response-phase keyword matchers
    resp_headers: Option<KeywordMatcher>,
    resp_body: Option<KeywordMatcher>,
    // IP blocklist CIDRs (from rules/addr/blocklist.txt)
    blocked_ip_nets: Vec<IpNet>,
    // Vectorscan databases split by phase
    #[cfg(feature = "vectorscan-engine")]
    req_vectorscan: Option<VectorscanMatcher>,
    #[cfg(feature = "vectorscan-engine")]
    resp_vectorscan: Option<VectorscanMatcher>,
    #[cfg(feature = "vectorscan-engine")]
    scanner_vectorscan: Option<VectorscanMatcher>,
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
    #[allow(clippy::too_many_arguments)]
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

    /// Expose the current rule set for use by server-layer access control (allowlist).
    pub fn rules_snapshot(&self) -> Arc<RuleSet> {
        self.snapshot.read().rules.clone()
    }

    pub async fn reload_from_dir(&self, root: &Path) -> Result<()> {
        let new_rules = Arc::new(RuleSet::from_dir(root)?);
        let new_matchers = build_matchers(&new_rules, self.vectorscan_enabled)?;
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
            return Decision::Block(Box::new(self.simple_finding(
                "Rate limit exceeded",
                Severity::High,
                "CWE-770",
                "The client exceeded the configured requests-per-minute threshold.",
                "https://cwe.mitre.org/data/definitions/770.html",
                "rate_limiter",
                "window_exceeded",
                format!("{} {}", ctx.method, ctx.uri),
            )));
        }

        if self.blocklist_ip_enabled {
            if let Some(client) = canonical_ip(&ctx.client_ip) {
                if rules.blocked_ips.iter().filter_map(|ip| canonical_ip(ip)).any(|blocked| blocked == client) {
                    return Decision::Block(Box::new(self.simple_finding(
                        "Blocked source IP",
                        Severity::High,
                        "CWE-693",
                        "The client IP matched an exact entry in the address blocklist.",
                        "https://cwe.mitre.org/data/definitions/693.html",
                        "addr/blocklist.txt",
                        "exact_match",
                        format!("{} {}", ctx.method, ctx.uri),
                    )));
                }

                if matchers.blocked_ip_nets.iter().any(|net| net.contains(&client)) {
                    return Decision::Block(Box::new(self.simple_finding(
                        "Blocked IP range",
                        Severity::High,
                        "CWE-693",
                        "The client IP matched a blocked CIDR in addr/blocklist.txt.",
                        "https://cwe.mitre.org/data/definitions/693.html",
                        "addr/blocklist.txt",
                        "cidr_match",
                        format!("{} {}", ctx.method, ctx.uri),
                    )));
                }
            }
        }

        // Scanner user-agent check: extract UA header and match against scanner patterns.
        if let Some(ua) = extract_header_value(&ctx.headers, "user-agent") {
            if self.vectorscan_enabled {
                #[cfg(feature = "vectorscan-engine")]
                {
                    if let Some(matcher) = &matchers.scanner_vectorscan {
                        if let Some(finding) = vectorscan_match(matcher, &ua, &ua) {
                            return Decision::Block(Box::new(finding));
                        }
                    }
                }
            }
            #[cfg(not(feature = "vectorscan-engine"))]
            {
                if let Some(finding) = keyword_match(matchers.req_scanner_agents.as_ref(), &ua, &ua) {
                    return Decision::Block(Box::new(finding));
                }
            }
            #[cfg(feature = "vectorscan-engine")]
            if matchers.scanner_vectorscan.is_none() || !self.vectorscan_enabled {
                if let Some(finding) = keyword_match(matchers.req_scanner_agents.as_ref(), &ua, &ua) {
                    return Decision::Block(Box::new(finding));
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

    /// Inspect a request payload. Only rules with `http_action: Request` fire here.
    pub fn inspect_complete_payload_with_context(&self, payload: &[u8], _method_hint: Option<&str>) -> Decision {
        let snap = self.snapshot.read().clone();
        let rules = &snap.rules;
        let matchers = &snap.matchers;

        let normalized_bytes = normalize_request_bytes(payload);
        let original_text = String::from_utf8_lossy(payload);
        let normalized_text = String::from_utf8_lossy(normalized_bytes.as_ref());

        {
            let dfa_lower = normalized_text.to_ascii_lowercase();
            if let Some(finding) = self.dfa_manager.inspect(&dfa_lower) {
                return Decision::Block(Box::new(finding));
            }
        }

        if self.libinjection_sqli_enabled || self.libinjection_xss_enabled {
            if let Some(finding) = libinjection_match(
                normalized_bytes.as_ref(),
                original_text.as_ref(),
                self.libinjection_sqli_enabled,
                self.libinjection_xss_enabled,
            ) {
                return Decision::Block(Box::new(finding));
            }
        }

        if self.vectorscan_enabled {
            #[cfg(feature = "vectorscan-engine")]
            {
                if let Some(matcher) = &matchers.req_vectorscan {
                    if let Some(finding) = vectorscan_match(matcher, normalized_text.as_ref(), original_text.as_ref()) {
                        return Decision::Block(Box::new(finding));
                    }
                }
            }
        }

        for view in inspection_views(normalized_text.as_ref()) {
            if let Some(finding) = keyword_match(matchers.req_uri.as_ref(), view, original_text.as_ref()) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = keyword_match(matchers.req_headers.as_ref(), view, original_text.as_ref()) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = keyword_match(matchers.req_body.as_ref(), view, original_text.as_ref()) {
                return Decision::Block(Box::new(finding));
            }

            if let Some(finding) = regex_match_phase(&rules.path_regex, view, original_text.as_ref(), &HttpAction::Request) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = regex_match_phase(&rules.header_regex, view, original_text.as_ref(), &HttpAction::Request) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = regex_match_phase(&rules.body_regex, view, original_text.as_ref(), &HttpAction::Request) {
                return Decision::Block(Box::new(finding));
            }
        }

        Decision::Allow
    }

    /// Inspect the upstream HTTP response. Only rules with `http_action: Response` fire here.
    pub fn inspect_response(&self, ctx: &ResponseContext) -> Decision {
        let snap = self.snapshot.read().clone();
        let rules = &snap.rules;
        let matchers = &snap.matchers;

        // Build a flat text representation of the response headers for matching.
        let header_payload = format!("HTTP/1.1 {}\n{}\n\n", ctx.status, ctx.headers);
        let header_normalized = normalize_request_bytes(header_payload.as_bytes());
        let header_original = String::from_utf8_lossy(header_payload.as_bytes());
        let header_normalized_text = String::from_utf8_lossy(header_normalized.as_ref());

        let body_normalized = normalize_request_bytes(&ctx.body);
        let body_original = String::from_utf8_lossy(&ctx.body);
        let body_normalized_text = String::from_utf8_lossy(body_normalized.as_ref());

        if self.vectorscan_enabled {
            #[cfg(feature = "vectorscan-engine")]
            {
                if let Some(matcher) = &matchers.resp_vectorscan {
                    if let Some(finding) = vectorscan_match(matcher, header_normalized_text.as_ref(), header_original.as_ref()) {
                        return Decision::Block(Box::new(finding));
                    }
                    if !body_normalized_text.is_empty() {
                        if let Some(finding) = vectorscan_match(matcher, body_normalized_text.as_ref(), body_original.as_ref()) {
                            return Decision::Block(Box::new(finding));
                        }
                    }
                }
            }
        }

        for view in inspection_views(header_normalized_text.as_ref()) {
            if let Some(finding) = keyword_match(matchers.resp_headers.as_ref(), view, header_original.as_ref()) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = regex_match_phase(&rules.header_regex, view, header_original.as_ref(), &HttpAction::Response) {
                return Decision::Block(Box::new(finding));
            }
        }

        for view in inspection_views(body_normalized_text.as_ref()) {
            if let Some(finding) = keyword_match(matchers.resp_body.as_ref(), view, body_original.as_ref()) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = regex_match_phase(&rules.body_regex, view, body_original.as_ref(), &HttpAction::Response) {
                return Decision::Block(Box::new(finding));
            }
        }

        Decision::Allow
    }

    #[allow(clippy::too_many_arguments)]
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
            rule_id: "00000".to_string(),
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

    let req_filter = |r: &&DetectionRule| r.http_action == HttpAction::Request;
    let resp_filter = |r: &&DetectionRule| r.http_action == HttpAction::Response;

    let req_uri_rules: Vec<DetectionRule> = rules.uri_keywords.iter().filter(req_filter).cloned().collect();
    let req_hdr_rules: Vec<DetectionRule> = rules.header_keywords.iter().filter(req_filter).cloned().collect();
    let req_body_rules: Vec<DetectionRule> = rules.body_keywords.iter().filter(req_filter).cloned().collect();
    let resp_hdr_rules: Vec<DetectionRule> = rules.header_keywords.iter().filter(resp_filter).cloned().collect();
    let resp_body_rules: Vec<DetectionRule> = rules.body_keywords.iter().filter(resp_filter).cloned().collect();

    // Build scanner-agent rules as synthetic DetectionRule entries.
    let scanner_rules: Vec<DetectionRule> = rules.scanner_agents.iter().enumerate().map(|(idx, pattern)| {
        DetectionRule {
            id: format!("{:05}", idx + 1),
            title: "Scanner/crawler user-agent detected".to_string(),
            severity: Severity::High,
            cwe: "CWE-200".to_string(),
            description: format!("A known scanning tool user-agent was detected: {}", pattern),
            reference_url: "https://owasp.org/www-project-web-security-testing-guide/".to_string(),
            rule_match: pattern.clone(),
            source: "user_agents/scanners.txt".to_string(),
            line: idx + 1,
            http_action: HttpAction::Request,
        }
    }).collect();

    #[cfg(feature = "vectorscan-engine")]
    let (req_vs_rules, resp_vs_rules): (Vec<_>, Vec<_>) = {
        let req: Vec<DetectionRule> = rules.vectorscan_keywords.iter().filter(req_filter).cloned().collect();
        let resp: Vec<DetectionRule> = rules.vectorscan_keywords.iter().filter(resp_filter).cloned().collect();
        (req, resp)
    };

    Ok(EngineMatchers {
        req_uri: build_keyword_matcher(&req_uri_rules)?,
        req_headers: build_keyword_matcher(&req_hdr_rules)?,
        req_body: build_keyword_matcher(&req_body_rules)?,
        req_scanner_agents: build_keyword_matcher(&scanner_rules)?,
        resp_headers: build_keyword_matcher(&resp_hdr_rules)?,
        resp_body: build_keyword_matcher(&resp_body_rules)?,
        blocked_ip_nets: rules.blocked_ip_prefixes.iter().filter_map(|entry| parse_ip_net(entry)).collect(),
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
            Some(build_vectorscan_matcher(&scanner_rules)?)
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

/// Regex match filtered by http_action phase — avoids building separate Vecs at load time.
fn regex_match_phase(rules: &[CompiledDetectionRule], haystack: &str, original_payload: &str, phase: &HttpAction) -> Option<Finding> {
    rules.iter()
        .filter(|r| &r.meta.http_action == phase)
        .find_map(|rule| rule.compiled.is_match(haystack).then(|| rule_to_finding(&rule.meta, original_payload)))
}

fn rule_to_finding(rule: &DetectionRule, haystack: &str) -> Finding {
    Finding {
        rule_id: rule.id.clone(),
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

fn inspection_views(normalized: &str) -> Vec<&str> {
    let mut views = Vec::with_capacity(8);
    if !normalized.is_empty() {
        views.push(normalized);
    }
    for part in normalized.split(['&', ';', '?', '\n', '\r', '\0']) {
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

/// Extract a header value by name from a flat `name: value\n...` header string.
fn extract_header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim().to_ascii_lowercase())
        } else {
            None
        }
    })
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
                rule_id: "00000".to_string(),
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
                rule_id: "00000".to_string(),
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
                "failed to compile Vectorscan database from {} rules. Underlying error: {}",
                rules.len(), err
            ));
        }
    };
    Ok(VectorscanMatcher { db, keywords: rules.to_vec() })
}

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan_pattern(rule: &DetectionRule, idx: usize) -> Result<Pattern> {
    let literal = rule.rule_match.trim();
    if literal.is_empty() {
        anyhow::bail!(
            "invalid Vectorscan rule #{} at {}:{} (title: {}). Rule content is empty.",
            idx + 1, rule.source, rule.line, rule.title,
        );
    }
    if literal.as_bytes().contains(&0) {
        anyhow::bail!(
            "invalid Vectorscan rule #{} at {}:{} (title: {}). Rule content contains a NUL byte.",
            idx + 1, rule.source, rule.line, rule.title,
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
                idx + 1, rule.source, rule.line, rule.title, rule.rule_match, err
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

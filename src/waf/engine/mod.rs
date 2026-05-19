mod finding;
mod ip_filter;
mod matchers;
mod normalize;

pub use finding::Finding;

use crate::cmc::CmcManager;
use crate::proxy::format_request_prefix_bytes;
use crate::update::{
    default_config_path, load_update_config, normalized_dqs_zones, query_spamhaus_dqs,
};
use crate::{
    metrics::WafMetrics,
    rules::{AddrListEntry, HttpAction, RuleSet, Severity},
    waf::rate_limit::{PersistenceMode, RateLimiter},
};
use anyhow::Result;
use chrono::Utc;
use parking_lot::RwLock;
use std::{path::Path, sync::Arc, time::Duration};

use ip_filter::{canonical_ip, extract_header_value};
use matchers::{
    build_matchers, keyword_match, libinjection_match, regex_match_phase_scored, EngineMatchers,
};
use normalize::{inspection_views, normalize_request_bytes};

#[cfg(feature = "vectorscan-engine")]
use matchers::vectorscan_match_scored;

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
    /// request and threaded through all log events, `SQLite` rows, and upstream
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
    /// Block the request/response and log to all security outputs.
    Block(Box<Finding>),
    /// Log the finding to all security outputs but do **not** block.
    /// Used when `untrust_level < 60` and the threat is not confirmed enough
    /// to justify blocking the upstream response.
    Monitor(Box<Finding>),
}

/// Immutable snapshot of rules + their pre-compiled matchers. Held behind a
/// single `Arc` so a hot-reload swaps both atomically — no window where a
/// reader can see new rules paired with stale matchers or vice versa.
struct RulesSnapshot {
    rules: Arc<RuleSet>,
    matchers: EngineMatchers,
}

/// Main `KrakenWaf` engine containing rules and optional accelerated detectors.
#[allow(clippy::struct_excessive_bools)]
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
    cmc_manager: Arc<CmcManager>,
    spamhaus_dqs: Option<SpamhausDqsConfig>,
}

#[derive(Debug, Clone)]
struct SpamhausDqsConfig {
    token: String,
    zones: Vec<String>,
}

impl WafEngine {
    /// # Errors
    /// Returns an error if the rate limiter or rule matchers fail to initialize.
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    pub fn new(
        rules: Arc<RuleSet>,
        rate_limit_per_minute: u32,
        blocklist_ip_enabled: bool,
        libinjection_sqli_enabled: bool,
        libinjection_xss_enabled: bool,
        vectorscan_enabled: bool,
        snapshot_path: &std::path::Path,
        rate_limit_persistence: PersistenceMode,
        metrics: Arc<WafMetrics>,
        cmc_manager: Arc<CmcManager>,
    ) -> Result<Self> {
        let rate_limiter = Arc::new(RateLimiter::new(
            rate_limit_per_minute,
            Duration::from_secs(60),
            snapshot_path,
            rate_limit_persistence,
        )?);
        rate_limiter.clone().spawn_persistence_task();
        let matchers = build_matchers(&rules, vectorscan_enabled)?;
        let spamhaus_dqs = load_spamhaus_dqs_config(blocklist_ip_enabled);
        Ok(Self {
            snapshot: RwLock::new(Arc::new(RulesSnapshot { rules, matchers })),
            rate_limiter,
            blocklist_ip_enabled,
            libinjection_sqli_enabled,
            libinjection_xss_enabled,
            vectorscan_enabled,
            metrics,
            cmc_manager,
            spamhaus_dqs,
        })
    }

    pub fn body_limit_for_path(&self, path: &str) -> usize {
        self.snapshot.read().rules.body_limit_for_path(path)
    }

    /// Expose the current rule set for use by server-layer access control (allowlist).
    pub fn rules_snapshot(&self) -> Arc<RuleSet> {
        self.snapshot.read().rules.clone()
    }

    /// # Errors
    /// Returns an error if the rule files are missing or contain invalid data.
    #[allow(clippy::unused_async)]
    pub async fn reload_from_dir(&self, root: &Path) -> Result<()> {
        let new_rules = Arc::new(RuleSet::from_dir(root)?);
        let new_matchers = build_matchers(&new_rules, self.vectorscan_enabled)?;
        *self.snapshot.write() = Arc::new(RulesSnapshot {
            rules: new_rules,
            matchers: new_matchers,
        });
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
                if rules
                    .blocked_ips
                    .iter()
                    .filter_map(|ip| canonical_ip(ip))
                    .any(|blocked| blocked == client)
                {
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

                if matchers
                    .blocked_ip_nets
                    .iter()
                    .any(|net| net.contains(&client))
                {
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

                if let Some(entry) = addr_list_match(&rules.addr_list_entries, &client) {
                    return Decision::Block(Box::new(addr_list_finding(entry, ctx)));
                }

                if let Some(finding) = self.spamhaus_dqs_finding(&client, ctx).await {
                    return Decision::Block(Box::new(finding));
                }
            }
        }

        // Scanner user-agent check.
        if let Some(ua) = extract_header_value(&ctx.headers, "user-agent") {
            if self.vectorscan_enabled {
                #[cfg(feature = "vectorscan-engine")]
                {
                    if let Some(matcher) = &matchers.scanner_vectorscan {
                        if let Some(finding) = vectorscan_match_scored(matcher, &ua, &ua) {
                            return Decision::Block(Box::new(finding));
                        }
                    }
                }
            }
            #[cfg(not(feature = "vectorscan-engine"))]
            {
                if let Some(finding) = keyword_match(matchers.req_scanner_agents.as_ref(), &ua, &ua)
                {
                    return Decision::Block(Box::new(finding));
                }
            }
            #[cfg(feature = "vectorscan-engine")]
            if matchers.scanner_vectorscan.is_none() || !self.vectorscan_enabled {
                if let Some(finding) = keyword_match(matchers.req_scanner_agents.as_ref(), &ua, &ua)
                {
                    return Decision::Block(Box::new(finding));
                }
            }
        }

        // URI-level CMC check (method + path only — runs before body assembly).
        if let Some(finding) = self.cmc_manager.inspect_uri(&ctx.method, &ctx.path) {
            return Decision::Block(Box::new(finding));
        }

        let early_request = format_request_prefix_bytes(ctx);
        self.inspect_complete_payload_with_context(&early_request, Some(&ctx.method))
    }

    async fn spamhaus_dqs_finding(
        &self,
        client: &std::net::IpAddr,
        ctx: &InspectionContext,
    ) -> Option<Finding> {
        let config = self.spamhaus_dqs.as_ref()?;
        for zone in &config.zones {
            match query_spamhaus_dqs(&client.to_string(), &config.token, zone).await {
                Ok(Some(hit)) => return Some(spamhaus_dqs_finding(&hit.zone, hit.response, ctx)),
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!(
                        target: "krakenwaf",
                        ip = %client,
                        zone,
                        error = %err,
                        "Spamhaus DQS lookup failed; request will not be blocked by this zone"
                    );
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn inspect_body_chunk(&self, chunk: &[u8]) -> Decision {
        self.inspect_complete_payload(chunk)
    }

    pub fn inspect_complete_payload(&self, payload: &[u8]) -> Decision {
        self.inspect_complete_payload_with_context(payload, None)
    }

    /// Inspect a request payload. Only rules with `http_action: Request` fire here.
    pub fn inspect_complete_payload_with_context(
        &self,
        payload: &[u8],
        _method_hint: Option<&str>,
    ) -> Decision {
        let snap = self.snapshot.read().clone();
        let rules = &snap.rules;
        let matchers = &snap.matchers;

        let normalized_bytes = normalize_request_bytes(payload);
        let original_text = String::from_utf8_lossy(payload);
        let normalized_text = String::from_utf8_lossy(normalized_bytes.as_ref());

        {
            let cmc_lower = normalized_text.to_ascii_lowercase();
            if let Some(finding) = self.cmc_manager.inspect(&cmc_lower) {
                return Decision::Block(Box::new(finding));
            }

            if normalized_bytes.as_ref() != payload {
                let original_lower = original_text.to_ascii_lowercase();
                if original_lower != cmc_lower {
                    if let Some(finding) = self.cmc_manager.inspect(&original_lower) {
                        return Decision::Block(Box::new(finding));
                    }
                }
            }
        }

        // Java deserialization detection runs on the ORIGINAL (non-lowercased) text
        // because base64 prefixes like rO0A are case-sensitive. Binary magic is
        // detected directly from the raw payload bytes.
        if let Some(cmc_finding) = self
            .cmc_manager
            .inspect_java_deser(original_text.as_ref(), payload)
        {
            return Decision::Block(Box::new(cmc_finding));
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
                    if let Some(finding) = vectorscan_match_scored(
                        matcher,
                        normalized_text.as_ref(),
                        original_text.as_ref(),
                    ) {
                        return Decision::Block(Box::new(finding));
                    }
                }
            }
        }

        for view in inspection_views(normalized_text.as_ref()) {
            if let Some(finding) =
                keyword_match(matchers.req_uri.as_ref(), view, original_text.as_ref())
            {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) =
                keyword_match(matchers.req_headers.as_ref(), view, original_text.as_ref())
            {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) =
                keyword_match(matchers.req_body.as_ref(), view, original_text.as_ref())
            {
                return Decision::Block(Box::new(finding));
            }

            if let Some(finding) = regex_match_phase_scored(
                &rules.path_regex,
                view,
                original_text.as_ref(),
                &HttpAction::Request,
            ) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = regex_match_phase_scored(
                &rules.header_regex,
                view,
                original_text.as_ref(),
                &HttpAction::Request,
            ) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = regex_match_phase_scored(
                &rules.body_regex,
                view,
                original_text.as_ref(),
                &HttpAction::Request,
            ) {
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
                    if let Some(finding) = vectorscan_match_scored(
                        matcher,
                        header_normalized_text.as_ref(),
                        header_original.as_ref(),
                    ) {
                        return Decision::Block(Box::new(finding));
                    }
                    if !body_normalized_text.is_empty() {
                        if let Some(finding) = vectorscan_match_scored(
                            matcher,
                            body_normalized_text.as_ref(),
                            body_original.as_ref(),
                        ) {
                            return Decision::Block(Box::new(finding));
                        }
                    }
                }
            }
        }

        for view in inspection_views(header_normalized_text.as_ref()) {
            if let Some(finding) = keyword_match(
                matchers.resp_headers.as_ref(),
                view,
                header_original.as_ref(),
            ) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = regex_match_phase_scored(
                &rules.header_regex,
                view,
                header_original.as_ref(),
                &HttpAction::Response,
            ) {
                return Decision::Block(Box::new(finding));
            }
        }

        for view in inspection_views(body_normalized_text.as_ref()) {
            if let Some(finding) =
                keyword_match(matchers.resp_body.as_ref(), view, body_original.as_ref())
            {
                return Decision::Block(Box::new(finding));
            }
            if let Some(finding) = regex_match_phase_scored(
                &rules.body_regex,
                view,
                body_original.as_ref(),
                &HttpAction::Response,
            ) {
                return Decision::Block(Box::new(finding));
            }
        }

        // CMC response-body scan: passwd/shadow leak + DB error detection.
        match self
            .cmc_manager
            .inspect_response_body(body_original.as_ref())
        {
            Some(crate::cmc::CmcResponseDecision::Block(f)) => {
                return Decision::Block(Box::new(f));
            }
            Some(crate::cmc::CmcResponseDecision::Monitor(f)) => {
                return Decision::Monitor(Box::new(f));
            }
            None => {}
        }

        // Java deserialization detection on upstream responses.
        let java_deser_text = format!("{header_payload}{body_original}");
        if let Some(cmc_finding) = self
            .cmc_manager
            .inspect_java_deser(&java_deser_text, &ctx.body)
        {
            return Decision::Block(Box::new(cmc_finding));
        }

        Decision::Allow
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::unused_self)]
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

fn load_spamhaus_dqs_config(blocklist_ip_enabled: bool) -> Option<SpamhausDqsConfig> {
    if !blocklist_ip_enabled {
        return None;
    }
    let config = load_update_config(&default_config_path()).ok()?;
    if !config.spamhaus.dqs_key {
        return None;
    }
    let token = std::env::var("SPAMHAUS_DQS_KEY").ok()?;
    (!token.trim().is_empty()).then(|| SpamhausDqsConfig {
        token,
        zones: normalized_dqs_zones(&config.spamhaus.zones),
    })
}

fn addr_list_match<'a>(
    entries: &'a [AddrListEntry],
    client: &std::net::IpAddr,
) -> Option<&'a AddrListEntry> {
    entries.iter().find(|entry| entry.contains(client))
}

fn addr_list_finding(entry: &AddrListEntry, ctx: &InspectionContext) -> Finding {
    Finding {
        rule_id: "00000".to_string(),
        title: entry.title.clone(),
        severity: Severity::High,
        cwe: "CWE-693".to_string(),
        description: format!(
            "The client IP matched address list {} loaded from {}.",
            entry.list_name, entry.path
        ),
        reference_url:
            "https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html"
                .to_string(),
        rule_match: format!("{} {}", entry.list_name, entry.network),
        rule_line_match: format!("{}:{}", entry.path, entry.line),
        request_payload: format!("{} {}", ctx.method, ctx.uri),
        timestamp: Utc::now().to_rfc3339(),
    }
}

fn spamhaus_dqs_finding(
    zone: &str,
    response: std::net::IpAddr,
    ctx: &InspectionContext,
) -> Finding {
    Finding {
        rule_id: "00000".to_string(),
        title: format!("Spamhaus DQS match: {}", zone.to_ascii_uppercase()),
        severity: Severity::High,
        cwe: "CWE-693".to_string(),
        description: "The client IP matched a Spamhaus DQS DNS reputation zone.".to_string(),
        reference_url:
            "https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html"
                .to_string(),
        rule_match: format!("Spamhaus DQS zone={zone} response={response}"),
        rule_line_match: format!("rules/addr/spamhaus/{}.txt:dqs", zone.to_ascii_uppercase()),
        request_payload: format!("{} {}", ctx.method, ctx.uri),
        timestamp: Utc::now().to_rfc3339(),
    }
}

mod finding;
mod ip_filter;
mod matchers;
pub mod normalize;
mod spamhaus_cache;

pub use finding::Finding;
pub use normalize::{normalize_str, strip_control_and_space_prefix};

use crate::cmc::{CmcController, CmcUpdateOutcome};
use crate::proxy::format_request_prefix_bytes;
use crate::update::{
    default_config_path, load_update_config, normalized_dqs_zones, query_spamhaus_dqs,
};
use crate::{
    metrics::WafMetrics,
    rules::{AddrListEntry, HttpAction, RuleSet, Severity},
    waf::rate_limit::{RateLimitDecision, RateLimiter},
};
use anyhow::Result;
use arc_swap::ArcSwap;
use chrono::Utc;
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use ip_filter::{canonical_ip, extract_header_value};
use spamhaus_cache::SpamhausDqsCache;
use matchers::{
    build_matchers, keyword_match, keyword_match_accumulate, libinjection_match,
    regex_match_phase_scored, regex_match_phase_scored_threshold_deadline, EngineMatchers,
    RegexDeadline, RegexScanResult, SCORE_BLOCK_THRESHOLD,
};
use normalize::{as_latin1, inspection_views, normalize_request_bytes};

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
    /// `GeoIP` country name resolved from `client_ip` at request time.
    /// Empty when the DB is not loaded or the IP is private/unresolvable.
    pub country: String,
    /// `GeoIP` continent name resolved from `client_ip` at request time.
    pub continent_name: String,
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
    /// Forward a **modified** response body where a matched substring has been
    /// scrubbed. Used by `silent_sql_errors` when `untrust_level < 80`: the
    /// finding is logged with low severity, the body is rewritten in place,
    /// and the proxy must update Content-Length before forwarding.
    SilentReplace {
        finding: Box<Finding>,
        body: bytes::Bytes,
    },
}

/// Immutable snapshot of rules + their pre-compiled matchers. Held behind a
/// single `Arc` so a hot-reload swaps both atomically — no window where a
/// reader can see new rules paired with stale matchers or vice versa.
struct RulesSnapshot {
    rules: Arc<RuleSet>,
    matchers: EngineMatchers,
}

/// All configuration needed to construct a `WafEngine`. Use `WafEngineFactory`
/// instead of calling `WafEngine` constructors directly.
#[allow(clippy::struct_excessive_bools)]
pub struct WafEngineConfig {
    pub rules: Arc<RuleSet>,
    pub rate_limiter: Arc<RateLimiter>,
    pub blocklist_ip_enabled: bool,
    pub libinjection_sqli_enabled: bool,
    pub libinjection_xss_enabled: bool,
    pub vectorscan_enabled: bool,
    pub metrics: Arc<WafMetrics>,
    pub cmc_manager: Arc<CmcController>,
    /// Anomaly-score block threshold. `0` falls back to the built-in default.
    pub anomaly_threshold: u32,
    /// Per-request wall-clock cap on WAF inspection in milliseconds. `0` = unlimited.
    pub max_inspection_ms: u64,
}

/// Adapter between the rate-limiter domain decision and the WAF event model.
pub struct RateLimitRejection {
    pub finding: Box<Finding>,
    pub decision: RateLimitDecision,
}

/// Factory for constructing a fully-initialised [`WafEngine`].
///
/// Calling `WafEngine::new` directly is no longer supported; use
/// `WafEngineFactory::create(WafEngineConfig { ... })`. The factory pattern
/// keeps the engine constructor stable as new optional features are added.
pub struct WafEngineFactory;

impl WafEngineFactory {
    /// # Errors
    /// Returns an error if the rule matchers fail to initialise.
    pub fn create(cfg: WafEngineConfig) -> Result<WafEngine> {
        WafEngine::new(cfg)
    }
}

/// Main `KrakenWaf` engine containing rules and optional accelerated detectors.
#[allow(clippy::struct_excessive_bools)]
pub struct WafEngine {
    /// Wait-free atomic swap of the immutable `(rules, matchers)` pair.
    /// Replaces the previous `RwLock<Arc<…>>` — every inspection path now
    /// performs a single relaxed atomic load instead of acquiring a read
    /// lock. Hot-reload still publishes a new snapshot atomically.
    snapshot: ArcSwap<RulesSnapshot>,
    rate_limiter: Arc<RateLimiter>,
    blocklist_ip_enabled: bool,
    libinjection_sqli_enabled: bool,
    libinjection_xss_enabled: bool,
    vectorscan_enabled: bool,
    metrics: Arc<WafMetrics>,
    cmc_manager: Arc<CmcController>,
    spamhaus_dqs: Option<SpamhausDqsConfig>,
    /// TTL cache for Spamhaus DQS lookups. `Some` exactly when `spamhaus_dqs`
    /// is, so the per-request DNS-over-TLS lookup is performed at most once per
    /// `(ip, zone)` per TTL instead of on every request.
    spamhaus_cache: Option<Arc<SpamhausDqsCache>>,
    anomaly_threshold: u32,
    max_inspection_ms: u64,
}

#[derive(Debug, Clone)]
struct SpamhausDqsConfig {
    token: String,
    zones: Vec<String>,
    positive_ttl: Duration,
    negative_ttl: Duration,
}

const FILTER_DEADLINE_LOG: &str = "logs/filter/deadline.jsonl";

#[derive(Debug, Clone, Copy)]
struct InspectionDeadline {
    started_at: Instant,
    expires_at: Instant,
    max_ms: u64,
}

impl InspectionDeadline {
    fn new(max_ms: u64) -> Self {
        let started_at = Instant::now();
        let duration = Duration::from_millis(max_ms);
        let expires_at = if let Some(expires_at) = started_at.checked_add(duration) {
            expires_at
        } else {
            tracing::warn!(
                target: "krakenwaf",
                max_ms,
                "max_inspection_ms overflowed Instant; treating inspection budget as already expired"
            );
            started_at
        };
        Self {
            started_at,
            expires_at,
            max_ms,
        }
    }

    fn expired(self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn elapsed_ms(self) -> u128 {
        self.started_at.elapsed().as_millis()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct DeadlineMetadata<'a> {
    id: Option<&'a str>,
    title: Option<&'a str>,
    match_text: Option<&'a str>,
    line_match: Option<&'a str>,
}

impl WafEngine {
    /// Construct directly from a [`WafEngineConfig`]. Prefer `WafEngineFactory::create`.
    ///
    /// # Errors
    /// Returns an error if the rule matchers fail to initialise.
    fn new(cfg: WafEngineConfig) -> Result<Self> {
        cfg.rate_limiter.clone().spawn_persistence_task();
        let matchers = build_matchers(&cfg.rules, cfg.vectorscan_enabled)?;
        let spamhaus_dqs = load_spamhaus_dqs_config(cfg.blocklist_ip_enabled);
        let spamhaus_cache = spamhaus_dqs
            .as_ref()
            .map(|c| Arc::new(SpamhausDqsCache::new(c.positive_ttl, c.negative_ttl)));
        let anomaly_threshold = if cfg.anomaly_threshold == 0 {
            SCORE_BLOCK_THRESHOLD
        } else {
            cfg.anomaly_threshold
        };
        Ok(Self {
            snapshot: ArcSwap::new(Arc::new(RulesSnapshot {
                rules: cfg.rules,
                matchers,
            })),
            rate_limiter: cfg.rate_limiter,
            blocklist_ip_enabled: cfg.blocklist_ip_enabled,
            libinjection_sqli_enabled: cfg.libinjection_sqli_enabled,
            libinjection_xss_enabled: cfg.libinjection_xss_enabled,
            vectorscan_enabled: cfg.vectorscan_enabled,
            metrics: cfg.metrics,
            cmc_manager: cfg.cmc_manager,
            spamhaus_dqs,
            spamhaus_cache,
            anomaly_threshold,
            max_inspection_ms: cfg.max_inspection_ms,
        })
    }

    pub fn body_limit_for_path(&self, path: &str) -> usize {
        self.snapshot.load().rules.body_limit_for_path(path)
    }

    /// Expose the current rule set for use by server-layer access control (allowlist).
    pub fn rules_snapshot(&self) -> Arc<RuleSet> {
        self.snapshot.load().rules.clone()
    }

    /// # Errors
    /// Returns an error if the rule files are missing or contain invalid data.
    #[allow(clippy::unused_async)]
    pub async fn reload_from_dir(&self, root: &Path) -> Result<()> {
        let new_rules = Arc::new(RuleSet::from_dir(root)?);
        let new_matchers = build_matchers(&new_rules, self.vectorscan_enabled)?;
        self.snapshot.store(Arc::new(RulesSnapshot {
            rules: new_rules,
            matchers: new_matchers,
        }));
        Ok(())
    }

    /// Snapshot the live enable state of every toggleable CMC module, in the
    /// canonical order. Backs `GET /rule/control/cmc/list`.
    #[must_use]
    pub fn cmc_module_states(&self) -> Vec<(&'static str, bool)> {
        self.cmc_manager.module_states()
    }

    /// Apply a partial CMC module patch in real time, atomically swapping the
    /// live detection table. Backs `POST /rule/control/cmc/update`.
    ///
    /// # Errors
    /// Returns the offending module key when the patch names an unknown module.
    pub fn cmc_apply_update(&self, patch: &[(String, bool)]) -> Result<CmcUpdateOutcome, String> {
        self.cmc_manager.apply_update(patch)
    }

    pub async fn inspect_early(&self, ctx: &InspectionContext) -> Decision {
        self.metrics.inc_inspected();
        let snap = self.snapshot.load_full();
        let rules = &snap.rules;
        let matchers = &snap.matchers;

        // The per-IP rate limit is intentionally NOT checked here. It is
        // enforced separately — for *every* request — in the proxy `dispatch`
        // via [`Self::rate_limit_finding`], so an allow-listed path (which
        // returns `Allow` just below and skips the rest of this method) is still
        // rate-limited. Keeping the budget check out of the signature pipeline
        // also lets the observability listener reuse it on `/metrics`.
        if rules.is_allowlisted(&ctx.path) {
            return Decision::Allow;
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

        // Scanner / bot user-agent check — fully delegated to the
        // `Detect_bots_n_scanners` CMC module. The module is responsible for
        // loading `rules/user_agents/scanners.txt`, gating on the global
        // `Untrust` level, and emitting a Low-severity finding when a known
        // scanner substring is matched.
        if let Some(ua) = extract_header_value(&ctx.headers, "user-agent") {
            if let Some(finding) = self.cmc_manager.inspect_user_agent(&ua) {
                return Decision::Block(Box::new(finding));
            }
        }

        // URI-level CMC check (method + path only — runs before body assembly).
        if let Some(finding) = self.cmc_manager.inspect_uri(&ctx.method, &ctx.path) {
            return Decision::Block(Box::new(finding));
        }

        let early_request = format_request_prefix_bytes(ctx);
        self.inspect_complete_payload_with_context(&early_request, Some(&ctx.method))
    }

    /// Check only the per-IP rate limit, independent of the signature pipeline.
    /// Returns `true` when the request is within budget, `false` when it must be
    /// throttled (and records a `rate_limit_hits` metric in that case).
    ///
    /// Exposed so two callers that must rate-limit *without* running CMC / regex
    /// / keyword inspection can share one budget: allow-listed request paths
    /// (via [`Self::rate_limit_finding`]) and the dedicated observability
    /// listener's `/metrics` endpoint.
    #[allow(dead_code)]
    pub async fn check_rate_limit_ip(&self, ip: &str) -> bool {
        self.rate_limit_decision_ip(ip).await.is_allowed()
    }

    /// Return the typed rate-limit decision and account rejected admissions.
    pub async fn rate_limit_decision_ip(&self, ip: &str) -> RateLimitDecision {
        let decision = self.rate_limiter.decide(ip).await;
        if !decision.is_allowed() {
            self.metrics.inc_rate_limit_hits();
        }
        decision
    }

    /// Flush local GCRA state from a blocking worker during graceful shutdown.
    /// Redis-backed limiters are already durable and return immediately.
    ///
    /// # Errors
    ///
    /// Returns an error when the local snapshot cannot be persisted.
    pub async fn persist_rate_limiter(&self) -> Result<()> {
        self.rate_limiter.persist_async().await
    }

    /// Build the rate-limit [`Finding`] for `ctx` when the client has exceeded
    /// its per-IP budget, otherwise `None`. The finding is byte-for-byte the one
    /// the engine produced inline before rate-limiting was split out of
    /// [`Self::inspect_early`], so logging, ban attribution
    /// ([`crate::banning::BlockReason::RateLimit`]), and metrics are unchanged.
    pub async fn rate_limit_finding(&self, ctx: &InspectionContext) -> Option<RateLimitRejection> {
        let decision = self.rate_limit_decision_ip(&ctx.client_ip).await;
        if decision.is_allowed() {
            return None;
        }
        Some(RateLimitRejection {
            finding: Box::new(self.simple_finding(
                "Rate limit exceeded",
                Severity::High,
                "CWE-770",
                "The client exceeded the configured GCRA request budget.",
                "https://cwe.mitre.org/data/definitions/770.html",
                "rate_limiter",
                "gcra_budget_exceeded",
                format!("{} {}", ctx.method, ctx.uri),
            )),
            decision,
        })
    }

    async fn spamhaus_dqs_finding(
        &self,
        client: &std::net::IpAddr,
        ctx: &InspectionContext,
    ) -> Option<Finding> {
        let config = self.spamhaus_dqs.as_ref()?;
        let cache = self.spamhaus_cache.as_ref();
        for zone in &config.zones {
            // Serve from the TTL cache first so a flood of requests from one IP
            // does not become a flood of DNS-over-TLS lookups. A cached negative
            // (`Some(None)`) skips the zone; a cached positive blocks immediately.
            if let Some(cache) = cache {
                match cache.get(client, zone, Instant::now()) {
                    spamhaus_cache::CacheLookup::Listed(hit) => {
                        return Some(spamhaus_dqs_finding(&hit.zone, hit.response, ctx))
                    }
                    spamhaus_cache::CacheLookup::NotListed => continue,
                    spamhaus_cache::CacheLookup::Miss => {}
                }
            }
            match query_spamhaus_dqs(&client.to_string(), &config.token, zone).await {
                Ok(Some(hit)) => {
                    if let Some(cache) = cache {
                        cache.insert(*client, zone, Some(hit.clone()), Instant::now());
                    }
                    return Some(spamhaus_dqs_finding(&hit.zone, hit.response, ctx));
                }
                Ok(None) => {
                    if let Some(cache) = cache {
                        cache.insert(*client, zone, None, Instant::now());
                    }
                }
                // Errors are intentionally NOT cached: a transient DoT failure
                // must not pin a "not listed" verdict for the whole TTL.
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

    /// Inspect a request's query string and body for HTTP Parameter Pollution
    /// (the `HPP_detect` CMC module). Both locations are decoded and checked
    /// independently; a duplicate parameter name (case-insensitive) in either
    /// yields a `Critical` finding so the existing `Untrust >= 60` gate blocks.
    ///
    /// `query` is the raw query string (without the leading `?`); `body` is the
    /// raw request body as text. The module is a no-op (returns `Allow`) when it
    /// is disabled in `conf/filter.yaml`.
    #[must_use]
    pub fn inspect_hpp(&self, query: &str, body: &str) -> Decision {
        match self.cmc_manager.inspect_hpp(query, body) {
            Some(finding) => Decision::Block(Box::new(finding)),
            None => Decision::Allow,
        }
    }

    /// Inspect a request's query string and body for Open Redirect / RFI in a
    /// hot redirect/inclusion parameter value (the `Open_redirect_n_RFI_detect`
    /// CMC module). `query` is the raw query string (without the leading `?`);
    /// `body` is the raw request body as text. Returns `Decision::Block` with a
    /// High-severity finding on the first detection, otherwise `Decision::Allow`.
    /// The module is a no-op (returns `Allow`) when disabled in
    /// `conf/filter.yaml`.
    #[must_use]
    pub fn inspect_open_redirect_rfi(&self, query: &str, body: &str) -> Decision {
        match self.cmc_manager.inspect_open_redirect_rfi(query, body) {
            Some(finding) => Decision::Block(Box::new(finding)),
            None => Decision::Allow,
        }
    }

    pub fn inspect_complete_payload(&self, payload: &[u8]) -> Decision {
        self.inspect_complete_payload_with_context(payload, None)
    }

    /// Inspect a request payload. Only rules with `http_action: Request` fire here.
    pub fn inspect_complete_payload_with_context(
        &self,
        payload: &[u8],
        method_hint: Option<&str>,
    ) -> Decision {
        let deadline = if self.max_inspection_ms == 0 {
            None
        } else {
            Some(InspectionDeadline::new(self.max_inspection_ms))
        };
        self.inspect_payload_inner(payload, method_hint, deadline)
    }

    #[allow(clippy::too_many_lines, unused_variables)]
    fn inspect_payload_inner(
        &self,
        payload: &[u8],
        _method_hint: Option<&str>,
        deadline: Option<InspectionDeadline>,
    ) -> Decision {
        let snap = self.snapshot.load_full();
        let rules = &snap.rules;
        let matchers = &snap.matchers;
        let threshold = self.anomaly_threshold;

        let normalized_bytes = normalize_request_bytes(payload);
        let original_text = String::from_utf8_lossy(payload);
        let normalized_text = String::from_utf8_lossy(normalized_bytes.as_ref());
        if let Some(decision) = Self::deadline_decision(
            deadline,
            "normalize_request_bytes",
            payload,
            Some(normalized_text.as_ref()),
            DeadlineMetadata::default(),
        ) {
            return decision;
        }

        {
            let cmc_lower = normalized_text.to_ascii_lowercase();
            if let Some(finding) = self.cmc_manager.inspect(&cmc_lower) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(decision) = Self::deadline_decision(
                deadline,
                "cmc::inspect(normalized)",
                payload,
                Some(cmc_lower.as_str()),
                DeadlineMetadata::default(),
            ) {
                return decision;
            }

            if normalized_bytes.as_ref() != payload {
                let original_lower = original_text.to_ascii_lowercase();
                if original_lower != cmc_lower {
                    if let Some(finding) = self.cmc_manager.inspect(&original_lower) {
                        return Decision::Block(Box::new(finding));
                    }
                    if let Some(decision) = Self::deadline_decision(
                        deadline,
                        "cmc::inspect(original)",
                        payload,
                        Some(original_lower.as_str()),
                        DeadlineMetadata::default(),
                    ) {
                        return decision;
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
        if let Some(decision) = Self::deadline_decision(
            deadline,
            "cmc::inspect_java_deser",
            payload,
            Some(original_text.as_ref()),
            DeadlineMetadata::default(),
        ) {
            return decision;
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
            if let Some(decision) = Self::deadline_decision(
                deadline,
                "libinjection",
                payload,
                Some(normalized_text.as_ref()),
                DeadlineMetadata::default(),
            ) {
                return decision;
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
                    if let Some(decision) = Self::deadline_decision(
                        deadline,
                        "vectorscan::request",
                        payload,
                        Some(normalized_text.as_ref()),
                        DeadlineMetadata::default(),
                    ) {
                        return decision;
                    }
                }
            }
        }

        // UTF-8 dual-form: when lossy conversion introduced replacement chars we
        // additionally inspect a Latin-1 form so byte-specific patterns are not
        // masked by `\u{FFFD}`. The Latin-1 string is computed lazily.
        let latin1_text: Option<String> = if normalized_text.contains('\u{FFFD}') {
            Some(as_latin1(normalized_bytes.as_ref()))
        } else {
            None
        };

        // Views are inspected from up to three forms so detection does not hinge
        // on the WAF and the upstream agreeing on how many times to percent-decode
        // or whether `+` means space (see `normalize` module docs):
        //   • the normalised form (fully percent-decoded, `+`→space),
        //   • the raw/original form — brings the keyword/regex matchers to parity
        //     with the CMC, libinjection and vectorscan engines above (which
        //     already inspect the original), catching rules written against the
        //     encoded bytes and payloads a decode pass would otherwise destroy,
        //   • a Latin-1 fallback when lossy UTF-8 introduced replacement chars.
        // Views are de-duplicated, so the common case (no encoding present,
        // original == normalised) adds no extra scanning.
        let views = inspection_views(normalized_text.as_ref());
        let original_views: Vec<&str> = if normalized_bytes.as_ref() == payload {
            Vec::new()
        } else {
            inspection_views(original_text.as_ref())
        };
        let latin1_views: Option<Vec<&str>> = latin1_text.as_deref().map(inspection_views);
        let mut seen_views: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let all_views = views
            .iter()
            .copied()
            .chain(original_views.iter().copied())
            .chain(
                latin1_views
                    .as_ref()
                    .map(|v| v.iter().copied())
                    .into_iter()
                    .flatten(),
            )
            .filter(move |view| seen_views.insert(*view));

        for view in all_views {
            if let Some(decision) = Self::deadline_decision(
                deadline,
                "signature_view_start",
                payload,
                Some(view),
                DeadlineMetadata::default(),
            ) {
                return decision;
            }

            // Each view is an independent inspection unit. The full-payload
            // view already accumulates score across delimited segments via
            // `find_iter` (keywords) or per-rule iteration (regex); carrying
            // a shared accumulator across views would double-count the same
            // rule when it matches both the full payload AND a sub-segment
            // (e.g. the form field value when newline-splitting the request).
            let mut sum_score: u32 = 0;

            if let Some(finding) = keyword_match_accumulate(
                matchers.req_uri.as_ref(),
                view,
                original_text.as_ref(),
                threshold,
                &mut sum_score,
            ) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(decision) = Self::deadline_decision(
                deadline,
                "keyword:req_uri",
                payload,
                Some(view),
                DeadlineMetadata::default(),
            ) {
                return decision;
            }
            if let Some(finding) = keyword_match_accumulate(
                matchers.req_headers.as_ref(),
                view,
                original_text.as_ref(),
                threshold,
                &mut sum_score,
            ) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(decision) = Self::deadline_decision(
                deadline,
                "keyword:req_headers",
                payload,
                Some(view),
                DeadlineMetadata::default(),
            ) {
                return decision;
            }
            if let Some(finding) = keyword_match_accumulate(
                matchers.req_body.as_ref(),
                view,
                original_text.as_ref(),
                threshold,
                &mut sum_score,
            ) {
                return Decision::Block(Box::new(finding));
            }
            if let Some(decision) = Self::deadline_decision(
                deadline,
                "keyword:req_body",
                payload,
                Some(view),
                DeadlineMetadata::default(),
            ) {
                return decision;
            }

            match regex_match_phase_scored_threshold_deadline(
                &rules.path_regex,
                view,
                original_text.as_ref(),
                &HttpAction::Request,
                threshold,
                &mut sum_score,
                deadline.map(|d| d.expires_at),
            ) {
                RegexScanResult::Match(finding) => return Decision::Block(Box::new(finding)),
                RegexScanResult::DeadlineExceeded(rule) => {
                    return Self::deadline_block_decision(
                        deadline,
                        "regex:path_regex",
                        payload,
                        Some(view),
                        deadline_metadata_from_regex(&rule),
                    );
                }
                RegexScanResult::NoMatch => {}
            }
            match regex_match_phase_scored_threshold_deadline(
                &rules.header_regex,
                view,
                original_text.as_ref(),
                &HttpAction::Request,
                threshold,
                &mut sum_score,
                deadline.map(|d| d.expires_at),
            ) {
                RegexScanResult::Match(finding) => return Decision::Block(Box::new(finding)),
                RegexScanResult::DeadlineExceeded(rule) => {
                    return Self::deadline_block_decision(
                        deadline,
                        "regex:header_regex",
                        payload,
                        Some(view),
                        deadline_metadata_from_regex(&rule),
                    );
                }
                RegexScanResult::NoMatch => {}
            }
            match regex_match_phase_scored_threshold_deadline(
                &rules.body_regex,
                view,
                original_text.as_ref(),
                &HttpAction::Request,
                threshold,
                &mut sum_score,
                deadline.map(|d| d.expires_at),
            ) {
                RegexScanResult::Match(finding) => return Decision::Block(Box::new(finding)),
                RegexScanResult::DeadlineExceeded(rule) => {
                    return Self::deadline_block_decision(
                        deadline,
                        "regex:body_regex",
                        payload,
                        Some(view),
                        deadline_metadata_from_regex(&rule),
                    );
                }
                RegexScanResult::NoMatch => {}
            }
        }

        Decision::Allow
    }

    /// Inspect the upstream HTTP response. Only rules with `http_action: Response` fire here.
    pub fn inspect_response(&self, ctx: &ResponseContext) -> Decision {
        let snap = self.snapshot.load_full();
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
            Some(crate::cmc::CmcResponseDecision::SilentReplace { finding, body }) => {
                return Decision::SilentReplace {
                    finding: Box::new(finding),
                    body,
                };
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

    fn deadline_decision(
        deadline: Option<InspectionDeadline>,
        stage: &str,
        payload: &[u8],
        view: Option<&str>,
        metadata: DeadlineMetadata<'_>,
    ) -> Option<Decision> {
        let deadline = deadline?;
        deadline
            .expired()
            .then(|| Self::deadline_block_decision(Some(deadline), stage, payload, view, metadata))
    }

    fn deadline_block_decision(
        deadline: Option<InspectionDeadline>,
        stage: &str,
        payload: &[u8],
        view: Option<&str>,
        metadata: DeadlineMetadata<'_>,
    ) -> Decision {
        let deadline = if let Some(deadline) = deadline {
            deadline
        } else {
            tracing::error!(
                target: "krakenwaf",
                stage,
                "internal error: deadline block requested without an inspection deadline"
            );
            InspectionDeadline::new(0)
        };
        let finding = Self::deadline_finding(deadline, stage, payload, metadata);
        Self::write_filter_deadline_event(deadline, stage, payload, view, metadata, &finding);
        Decision::Block(Box::new(finding))
    }

    fn deadline_finding(
        deadline: InspectionDeadline,
        stage: &str,
        payload: &[u8],
        metadata: DeadlineMetadata<'_>,
    ) -> Finding {
        let payload_text = String::from_utf8_lossy(payload);
        let rule_match = if let Some(rule_match) = metadata.match_text {
            format!("deadline::{stage}:rule={rule_match}")
        } else {
            tracing::debug!(
                target: "krakenwaf",
                stage,
                "filter deadline finding has no rule_match metadata"
            );
            format!("deadline::{stage}")
        };
        let rule_line_match = if let Some(line) = metadata.line_match {
            format!("deadline/{line}")
        } else {
            tracing::debug!(
                target: "krakenwaf",
                stage,
                "filter deadline finding has no rule_line_match metadata"
            );
            format!("deadline/{stage}")
        };
        let rule_id = metadata.id.unwrap_or_else(|| {
            tracing::debug!(
                target: "krakenwaf",
                stage,
                "filter deadline finding has no rule_id metadata; using synthetic rule id"
            );
            "00000"
        });
        let title = metadata.title.unwrap_or_else(|| {
            tracing::debug!(
                target: "krakenwaf",
                stage,
                "filter deadline finding has no rule title metadata; using generic title"
            );
            "WAF inspection deadline exceeded"
        });
        Finding {
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            severity: Severity::High,
            cwe: "CWE-400".to_string(),
            description: format!(
                "WAF inspection exceeded the configured {}ms budget during stage '{stage}' after {}ms; request was blocked fail-closed.",
                deadline.max_ms,
                deadline.elapsed_ms()
            ),
            reference_url: "https://cwe.mitre.org/data/definitions/400.html".to_string(),
            rule_match,
            rule_line_match,
            request_payload: finding::truncate_payload(payload_text.as_ref()).into_owned(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    fn write_filter_deadline_event(
        deadline: InspectionDeadline,
        stage: &str,
        payload: &[u8],
        view: Option<&str>,
        metadata: DeadlineMetadata<'_>,
        finding: &Finding,
    ) {
        let view_sample = view.map(|value| finding::truncate_payload(value).into_owned());
        let rule_id = metadata.id.unwrap_or_else(|| {
            tracing::debug!(
                target: "krakenwaf",
                stage,
                "filter deadline log event has no rule_id metadata"
            );
            "no-rule-id"
        });
        let rule_line_match = metadata.line_match.unwrap_or_else(|| {
            tracing::debug!(
                target: "krakenwaf",
                stage,
                "filter deadline log event has no rule_line_match metadata"
            );
            "no-rule-line"
        });
        let event = serde_json::json!({
            "timestamp": finding.timestamp,
            "stage": stage,
            "budget_ms": deadline.max_ms,
            "elapsed_ms": deadline.elapsed_ms(),
            "payload_len": payload.len(),
            "view_len": view.map(str::len),
            "rule_id": metadata.id,
            "rule_title": metadata.title,
            "rule_match": metadata.match_text,
            "rule_line_match": metadata.line_match,
            "finding_title": finding.title,
            "finding_rule_match": finding.rule_match,
            "payload_sample": finding.request_payload,
            "view_sample": view_sample,
        });
        tracing::warn!(
            target: "krakenwaf",
            stage,
            budget_ms = deadline.max_ms,
            elapsed_ms = deadline.elapsed_ms(),
            rule_id,
            rule_line_match,
            "WAF inspection deadline exceeded; blocking fail-closed and recording filter deadline event"
        );
        if let Err(err) = append_filter_deadline_event(&event) {
            tracing::warn!(
                target: "krakenwaf",
                error = %err,
                path = FILTER_DEADLINE_LOG,
                "failed to write filter deadline event"
            );
        }
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
    // File-first secret (see `crate::secrets`); falls back to the
    // SPAMHAUS_DQS_KEY env var. `load_secret` already trims and rejects empty.
    let token = crate::secrets::load_secret("SPAMHAUS_DQS_KEY")?;
    Some(SpamhausDqsConfig {
        token,
        zones: normalized_dqs_zones(&config.spamhaus.zones),
        positive_ttl: Duration::from_secs(config.spamhaus.dqs_cache_ttl_secs),
        negative_ttl: Duration::from_secs(config.spamhaus.dqs_cache_negative_ttl_secs),
    })
}

fn addr_list_match<'a>(
    entries: &'a [AddrListEntry],
    client: &std::net::IpAddr,
) -> Option<&'a AddrListEntry> {
    entries.iter().find(|entry| entry.contains(client))
}

fn deadline_metadata_from_regex(rule: &RegexDeadline) -> DeadlineMetadata<'_> {
    DeadlineMetadata {
        id: Some(rule.rule_id.as_str()),
        title: Some(rule.title.as_str()),
        match_text: Some(rule.rule_match.as_str()),
        line_match: Some(rule.rule_line_match.as_str()),
    }
}

fn append_filter_deadline_event(event: &serde_json::Value) -> std::io::Result<()> {
    let path = Path::new(FILTER_DEADLINE_LOG);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{event}")
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

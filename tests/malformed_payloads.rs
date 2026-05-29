use krakenwaf::{
    cmc::{CmcConfig, CmcManagerBuilder},
    metrics::WafMetrics,
    rules::{CompiledDetectionRule, DetectionRule, HttpAction, RuleSet, Severity},
    waf::{rate_limit::{PersistenceMode, RateLimiter}, Decision, ResponseContext, WafEngineConfig, WafEngineFactory},
};
use regex::Regex;
use std::{collections::HashMap, sync::Arc};

fn empty_cmc_manager() -> Arc<krakenwaf::cmc::CmcManager> {
    Arc::new(CmcManagerBuilder::new(CmcConfig::default()).build())
}

fn make_test_rl() -> Arc<RateLimiter> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rate_limit.db");
    let rl = Arc::new(
        RateLimiter::new(60, std::time::Duration::from_mins(1), &path, PersistenceMode::Sqlite)
            .expect("rate limiter"),
    );
    drop(dir);
    rl
}

#[test]
fn blocks_malformed_traversal_payload() {
    let rules = Arc::new(RuleSet {
        blocked_ips: vec![],
        blocked_ip_prefixes: vec![],
        addr_list_entries: vec![],
        uri_keywords: vec![],
        header_keywords: vec![],
        body_keywords: vec![DetectionRule {
            id: "00001".into(),
            line: 1,
            title: "Traversal".into(),
            severity: Severity::High,
            score: 1000,
            cwe: "CWE-22".into(),
            description: "Directory traversal payload".into(),
            reference_url: "https://cwe.mitre.org/data/definitions/22.html".into(),
            rule_match: "../".into(),
            source: "rules.json:body_keywords".into(),
            http_action: HttpAction::Request,
        }],
        allowed_ips: vec![],

        allow_paths: vec![],
        body_limits: HashMap::new(),
        path_regex: vec![],
        body_regex: vec![],
        header_regex: vec![],
        vectorscan_keywords: vec![],
    });

    let engine = WafEngineFactory::create(WafEngineConfig {
        rules,
        rate_limiter: make_test_rl(),
        blocklist_ip_enabled: false,
        libinjection_sqli_enabled: false,
        libinjection_xss_enabled: false,
        vectorscan_enabled: false,
        metrics: Arc::new(WafMetrics::default()),
        cmc_manager: empty_cmc_manager(),
        anomaly_threshold: 600,
        max_inspection_ms: 0,
    })
    .expect("test");
    let decision = engine.inspect_body_chunk(br"../../../../etc/passwd");
    assert!(matches!(decision, Decision::Block(_)));
}

#[test]
fn blocks_regex_based_rce_pattern() {
    let rules = Arc::new(RuleSet {
        blocked_ips: vec![],
        blocked_ip_prefixes: vec![],
        addr_list_entries: vec![],
        uri_keywords: vec![],
        header_keywords: vec![],
        body_keywords: vec![],
        allow_paths: vec![],
        body_limits: HashMap::new(),
        allowed_ips: vec![],

        path_regex: vec![],
        body_regex: vec![CompiledDetectionRule {
            meta: DetectionRule {
                id: "00001".into(),
                line: 1,
                title: "RCE regex".into(),
                severity: Severity::Critical,
                score: 1000,
                cwe: "CWE-78".into(),
                description: "Command execution payload".into(),
                reference_url: "https://cwe.mitre.org/data/definitions/78.html".into(),
                rule_match: r"(?i)(cmd(\.exe)?\s+/c|powershell\s+-enc)".into(),
                source: "regex/body_regex.json".into(),
                http_action: HttpAction::Request,
            },
            compiled: Regex::new(r"(?i)(cmd(\.exe)?\s+/c|powershell\s+-enc)").expect("test"),
        }],
        header_regex: vec![],
        vectorscan_keywords: vec![],
    });

    let engine = WafEngineFactory::create(WafEngineConfig {
        rules,
        rate_limiter: make_test_rl(),
        blocklist_ip_enabled: false,
        libinjection_sqli_enabled: false,
        libinjection_xss_enabled: false,
        vectorscan_enabled: false,
        metrics: Arc::new(WafMetrics::default()),
        cmc_manager: empty_cmc_manager(),
        anomaly_threshold: 600,
        max_inspection_ms: 0,
    })
    .expect("test");
    let decision = engine.inspect_body_chunk(br"powershell -enc AAAA");
    assert!(matches!(decision, Decision::Block(_)));
}

#[test]
fn allows_single_low_score_regex_and_blocks_accumulated_score() {
    let low_one = CompiledDetectionRule {
        meta: DetectionRule {
            id: "score-001".into(),
            line: 1,
            title: "Low score marker one".into(),
            severity: Severity::Low,
            score: 250,
            cwe: "CWE-693".into(),
            description: "First low-score score-engine marker".into(),
            reference_url: "https://owasp.org/www-project-web-security-testing-guide/".into(),
            rule_match: "kwaf-score-low-a".into(),
            source: "regex/body_regex.json".into(),
            http_action: HttpAction::Request,
        },
        compiled: Regex::new("kwaf-score-low-a").expect("test"),
    };
    let low_two = CompiledDetectionRule {
        meta: DetectionRule {
            id: "score-002".into(),
            line: 2,
            title: "Low score marker two".into(),
            severity: Severity::Low,
            score: 250,
            cwe: "CWE-693".into(),
            description: "Second low-score score-engine marker".into(),
            reference_url: "https://owasp.org/www-project-web-security-testing-guide/".into(),
            rule_match: "kwaf-score-low-b".into(),
            source: "regex/body_regex.json".into(),
            http_action: HttpAction::Request,
        },
        compiled: Regex::new("kwaf-score-low-b").expect("test"),
    };
    let low_three = CompiledDetectionRule {
        meta: DetectionRule {
            id: "score-003".into(),
            line: 3,
            title: "Low score marker three".into(),
            severity: Severity::Low,
            score: 250,
            cwe: "CWE-693".into(),
            description: "Third low-score score-engine marker".into(),
            reference_url: "https://owasp.org/www-project-web-security-testing-guide/".into(),
            rule_match: "kwaf-score-low-c".into(),
            source: "regex/body_regex.json".into(),
            http_action: HttpAction::Request,
        },
        compiled: Regex::new("kwaf-score-low-c").expect("test"),
    };

    let engine = WafEngineFactory::create(WafEngineConfig {
        rules: Arc::new(RuleSet {
            blocked_ips: vec![],
            blocked_ip_prefixes: vec![],
            addr_list_entries: vec![],
            uri_keywords: vec![],
            header_keywords: vec![],
            body_keywords: vec![],
            allow_paths: vec![],
            body_limits: HashMap::new(),
            allowed_ips: vec![],

            path_regex: vec![],
            body_regex: vec![low_one, low_two, low_three],
            header_regex: vec![],
            vectorscan_keywords: vec![],
        }),
        rate_limiter: make_test_rl(),
        blocklist_ip_enabled: false,
        libinjection_sqli_enabled: false,
        libinjection_xss_enabled: false,
        vectorscan_enabled: false,
        metrics: Arc::new(WafMetrics::default()),
        cmc_manager: empty_cmc_manager(),
        anomaly_threshold: 600,
        max_inspection_ms: 0,
    })
    .expect("test");

    assert!(matches!(
        engine.inspect_body_chunk(b"payload_test=kwaf-score-low-a"),
        Decision::Allow | Decision::Monitor(_) | Decision::SilentReplace { .. }
    ));
    assert!(matches!(
        engine
            .inspect_body_chunk(b"payload_test=kwaf-score-low-a kwaf-score-low-b kwaf-score-low-c"),
        Decision::Block(_)
    ));

    // Regression test for finding #7: when the same three substring rules are
    // delimited by query-string separators (`&`, `;`) or newlines they must
    // still accumulate score against the full normalized payload — an attacker
    // splitting the payload across delimiters cannot keep each segment under
    // the block threshold.
    assert!(matches!(
        engine.inspect_body_chunk(b"kwaf-score-low-a&kwaf-score-low-b&kwaf-score-low-c"),
        Decision::Block(_),
    ));
    assert!(matches!(
        engine.inspect_body_chunk(b"kwaf-score-low-a;kwaf-score-low-b;kwaf-score-low-c"),
        Decision::Block(_),
    ));
    assert!(matches!(
        engine.inspect_body_chunk(b"kwaf-score-low-a\nkwaf-score-low-b\nkwaf-score-low-c"),
        Decision::Block(_),
    ));
}

#[test]
fn single_near_threshold_rule_in_full_request_is_not_double_counted_across_views() {
    // Regression test for the v2.25.0 score-accumulator double-counting bug.
    //
    // A rule scoring 599 (below the 600 default threshold) used to be wrongly
    // blocked because `inspection_views` produces both the full normalized
    // request AND each segment split on `\n`, `&`, `;`, `?`, `\r`, `\0`. The
    // shared `sum_score` carried across views accumulated the same rule hit
    // twice (599 + 599 = 1198), tripping the threshold.
    //
    // Each view must score independently; cross-segment attacks remain caught
    // by the full-payload view via `find_iter`/per-rule iteration.
    let near_threshold = CompiledDetectionRule {
        meta: DetectionRule {
            id: "score-near-001".into(),
            line: 1,
            title: "Near-threshold single rule".into(),
            severity: Severity::Low,
            score: 599,
            cwe: "CWE-693".into(),
            description: "Rule scoring just below the default block threshold (600).".into(),
            reference_url: "https://owasp.org/www-project-web-security-testing-guide/".into(),
            rule_match: "kwaf-score-near-threshold".into(),
            source: "regex/body_regex.json".into(),
            http_action: HttpAction::Request,
        },
        compiled: Regex::new("kwaf-score-near-threshold").expect("test"),
    };

    let engine = WafEngineFactory::create(WafEngineConfig {
        rules: Arc::new(RuleSet {
            blocked_ips: vec![],
            blocked_ip_prefixes: vec![],
            addr_list_entries: vec![],
            uri_keywords: vec![],
            header_keywords: vec![],
            body_keywords: vec![],
            allow_paths: vec![],
            body_limits: HashMap::new(),
            allowed_ips: vec![],

            path_regex: vec![],
            body_regex: vec![near_threshold],
            header_regex: vec![],
            vectorscan_keywords: vec![],
        }),
        rate_limiter: make_test_rl(),
        blocklist_ip_enabled: false,
        libinjection_sqli_enabled: false,
        libinjection_xss_enabled: false,
        vectorscan_enabled: false,
        metrics: Arc::new(WafMetrics::default()),
        cmc_manager: empty_cmc_manager(),
        anomaly_threshold: 600,
        max_inspection_ms: 0,
    })
    .expect("test");

    // The full request mimics what the proxy assembles: HTTP request line,
    // headers, blank line, body. The rule literal appears once inside the
    // form body. Score is 599 — strictly below the 600 threshold — so the
    // decision MUST be Allow / Monitor / SilentReplace, never Block.
    let full_request: &[u8] =
        b"POST /test_post HTTP/1.1\nhost: 127.0.0.1\ncontent-type: application/x-www-form-urlencoded\ncontent-length: 38\n\npayload_test=kwaf-score-near-threshold";
    assert!(
        matches!(
            engine.inspect_complete_payload(full_request),
            Decision::Allow | Decision::Monitor(_) | Decision::SilentReplace { .. }
        ),
        "single rule scoring 599 must not be double-counted across inspection views"
    );
}

#[test]
fn blocks_response_when_accumulated_regex_score_reaches_threshold() {
    let response_rules = [
        "kwaf-score-response-a",
        "kwaf-score-response-b",
        "kwaf-score-response-c",
    ]
    .into_iter()
    .enumerate()
    .map(|(idx, marker)| CompiledDetectionRule {
        meta: DetectionRule {
            id: format!("score-response-{}", idx + 1),
            line: idx + 1,
            title: format!("Response score marker {}", idx + 1),
            severity: Severity::Low,
            score: 200,
            cwe: "CWE-693".into(),
            description: "Low-score response score-engine marker".into(),
            reference_url: "https://owasp.org/www-project-web-security-testing-guide/".into(),
            rule_match: marker.into(),
            source: "regex/body_regex.json".into(),
            http_action: HttpAction::Response,
        },
        compiled: Regex::new(marker).expect("test"),
    })
    .collect::<Vec<_>>();

    let engine = WafEngineFactory::create(WafEngineConfig {
        rules: Arc::new(RuleSet {
            blocked_ips: vec![],
            blocked_ip_prefixes: vec![],
            addr_list_entries: vec![],
            uri_keywords: vec![],
            header_keywords: vec![],
            body_keywords: vec![],
            allow_paths: vec![],
            body_limits: HashMap::new(),
            allowed_ips: vec![],

            path_regex: vec![],
            body_regex: response_rules,
            header_regex: vec![],
            vectorscan_keywords: vec![],
        }),
        rate_limiter: make_test_rl(),
        blocklist_ip_enabled: false,
        libinjection_sqli_enabled: false,
        libinjection_xss_enabled: false,
        vectorscan_enabled: false,
        metrics: Arc::new(WafMetrics::default()),
        cmc_manager: empty_cmc_manager(),
        anomaly_threshold: 600,
        max_inspection_ms: 0,
    })
    .expect("test");

    let ctx = ResponseContext {
        status: 200,
        headers: "content-type: text/html".into(),
        body: bytes::Bytes::from_static(
            b"kwaf-score-response-a kwaf-score-response-b kwaf-score-response-c",
        ),
    };

    assert!(matches!(engine.inspect_response(&ctx), Decision::Block(_)));
}

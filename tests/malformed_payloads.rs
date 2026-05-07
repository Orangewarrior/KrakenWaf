use krakenwaf::{
    dfa::{DfaConfig, DfaManagerBuilder},
    metrics::WafMetrics,
    rules::{CompiledDetectionRule, DetectionRule, HttpAction, RuleSet, Severity},
    waf::{Decision, ResponseContext, WafEngine},
};
use regex::Regex;
use std::{collections::HashMap, sync::Arc};

fn empty_dfa_manager() -> Arc<krakenwaf::dfa::DfaManager> {
    Arc::new(DfaManagerBuilder::new(DfaConfig::default()).build())
}

#[test]
fn blocks_malformed_traversal_payload() {
    let rules = Arc::new(RuleSet {
        blocked_ips: vec![],
        blocked_ip_prefixes: vec![],
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
        scanner_agents: vec![],
        allow_paths: vec![],
        body_limits: HashMap::new(),
        path_regex: vec![],
        body_regex: vec![],
        header_regex: vec![],
        vectorscan_keywords: vec![],
    });

    let engine = WafEngine::new(
        rules,
        60,
        false,
        false,
        false,
        false,
        tempfile::tempdir().unwrap().path().join("rate_limit.json"),
        Arc::new(WafMetrics::default()),
        empty_dfa_manager(),
    )
    .unwrap();
    let decision = engine.inspect_body_chunk(br"../../../../etc/passwd");
    assert!(matches!(decision, Decision::Block(_)));
}

#[test]
fn blocks_regex_based_rce_pattern() {
    let rules = Arc::new(RuleSet {
        blocked_ips: vec![],
        blocked_ip_prefixes: vec![],
        uri_keywords: vec![],
        header_keywords: vec![],
        body_keywords: vec![],
        allow_paths: vec![],
        body_limits: HashMap::new(),
        allowed_ips: vec![],
        scanner_agents: vec![],
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
            compiled: Regex::new(r"(?i)(cmd(\.exe)?\s+/c|powershell\s+-enc)").unwrap(),
        }],
        header_regex: vec![],
        vectorscan_keywords: vec![],
    });

    let engine = WafEngine::new(
        rules,
        60,
        false,
        false,
        false,
        false,
        tempfile::tempdir().unwrap().path().join("rate_limit.json"),
        Arc::new(WafMetrics::default()),
        empty_dfa_manager(),
    )
    .unwrap();
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
        compiled: Regex::new("kwaf-score-low-a").unwrap(),
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
        compiled: Regex::new("kwaf-score-low-b").unwrap(),
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
        compiled: Regex::new("kwaf-score-low-c").unwrap(),
    };

    let engine = WafEngine::new(
        Arc::new(RuleSet {
            blocked_ips: vec![],
            blocked_ip_prefixes: vec![],
            uri_keywords: vec![],
            header_keywords: vec![],
            body_keywords: vec![],
            allow_paths: vec![],
            body_limits: HashMap::new(),
            allowed_ips: vec![],
            scanner_agents: vec![],
            path_regex: vec![],
            body_regex: vec![low_one, low_two, low_three],
            header_regex: vec![],
            vectorscan_keywords: vec![],
        }),
        60,
        false,
        false,
        false,
        false,
        tempfile::tempdir().unwrap().path().join("rate_limit.json"),
        Arc::new(WafMetrics::default()),
        empty_dfa_manager(),
    )
    .unwrap();

    assert!(matches!(
        engine.inspect_body_chunk(b"payload_test=kwaf-score-low-a"),
        Decision::Allow
    ));
    assert!(matches!(
        engine
            .inspect_body_chunk(b"payload_test=kwaf-score-low-a kwaf-score-low-b kwaf-score-low-c"),
        Decision::Block(_)
    ));
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
        compiled: Regex::new(marker).unwrap(),
    })
    .collect::<Vec<_>>();

    let engine = WafEngine::new(
        Arc::new(RuleSet {
            blocked_ips: vec![],
            blocked_ip_prefixes: vec![],
            uri_keywords: vec![],
            header_keywords: vec![],
            body_keywords: vec![],
            allow_paths: vec![],
            body_limits: HashMap::new(),
            allowed_ips: vec![],
            scanner_agents: vec![],
            path_regex: vec![],
            body_regex: response_rules,
            header_regex: vec![],
            vectorscan_keywords: vec![],
        }),
        60,
        false,
        false,
        false,
        false,
        tempfile::tempdir().unwrap().path().join("rate_limit.json"),
        Arc::new(WafMetrics::default()),
        empty_dfa_manager(),
    )
    .unwrap();

    let ctx = ResponseContext {
        status: 200,
        headers: "content-type: text/html".into(),
        body: bytes::Bytes::from_static(
            b"kwaf-score-response-a kwaf-score-response-b kwaf-score-response-c",
        ),
    };

    assert!(matches!(engine.inspect_response(&ctx), Decision::Block(_)));
}

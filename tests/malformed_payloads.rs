
use krakenwaf::{
    metrics::WafMetrics,
    rules::{CompiledDetectionRule, DetectionRule, RuleSet, Severity},
    waf::{Decision, WafEngine},
};
use regex::Regex;
use std::{collections::HashMap, sync::Arc};

#[test]
fn blocks_malformed_traversal_payload() {
    let rules = Arc::new(RuleSet {
        blocked_ips: vec![],
        blocked_ip_prefixes: vec![],
        uri_keywords: vec![],
        header_keywords: vec![],
        body_keywords: vec![DetectionRule {
            line: 1,
            title: "Traversal".into(),
            severity: Severity::High,
            cwe: "CWE-22".into(),
            description: "Directory traversal payload".into(),
            reference_url: "https://cwe.mitre.org/data/definitions/22.html".into(),
            rule_match: "../".into(),
            source: "rules.json:body_keywords".into(),
        }],
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
        tempfile::tempdir().unwrap().path().join("rate_limit.json"),
        Arc::new(WafMetrics::default()),
    ).unwrap();
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
        path_regex: vec![],
        body_regex: vec![CompiledDetectionRule {
            meta: DetectionRule {
                line: 1,
                title: "RCE regex".into(),
                severity: Severity::Critical,
                cwe: "CWE-78".into(),
                description: "Command execution payload".into(),
                reference_url: "https://cwe.mitre.org/data/definitions/78.html".into(),
                rule_match: r"(?i)(cmd(\.exe)?\s+/c|powershell\s+-enc)".into(),
                source: "regex/body_regex.json".into(),
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
        tempfile::tempdir().unwrap().path().join("rate_limit.json"),
        Arc::new(WafMetrics::default()),
    ).unwrap();
    let decision = engine.inspect_body_chunk(br"powershell -enc AAAA");
    assert!(matches!(decision, Decision::Block(_)));
}

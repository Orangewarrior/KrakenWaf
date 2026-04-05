use krakenwaf::{
    metrics::WafMetrics,
    rules::RuleSet,
    waf::{Decision, InspectionContext, WafEngine},
};
use std::{sync::Arc, path::Path};

fn build_engine(vectorscan_enabled: bool) -> WafEngine {
    let rules = Arc::new(RuleSet::from_dir(Path::new("./rules")).expect("load bundled rules"));
    WafEngine::new(
        rules,
        240,
        false,
        false,
        vectorscan_enabled,
        tempfile::tempdir().unwrap().path().join("rate_limit.json"),
        Arc::new(WafMetrics::default()),
    )
    .expect("engine")
}

#[tokio::test]
async fn blocks_common_dvwa_get_sqli_probe() {
    let engine = build_engine(false);
    let ctx = InspectionContext {
        client_ip: "203.0.113.10".into(),
        method: "GET".into(),
        uri: "/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201,2&Submit=Submit".into(),
        path: "/vulnerabilities/sqli/".into(),
        headers: "host: localhost\nuser-agent: curl/8.0".into(),
        body_limit: 1024 * 1024,
    };

    assert!(matches!(engine.inspect_early(&ctx).await, Decision::Block(_)));
}

#[test]
fn blocks_common_dvwa_post_xss_probe() {
    let engine = build_engine(false);
    let body = br"txtName=%3Cscript%3Ealert(1)%3C%2Fscript%3E&mtxMessage=owned";
    assert!(matches!(engine.inspect_complete_payload(body), Decision::Block(_)));
}

#[test]
fn blocks_common_dvwa_post_sqli_probe() {
    let engine = build_engine(false);
    let body = br"username=admin%27%20OR%20%271%27%3D%271&password=pw&Login=Login";
    assert!(matches!(engine.inspect_complete_payload(body), Decision::Block(_)));
}

#[cfg(feature = "vectorscan-engine")]
#[test]
fn vectorscan_engine_blocks_fast_literals() {
    let engine = build_engine(true);
    let body = br"username=admin' or '1'='1&cmd=cmd.exe /c calc";
    assert!(matches!(engine.inspect_complete_payload(body), Decision::Block(_)));
}

#[cfg(feature = "vectorscan-engine")]
#[test]
fn vectorscan_engine_blocks_form_urlencoded_plus_payloads() {
    let engine = build_engine(true);
    let body = br"txtName=union+select&mtxMessage=hello+world";
    assert!(matches!(engine.inspect_complete_payload(body), Decision::Block(_)));
}

#[cfg(feature = "vectorscan-engine")]
#[test]
fn vectorscan_engine_blocks_long_post_payload_beyond_old_overlap_window() {
    let engine = build_engine(true);
    let long_prefix = "a".repeat(5000);
    let body = format!("txtName=test&mtxMessage={}union+select", long_prefix);
    assert!(matches!(engine.inspect_complete_payload(body.as_bytes()), Decision::Block(_)));
}


#[test]
fn blocks_common_dvwa_get_sqli_probe_via_full_payload() {
    let engine = build_engine(false);
    let query = br"id=1%27%20UNION%20SELECT%201,2&Submit=Submit";
    assert!(matches!(engine.inspect_complete_payload(query), Decision::Block(_)));
}

#[test]
fn lowercases_before_matching_post_payloads() {
    let engine = build_engine(false);
    let body = br"txtName=%3CSCRIPT%3Ealert(1)%3C%2FSCRIPT%3E&mtxMessage=owned";
    assert!(matches!(engine.inspect_complete_payload(body), Decision::Block(_)));
}


use krakenwaf::rules::{RuleSet, Severity};
use std::fs;

#[test]
fn loads_external_rule_tree() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("regex")).unwrap();
    fs::create_dir_all(tmp.path().join("Vectorscan")).unwrap();
    fs::write(
        tmp.path().join("rules.json"),
        r#"{
            "blocked_ip_prefixes": ["10.10.10."],
            "uri_keywords": [
                {"title":"SQLi URI","severity":"critical","cwe":"CWE-89","description":"URI SQLi probe","url":"https://cwe.mitre.org/data/definitions/89.html","rule_match":"union select"}
            ],
            "header_keywords": [
                {"title":"Scanner UA","severity":"medium","cwe":"CWE-113","description":"Scanner header detected","url":"https://owasp.org","rule_match":"sqlmap"}
            ],
            "body_keywords": [
                {"title":"Traversal","severity":"high","cwe":"CWE-22","description":"Traversal payload","url":"https://cwe.mitre.org/data/definitions/22.html","rule_match":"../"}
            ],
            "allow_paths": ["/health"],
            "body_limits": {"/upload": 2048}
        }"#,
    ).unwrap();
    fs::write(tmp.path().join("blocklist_ip.txt"), "203.0.113.10
").unwrap();
    fs::write(
        tmp.path().join("regex/path_regex.json"),
        r#"{"rules":[{"title":"Admin path","severity":"high","cwe":"CWE-306","description":"Admin path hit","url":"https://cwe.mitre.org/data/definitions/306.html","rule_match":"(?i)/admin"}]}"#,
    ).unwrap();
    fs::write(
        tmp.path().join("regex/body_regex.json"),
        r#"{"rules":[{"title":"RCE regex","severity":"critical","cwe":"CWE-78","description":"Command execution payload","url":"https://cwe.mitre.org/data/definitions/78.html","rule_match":"(?i)powershell\s+-enc"}]}"#,
    ).unwrap();
    fs::write(
        tmp.path().join("regex/header_regex.json"),
        r#"{"rules":[{"title":"Scanner header regex","severity":"medium","cwe":"CWE-113","description":"Scanner header regex","url":"https://owasp.org","rule_match":"(?i)sqlmap"}]}"#,
    ).unwrap();
    fs::write(
        tmp.path().join("Vectorscan/strings2block.json"),
        r#"{"rules":[{"title":"Vectorscan cmd","severity":"critical","cwe":"CWE-78","description":"Command invocation","url":"https://cwe.mitre.org/data/definitions/78.html","rule_match":"cmd.exe"}]}"#,
    ).unwrap();

    let rules = RuleSet::from_dir(tmp.path()).unwrap();
    assert_eq!(rules.blocked_ips, vec!["203.0.113.10"]);
    assert_eq!(rules.uri_keywords.len(), 1);
    assert_eq!(rules.uri_keywords[0].severity, Severity::Critical);
    assert_eq!(rules.header_keywords.len(), 1);
    assert_eq!(rules.body_keywords.len(), 1);
    assert_eq!(rules.body_limit_for_path("/upload/file"), 2048);
    assert!(!rules.is_allowlisted("/health/../../admin"));
    assert_eq!(rules.vectorscan_keywords[0].rule_match, "cmd.exe");
}

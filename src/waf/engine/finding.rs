use std::borrow::Cow;

use chrono::Utc;

use crate::rules::{DetectionRule, Severity};

/// Normalised structured detection finding produced by the WAF engine.
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

pub(super) fn rule_to_finding(rule: &DetectionRule, haystack: &str) -> Finding {
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

pub(super) fn truncate_payload(value: &str) -> Cow<'_, str> {
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

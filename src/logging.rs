use crate::{
    rules::Severity,
    waf::{Finding, InspectionContext},
};
use anyhow::Result;
use serde::Serialize;
use std::{fs, io::Write as _, path::Path};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[allow(dead_code)]
pub struct LoggingHandles {
    pub raw_guard: WorkerGuard,
    pub json_guard: WorkerGuard,
    pub critical_writer: NonBlocking,
    pub critical_guard: WorkerGuard,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub request_id: String,
    pub client_ip: String,
    pub country: String,
    pub continent_name: String,
    pub method: String,
    pub uri: String,
    pub fullpath_evidence: String,
    pub engine: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub cwe: String,
    pub description: String,
    pub reference_url: String,
    pub rule_match: String,
    pub rule_line_match: String,
    #[serde(skip_serializing)]
    pub request_payload: String,
}

impl SecurityEvent {
    #[must_use]
    pub fn from_finding(
        finding: &Finding,
        ctx: &InspectionContext,
        request_payload: String,
    ) -> Self {
        Self {
            timestamp: finding.timestamp.clone(),
            request_id: ctx.request_id.clone(),
            client_ip: sanitize_for_log(&ctx.client_ip),
            country: sanitize_for_log(&ctx.country),
            continent_name: sanitize_for_log(&ctx.continent_name),
            method: sanitize_for_log(&ctx.method),
            uri: sanitize_for_log(&ctx.uri),
            fullpath_evidence: sanitize_for_log(&ctx.uri),
            engine: derive_engine_label(finding),
            rule_id: finding.rule_id.clone(),
            title: sanitize_for_log(&finding.title),
            severity: finding.severity.clone(),
            cwe: sanitize_for_log(&finding.cwe),
            description: sanitize_for_log(&finding.description),
            reference_url: sanitize_for_log(&finding.reference_url),
            rule_match: sanitize_for_log(&finding.rule_match),
            rule_line_match: sanitize_for_log(&finding.rule_line_match),
            request_payload,
        }
    }
}

/// # Errors
/// Returns an error if log directories cannot be created or file appenders fail to initialize.
pub fn init_logging(root: &Path, verbose: bool) -> Result<LoggingHandles> {
    fs::create_dir_all(root.join("logs/json"))?;
    fs::create_dir_all(root.join("logs/raw"))?;
    fs::create_dir_all(root.join("logs/db"))?;

    let raw_appender = tracing_appender::rolling::daily(root.join("logs"), "krakenwaf.log");
    let json_appender = tracing_appender::rolling::daily(root.join("logs/json"), "krakenwaf.jsonl");
    let critical_appender = tracing_appender::rolling::daily(root.join("logs/raw"), "critical.log");

    let (raw_writer, raw_guard) = tracing_appender::non_blocking(raw_appender);
    let (json_writer, json_guard) = tracing_appender::non_blocking(json_appender);
    let (critical_writer, critical_guard) = tracing_appender::non_blocking(critical_appender);

    let filter = if verbose {
        EnvFilter::new("info,krakenwaf=debug,hyper_util=warn")
    } else {
        EnvFilter::new("info,hyper_util=warn")
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_writer(raw_writer)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true),
        )
        .with(
            fmt::layer()
                .json()
                .with_writer(json_writer)
                .with_current_span(true)
                .with_span_list(false),
        )
        .init();

    Ok(LoggingHandles {
        raw_guard,
        json_guard,
        critical_writer,
        critical_guard,
    })
}

#[must_use]
pub fn sanitize_for_log(s: &str) -> String {
    // Strip control characters (except the three we translate), then escape
    // characters that could break the key="value" format used by write_critical:
    // a raw `"` would terminate the quoted field and inject new key=value pairs.
    s.chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\r' | '\t'))
        .collect::<String>()
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
        .replace('"', "\\\"")
}

pub fn write_critical(handles: &LoggingHandles, event: &SecurityEvent) {
    // Values are quoted so a payload containing ` injected=field` cannot forge
    // additional key=value pairs. sanitize_for_log() also escapes inner `"`.
    let line = format!(
        "[{}] request_id=\"{}\" severity=\"{}\" engine=\"{}\" rule_id=\"{}\" title=\"{}\" ip=\"{}\" country=\"{}\" continent=\"{}\" method=\"{}\" uri=\"{}\" fullpath_evidence=\"{}\" rule=\"{}\" source=\"{}\" cwe=\"{}\" reference_url=\"{}\"\n",
        event.timestamp,
        event.request_id,
        event.severity,
        event.engine,
        event.rule_id,
        event.title,
        event.client_ip,
        event.country,
        event.continent_name,
        event.method,
        event.uri,
        event.fullpath_evidence,
        event.rule_match,
        event.rule_line_match,
        event.cwe,
        event.reference_url,
    );
    if let Err(err) =
        std::io::Write::write_all(&mut handles.critical_writer.clone(), line.as_bytes())
    {
        // Avoid routing through tracing here (would recurse into write_critical).
        let _ = writeln!(
            std::io::stderr(),
            "krakenwaf: critical log write failed: {err}"
        );
    }
}

/// Engine label stored in the structured logs / `SQLite` rows and consumed by
/// the per-module Prometheus counter.
///
/// Custom regex rules (`rules/regex/*.json`) are not CMC modules, so the bare
/// `"regex"` engine used to surface as `unknown:regex` in the per-module
/// breakdown — leaving the operator blind to which rule actually fired. For
/// those rules the label embeds the `title` and `id` fields from the rule
/// JSON: `"<title>, ID <id>:Regex rule"`, e.g.
/// `"Shell downloader body, ID 00003:Regex rule"`.
fn derive_engine_label(finding: &Finding) -> String {
    let engine = infer_engine(&finding.rule_line_match, &finding.rule_match);
    if engine == "regex" {
        format!(
            "{}, ID {}:Regex rule",
            sanitize_for_log(&finding.title),
            sanitize_for_log(&finding.rule_id)
        )
    } else {
        engine
    }
}

fn infer_engine(rule_line_match: &str, rule_match: &str) -> String {
    if rule_match.starts_with("libinjection::") {
        "libinjection".to_string()
    } else if rule_line_match.starts_with("Vectorscan/") {
        "vectorscan".to_string()
    } else if rule_line_match.starts_with("regex/") {
        "regex".to_string()
    } else if rule_line_match.starts_with("cmc/") || rule_match.starts_with("cmc::") {
        "cmc".to_string()
    } else {
        "keyword".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_engine_label, SecurityEvent};
    use crate::rules::Severity;
    use crate::waf::{Finding, InspectionContext};

    fn finding(rule_id: &str, title: &str, rule_line_match: &str, rule_match: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            severity: Severity::High,
            cwe: "CWE-78".to_string(),
            description: "test".to_string(),
            reference_url: "https://example.com".to_string(),
            rule_match: rule_match.to_string(),
            rule_line_match: rule_line_match.to_string(),
            request_payload: "payload".to_string(),
            timestamp: "2026-06-12T00:00:00+00:00".to_string(),
        }
    }

    fn ctx() -> InspectionContext {
        InspectionContext {
            client_ip: "203.0.113.7".to_string(),
            method: "POST".to_string(),
            uri: "/upload".to_string(),
            path: "/upload".to_string(),
            headers: String::new(),
            body_limit: 0,
            request_id: "abc123".to_string(),
            country: String::new(),
            continent_name: String::new(),
        }
    }

    /// A custom regex rule must carry its title and ID in the engine label
    /// instead of the blind `regex` (rendered as `unknown:regex` in metrics).
    #[test]
    fn regex_rule_engine_label_embeds_title_and_id() {
        let f = finding(
            "00003",
            "Shell downloader body",
            "regex/body_regex.json:12",
            r"(?i)wget\s+https?://",
        );
        assert_eq!(
            derive_engine_label(&f),
            "Shell downloader body, ID 00003:Regex rule"
        );

        let event = SecurityEvent::from_finding(&f, &ctx(), "payload".to_string());
        assert_eq!(event.engine, "Shell downloader body, ID 00003:Regex rule");
    }

    /// Non-regex engines keep their short labels.
    #[test]
    fn non_regex_engines_keep_short_labels() {
        let cmc = finding("cmc-1", "SQLi comments", "cmc/sqli", "cmc::sqli_comments_detect:x");
        assert_eq!(derive_engine_label(&cmc), "cmc");

        let libinj = finding("li-1", "SQLi", "body", "libinjection::sqli:s&1c");
        assert_eq!(derive_engine_label(&libinj), "libinjection");

        let vector = finding("vs-1", "Bad string", "Vectorscan/strings2block.json:3", "evil");
        assert_eq!(derive_engine_label(&vector), "vectorscan");

        let keyword = finding("kw-1", "URI keyword", "rules.json:uri_keywords:2", "evil");
        assert_eq!(derive_engine_label(&keyword), "keyword");
    }

    /// Title/ID coming from rule files are sanitized so a crafted rule file
    /// cannot inject log fields or break the Prometheus exposition format.
    #[test]
    fn regex_rule_engine_label_is_sanitized() {
        let f = finding(
            "00\n42",
            "bad\"title",
            "regex/header_regex.json:1",
            "x",
        );
        assert_eq!(derive_engine_label(&f), "bad\\\"title, ID 00\\n42:Regex rule");
    }
}

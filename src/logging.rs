use crate::{rules::Severity, waf::{Finding, InspectionContext}};
use anyhow::Result;
use serde::Serialize;
use std::{fs, path::Path};
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
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub fullpath_evidence: String,
    pub engine: String,
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
    pub fn from_finding(finding: &Finding, ctx: &InspectionContext, request_payload: String) -> Self {
        Self {
            timestamp: finding.timestamp.clone(),
            client_ip: sanitize_for_log(&ctx.client_ip),
            method: sanitize_for_log(&ctx.method),
            uri: sanitize_for_log(&ctx.uri),
            fullpath_evidence: sanitize_for_log(&ctx.uri),
            engine: infer_engine(&finding.rule_line_match, &finding.rule_match),
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
        EnvFilter::new("info,krakenwaf=debug,hyper_util=warn,reqwest=warn")
    } else {
        EnvFilter::new("info,hyper_util=warn,reqwest=warn")
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

    Ok(LoggingHandles { raw_guard, json_guard, critical_writer, critical_guard })
}

pub fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\r' | '\t'))
        .collect::<String>()
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}


pub fn write_critical(handles: &LoggingHandles, event: &SecurityEvent) {
    let line = format!(
        "[{}] severity={} engine={} title={} ip={} method={} uri={} fullpath_evidence={} rule={} source={} cwe={} reference_url={}\n",
        event.timestamp,
        event.severity,
        event.engine,
        event.title,
        event.client_ip,
        event.method,
        event.uri,
        event.fullpath_evidence,
        event.rule_match,
        event.rule_line_match,
        event.cwe,
        event.reference_url,
    );
    let _ = std::io::Write::write_all(&mut handles.critical_writer.clone(), line.as_bytes());
}

fn infer_engine(rule_line_match: &str, rule_match: &str) -> String {
    if rule_match.starts_with("libinjection::") {
        "libinjection".to_string()
    } else if rule_line_match.starts_with("Vectorscan/") {
        "vectorscan".to_string()
    } else if rule_line_match.starts_with("regex/") {
        "regex".to_string()
    } else if rule_line_match.starts_with("dfa/") || rule_match.starts_with("dfa::") {
        "dfa".to_string()
    } else {
        "keyword".to_string()
    }
}

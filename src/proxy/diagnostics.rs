//! Developer and critical proxy diagnostics persisted as JSONL.
//!
//! Two sinks:
//! * `logs/proxy_errors_dev/proxy_errors.jsonl` — noisier developer events,
//!   gated behind `--debug-proxy-dev` (unless flagged `always_save`).
//! * `logs/proxy/critical.jsonl` — failures that produced an error response to
//!   the client; always persisted so they remain auditable even if the tracing
//!   sink is unavailable.

use chrono::Utc;
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
};
use tracing::warn;

const PROXY_ERROR_DEV_LOG: &str = "logs/proxy_errors_dev/proxy_errors.jsonl";
const PROXY_CRITICAL_LOG: &str = "logs/proxy/critical.jsonl";

#[track_caller]
pub(crate) fn write_proxy_error_dev(
    debug_proxy_dev: bool,
    always_save: bool,
    function: &str,
    code: &str,
    message: &str,
    fields: &serde_json::Value,
) {
    let severity = if always_save { "critical" } else { "diagnostic" };
    if !debug_proxy_dev && !always_save {
        tracing::debug!(
            target: "krakenwaf",
            function,
            code,
            message,
            "diagnostic proxy dev event suppressed; enable debug-proxy-dev to persist it"
        );
        return;
    }

    let location = std::panic::Location::caller();
    let event = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "severity": severity,
        "debug_proxy_dev": debug_proxy_dev,
        "function": function,
        "file": location.file(),
        "line": location.line(),
        "code": code,
        "message": message,
        "fields": fields,
    });
    if let Err(err) = append_proxy_error_dev_event(&event) {
        warn!(
            target: "krakenwaf",
            error = %err,
            path = PROXY_ERROR_DEV_LOG,
            function,
            code,
            "failed to write proxy error dev event"
        );
    }
}

fn append_proxy_error_dev_event(event: &serde_json::Value) -> std::io::Result<()> {
    let path = Path::new(PROXY_ERROR_DEV_LOG);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{event}")
}

/// Persist a critical proxy event to `logs/proxy/critical.jsonl`, creating the
/// directory if it does not exist. Unlike [`write_proxy_error_dev`] (which is
/// gated behind `--debug-proxy-dev`), these events are always persisted: they
/// represent failures that produced an error response to the client (upstream
/// failure, un-inspectable body) and must be auditable even if the tracing sink
/// is unavailable.
pub(crate) fn write_proxy_critical(
    function: &str,
    code: &str,
    message: &str,
    fields: &serde_json::Value,
) {
    let event = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "severity": "critical",
        "component": "proxy",
        "function": function,
        "code": code,
        "message": message,
        "fields": fields,
    });
    let path = Path::new(PROXY_CRITICAL_LOG);
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{event}")
    })();
    if let Err(err) = result {
        warn!(
            target: "krakenwaf",
            error = %err,
            path = PROXY_CRITICAL_LOG,
            function,
            code,
            "failed to persist critical proxy event"
        );
    }
}

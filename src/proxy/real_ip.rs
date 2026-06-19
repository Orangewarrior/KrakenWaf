use crate::app::AppState;
use chrono::Utc;
use http::HeaderMap;
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    net::IpAddr,
    path::Path,
};
use tracing::warn;

const PROXY_ERROR_DEV_LOG: &str = "logs/proxy_errors_dev/proxy_errors.jsonl";

fn header_value_case_insensitive(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.as_str().eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.to_str().ok())
        .map(str::to_owned)
}

#[track_caller]
fn write_proxy_error_dev(
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
    if let Err(error) = append_proxy_error_dev_event(&event) {
        warn!(
            target: "krakenwaf",
            %error,
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

/// Return the rightmost RFC 7239 `for=` address that is not a trusted proxy.
fn forwarded_header_real_ip(
    headers: &HeaderMap,
    trusted: &[ipnet::IpNet],
    debug_proxy_dev: bool,
) -> Option<String> {
    let raw = header_value_case_insensitive(headers, "forwarded")?;
    let elements: Vec<&str> = raw.split(',').collect();
    for element in elements.iter().rev() {
        for pair in element.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else { continue };
            if !name.eq_ignore_ascii_case("for") {
                continue;
            }
            let stripped = value.trim().trim_matches('"');
            let host_only = if let Some(rest) = stripped.strip_prefix('[') {
                let Some((host, _suffix)) = rest.split_once(']') else {
                    write_proxy_error_dev(
                        debug_proxy_dev,
                        false,
                        "forwarded_header_real_ip",
                        "malformed_forwarded_ipv6",
                        "Forwarded for= value starts with '[' but has no closing ']'",
                        &serde_json::json!({
                            "raw_header": raw,
                            "element": element,
                            "value": stripped,
                        }),
                    );
                    continue;
                };
                host
            } else if stripped.matches(':').count() == 1 {
                stripped.split_once(':').map_or(stripped, |(host, _)| host)
            } else {
                stripped
            };
            let Ok(parsed) = host_only.parse::<IpAddr>() else {
                if !host_only.starts_with('_') {
                    write_proxy_error_dev(
                        debug_proxy_dev,
                        false,
                        "forwarded_header_real_ip",
                        "invalid_forwarded_for_ip",
                        "Forwarded for= value could not be parsed as an IP address",
                        &serde_json::json!({
                            "raw_header": raw,
                            "element": element,
                            "value": stripped,
                            "host_only": host_only,
                        }),
                    );
                }
                continue;
            };
            if !trusted.iter().any(|network| network.contains(&parsed)) {
                return Some(parsed.to_string());
            }
        }
    }
    None
}

pub(crate) fn effective_client_ip(
    peer_ip: &str,
    headers: &HeaderMap,
    state: &AppState,
) -> String {
    let Ok(peer) = peer_ip.parse::<IpAddr>() else {
        return peer_ip.to_string();
    };
    let trusted_nets = state.trusted_proxy_nets.as_slice();
    if !trusted_nets.iter().any(|network| network.contains(&peer)) {
        return peer.to_string();
    }

    if let Some(ip) = forwarded_header_real_ip(headers, trusted_nets, state.cli.debug_proxy_dev) {
        return ip;
    }

    let header_name = match state.cli.real_ip_header.as_deref() {
        Some(name) if !name.trim().is_empty() => name.trim(),
        _ => "x-real-ip",
    };
    let Some(raw) = header_value_case_insensitive(headers, header_name) else {
        return peer.to_string();
    };
    let candidate = if header_name.eq_ignore_ascii_case("x-forwarded-for") {
        raw.split(',')
            .rev()
            .map(str::trim)
            .find(|value| {
                !value.parse::<IpAddr>().ok().is_some_and(|ip| {
                    trusted_nets.iter().any(|network| network.contains(&ip))
                })
            })
            .unwrap_or(peer_ip)
            .to_string()
    } else {
        raw.trim().to_string()
    };
    candidate
        .parse::<IpAddr>()
        .map_or_else(|_| peer.to_string(), |ip| ip.to_string())
}

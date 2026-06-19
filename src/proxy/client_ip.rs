//! Client-IP resolution and trusted-proxy handling.
//!
//! Resolves the effective client IP honouring RFC 7239 `Forwarded:`,
//! `X-Forwarded-For` (rightmost-trusted), and `X-Real-IP`, but only when the TCP
//! peer falls inside a configured trusted-proxy CIDR. Also hosts the
//! startup-time trusted-proxy CIDR parser and the W3C traceparent builder.

use anyhow::{Context, Result};
use http::HeaderMap;
use uuid::Uuid;

use crate::app::AppState;
use crate::metrics::WafMetrics;

use super::diagnostics::write_proxy_error_dev;

/// Parse a single `--trusted-proxy-cidrs` / `proxy.yaml` entry. Accepts either
/// CIDR notation (`10.0.0.0/8`, `2001:db8::/32`) or a bare IP literal
/// (`192.0.2.1`, treated as a `/32`; `2001:db8::1` as a `/128`). Surrounding
/// whitespace is trimmed.
///
/// # Errors
/// Returns an error when `entry` is neither a valid IP nor a valid CIDR.
pub fn parse_trusted_proxy_cidr(entry: &str) -> Result<ipnet::IpNet> {
    let trimmed = entry.trim();
    if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
        return Ok(net);
    }
    let ip = trimmed.parse::<std::net::IpAddr>().map_err(|_| {
        anyhow::anyhow!(
            "'{entry}' is not a valid IP address or CIDR (e.g. 10.0.0.0/8 or 192.0.2.1)"
        )
    })?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    ipnet::IpNet::new(ip, prefix)
        .with_context(|| format!("failed to build a host network for '{entry}'"))
}

/// Parse every trusted-proxy entry once, failing on the first malformed value.
/// Empty entries are skipped. Done eagerly at startup so a typo fails fast
/// instead of being silently dropped on every request — a dropped entry would
/// make the proxy's own IP look like the client and break rate-limit, ban, and
/// blocklist keying.
///
/// # Errors
/// Returns an error if any entry is neither a valid IP nor a valid CIDR.
pub fn parse_trusted_proxy_cidrs(entries: &[String]) -> Result<Vec<ipnet::IpNet>> {
    entries
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(parse_trusted_proxy_cidr)
        .collect()
}

pub(crate) fn host_port(host: &str) -> Option<u16> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (_, port) = rest.rsplit_once("]:")?;
        return port.parse().ok();
    }
    let (_, port) = trimmed.rsplit_once(':')?;
    port.parse().ok()
}

fn header_value_case_insensitive(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.to_str().ok())
        .map(str::to_owned)
}

/// Parse the RFC 7239 `Forwarded:` header chain and return the rightmost
/// `for=` value whose IP does **not** belong to a trusted proxy CIDR.
///
/// Browsers / users do not send `Forwarded:` directly; only intermediaries
/// do. The rightmost untrusted value is therefore the real client. Returns
/// `None` when the header is absent, malformed, or every value resolves to
/// a trusted hop.
fn forwarded_header_real_ip(
    headers: &HeaderMap,
    trusted: &[ipnet::IpNet],
    debug_proxy_dev: bool,
) -> Option<String> {
    use std::net::IpAddr;
    let raw = header_value_case_insensitive(headers, "forwarded")?;
    let elements: Vec<&str> = raw.split(',').collect();
    for element in elements.iter().rev() {
        for kv in element.split(';') {
            let kv = kv.trim();
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            if !k.eq_ignore_ascii_case("for") {
                continue;
            }
            // Allowed forms: `for=192.0.2.1`, `for="192.0.2.1:4711"`,
            // `for="[2001:db8::1]"`, `for="_obfuscated"`.
            let stripped = v.trim().trim_matches('"');
            // Strip an optional port and surrounding `[]` for IPv6.
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
                // `host:port` for IPv4.
                if let Some((host, _port)) = stripped.split_once(':') {
                    host
                } else {
                    stripped
                }
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
            if !trusted.iter().any(|net| net.contains(&parsed)) {
                return Some(host_only.to_string());
            }
        }
    }
    None
}

pub(crate) fn effective_client_ip(peer_ip: &str, headers: &HeaderMap, state: &AppState) -> String {
    use std::net::IpAddr;
    let Ok(peer) = peer_ip.parse::<IpAddr>() else {
        return peer_ip.to_string();
    };
    // Trusted-proxy CIDRs are parsed and validated once at startup
    // (see `parse_trusted_proxy_cidrs`), so the request path is a cheap slice
    // scan instead of re-parsing strings — and a malformed entry can no longer
    // be silently dropped here (it fails the process at boot instead).
    let trusted_nets = state.trusted_proxy_nets.as_slice();
    if !trusted_nets.iter().any(|net| net.contains(&peer)) {
        return peer_ip.to_string();
    }

    // RFC 7239 `Forwarded:` header takes precedence when present — modern
    // proxies (HAProxy 2.x, recent nginx with the realip module) emit it
    // instead of `X-Forwarded-For`. We walk the chain right-to-left and pick
    // the first `for=` value whose IP is *not* one of our trusted proxies.
    if let Some(ip) = forwarded_header_real_ip(headers, trusted_nets, state.cli.debug_proxy_dev) {
        return ip;
    }

    let header_name = match state.cli.real_ip_header.as_deref() {
        Some(h) if !h.trim().is_empty() => h.trim(),
        // Even without an explicit --real-ip-header we still honour the
        // de-facto standard `X-Real-IP` if the peer is a trusted proxy.
        _ => "x-real-ip",
    };
    let Some(raw) = header_value_case_insensitive(headers, header_name) else {
        return peer_ip.to_string();
    };
    let candidate = if header_name.eq_ignore_ascii_case("x-forwarded-for") {
        // Rightmost-trusted algorithm (RFC 7239 §5.3): walk right-to-left, skip IPs that
        // belong to a trusted proxy CIDR, and pick the first one that does not. Using the
        // leftmost value (split(',').next()) is client-controlled and trivially bypassable —
        // an attacker can prepend any IP to spoof past blocklist and rate-limit checks.
        raw.split(',')
            .rev()
            .map(str::trim)
            .find(|s| {
                !s.parse::<IpAddr>()
                    .ok()
                    .is_some_and(|ip| trusted_nets.iter().any(|net| net.contains(&ip)))
            })
            .unwrap_or(peer_ip)
            .to_string()
    } else {
        raw.trim().to_string()
    };
    if candidate.parse::<IpAddr>().is_ok() {
        candidate
    } else {
        peer_ip.to_string()
    }
}

/// Build or propagate a W3C traceparent header value.
///
/// Rules:
/// - If the incoming value is present and has a valid 32-hex trace-id in field[1],
///   the trace-id is preserved and a new parent-id span is generated.
/// - Otherwise (absent or malformed) both trace-id and parent-id are freshly
///   generated from UUID v4.
pub(crate) fn build_traceparent(incoming: Option<&str>, metrics: &WafMetrics) -> String {
    fn new_parent_id() -> String {
        let parent_bytes = *Uuid::new_v4().as_bytes();
        format!(
            "{:016x}",
            u64::from_be_bytes([
                parent_bytes[0],
                parent_bytes[1],
                parent_bytes[2],
                parent_bytes[3],
                parent_bytes[4],
                parent_bytes[5],
                parent_bytes[6],
                parent_bytes[7],
            ])
        )
    }

    if let Some(tp) = incoming {
        let parts: Vec<&str> = tp.splitn(4, '-').collect();
        if parts.len() >= 3
            && parts[1].len() == 32
            && parts[1].chars().all(|c| c.is_ascii_hexdigit())
        {
            let trace_id = parts[1];
            metrics.inc_traceparent_forwarded();
            return format!("00-{trace_id}-{}-01", new_parent_id());
        }
    }
    // No valid incoming — generate fresh traceparent.
    let trace_id = format!("{:032x}", Uuid::new_v4().as_u128());
    metrics.inc_traceparent_generated();
    format!("00-{trace_id}-{}-01", new_parent_id())
}

#[cfg(test)]
mod trusted_proxy_cidr_tests {
    use super::{parse_trusted_proxy_cidr, parse_trusted_proxy_cidrs};

    #[test]
    fn accepts_cidr_and_bare_ip() {
        // CIDR notation passes through unchanged.
        assert_eq!(
            parse_trusted_proxy_cidr("10.0.0.0/8").expect("cidr").to_string(),
            "10.0.0.0/8"
        );
        // A bare IPv4 becomes a /32 host network.
        assert_eq!(
            parse_trusted_proxy_cidr("192.0.2.1").expect("v4 host").to_string(),
            "192.0.2.1/32"
        );
        // A bare IPv6 becomes a /128 host network.
        assert_eq!(
            parse_trusted_proxy_cidr("2001:db8::1").expect("v6 host").to_string(),
            "2001:db8::1/128"
        );
        // Surrounding whitespace is tolerated.
        assert!(parse_trusted_proxy_cidr("  127.0.0.1/32  ").is_ok());
    }

    #[test]
    fn rejects_malformed_entry() {
        // A typo no longer fails silently — it is a hard error at parse time.
        assert!(parse_trusted_proxy_cidr("999.0.0.0/8").is_err());
        assert!(parse_trusted_proxy_cidr("not-an-ip").is_err());
        assert!(parse_trusted_proxy_cidr("10.0.0.0/40").is_err());
    }

    #[test]
    fn parses_list_skipping_blanks_and_fails_on_first_bad() {
        let nets = parse_trusted_proxy_cidrs(&[
            "127.0.0.1/32".to_string(),
            "  ".to_string(),
            "10.0.0.0/8".to_string(),
        ])
        .expect("all valid");
        assert_eq!(nets.len(), 2, "blank entries are skipped");

        let err = parse_trusted_proxy_cidrs(&[
            "127.0.0.1/32".to_string(),
            "bogus".to_string(),
        ]);
        assert!(err.is_err(), "one malformed entry fails the whole parse");
    }
}

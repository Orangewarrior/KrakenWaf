use std::net::IpAddr;

use ipnet::IpNet;
use tracing::warn;

pub(super) fn canonical_ip(input: &str) -> Option<IpAddr> {
    let trimmed = input.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            other @ IpAddr::V4(_) => other,
        });
    }
    let parts = trimmed.split('.').collect::<Vec<_>>();
    if parts.len() == 4 {
        let octets = parts
            .into_iter()
            .map(|part| part.parse::<u8>())
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        return Some(IpAddr::from([octets[0], octets[1], octets[2], octets[3]]));
    }
    None
}

pub(super) fn parse_ip_net(value: &str) -> Option<IpNet> {
    let trimmed = value.trim();
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Some(net);
    }
    if trimmed.ends_with('.') {
        let parts = trimmed.trim_end_matches('.').split('.').collect::<Vec<_>>();
        let (cidr, expanded_prefix) = match parts.len() {
            1 => (format!("{}.0.0.0/8", parts[0]), 8u8),
            2 => (format!("{}.{}.0.0/16", parts[0], parts[1]), 16),
            3 => (
                format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]),
                24,
            ),
            _ => return None,
        };
        let parsed = cidr.parse::<IpNet>().ok();
        if parsed.is_some() {
            warn!(
                target: "krakenwaf",
                input = %trimmed,
                expanded_to = %cidr,
                prefix_bits = expanded_prefix,
                "blocked_ip_prefixes entry expanded from dotted prefix; prefer explicit CIDR notation"
            );
        }
        return parsed;
    }
    canonical_ip(trimmed).map(|ip| match ip {
        IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), 32).ok(),
        IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), 128).ok(),
    })?
}

/// Extract a header value by name from a flat `name: value\n...` header string.
pub(super) fn extract_header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim().to_ascii_lowercase())
        } else {
            None
        }
    })
}

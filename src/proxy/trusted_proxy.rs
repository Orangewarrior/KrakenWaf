use anyhow::{Context, Result};

/// Parse one trusted-proxy IP or CIDR into a normalized network.
///
/// # Errors
/// Returns an error when `entry` is neither a valid IP nor a valid CIDR.
pub fn parse_trusted_proxy_cidr(entry: &str) -> Result<ipnet::IpNet> {
    let trimmed = entry.trim();
    if let Ok(network) = trimmed.parse::<ipnet::IpNet>() {
        return Ok(network);
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

/// Parse every trusted-proxy entry eagerly and fail on malformed input.
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

#[cfg(test)]
mod tests {
    use super::{parse_trusted_proxy_cidr, parse_trusted_proxy_cidrs};

    #[test]
    fn accepts_cidr_and_bare_ip() {
        assert_eq!(
            parse_trusted_proxy_cidr("10.0.0.0/8").expect("CIDR").to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            parse_trusted_proxy_cidr("192.0.2.1").expect("IPv4 host").to_string(),
            "192.0.2.1/32"
        );
        assert_eq!(
            parse_trusted_proxy_cidr("2001:db8::1").expect("IPv6 host").to_string(),
            "2001:db8::1/128"
        );
    }

    #[test]
    fn rejects_malformed_entry() {
        assert!(parse_trusted_proxy_cidr("999.0.0.0/8").is_err());
        assert!(parse_trusted_proxy_cidr("not-an-ip").is_err());
        assert!(parse_trusted_proxy_cidr("10.0.0.0/40").is_err());
    }

    #[test]
    fn list_skips_blanks_and_fails_on_invalid_entry() {
        let networks = parse_trusted_proxy_cidrs(&[
            "127.0.0.1/32".to_string(),
            "  ".to_string(),
            "10.0.0.0/8".to_string(),
        ])
        .expect("valid networks");
        assert_eq!(networks.len(), 2);
        assert!(parse_trusted_proxy_cidrs(&["127.0.0.1/32".into(), "bogus".into()]).is_err());
    }
}

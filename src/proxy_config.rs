//! Proxy configuration loaded from `conf/proxy.yaml` (or an explicit path via
//! `--external-proxy-conf`).
//!
//! The file mirrors the proxy-related CLI flags so a deployment can keep the
//! command line terse and version-control its proxy topology instead. It is a
//! deliberately flat `key: value` document — a strict subset of YAML — parsed
//! by a small line reader that:
//!
//!   * treats a `#` at the start of a line, or preceded by whitespace, as the
//!     start of a comment and ignores the remainder of the line (YAML rule);
//!   * reads `key: value` on a single line, splitting on the **first** colon so
//!     values may themselves contain colons (e.g. `https://host:8080`);
//!   * leaves a key whose value is empty as *unset* (`None`) so the WAF keeps
//!     its built-in default for that knob.
//!
//! Resolution (highest precedence first): an explicitly-passed CLI flag always
//! wins; otherwise a non-empty value from `conf/proxy.yaml` is applied; finally
//! the built-in default stands. Empty fields never override anything — an empty
//! `internal-header-name`, for example, leaves the internal header disabled.

use crate::cli::Cli;
use anyhow::{bail, Context, Result};
use std::{fs, net::SocketAddr, path::Path};

/// Parsed view of `conf/proxy.yaml`. Every field is optional: a missing key, or
/// a key with an empty value, leaves the corresponding entry `None` so the WAF
/// keeps its default.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ProxyConfig {
    pub listen: Option<String>,
    pub upstream: Option<String>,
    pub upstream_timeout_secs: Option<u64>,
    pub upstream_ca: Option<String>,
    pub allow_private_upstream: Option<bool>,
    pub internal_header_name: Option<String>,
    pub real_ip_header: Option<String>,
    pub trusted_proxy_cidrs: Option<Vec<String>>,
    pub sni_map: Option<String>,
    pub no_tls: Option<bool>,
    pub header_protection_injection: Option<String>,
    pub blockmsg: Option<String>,
    pub metrics_port: Option<u16>,
    pub rule_management_port: Option<u16>,
}

impl ProxyConfig {
    /// Load + validate `<root>/conf/proxy.yaml`.
    ///
    /// # Errors
    /// Returns an error if the file is absent, unreadable, malformed, or fails
    /// validation. Unlike the rate-limit loader this is **not** lenient about a
    /// missing file: `--external-proxy-conf` is an explicit request to read a
    /// specific file, so its absence is a hard error rather than a silent
    /// fall-back to defaults.
    #[allow(dead_code)] // Public API for downstream consumers / tests; the binary loads via load_from.
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_from(&root.join("conf").join("proxy.yaml"))
    }

    /// Load + validate from an explicit path.
    ///
    /// # Errors
    /// Returns an error if the file is absent, unreadable, malformed, or fails
    /// validation.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!(
                "proxy config '{}' not found (required by --external-proxy-conf)",
                path.display()
            );
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        let cfg = Self::parse(&raw)
            .with_context(|| format!("failed to parse '{}'", path.display()))?;
        cfg.validate()
            .with_context(|| format!("invalid proxy config '{}'", path.display()))?;
        Ok(cfg)
    }

    /// Parse the flat `key: value` document. Exposed so unit tests can exercise
    /// the parser without touching the filesystem.
    ///
    /// # Errors
    /// Returns an error on a malformed line (no colon), an unknown key, or a
    /// value that does not parse for its key's type (booleans, integers).
    #[allow(clippy::too_many_lines)]
    pub fn parse(raw: &str) -> Result<Self> {
        let mut cfg = Self::default();
        for (idx, line) in raw.lines().enumerate() {
            let lineno = idx + 1;
            let content = strip_comment(line);
            if content.trim().is_empty() {
                continue;
            }
            let Some((key_raw, value_raw)) = content.split_once(':') else {
                bail!("line {lineno}: expected 'key: value', got '{}'", line.trim());
            };
            let key = key_raw.trim().to_ascii_lowercase();
            let value = value_raw.trim();
            let set = !value.is_empty();
            match key.as_str() {
                "listen" => {
                    if set {
                        cfg.listen = Some(value.to_string());
                    }
                }
                "upstream" => {
                    if set {
                        cfg.upstream = Some(value.to_string());
                    }
                }
                "upstream-timeout-secs" => {
                    if set {
                        cfg.upstream_timeout_secs = Some(value.parse().with_context(|| {
                            format!(
                                "line {lineno}: 'upstream-timeout-secs' must be a non-negative \
                                 integer, got '{value}'"
                            )
                        })?);
                    }
                }
                "upstream-ca" => {
                    if set {
                        cfg.upstream_ca = Some(value.to_string());
                    }
                }
                "allow-private-upstream" => {
                    if set {
                        cfg.allow_private_upstream = Some(parse_bool(value, lineno)?);
                    }
                }
                "internal-header-name" => {
                    if set {
                        cfg.internal_header_name = Some(value.to_string());
                    }
                }
                "real-ip-header" => {
                    if set {
                        cfg.real_ip_header = Some(value.to_string());
                    }
                }
                "trusted-proxy-cidrs" => {
                    let list: Vec<String> = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !list.is_empty() {
                        cfg.trusted_proxy_cidrs = Some(list);
                    }
                }
                "sni-map" => {
                    if set {
                        cfg.sni_map = Some(value.to_string());
                    }
                }
                "no-tls" => {
                    if set {
                        cfg.no_tls = Some(parse_bool(value, lineno)?);
                    }
                }
                "header-protection-injection" => {
                    if set {
                        cfg.header_protection_injection = Some(value.to_string());
                    }
                }
                "blockmsg" => {
                    if set {
                        cfg.blockmsg = Some(value.to_string());
                    }
                }
                "metrics-port" => {
                    if set {
                        cfg.metrics_port = Some(value.parse().with_context(|| {
                            format!(
                                "line {lineno}: 'metrics-port' must be a TCP port in 1..=65535, \
                                 got '{value}'"
                            )
                        })?);
                    }
                }
                "rule_management_port" | "rule-management-port" => {
                    if set {
                        cfg.rule_management_port = Some(value.parse().with_context(|| {
                            format!(
                                "line {lineno}: 'rule_management_port' must be a TCP port in \
                                 1..=65535, got '{value}'"
                            )
                        })?);
                    }
                }
                other => bail!("line {lineno}: unknown proxy config key '{other}'"),
            }
        }
        Ok(cfg)
    }

    /// Validate the semantic constraints of every populated field. Pure (no
    /// filesystem access) so it is cheap and unit-testable; path-valued fields
    /// (`sni_map`, `blockmsg`, `header_protection_injection`) are validated for
    /// presence here and for existence/structure by their own loaders later.
    ///
    /// # Errors
    /// Returns a descriptive error when a populated field is malformed:
    /// `listen` not a socket address, `upstream` not an http(s) URL, a CIDR that
    /// does not parse, or a header name that is not a valid HTTP token.
    pub fn validate(&self) -> Result<()> {
        if let Some(listen) = &self.listen {
            listen.parse::<SocketAddr>().with_context(|| {
                format!("'listen' is not a valid socket address: '{listen}' (expected host:port, e.g. 127.0.0.1:443)")
            })?;
        }
        if let Some(upstream) = &self.upstream {
            let url = url::Url::parse(upstream)
                .with_context(|| format!("'upstream' is not a valid URL: '{upstream}'"))?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!(
                    "'upstream' must use the http or https scheme, got '{}://…'",
                    url.scheme()
                );
            }
        }
        if let Some(cidrs) = &self.trusted_proxy_cidrs {
            for cidr in cidrs {
                // Shared with the startup parser so `config validate` and the
                // running WAF accept exactly the same set (CIDR or bare IP).
                crate::proxy::parse_trusted_proxy_cidr(cidr).with_context(|| {
                    format!("'trusted-proxy-cidrs' entry '{cidr}' is invalid")
                })?;
            }
        }
        if let Some(name) = &self.internal_header_name {
            http::header::HeaderName::from_bytes(name.as_bytes()).with_context(|| {
                format!("'internal-header-name' is not a valid HTTP header name: '{name}'")
            })?;
        }
        if let Some(name) = &self.real_ip_header {
            http::header::HeaderName::from_bytes(name.as_bytes()).with_context(|| {
                format!("'real-ip-header' is not a valid HTTP header name: '{name}'")
            })?;
        }
        if let Some(port) = self.metrics_port {
            if port == 0 {
                bail!("'metrics-port' must be a TCP port in 1..=65535, got 0");
            }
        }
        if let Some(port) = self.rule_management_port {
            if port == 0 {
                bail!("'rule_management_port' must be a TCP port in 1..=65535, got 0");
            }
        }
        Ok(())
    }

    /// Overlay the populated fields onto `cli`, but only for flags the operator
    /// did **not** pass explicitly (`is_explicit` returns true for those). This
    /// keeps the documented precedence: explicit CLI flag → `conf/proxy.yaml` →
    /// built-in default. An empty YAML field is `None` here and never overrides.
    pub fn merge_into(&self, cli: &mut Cli, is_explicit: &dyn Fn(&str) -> bool) {
        if let Some(listen) = &self.listen {
            if !is_explicit("listen") {
                if let Ok(addr) = listen.parse::<SocketAddr>() {
                    cli.listen = addr;
                }
            }
        }
        if let Some(upstream) = &self.upstream {
            if !is_explicit("upstream") {
                cli.upstream.clone_from(upstream);
            }
        }
        if let Some(secs) = self.upstream_timeout_secs {
            if !is_explicit("upstream-timeout-secs") {
                cli.upstream_timeout_secs = secs;
            }
        }
        if let Some(ca) = &self.upstream_ca {
            if !is_explicit("upstream-ca") {
                cli.upstream_ca = Some(ca.clone());
            }
        }
        if let Some(allow) = self.allow_private_upstream {
            if !is_explicit("allow-private-upstream") {
                cli.allow_private_upstream = allow;
            }
        }
        if let Some(name) = &self.internal_header_name {
            if !is_explicit("internal-header-name") {
                cli.internal_header_name.clone_from(name);
            }
        }
        if let Some(header) = &self.real_ip_header {
            if !is_explicit("real-ip-header") {
                cli.real_ip_header = Some(header.clone());
            }
        }
        if let Some(cidrs) = &self.trusted_proxy_cidrs {
            if !is_explicit("trusted-proxy-cidrs") {
                cli.trusted_proxy_cidrs.clone_from(cidrs);
            }
        }
        if let Some(sni_map) = &self.sni_map {
            if !is_explicit("sni-map") {
                cli.sni_map.clone_from(sni_map);
            }
        }
        if let Some(no_tls) = self.no_tls {
            if !is_explicit("no-tls") {
                cli.no_tls = no_tls;
            }
        }
        if let Some(headers) = &self.header_protection_injection {
            if !is_explicit("header-protection-injection") {
                cli.header_protection_injection = Some(headers.clone());
            }
        }
        if let Some(blockmsg) = &self.blockmsg {
            if !is_explicit("blockmsg") {
                cli.blockmsg = Some(blockmsg.clone());
            }
        }
        if let Some(port) = self.metrics_port {
            if !is_explicit("metrics-port") {
                cli.metrics_port = Some(port);
            }
        }
        if let Some(port) = self.rule_management_port {
            if !is_explicit("rule-management-port") {
                cli.rule_management_port = Some(port);
            }
        }
    }
}

/// True when `--<flag>` (or `--<flag>=value`) appears on the process command
/// line. Used to give an explicitly-passed CLI flag precedence over the file.
#[must_use]
pub fn cli_flag_present(flag: &str) -> bool {
    let long = format!("--{flag}");
    let long_eq = format!("--{flag}=");
    std::env::args()
        .skip(1)
        .any(|a| a == long || a.starts_with(&long_eq))
}

/// Strip a trailing `# comment`. A `#` opens a comment only at the start of the
/// line or when preceded by whitespace — matching YAML, and ensuring a `#`
/// inside a value (e.g. a URL fragment) is not mistaken for a comment.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

fn parse_bool(value: &str, lineno: usize) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => bail!("line {lineno}: expected a boolean (true/false), got '{other}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical example file the operator docs ship. Mirrors
    /// `conf/proxy.yaml`, including the `key : value` spacing and inline
    /// comments, so the parser is pinned against the exact shipped format.
    const CANONICAL: &str = "\
listen : 127.0.0.1:443
upstream : https://127.0.0.1:8080 # host defined by the user
upstream-timeout-secs: # when empty, defaults to a value defined by the WAF
upstream-ca: # empty -> trusts only public CAs
allow-private-upstream: false # disabled
internal-header-name: # empty: disabled by default
real-ip-header: X-Forwarded-For
trusted-proxy-cidrs: 127.0.0.1/32
sni-map: ./rules/tls/sni_map.csv # default
no-tls: false # no-tls disabled by default
header-protection-injection: ./rules/headers_http/relax.headers
blockmsg: ./alert/blockalert.html # if left empty, no page is used
metrics-port: 4343
rule_management_port: 4342
";

    #[test]
    fn parses_canonical_example_with_comments_and_spacing() {
        let cfg = ProxyConfig::parse(CANONICAL).expect("parses");
        assert_eq!(cfg.listen.as_deref(), Some("127.0.0.1:443"));
        // Inline comment after the URL is stripped; the colon inside the URL is kept.
        assert_eq!(cfg.upstream.as_deref(), Some("https://127.0.0.1:8080"));
        // Empty value → None → WAF keeps its built-in default.
        assert_eq!(cfg.upstream_timeout_secs, None);
        assert_eq!(cfg.upstream_ca, None);
        assert_eq!(cfg.allow_private_upstream, Some(false));
        // `# empty…` directly after the colon is a comment → field stays unset.
        assert_eq!(cfg.internal_header_name, None);
        assert_eq!(cfg.real_ip_header.as_deref(), Some("X-Forwarded-For"));
        assert_eq!(
            cfg.trusted_proxy_cidrs.as_deref(),
            Some(["127.0.0.1/32".to_string()].as_slice())
        );
        assert_eq!(cfg.sni_map.as_deref(), Some("./rules/tls/sni_map.csv"));
        assert_eq!(cfg.no_tls, Some(false));
        assert_eq!(
            cfg.header_protection_injection.as_deref(),
            Some("./rules/headers_http/relax.headers")
        );
        assert_eq!(cfg.blockmsg.as_deref(), Some("./alert/blockalert.html"));
        assert_eq!(cfg.metrics_port, Some(4343));
        assert_eq!(cfg.rule_management_port, Some(4342));
    }

    #[test]
    fn rule_management_port_parses_and_merges() {
        let cfg = ProxyConfig::parse("rule_management_port: 5005\n").expect("parses");
        assert_eq!(cfg.rule_management_port, Some(5005));
        let mut cli = base_cli();
        cfg.merge_into(&mut cli, &|_| false);
        assert_eq!(cli.rule_management_port, Some(5005));
        // Explicit CLI flag wins over the file.
        let mut cli2 = base_cli();
        cli2.rule_management_port = Some(6006);
        cfg.merge_into(&mut cli2, &|f| f == "rule-management-port");
        assert_eq!(cli2.rule_management_port, Some(6006));
    }

    #[test]
    fn zero_rule_management_port_fails_validation() {
        let cfg = ProxyConfig {
            rule_management_port: Some(0),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn canonical_example_validates() {
        ProxyConfig::parse(CANONICAL)
            .expect("parses")
            .validate()
            .expect("valid");
    }

    #[test]
    fn comment_and_blank_lines_are_ignored() {
        let cfg = ProxyConfig::parse(
            "# full-line comment\n\n   # indented comment\nupstream: http://example.com\n",
        )
        .expect("parses");
        assert_eq!(cfg.upstream.as_deref(), Some("http://example.com"));
        assert_eq!(cfg.listen, None);
    }

    #[test]
    fn hash_inside_value_is_not_a_comment() {
        // No whitespace before '#': it belongs to the value.
        let cfg = ProxyConfig::parse("upstream: http://example.com/a#frag\n").expect("parses");
        assert_eq!(cfg.upstream.as_deref(), Some("http://example.com/a#frag"));
    }

    #[test]
    fn multiple_cidrs_split_on_commas() {
        let cfg = ProxyConfig::parse("trusted-proxy-cidrs: 127.0.0.1/32, 10.0.0.0/8\n")
            .expect("parses");
        assert_eq!(
            cfg.trusted_proxy_cidrs.as_deref(),
            Some(["127.0.0.1/32".to_string(), "10.0.0.0/8".to_string()].as_slice())
        );
    }

    #[test]
    fn unknown_key_is_rejected() {
        assert!(ProxyConfig::parse("bogus-key: 1\n").is_err());
    }

    #[test]
    fn malformed_line_without_colon_is_rejected() {
        assert!(ProxyConfig::parse("listen 127.0.0.1:443\n").is_err());
    }

    #[test]
    fn non_numeric_timeout_is_rejected() {
        assert!(ProxyConfig::parse("upstream-timeout-secs: soon\n").is_err());
    }

    #[test]
    fn non_boolean_no_tls_is_rejected() {
        assert!(ProxyConfig::parse("no-tls: maybe\n").is_err());
    }

    #[test]
    fn non_numeric_metrics_port_is_rejected() {
        assert!(ProxyConfig::parse("metrics-port: soon\n").is_err());
    }

    #[test]
    fn zero_metrics_port_fails_validation() {
        let cfg = ProxyConfig {
            metrics_port: Some(0),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn metrics_port_merges_when_flag_absent() {
        let cfg = ProxyConfig {
            metrics_port: Some(9443),
            ..Default::default()
        };
        let mut cli = base_cli();
        cfg.merge_into(&mut cli, &|_| false);
        assert_eq!(cli.metrics_port, Some(9443));
        // Explicit CLI flag wins over the file.
        let mut cli2 = base_cli();
        cli2.metrics_port = Some(7000);
        cfg.merge_into(&mut cli2, &|f| f == "metrics-port");
        assert_eq!(cli2.metrics_port, Some(7000));
    }

    #[test]
    fn validate_rejects_bad_listen() {
        let cfg = ProxyConfig {
            listen: Some("not-an-addr".to_string()),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_non_http_upstream() {
        let cfg = ProxyConfig {
            upstream: Some("ftp://example.com".to_string()),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_cidr() {
        let cfg = ProxyConfig {
            trusted_proxy_cidrs: Some(vec!["999.0.0.0/8".to_string()]),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_header_name() {
        let cfg = ProxyConfig {
            real_ip_header: Some("Bad Header".to_string()),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn merge_applies_yaml_when_flag_absent() {
        let cfg = ProxyConfig::parse(CANONICAL).expect("parses");
        let mut cli = base_cli();
        cfg.merge_into(&mut cli, &|_| false); // nothing explicit
        assert_eq!(cli.listen.to_string(), "127.0.0.1:443");
        assert_eq!(cli.upstream, "https://127.0.0.1:8080");
        // Empty YAML field → WAF default preserved (clap default 15 s).
        assert_eq!(cli.upstream_timeout_secs, 15);
        // Empty internal-header-name → stays disabled ("").
        assert_eq!(cli.internal_header_name, "");
        assert_eq!(cli.real_ip_header.as_deref(), Some("X-Forwarded-For"));
        assert_eq!(cli.trusted_proxy_cidrs, vec!["127.0.0.1/32".to_string()]);
        assert_eq!(cli.sni_map, "./rules/tls/sni_map.csv");
        assert!(!cli.no_tls);
        assert_eq!(
            cli.header_protection_injection.as_deref(),
            Some("./rules/headers_http/relax.headers")
        );
        assert_eq!(cli.blockmsg.as_deref(), Some("./alert/blockalert.html"));
        assert_eq!(cli.metrics_port, Some(4343));
    }

    #[test]
    fn upstream_ca_parses_and_merges() {
        let cfg = ProxyConfig::parse(
            "upstream: https://backend.internal:8443\nupstream-ca: /etc/krakenwaf/upstream-ca.pem\n",
        )
        .expect("parses");
        assert_eq!(
            cfg.upstream_ca.as_deref(),
            Some("/etc/krakenwaf/upstream-ca.pem")
        );
        let mut cli = base_cli();
        cfg.merge_into(&mut cli, &|_| false);
        assert_eq!(
            cli.upstream_ca.as_deref(),
            Some("/etc/krakenwaf/upstream-ca.pem")
        );
        // Explicit CLI flag wins over the file.
        let mut cli2 = base_cli();
        cli2.upstream_ca = Some("/cli/path.pem".to_string());
        cfg.merge_into(&mut cli2, &|f| f == "upstream-ca");
        assert_eq!(cli2.upstream_ca.as_deref(), Some("/cli/path.pem"));
    }

    #[test]
    fn merge_respects_explicit_cli_flag() {
        let cfg = ProxyConfig {
            upstream: Some("https://from-file:9000".to_string()),
            ..Default::default()
        };
        let mut cli = base_cli();
        "https://from-cli:1234".clone_into(&mut cli.upstream);
        // `upstream` was passed explicitly → file must not override it.
        cfg.merge_into(&mut cli, &|f| f == "upstream");
        assert_eq!(cli.upstream, "https://from-cli:1234");
    }

    /// A `Cli` populated with the clap defaults, built without invoking the
    /// parser so the unit test does not depend on the test binary's argv.
    fn base_cli() -> Cli {
        use clap::Parser;
        Cli::parse_from(["krakenwaf"])
    }
}

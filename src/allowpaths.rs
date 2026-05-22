use anyhow::{Context, Result};
use ipnet::IpNet;
use memchr::memmem;
use serde::Deserialize;
use std::{fs, net::IpAddr, path::Path};

// ── IP entry types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum IpEntry {
    Net(IpNet),
    Range { start: IpAddr, end: IpAddr },
}

impl IpEntry {
    fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Net(net) => net.contains(ip),
            Self::Range { start, end } => ip_in_range(ip, start, end),
        }
    }
}

fn ip_in_range(ip: &IpAddr, start: &IpAddr, end: &IpAddr) -> bool {
    match (ip, start, end) {
        (IpAddr::V4(ip4), IpAddr::V4(s4), IpAddr::V4(e4)) => {
            let n = u32::from(*ip4);
            n >= u32::from(*s4) && n <= u32::from(*e4)
        }
        (IpAddr::V6(ip6), IpAddr::V6(s6), IpAddr::V6(e6)) => {
            let n = u128::from(*ip6);
            n >= u128::from(*s6) && n <= u128::from(*e6)
        }
        _ => false,
    }
}

/// Parsed set of allowed IP addresses (exact, CIDR, or start–end range).
///
/// Supports:
/// - Exact IP: `127.0.0.1`
/// - CIDR: `127.0.0.0/25`
/// - Range: `127.0.0.1-127.0.0.127`
///
/// Lines starting with `#` and empty lines are ignored.
#[derive(Debug, Clone, Default)]
pub struct AddrRestriction {
    entries: Vec<IpEntry>,
}

impl AddrRestriction {
    /// Load from a file. Uses `fs::canonicalize` before opening to prevent path traversal.
    fn from_file(path: &Path) -> Result<Self> {
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("only_addrs: cannot canonicalize '{}'", path.display()))?;
        let content = fs::read(&canonical)
            .with_context(|| format!("only_addrs: cannot read '{}'", canonical.display()))?;
        Ok(Self { entries: parse_addr_bytes(&content) })
    }

    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.entries.iter().any(|e| e.contains(ip))
    }

    /// Number of parsed IP entries (for tests and diagnostics).
    #[must_use]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Parse a newline-delimited byte slice into IP entries.
/// Uses `memchr` for zero-copy newline scanning.
fn parse_addr_bytes(data: &[u8]) -> Vec<IpEntry> {
    let mut entries = Vec::new();
    let mut start = 0usize;

    for pos in memchr::memchr_iter(b'\n', data) {
        let line = &data[start..pos];
        // Strip \r for Windows line endings.
        let line = if line.last() == Some(&b'\r') { &line[..line.len() - 1] } else { line };
        if let Ok(s) = std::str::from_utf8(line) {
            if let Some(e) = parse_ip_entry(s) {
                entries.push(e);
            }
        }
        start = pos + 1;
    }
    // Handle last line with no trailing newline.
    if start < data.len() {
        if let Ok(s) = std::str::from_utf8(&data[start..]) {
            if let Some(e) = parse_ip_entry(s) {
                entries.push(e);
            }
        }
    }
    entries
}

/// Parse one line into an `IpEntry`. Returns `None` for comments and empty lines.
fn parse_ip_entry(line: &str) -> Option<IpEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // 1. CIDR notation (e.g. "127.0.0.0/25" or "::1/128").
    if let Ok(net) = line.parse::<IpNet>() {
        return Some(IpEntry::Net(net));
    }
    // 2. IP range notation: "a.b.c.d-e.f.g.h".
    //    Use memchr for the separator scan instead of str::contains.
    if let Some(dash) = memchr::memchr(b'-', line.as_bytes()) {
        let left = line[..dash].trim();
        let right = line[dash + 1..].trim();
        if let (Ok(s), Ok(e)) = (left.parse::<IpAddr>(), right.parse::<IpAddr>()) {
            return Some(IpEntry::Range { start: s, end: e });
        }
    }
    // 3. Exact IP address.
    if let Ok(ip) = line.parse::<IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return IpNet::new(ip, prefix).ok().map(IpEntry::Net);
    }
    None
}

// ── Allow-path entry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AllowPathEntry {
    pub order: u32,
    pub title: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    #[serde(default)]
    pub log: bool,
    pub paths: Vec<String>,
    /// Path (relative to WAF root) of a file listing allowed client IPs.
    /// When set, only IPs in that file may reach any of `paths`. All other
    /// source IPs receive HTTP 403 — even if the path matches.
    #[serde(default)]
    pub only_addrs: Option<String>,
    /// Resolved from `only_addrs` during `load_and_validate`; not in the YAML.
    #[serde(skip)]
    pub addr_restriction: Option<AddrRestriction>,
}

// ── Path-access decision ──────────────────────────────────────────────────────

/// Result of [`AllowPathConfig::check`].
pub enum PathDecision<'a> {
    /// No configured path matched — proceed with normal WAF inspection.
    NoMatch,
    /// Path matched (client IP is in the allowlist, or no IP restriction is configured)
    /// — skip WAF inspection and forward directly to upstream.
    Allow(&'a AllowPathEntry),
    /// The path (or the full URI) matched an IP-restricted entry and the client
    /// IP is **not** in the `only_addrs` list — block immediately with HTTP 403.
    Block,
}

// ── AllowPathConfig ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AllowPathConfig {
    pub entries: Vec<AllowPathEntry>,
}

impl AllowPathConfig {
    /// Read and parse an allow-paths YAML file.
    ///
    /// `base_dir` is the WAF root directory used to resolve relative `only_addrs`
    /// paths. Uses `fs::canonicalize` before opening every file to prevent path
    /// traversal attacks.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, parsed, or an `only_addrs`
    /// file fails to load.
    pub fn from_file(path: &Path, base_dir: &Path) -> Result<Self> {
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("failed to canonicalize allow-paths file '{}'", path.display()))?;
        let content = fs::read_to_string(&canonical)
            .with_context(|| format!("failed to read allow-paths file '{}'", canonical.display()))?;
        Self::from_str_inner(&content, &canonical, base_dir)
    }

    fn from_str_inner(content: &str, yaml_path: &Path, base_dir: &Path) -> Result<Self> {
        #[derive(Deserialize)]
        struct Root {
            #[serde(default)]
            allow: Vec<AllowPathEntry>,
        }

        let root: Root = serde_yaml::from_str(content)
            .with_context(|| format!("failed to parse allow-paths YAML '{}'", yaml_path.display()))?;

        let mut entries = root.allow;
        entries.sort_by_key(|e| e.order);

        for entry in &mut entries {
            if let Some(ref raw_path) = entry.only_addrs.clone() {
                let addr_path = if std::path::Path::new(raw_path).is_absolute() {
                    std::path::PathBuf::from(raw_path)
                } else {
                    base_dir.join(raw_path)
                };
                let restriction = AddrRestriction::from_file(&addr_path)
                    .with_context(|| {
                        format!(
                            "allow-paths entry '{}': failed to load only_addrs file '{}'",
                            entry.title, raw_path
                        )
                    })?;
                entry.addr_restriction = Some(restriction);
            }
        }

        Ok(Self { entries })
    }

    /// IP-aware access check. Called per request in the WAF proxy pipeline.
    ///
    /// - `path`:      normalized URI path (percent-decoded, `..` collapsed)
    /// - `full_uri`:  raw request URI including query string; scanned with `memmem`
    ///   to catch endpoint names embedded in query parameters
    /// - `client_ip`: effective client IP string (may include `X-Forwarded-For`)
    ///
    /// Returns:
    /// - [`PathDecision::Allow`] — WAF inspection can be skipped
    /// - [`PathDecision::Block`] — block immediately (IP restriction violated)
    /// - [`PathDecision::NoMatch`] — no configured path matched; apply normal WAF
    #[must_use]
    pub fn check<'a>(&'a self, path: &str, full_uri: &str, client_ip: &str) -> PathDecision<'a> {
        let normalized = crate::rules::normalize_url_path(path);
        let full_uri_bytes = full_uri.as_bytes();

        for entry in &self.entries {
            // Prefix match on the canonicalized path.
            let path_matches = entry.paths.iter().any(|p| {
                let allowed = crate::rules::normalize_url_path(p);
                normalized == allowed || normalized.starts_with(&format!("{allowed}/"))
            });

            // For IP-restricted entries, also scan the full URI (including query
            // string) with memmem so a restricted path in a redirect param is caught.
            let uri_contains = entry.addr_restriction.is_some()
                && !path_matches
                && entry.paths.iter().any(|p| {
                    let allowed = crate::rules::normalize_url_path(p);
                    memmem::find(full_uri_bytes, allowed.as_bytes()).is_some()
                });

            if path_matches || uri_contains {
                if let Some(restriction) = &entry.addr_restriction {
                    let ip_allowed = client_ip
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| restriction.contains(&ip));
                    return if ip_allowed {
                        PathDecision::Allow(entry)
                    } else {
                        PathDecision::Block
                    };
                }
                return PathDecision::Allow(entry);
            }
        }
        PathDecision::NoMatch
    }

    /// Path-only match (no IP enforcement). Kept for backwards-compatibility and
    /// path-matching unit tests.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_allowed(&self, uri_path: &str) -> Option<&AllowPathEntry> {
        let normalized = crate::rules::normalize_url_path(uri_path);
        self.entries.iter().find(|entry| {
            entry.paths.iter().any(|p| {
                let allowed = crate::rules::normalize_url_path(p);
                normalized == allowed || normalized.starts_with(&format!("{allowed}/"))
            })
        })
    }
}

/// Load and validate an allow-paths YAML file.
///
/// `base_dir` is used to resolve relative `only_addrs` paths (typically the
/// WAF working directory). Exits with an error if the file is missing, invalid,
/// or if any `only_addrs` file cannot be loaded.
///
/// # Errors
/// Returns an error if any validation step fails.
pub fn load_and_validate(path: &Path, base_dir: &Path) -> Result<AllowPathConfig> {
    let config = AllowPathConfig::from_file(path, base_dir)?;
    for entry in &config.entries {
        if entry.title.trim().is_empty() {
            anyhow::bail!("allow-paths entry with order={} has an empty title", entry.order);
        }
        if entry.paths.is_empty() {
            anyhow::bail!(
                "allow-paths entry '{}' (order={}) has no paths listed",
                entry.title,
                entry.order
            );
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn restriction_from_str(s: &str) -> AddrRestriction {
        AddrRestriction { entries: parse_addr_bytes(s.as_bytes()) }
    }

    fn parse_ip(s: &str) -> IpAddr {
        s.parse().expect("test IP literal must be valid")
    }

    #[test]
    fn exact_ip_match() {
        let r = restriction_from_str("127.0.0.1\n");
        assert!(r.contains(&parse_ip("127.0.0.1")));
        assert!(!r.contains(&parse_ip("127.0.0.2")));
    }

    #[test]
    fn cidr_match() {
        let r = restriction_from_str("127.0.0.0/25\n");
        assert!(r.contains(&parse_ip("127.0.0.100")));
        assert!(!r.contains(&parse_ip("127.0.0.200")));
    }

    #[test]
    fn range_match() {
        let r = restriction_from_str("127.0.0.1-127.0.0.110\n");
        assert!(r.contains(&parse_ip("127.0.0.55")));
        assert!(!r.contains(&parse_ip("127.0.0.0")));
        assert!(!r.contains(&parse_ip("127.0.0.111")));
    }

    #[test]
    fn comments_and_empty_lines_ignored() {
        let r = restriction_from_str("# comment\n\n127.0.0.1\n");
        assert_eq!(r.len(), 1);
    }

    fn make_config_with_restriction(tmpdir: &tempfile::TempDir) -> AllowPathConfig {
        let addr_file = tmpdir.path().join("allow_addrs.txt");
        std::fs::write(&addr_file, "127.0.0.1\n").expect("write allow_addrs.txt");

        let yaml = r#"allow:
  - order: 1
    title: "Health"
    log: false
    only_addrs: allow_addrs.txt
    paths:
      - /healthz
      - /metrics
"#;
        let yaml_file = tmpdir.path().join("lists.yaml");
        std::fs::write(&yaml_file, yaml).expect("write lists.yaml");

        AllowPathConfig::from_file(&yaml_file, tmpdir.path()).expect("load allow-paths config")
    }

    fn expect_allow(decision: &PathDecision<'_>) {
        assert!(matches!(decision, PathDecision::Allow(_)), "expected Allow variant");
    }

    fn expect_block(decision: &PathDecision<'_>) {
        assert!(matches!(decision, PathDecision::Block), "expected Block variant");
    }

    fn expect_no_match(decision: &PathDecision<'_>) {
        assert!(matches!(decision, PathDecision::NoMatch), "expected NoMatch variant");
    }

    #[test]
    fn check_ip_allowed() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let config = make_config_with_restriction(&tmpdir);
        expect_allow(&config.check("/healthz", "/healthz", "127.0.0.1"));
    }

    #[test]
    fn check_ip_blocked() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let config = make_config_with_restriction(&tmpdir);
        expect_block(&config.check("/healthz", "/healthz", "203.0.113.1"));
    }

    #[test]
    fn check_no_match_returns_nomatch() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let config = make_config_with_restriction(&tmpdir);
        expect_no_match(&config.check("/api/users", "/api/users", "203.0.113.1"));
    }

    #[test]
    fn check_uri_qs_blocked_foreign_ip() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let config = make_config_with_restriction(&tmpdir);
        // The path itself doesn't match, but full URI contains /healthz in query string.
        expect_block(&config.check("/api", "/api?next=/healthz", "1.2.3.4"));
    }

    #[test]
    fn check_uri_qs_allowed_localhost() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let config = make_config_with_restriction(&tmpdir);
        expect_allow(&config.check("/api", "/api?next=/healthz", "127.0.0.1"));
    }

    #[test]
    fn no_restriction_entry_always_allowed() {
        let yaml = r#"allow:
  - order: 1
    title: "Open"
    log: false
    paths:
      - /open
"#;
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let yaml_file = tmpdir.path().join("lists.yaml");
        std::fs::write(&yaml_file, yaml).expect("write lists.yaml");
        let config = AllowPathConfig::from_file(&yaml_file, tmpdir.path())
            .expect("load allow-paths config");
        expect_allow(&config.check("/open", "/open", "1.2.3.4"));
    }
}

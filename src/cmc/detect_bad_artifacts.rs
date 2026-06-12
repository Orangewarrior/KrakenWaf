//! CMC module: Bad Artifact Detection
//!
//! Inspects request URI paths for sensitive file/directory artifacts that
//! should never be publicly accessible: dotfiles, config files, debug logs,
//! credentials, framework-specific files, /proc and /sys entries, etc.
//!
//! Pattern source: OWASP Core Rule Set `restricted-files.data`
//! <https://github.com/coreruleset/coreruleset/blob/main/rules/restricted-files.data>
//!
//! Detection strategy:
//! * **Pattern file** — literal strings loaded from
//!   `rules/artifacts/file_pitfalls.txt` at WAF startup. One per non-empty
//!   non-comment line.
//! * **Fast path** — `memchr::memmem::Finder` per pattern (Boyer-Moore SIMD).
//! * **Vectorscan path** — `BlockDatabase` with `SINGLEMATCH` when enabled.
//! * **Action** — controlled by `untrust_level`:
//!   - `>= 60` → block (HTTP 403), log to all outputs (High severity)
//!   - `< 60` → silent log only (Low severity), request is forwarded

use anyhow::{Context, Result};
use memchr::memmem::Finder;
use std::path::Path;

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Scan};

/// Result of a successful scan: the literal pattern that matched, used for logs.
#[derive(Debug, Clone)]
pub struct BadArtifactMatch {
    pub matched_pattern: String,
}

impl BadArtifactMatch {
    /// The literal pattern that was found in the URI path.
    #[must_use]
    pub fn matched_pattern(&self) -> &str {
        &self.matched_pattern
    }
}

/// Compiled detector. Build once with [`BadArtifactsDetector::from_file`];
/// call [`BadArtifactsDetector::scan`] per request URI path.
#[derive(Debug, Clone)]
pub struct BadArtifactsDetector {
    /// Original literal pattern strings, indexed by pattern id.
    patterns: Vec<String>,
    /// Pre-built Boyer-Moore searchers for the CPU fast path.
    finders: Vec<Finder<'static>>,
    /// Optional Hyperscan/Vectorscan acceleration database.
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl BadArtifactsDetector {
    /// Load and compile patterns from `path`.
    ///
    /// Lines that are empty or start with `#` are skipped. Patterns are
    /// interpreted as **literal byte strings** — no regex metacharacter
    /// interpretation on the memchr path. The Vectorscan path regex-escapes
    /// each pattern before handing it to Hyperscan.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or contains no usable
    /// patterns.
    pub fn from_file(path: &Path, vectorscan_enabled: bool) -> Result<Self> {
        let content = std::fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read Detect_bad_artifacts patterns from {}",
                path.display()
            )
        })?;

        let patterns: Vec<String> = content
            .lines()
            .map(str::trim_end)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();

        anyhow::ensure!(
            !patterns.is_empty(),
            "Detect_bad_artifacts pattern file {} contains no usable patterns",
            path.display()
        );

        let finders: Vec<Finder<'static>> = patterns
            .iter()
            .map(|p| Finder::new(p.as_bytes()).into_owned())
            .collect();

        #[cfg(feature = "vectorscan-engine")]
        let vectorscan = if vectorscan_enabled {
            build_vectorscan(&patterns)
        } else {
            None
        };

        Ok(Self {
            patterns,
            finders,
            #[cfg(feature = "vectorscan-engine")]
            vectorscan,
            vectorscan_enabled,
        })
    }

    /// Scan `uri` for any known sensitive file/directory artifact pattern.
    ///
    /// Returns the first match or `None` if the URI is clean.
    /// Uses Vectorscan when available; otherwise iterates the memchr finders.
    #[must_use]
    pub fn scan(&self, uri: &[u8]) -> Option<BadArtifactMatch> {
        #[cfg(feature = "vectorscan-engine")]
        if self.vectorscan_enabled {
            if let Some(db) = &self.vectorscan {
                return vectorscan_scan(db, &self.patterns, uri);
            }
        }
        #[cfg(not(feature = "vectorscan-engine"))]
        let _ = self.vectorscan_enabled;

        // CPU fast path: return first matching pattern found.
        for (idx, finder) in self.finders.iter().enumerate() {
            if finder.find(uri).is_some() {
                return self.patterns.get(idx).map(|p| BadArtifactMatch {
                    matched_pattern: p.clone(),
                });
            }
        }
        None
    }

    /// Number of patterns loaded.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ─── Vectorscan helpers ───────────────────────────────────────────────────────

#[cfg(feature = "vectorscan-engine")]
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'.' | b'^' | b'$' | b'*' | b'+' | b'?' | b'(' | b')' | b'[' | b']' | b'{' | b'}'
            | b'|' | b'\\' | b'/' => {
                out.push('\\');
                out.push(b as char);
            }
            _ => out.push(b as char),
        }
    }
    out
}

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan(patterns: &[String]) -> Option<BlockDatabase> {
    super::vectorscan_util::build_block_database(patterns, Flag::SINGLEMATCH, |p| {
        regex_escape(p).into_bytes()
    })
}

#[cfg(feature = "vectorscan-engine")]
fn vectorscan_scan(
    db: &BlockDatabase,
    patterns: &[String],
    uri: &[u8],
) -> Option<BadArtifactMatch> {
    let mut scanner = db.create_scanner().ok()?;
    let mut best: Option<(u32, usize)> = None; // (id, pattern_idx)
    let _ = scanner.scan(uri, |id, _from, _to, _flags| {
        if let Ok(idx) = usize::try_from(id) {
            let beats = match best {
                Some((cur_id, _)) => id < cur_id,
                None => true,
            };
            if beats {
                best = Some((id, idx));
            }
        }
        Scan::Continue
    });
    best.and_then(|(_, idx)| {
        patterns.get(idx).map(|p| BadArtifactMatch {
            matched_pattern: p.clone(),
        })
    })
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::BadArtifactsDetector;
    use std::io::Write as _;

    fn detector_from_patterns(patterns: &[&str]) -> BadArtifactsDetector {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        for p in patterns {
            writeln!(tmp, "{p}").expect("write pattern");
        }
        BadArtifactsDetector::from_file(tmp.path(), false).expect("build detector")
    }

    fn real_detector() -> BadArtifactsDetector {
        let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rules/artifacts/file_pitfalls.txt");
        BadArtifactsDetector::from_file(&rules_path, false).expect("load real rules")
    }

    #[test]
    fn detects_dotenv_in_uri() {
        let d = real_detector();
        let uri = b"/app/.env";
        let m = d.scan(uri).expect(".env should be detected");
        assert!(m.matched_pattern.contains(".env"), "pattern should mention .env: {}", m.matched_pattern());
    }

    #[test]
    fn detects_git_config_in_uri() {
        let d = real_detector();
        let uri = b"/.git/config";
        let m = d.scan(uri).expect(".git/ should be detected");
        assert!(m.matched_pattern.contains(".git/"), "pattern should mention .git/: {}", m.matched_pattern());
    }

    #[test]
    fn detects_wp_config_in_uri() {
        let d = real_detector();
        let uri = b"/wp-config.php";
        // The URI contains both config.php and wp-config. — the first matching
        // pattern in the list wins. Either way, the URI must be flagged.
        let m = d.scan(uri).expect("wp-config.php URI should be detected");
        // Accept any pattern that correctly explains why this path is sensitive.
        assert!(
            m.matched_pattern.contains("wp-config.") || m.matched_pattern.contains("config.php"),
            "pattern should explain why /wp-config.php is sensitive: {}",
            m.matched_pattern()
        );
    }

    #[test]
    fn detects_proc_cpuinfo_in_uri() {
        let d = real_detector();
        let uri = b"/proc/cpuinfo";
        let m = d.scan(uri).expect("proc/cpuinfo should be detected");
        assert!(m.matched_pattern.contains("proc/cpuinfo"), "pattern should mention proc/cpuinfo: {}", m.matched_pattern());
    }

    #[test]
    fn detects_slash_proc_slash_in_uri() {
        let d = real_detector();
        let uri = b"/../proc/";
        let m = d.scan(uri).expect("/proc/ should be detected");
        assert!(m.matched_pattern.contains("/proc/"), "pattern should mention /proc/: {}", m.matched_pattern());
    }

    #[test]
    fn detects_credentials_json_in_uri() {
        let d = real_detector();
        let uri = b"/static/credentials.json";
        let m = d.scan(uri).expect("credentials.json should be detected");
        assert!(m.matched_pattern.contains("credentials.json"), "pattern should mention credentials.json: {}", m.matched_pattern());
    }

    #[test]
    fn detects_aws_credentials_in_uri() {
        let d = real_detector();
        let uri = b"/.aws/credentials";
        let m = d.scan(uri).expect(".aws/ should be detected");
        assert!(m.matched_pattern.contains(".aws/"), "pattern should mention .aws/: {}", m.matched_pattern());
    }

    #[test]
    fn clean_uri_returns_none() {
        let d = real_detector();
        let uri = b"/api/users";
        assert!(d.scan(uri).is_none(), "/api/users should not be flagged");
    }

    #[test]
    fn detects_config_json_in_uri() {
        let d = real_detector();
        let uri = b"/config.json";
        let m = d.scan(uri).expect("config.json should be detected");
        assert!(m.matched_pattern.contains("config.json"), "pattern should mention config.json: {}", m.matched_pattern());
    }

    #[test]
    fn comment_lines_are_skipped() {
        // Build a detector with only comment and empty lines plus one real pattern.
        let d = detector_from_patterns(&["# Apache", "# home level dotfiles", "", ".htpasswd"]);
        // Should have only 1 real pattern (.htpasswd), no false positives from comments.
        assert_eq!(d.pattern_count(), 1, "only .htpasswd should be loaded, not comment lines");
        // Comment text should not match.
        assert!(d.scan(b"# Apache").is_none(), "comment text should not be a pattern");
        assert!(d.scan(b"# home level dotfiles").is_none(), "comment text should not be a pattern");
        // The real pattern should match.
        assert!(d.scan(b"/.htpasswd").is_some(), ".htpasswd should be detected");
    }
}

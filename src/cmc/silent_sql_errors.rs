//! CMC module: Silent SQL Error Scrubber
//!
//! Inspects upstream HTTP response bodies for verbose DBMS error fingerprints
//! (OWASP Core Rule Set `sql-errors.data`) and either **scrubs** the matched
//! substring out of the response or **blocks** the response entirely, based on
//! the operator's `untrust` (paranoia) level.
//!
//! Detection strategy
//! ------------------
//! * **Pattern file** — literal strings are loaded from
//!   `rules/error_msgs/sql_errors_static.txt`. One string per non-empty,
//!   non-comment line. No regex metacharacters are interpreted — patterns are
//!   matched as bytes.
//! * **Fast path (default)** — `memchr::memmem::Finder` builds a Boyer-Moore-
//!   like searcher per pattern at startup. Per-response cost is one linear
//!   scan across the patterns, short-circuiting on first match.
//! * **Vectorscan acceleration** — when `--enable-vectorscan` is active a
//!   Hyperscan `BlockDatabase` with `SOM_LEFTMOST | SINGLEMATCH` is used. The
//!   SIMD engine processes all patterns in a single pass and reports the exact
//!   match offsets needed for the scrub.
//! * **Action gated by `untrust_level`** — `>= 80` blocks the response and
//!   logs the event; `< 80` replaces the matched bytes with a single ASCII
//!   space and forwards the response, low-severity log entry only.
//!
//! Reference: <https://github.com/coreruleset/coreruleset/blob/main/rules/sql-errors.data>

use anyhow::{Context, Result};
use memchr::memmem::Finder;
use std::path::Path;

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Scan};

/// Result of a successful scan: byte offsets of the matched fingerprint within
/// the inspected body, plus the literal pattern that matched (used for logs).
#[derive(Debug, Clone)]
pub struct SilentMatch {
    pub start: usize,
    pub end: usize,
    pub matched_pattern: String,
}

/// Compiled detector. Build once with [`SilentSqlErrorsDetector::from_file`];
/// call [`SilentSqlErrorsDetector::scan`] per response body.
#[derive(Debug, Clone)]
pub struct SilentSqlErrorsDetector {
    /// Original literal pattern strings, indexed by pattern id.
    patterns: Vec<String>,
    /// Pre-built Boyer-Moore searchers for the CPU fast path.
    finders: Vec<Finder<'static>>,
    /// Optional Hyperscan/Vectorscan acceleration database.
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl SilentSqlErrorsDetector {
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
                "failed to read Silent_sql_errors patterns from {}",
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
            "Silent_sql_errors pattern file {} contains no usable patterns",
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

    /// Scan `body` for any known DBMS error fingerprint.
    ///
    /// Returns the first match (lowest offset) or `None` if the body is clean.
    /// Uses Vectorscan when available; otherwise iterates the memchr finders.
    #[must_use]
    pub fn scan(&self, body: &[u8]) -> Option<SilentMatch> {
        #[cfg(feature = "vectorscan-engine")]
        if self.vectorscan_enabled {
            if let Some(db) = &self.vectorscan {
                return vectorscan_scan(db, &self.patterns, body);
            }
        }
        #[cfg(not(feature = "vectorscan-engine"))]
        let _ = self.vectorscan_enabled;

        // memchr fast path: take the leftmost match across all patterns so the
        // scrub always targets the earliest DBMS-error giveaway.
        let mut best: Option<(usize, usize)> = None;
        for (idx, finder) in self.finders.iter().enumerate() {
            if let Some(pos) = finder.find(body) {
                let beats = match best {
                    Some((cur_start, _)) => pos < cur_start,
                    None => true,
                };
                if beats {
                    best = Some((pos, idx));
                    if pos == 0 {
                        break;
                    }
                }
            }
        }
        best.and_then(|(start, idx)| {
            self.patterns.get(idx).map(|p| SilentMatch {
                start,
                end: start + p.len(),
                matched_pattern: p.clone(),
            })
        })
    }

    /// Number of patterns loaded.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ─── Body scrubbing helper ────────────────────────────────────────────────────

/// Produce a new body where `body[m.start..m.end]` is replaced with a single
/// ASCII space. The returned buffer is the modified body to forward to the
/// client; the caller is responsible for updating Content-Length.
#[must_use]
pub fn scrub(body: &[u8], m: &SilentMatch) -> Vec<u8> {
    debug_assert!(m.end <= body.len());
    debug_assert!(m.start <= m.end);
    let mut out = Vec::with_capacity(body.len().saturating_sub(m.end - m.start) + 1);
    out.extend_from_slice(&body[..m.start]);
    out.push(b' ');
    out.extend_from_slice(&body[m.end..]);
    out
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
    super::vectorscan_util::build_block_database(
        patterns,
        Flag::SOM_LEFTMOST | Flag::SINGLEMATCH,
        |p| regex_escape(p).into_bytes(),
    )
}

#[cfg(feature = "vectorscan-engine")]
fn vectorscan_scan(
    db: &BlockDatabase,
    patterns: &[String],
    body: &[u8],
) -> Option<SilentMatch> {
    let mut scanner = db.create_scanner().ok()?;
    let mut best: Option<(usize, usize, usize)> = None; // (start, end, pattern_idx)
    let _ = scanner.scan(body, |id, from, to, _flags| {
        if let (Ok(start), Ok(end), Ok(idx)) = (
            usize::try_from(from),
            usize::try_from(to),
            usize::try_from(id),
        ) {
            let beats = match best {
                Some((cur, _, _)) => start < cur,
                None => true,
            };
            if beats {
                best = Some((start, end, idx));
            }
        }
        Scan::Continue
    });
    best.and_then(|(start, end, idx)| {
        patterns.get(idx).map(|p| SilentMatch {
            start,
            end,
            matched_pattern: p.clone(),
        })
    })
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{scrub, SilentMatch, SilentSqlErrorsDetector};
    use std::io::Write as _;

    fn detector_from_patterns(patterns: &[&str]) -> SilentSqlErrorsDetector {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        for p in patterns {
            writeln!(tmp, "{p}").expect("write pattern");
        }
        SilentSqlErrorsDetector::from_file(tmp.path(), false).expect("build detector")
    }

    fn real_detector() -> SilentSqlErrorsDetector {
        let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rules/error_msgs/sql_errors_static.txt");
        SilentSqlErrorsDetector::from_file(&rules_path, false).expect("load real rules")
    }

    #[test]
    fn detects_mysql_fingerprint() {
        let d = real_detector();
        let body = b"<html>You have an error in your SQL syntax; near</html>";
        let m = d.scan(body).expect("should match MySQL");
        assert!(m.matched_pattern.contains("You have an error in your SQL syntax"));
        assert_eq!(&body[m.start..m.end], m.matched_pattern.as_bytes());
    }

    #[test]
    fn detects_oracle_ora_prefix() {
        let d = real_detector();
        let body = b"ORA-00933: SQL command not properly ended";
        let m = d.scan(body).expect("should match ORA-");
        assert_eq!(&body[m.start..m.end], b"ORA-");
    }

    #[test]
    fn detects_postgresql_fingerprint() {
        let d = real_detector();
        let body = b"PostgreSQL query failed: ERROR: parser: parse error";
        assert!(d.scan(body).is_some());
    }

    #[test]
    fn detects_sqlite_fingerprint() {
        let d = real_detector();
        let body = b"sqlite3.OperationalError: near 'SELECT': syntax error";
        assert!(d.scan(body).is_some());
    }

    #[test]
    fn detects_mssql_unclosed_quotation() {
        let d = real_detector();
        let body = b"Unclosed quotation mark after the character string 'foo'";
        assert!(d.scan(body).is_some());
    }

    #[test]
    fn detects_db2_fingerprint() {
        let d = real_detector();
        let body = b"[IBM][CLI Driver][DB2/6000] SQL0204N is undefined";
        assert!(d.scan(body).is_some());
    }

    #[test]
    fn detects_npgsql_dotnet_fingerprint() {
        let d = real_detector();
        let body = b"Npgsql.PostgresException at row 1";
        assert!(d.scan(body).is_some());
    }

    #[test]
    fn detects_sybase_message() {
        let d = real_detector();
        let body = b"Sybase message: malformed identifier";
        assert!(d.scan(body).is_some());
    }

    #[test]
    fn clean_response_not_flagged() {
        let d = real_detector();
        let body = b"<html><body><h1>Welcome!</h1><p>Your order was processed.</p></body></html>";
        assert!(d.scan(body).is_none());
    }

    #[test]
    fn json_success_not_flagged() {
        let d = real_detector();
        let body = br#"{"status":"ok","data":{"id":42,"name":"Alice"}}"#;
        assert!(d.scan(body).is_none());
    }

    #[test]
    fn scrub_replaces_matched_range_with_single_space() {
        let body = b"<p>You have an error in your SQL syntax; near 'a'</p>";
        let m = SilentMatch {
            start: 3,
            end: 3 + "You have an error in your SQL syntax;".len(),
            matched_pattern: "You have an error in your SQL syntax;".to_string(),
        };
        let scrubbed = scrub(body, &m);
        assert_eq!(&scrubbed[..3], b"<p>");
        assert_eq!(scrubbed[3], b' ');
        // Tail after the scrub matches the tail of the original body.
        assert!(scrubbed.ends_with(b" near 'a'</p>"));
        assert_eq!(scrubbed.len(), body.len() - m.matched_pattern.len() + 1);
    }

    #[test]
    fn skips_comment_and_empty_lines() {
        let d = detector_from_patterns(&["# a comment", "", "ORA-", "  "]);
        // Only "ORA-" should remain; whitespace-only lines are kept as-is in
        // the data file but our trim_end keeps them empty after trimming.
        // The implementation filters by `is_empty() || starts_with('#')` after
        // trim_end, so the "  " case (2 spaces) becomes empty too.
        assert_eq!(d.pattern_count(), 1);
    }

    #[test]
    fn returns_leftmost_match_when_multiple_patterns_match() {
        let d = detector_from_patterns(&["B-PATTERN", "A-PATTERN"]);
        let body = b"prefix A-PATTERN middle B-PATTERN suffix";
        let m = d.scan(body).expect("should match");
        assert_eq!(m.matched_pattern, "A-PATTERN");
        assert_eq!(&body[m.start..m.end], b"A-PATTERN");
    }
}

//! CMC module: DB Error-Based Attack Detection
//!
//! Scans upstream HTTP response bodies for fingerprints of database error
//! messages.  When an attacker probes a backend with injection payloads the
//! DBMS often reflects a verbose error string back through the application.
//! Intercepting that string before it reaches the attacker:
//!
//! * denies error-based SQL/NoSQL injection feedback loops;
//! * prevents information disclosure about the DB engine, schema, or version.
//!
//! Detection strategy
//! ------------------
//! * **Pattern file** — patterns are loaded from `rules/error_msgs/sql_errors.txt`
//!   at WAF startup.  Each non-empty, non-comment line is a PCRE-compatible
//!   regex.  Lines starting with `#` are ignored.
//! * **Compiled at startup** — patterns are compiled into a [`regex::RegexSet`]
//!   once.  Per-response cost is a single linear scan (no recompilation).
//! * **Vectorscan acceleration** — when the `vectorscan-engine` feature is
//!   compiled in and `--enable-vectorscan` is passed, a Hyperscan
//!   [`BlockDatabase`] is built from the same patterns.  The SIMD engine then
//!   does the heavy lifting; the `RegexSet` acts as the CPU fallback if the
//!   vectorscan database could not be compiled (some complex PCRE constructs
//!   are not supported by Hyperscan).
//! * **Threshold-gated action** — the `untrust_level` from
//!   `rules/cmc/config.yaml` controls the response:
//!   - **≥ 60** → block the response (return `Some(DbErrorMatch)`)
//!   - **< 60**  → detection is still reported via the caller (returns
//!     `Some(DbErrorMatch)`) but the `CmcManager` converts this into a
//!     monitor/log-only decision, so the response IS forwarded to the client
//!     while the finding is written to all security log outputs.

use anyhow::{Context, Result};
use regex::RegexSet;
use std::path::Path;

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

// ─── Match result ─────────────────────────────────────────────────────────────

/// Returned when a DB error fingerprint is found in a response body.
#[derive(Debug, Clone)]
pub struct DbErrorMatch {
    matched_pattern: String,
}

impl DbErrorMatch {
    /// The regex pattern that triggered the detection.
    #[must_use]
    pub fn matched_pattern(&self) -> &str {
        &self.matched_pattern
    }
}

// ─── Detector ─────────────────────────────────────────────────────────────────

/// Compiled DB error pattern set.  Build once with [`DbErrorDetector::from_file`];
/// call [`DbErrorDetector::detect`] for each response body.
#[derive(Debug, Clone)]
pub struct DbErrorDetector {
    /// Original pattern strings — needed for reporting the matched pattern.
    patterns: Vec<String>,
    /// All patterns compiled into a single automaton for O(n) scanning.
    compiled: RegexSet,
    /// Optional Hyperscan/Vectorscan acceleration database.
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl DbErrorDetector {
    /// Load and compile patterns from `path`.
    ///
    /// Lines that are empty, start with `#`, or equal `<REGEX_LITERAL>` (a
    /// placeholder sometimes found in templated rule sets) are silently skipped.
    /// Individual patterns that fail to compile as Rust regexes are skipped with
    /// a warning so a single bad rule cannot disable the entire module.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if *no* patterns compile
    /// successfully.
    pub fn from_file(path: &Path, vectorscan_enabled: bool) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read DB error patterns from {}", path.display()))?;

        let patterns: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && *l != "<REGEX_LITERAL>")
            .map(String::from)
            .collect();

        if patterns.is_empty() {
            anyhow::bail!(
                "DB error pattern file {} contains no usable patterns",
                path.display()
            );
        }

        // Filter out patterns that the Rust regex crate cannot compile.
        let valid: Vec<String> = patterns
            .iter()
            .filter(|p| regex::Regex::new(p).is_ok())
            .cloned()
            .collect();

        anyhow::ensure!(
            !valid.is_empty(),
            "no DB error patterns compiled successfully from {}",
            path.display()
        );

        let compiled = RegexSet::new(&valid)
            .with_context(|| "failed to build RegexSet for DB error patterns")?;

        #[cfg(feature = "vectorscan-engine")]
        let vectorscan = if vectorscan_enabled {
            build_vectorscan(&valid)
        } else {
            None
        };

        Ok(Self {
            patterns: valid,
            compiled,
            #[cfg(feature = "vectorscan-engine")]
            vectorscan,
            vectorscan_enabled,
        })
    }

    /// Scan `body` for any known DB error fingerprint.
    ///
    /// Returns the first matching [`DbErrorMatch`], or `None` if the body is
    /// clean.  Vectorscan is used when available; otherwise falls back to the
    /// pre-compiled `RegexSet`.
    #[must_use]
    pub fn detect(&self, body: &str) -> Option<DbErrorMatch> {
        #[cfg(feature = "vectorscan-engine")]
        if self.vectorscan_enabled {
            if let Some(db) = &self.vectorscan {
                return vectorscan_detect(db, &self.patterns, body);
            }
        }

        #[cfg(not(feature = "vectorscan-engine"))]
        let _ = self.vectorscan_enabled;

        self.compiled
            .matches(body)
            .iter()
            .next()
            .and_then(|idx| self.patterns.get(idx))
            .map(|p| DbErrorMatch {
                matched_pattern: p.clone(),
            })
    }

    /// Number of patterns loaded.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ─── Vectorscan helpers ───────────────────────────────────────────────────────

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan(patterns: &[String]) -> Option<BlockDatabase> {
    let vpatterns: Vec<Pattern> = patterns
        .iter()
        .enumerate()
        .filter_map(|(idx, pattern)| {
            u32::try_from(idx).ok().map(|id| {
                Pattern::new(
                    pattern.as_bytes().to_vec(),
                    Flag::SINGLEMATCH | Flag::MULTILINE,
                    Some(id),
                )
            })
        })
        .collect();

    BlockDatabase::new(vpatterns).ok()
}

#[cfg(feature = "vectorscan-engine")]
fn vectorscan_detect(
    db: &BlockDatabase,
    patterns: &[String],
    body: &str,
) -> Option<DbErrorMatch> {
    let mut scanner = db.create_scanner().ok()?;
    let mut matched_idx: Option<usize> = None;

    let _ = scanner.scan(body.as_bytes(), |id, _from, _to, _flags| {
        matched_idx = usize::try_from(id).ok();
        Scan::Terminate
    });

    matched_idx
        .and_then(|idx| patterns.get(idx))
        .map(|p| DbErrorMatch {
            matched_pattern: p.clone(),
        })
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::DbErrorDetector;
    use std::io::Write as _;

    fn detector_from_patterns(patterns: &[&str]) -> DbErrorDetector {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        for p in patterns {
            writeln!(tmp, "{p}").expect("write pattern");
        }
        DbErrorDetector::from_file(tmp.path(), false).expect("build detector")
    }

    fn real_detector() -> DbErrorDetector {
        let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rules/error_msgs/sql_errors.txt");
        DbErrorDetector::from_file(&rules_path, false).expect("load real rules")
    }

    #[test]
    fn detects_mysql_syntax_error() {
        let d = real_detector();
        let body = "You have an error in your SQL syntax; check the manual that \
                    corresponds to your MySQL server version for the right syntax";
        assert!(d.detect(body).is_some(), "should detect MySQL error");
    }

    #[test]
    fn detects_postgresql_error() {
        let d = real_detector();
        let body = "PostgreSQL query failed: ERROR: syntax error at or near \"'\"";
        assert!(d.detect(body).is_some(), "should detect PostgreSQL error");
    }

    #[test]
    fn detects_oracle_ora_error() {
        let d = real_detector();
        let body = "ORA-00933: SQL command not properly ended";
        assert!(d.detect(body).is_some(), "should detect Oracle ORA error");
    }

    #[test]
    fn detects_mssql_error() {
        let d = real_detector();
        let body = "Unclosed quotation mark after the character string 'test'.";
        assert!(d.detect(body).is_some(), "should detect MSSQL error");
    }

    #[test]
    fn detects_mongodb_error() {
        let d = real_detector();
        let body = r#"{"error":"MongoServerError","message":"E11000 duplicate key error"}"#;
        assert!(d.detect(body).is_some(), "should detect MongoDB error");
    }

    #[test]
    fn detects_redis_error() {
        let d = real_detector();
        let body = "ERR syntax error";
        assert!(d.detect(body).is_some(), "should detect Redis error");
    }

    #[test]
    fn detects_sqlite_error() {
        let d = real_detector();
        let body = "sqlite3.OperationalError: near \"SELECT\": syntax error";
        assert!(d.detect(body).is_some(), "should detect SQLite error");
    }

    #[test]
    fn detects_neo4j_cypher_error() {
        let d = real_detector();
        let body = "Neo.ClientError.Statement.SyntaxError: Invalid input";
        assert!(d.detect(body).is_some(), "should detect Neo4j error");
    }

    #[test]
    fn clean_response_not_flagged() {
        let d = real_detector();
        let body = "<html><body><h1>Welcome!</h1><p>Your order was processed.</p></body></html>";
        assert!(d.detect(body).is_none(), "clean HTML should not be flagged");
    }

    #[test]
    fn json_api_success_not_flagged() {
        let d = real_detector();
        let body = r#"{"status":"ok","data":{"id":42,"name":"Alice"}}"#;
        assert!(d.detect(body).is_none(), "clean JSON should not be flagged");
    }

    #[test]
    fn matched_pattern_is_reported() {
        let patterns = &["ORA-\\d{5}", "MySQL.*?error"];
        let d = detector_from_patterns(patterns);
        let m = d
            .detect("ORA-00907: missing right parenthesis")
            .expect("should match ORA error");
        assert!(
            m.matched_pattern().contains("ORA"),
            "matched_pattern should contain ORA"
        );
    }

    #[test]
    fn skips_comment_and_empty_lines() {
        let patterns = &[
            "# this is a comment",
            "",
            "ORA-\\d{5}",
            "<REGEX_LITERAL>",
        ];
        let d = detector_from_patterns(patterns);
        assert_eq!(d.pattern_count(), 1, "only one real pattern");
    }
}

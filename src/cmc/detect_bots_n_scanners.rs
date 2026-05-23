//! CMC module: `Detect_bots_n_scanners`
//!
//! Inspects the request `User-Agent` header for known scanner / crawler /
//! offensive-tooling substrings (Nikto, sqlmap, Nmap, masscan, Nessus,
//! `OpenVAS`, gobuster, dirbuster, Arachni, Nuclei, wfuzz, commix, Acunetix,
//! Havij, …).
//!
//! Pattern source: OWASP Core Rule Set
//! [`scanners-user-agents.data`](https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data)
//! shipped at `rules/user_agents/scanners.txt`.
//!
//! ## Detection strategy
//!
//! * **Pattern file** — one substring per line, comments (`#`) and blank
//!   lines are skipped.
//! * **Fast path** — `aho_corasick::AhoCorasick` (multi-pattern,
//!   case-insensitive) shared across requests.
//! * **Vectorscan path** — when the `vectorscan-engine` feature is compiled
//!   and `--enable-vectorscan` is passed, a Hyperscan `BlockDatabase` of
//!   regex-escaped literals is used instead.
//! * **Action** — governed by the global `Untrust` level:
//!   - `>= 60` → **block** (HTTP 403). The finding is logged at `Low`
//!     severity to raw, `JSONL` and `SQLite` outputs as a bot/scanner sweep.
//!   - `< 60` → silent log only via `tracing::warn!`, request is forwarded.
//!
//! Disabling the module entirely (`Detect_bots_n_scanners: false` in
//! `rules/cmc/config.yaml`) removes all scanner-UA blocking from the engine.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result};
use std::path::Path;

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

/// Result returned by [`DetectBotsNScannersCmc::detect`] when the request
/// `User-Agent` value contains one of the known scanner substrings.
#[derive(Debug, Clone)]
pub struct DetectBotsMatch {
    /// The literal pattern (verbatim from `scanners.txt`) that matched.
    pub matched_pattern: String,
}

impl DetectBotsMatch {
    #[must_use]
    pub fn matched_pattern(&self) -> &str {
        &self.matched_pattern
    }
}

/// Compiled detector. Build once with [`DetectBotsNScannersCmc::from_file`];
/// call [`DetectBotsNScannersCmc::detect`] per request.
#[derive(Debug, Clone)]
pub struct DetectBotsNScannersCmc {
    /// Original literal pattern strings, indexed by Aho-Corasick pattern id.
    patterns: Vec<String>,
    /// Case-insensitive Aho-Corasick matcher used in the CPU fast path.
    ac: AhoCorasick,
    /// Optional Hyperscan/Vectorscan acceleration database.
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl DetectBotsNScannersCmc {
    /// Load and compile patterns from `path`.
    ///
    /// Lines that are empty or start with `#` are skipped. Patterns are
    /// interpreted as **literal byte strings** — case-insensitive substring
    /// match against the `User-Agent` header value.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or contains no usable
    /// patterns, or if the Aho-Corasick automaton fails to build.
    pub fn from_file(path: &Path, vectorscan_enabled: bool) -> Result<Self> {
        let content = std::fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read Detect_bots_n_scanners patterns from {}",
                path.display()
            )
        })?;

        let patterns: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();

        anyhow::ensure!(
            !patterns.is_empty(),
            "Detect_bots_n_scanners pattern file {} contains no usable patterns",
            path.display()
        );

        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns.iter().map(String::as_str))
            .context("failed to compile Detect_bots_n_scanners Aho-Corasick matcher")?;

        #[cfg(feature = "vectorscan-engine")]
        let vectorscan = if vectorscan_enabled {
            build_vectorscan(&patterns)
        } else {
            None
        };

        Ok(Self {
            patterns,
            ac,
            #[cfg(feature = "vectorscan-engine")]
            vectorscan,
            vectorscan_enabled,
        })
    }

    /// Scan the `User-Agent` value for any known scanner / crawler / offensive
    /// tooling substring. Returns the first match or `None` if clean.
    #[must_use]
    pub fn detect(&self, user_agent: &str) -> Option<DetectBotsMatch> {
        if user_agent.is_empty() {
            return None;
        }

        #[cfg(feature = "vectorscan-engine")]
        if self.vectorscan_enabled {
            if let Some(db) = &self.vectorscan {
                return vectorscan_scan(db, &self.patterns, user_agent.as_bytes());
            }
        }
        #[cfg(not(feature = "vectorscan-engine"))]
        let _ = self.vectorscan_enabled;

        let mat = self.ac.find(user_agent)?;
        self.patterns.get(mat.pattern().as_usize()).map(|p| DetectBotsMatch {
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
fn regex_escape_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if matches!(
            c,
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' | '/'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan(patterns: &[String]) -> Option<BlockDatabase> {
    let vpatterns: Vec<Pattern> = patterns
        .iter()
        .enumerate()
        .filter_map(|(idx, pattern)| {
            u32::try_from(idx).ok().map(|id| {
                Pattern::new(
                    regex_escape_literal(pattern).into_bytes(),
                    Flag::SINGLEMATCH | Flag::CASELESS,
                    Some(id),
                )
            })
        })
        .collect();
    BlockDatabase::new(vpatterns).ok()
}

#[cfg(feature = "vectorscan-engine")]
fn vectorscan_scan(
    db: &BlockDatabase,
    patterns: &[String],
    haystack: &[u8],
) -> Option<DetectBotsMatch> {
    let mut scanner = db.create_scanner().ok()?;
    let mut best: Option<(u32, usize)> = None; // (id, pattern_idx)
    let _ = scanner.scan(haystack, |id, _from, _to, _flags| {
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
        patterns.get(idx).map(|p| DetectBotsMatch {
            matched_pattern: p.clone(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::DetectBotsNScannersCmc;
    use std::io::Write;

    fn write_tmp(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tmp");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    #[test]
    fn detects_nikto_case_insensitive() {
        let f = write_tmp("# header\nnikto\nsqlmap\n");
        let d = DetectBotsNScannersCmc::from_file(f.path(), false).expect("build");
        assert_eq!(d.pattern_count(), 2);
        let m = d.detect("Mozilla/5.0 NIKTO/2.1.6").expect("hit");
        assert_eq!(m.matched_pattern(), "nikto");
    }

    #[test]
    fn detects_sqlmap_substring() {
        let f = write_tmp("nikto\nsqlmap\n");
        let d = DetectBotsNScannersCmc::from_file(f.path(), false).expect("build");
        let m = d.detect("sqlmap/1.7-dev").expect("hit");
        assert_eq!(m.matched_pattern(), "sqlmap");
    }

    #[test]
    fn clean_user_agent_passes() {
        let f = write_tmp("nikto\nsqlmap\n");
        let d = DetectBotsNScannersCmc::from_file(f.path(), false).expect("build");
        assert!(d
            .detect("Mozilla/5.0 (X11; Linux x86_64) Chrome/120")
            .is_none());
    }

    #[test]
    fn empty_user_agent_passes() {
        let f = write_tmp("nikto\n");
        let d = DetectBotsNScannersCmc::from_file(f.path(), false).expect("build");
        assert!(d.detect("").is_none());
    }

    #[test]
    fn comments_and_blanks_are_skipped() {
        let f = write_tmp("# a comment\n\nnikto\n  \nsqlmap\n");
        let d = DetectBotsNScannersCmc::from_file(f.path(), false).expect("build");
        assert_eq!(d.pattern_count(), 2);
    }

    #[test]
    fn empty_file_errors() {
        let f = write_tmp("# only comments\n\n");
        let err = DetectBotsNScannersCmc::from_file(f.path(), false);
        assert!(err.is_err(), "expected error on empty pattern file");
    }

    #[test]
    fn nmap_partial_substring_matches() {
        let f = write_tmp("Nmap Scripting Engine\nopenvas\n");
        let d = DetectBotsNScannersCmc::from_file(f.path(), false).expect("build");
        let m = d.detect("Mozilla/5.0 Nmap Scripting Engine/7.94").expect("hit");
        assert_eq!(m.matched_pattern(), "Nmap Scripting Engine");
    }

    #[test]
    fn checks_real_scanners_txt() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rules/user_agents/scanners.txt");
        let d = DetectBotsNScannersCmc::from_file(&p, false).expect("real scanners.txt builds");
        assert!(d.pattern_count() > 20, "expected substantial pattern set");
        // Each of the 5 attack UAs from attack.rs should fire.
        for ua in [
            "nikto/2.1.6",
            "sqlmap/1.7",
            "Nmap Scripting Engine",
            "masscan/1.3",
            "nessus/10.0",
        ] {
            assert!(d.detect(ua).is_some(), "scanner UA not detected: {ua}");
        }
    }
}

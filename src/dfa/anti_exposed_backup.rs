//! DFA module: Anti-Exposed-Backup detector
//!
//! Blocks GET and HEAD requests whose URI path ends with a known backup,
//! temporary, or configuration-leak file extension.  These suffixes are a
//! reliable signal that an operator accidentally left sensitive files reachable
//! on a public URL (e.g. `wp-config.php.bak`, `.env`, `database.sql.`).
//!
//! Detection strategy
//! ------------------
//! * **Method filter** — only GET and HEAD are inspected; POST/PUT/PATCH/DELETE
//!   are never blocked by this module.
//! * **Path extraction** — the raw URI path is stripped of query-string (`?…`)
//!   and fragment (`#…`) before matching so that appending `?foo=1` cannot
//!   bypass a suffix rule.
//! * **Case-insensitive** — `/Admin/Config.BAK` matches the same as
//!   `/admin/config.bak`.
//! * **Suffix-only** — the pattern must end at the last character of the path;
//!   `/file.bak.txt` does **not** match `.bak`.
//! * **Vectorscan acceleration** — when the `vectorscan-engine` feature is
//!   compiled in and `--enable-vectorscan` is passed, the SIMD multi-pattern
//!   engine scans all suffixes simultaneously and post-filters by end-position,
//!   giving a performance boost on long URIs with many segments.

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

/// The canonical list of backup / temporary / leak-prone file extensions.
/// Every entry is matched case-insensitively at the **end** of the URI path.
pub const HIGH_CONFIDENCE_BACKUP_SUFFIXES: &[&str] = &[
    ".bak",
    ".bkp",
    ".backup",
    ".old",
    ".orig",
    ".save",
    ".sav",
    ".swp",
    ".swo",
    ".swn",
    ".swx",
    ".un~",
    ".tmp",
    ".temp",
    ".wbk",
    ".env",
    ".sql.",
    ".dump",
];

// ─── Public types ─────────────────────────────────────────────────────────────

/// Result returned when a backup-file suffix is detected.
#[derive(Debug, Clone, Copy)]
pub struct AntiExposedBackupMatch {
    suffix: &'static str,
}

impl AntiExposedBackupMatch {
    /// The matched suffix string (e.g. `".bak"`).
    pub fn suffix(self) -> &'static str {
        self.suffix
    }
}

// ─── Builder ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AntiExposedBackupDfaBuilder {
    vectorscan_enabled: bool,
}

impl AntiExposedBackupDfaBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vectorscan_enabled(mut self, enabled: bool) -> Self {
        self.vectorscan_enabled = enabled;
        self
    }

    pub fn build(self) -> AntiExposedBackupDfa {
        AntiExposedBackupDfa {
            #[cfg(feature = "vectorscan-engine")]
            vectorscan: self
                .vectorscan_enabled
                .then(build_vectorscan)
                .flatten(),
            vectorscan_enabled: self.vectorscan_enabled,
        }
    }
}

// ─── Detector ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AntiExposedBackupDfa {
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl AntiExposedBackupDfa {
    /// Returns `Some(match)` when the request should be blocked:
    /// - method is GET or HEAD, **and**
    /// - the URI path (without query string) ends with a known backup suffix.
    pub fn detect(&self, method: &str, path: &str) -> Option<AntiExposedBackupMatch> {
        // Only inspect read-only methods; POST/PUT/DELETE are not probes for
        // forgotten backup files in the typical attacker model.
        let m = method.as_bytes();
        let is_get = m.eq_ignore_ascii_case(b"GET");
        let is_head = m.eq_ignore_ascii_case(b"HEAD");
        if !is_get && !is_head {
            return None;
        }

        // Strip query string and fragment — only the path component matters.
        let path = path
            .split_once('?')
            .map(|(p, _)| p)
            .unwrap_or(path);
        let path = path
            .split_once('#')
            .map(|(p, _)| p)
            .unwrap_or(path);

        if path.is_empty() {
            return None;
        }

        // Vectorscan fast path: SIMD multi-pattern scan with end-position filter.
        #[cfg(feature = "vectorscan-engine")]
        if self.vectorscan_enabled {
            if let Some(db) = &self.vectorscan {
                if let Some(suffix) = vectorscan_suffix_find(db, path) {
                    return Some(AntiExposedBackupMatch { suffix });
                }
                // Vectorscan compiled successfully — no match found.
                return None;
            }
        }

        #[cfg(not(feature = "vectorscan-engine"))]
        let _ = self.vectorscan_enabled;

        // Fallback: plain case-insensitive suffix comparison.
        suffix_find_plain(path)
    }
}

// ─── Plain suffix scan ────────────────────────────────────────────────────────

fn suffix_find_plain(path: &str) -> Option<AntiExposedBackupMatch> {
    // Allocate once; typical URIs are short.
    let lower = path.to_ascii_lowercase();
    for &suffix in HIGH_CONFIDENCE_BACKUP_SUFFIXES {
        if lower.ends_with(suffix) {
            return Some(AntiExposedBackupMatch { suffix });
        }
    }
    None
}

// ─── Vectorscan helpers ───────────────────────────────────────────────────────

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan() -> Option<BlockDatabase> {
    let patterns = HIGH_CONFIDENCE_BACKUP_SUFFIXES
        .iter()
        .enumerate()
        .map(|(idx, suffix)| {
            Pattern::new(
                suffix.as_bytes().to_vec(),
                Flag::CASELESS | Flag::SINGLEMATCH,
                Some(idx as u32),
            )
        })
        .collect::<Vec<_>>();

    BlockDatabase::new(patterns).ok()
}

/// Scan `path` for any suffix pattern; accept a match only when it ends at the
/// last byte of `path` (suffix semantics).
#[cfg(feature = "vectorscan-engine")]
fn vectorscan_suffix_find(db: &BlockDatabase, path: &str) -> Option<&'static str> {
    let mut scanner = db.create_scanner().ok()?;
    let bytes = path.as_bytes();
    let end = bytes.len();
    let mut found: Option<&'static str> = None;

    let _ = scanner.scan(bytes, |id, _from, to, _flags| {
        if to as usize == end {
            found = HIGH_CONFIDENCE_BACKUP_SUFFIXES.get(id as usize).copied();
            Scan::Terminate
        } else {
            Scan::Continue
        }
    });

    found
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{AntiExposedBackupDfaBuilder, HIGH_CONFIDENCE_BACKUP_SUFFIXES};

    fn dfa() -> super::AntiExposedBackupDfa {
        AntiExposedBackupDfaBuilder::new().build()
    }

    // ── Positive cases (should block) ─────────────────────────────────────────

    #[test]
    fn blocks_all_suffixes_on_get() {
        let d = dfa();
        for suffix in HIGH_CONFIDENCE_BACKUP_SUFFIXES {
            let path = format!("/var/www/html/config{suffix}");
            assert!(
                d.detect("GET", &path).is_some(),
                "expected block for suffix {suffix:?} in GET {path}"
            );
        }
    }

    #[test]
    fn blocks_head_requests() {
        let d = dfa();
        assert!(d.detect("HEAD", "/wp-config.php.bak").is_some());
        assert!(d.detect("HEAD", "/.env").is_some());
    }

    #[test]
    fn env_dotfile_blocked() {
        let d = dfa();
        assert!(d.detect("GET", "/.env").is_some());
        assert!(d.detect("GET", "/app/.env").is_some());
        assert!(d.detect("GET", "/secrets/.env").is_some());
    }

    #[test]
    fn vim_swap_files_blocked() {
        let d = dfa();
        assert!(d.detect("GET", "/.wp-config.php.swp").is_some());
        assert!(d.detect("GET", "/index.php.swo").is_some());
        assert!(d.detect("GET", "/config.php.swn").is_some());
    }

    #[test]
    fn case_insensitive_match() {
        let d = dfa();
        assert!(d.detect("GET", "/Admin/Config.BAK").is_some());
        assert!(d.detect("GET", "/DB.BACKUP").is_some());
        assert!(d.detect("GET", "/secrets.ENV").is_some());
        assert!(d.detect("GET", "/data.DUMP").is_some());
    }

    #[test]
    fn query_string_stripped_before_match() {
        let d = dfa();
        // Path ends in .bak even with a query string → blocked
        assert!(d.detect("GET", "/config.bak?v=1").is_some());
        // Path does NOT end in .bak; .bak appears only in query string → allowed
        assert!(d.detect("GET", "/api/v1?file=backup.bak").is_none());
    }

    #[test]
    fn fragment_stripped_before_match() {
        let d = dfa();
        assert!(d.detect("GET", "/config.bak#section").is_some());
    }

    // ── Negative cases (should allow) ─────────────────────────────────────────

    #[test]
    fn post_put_delete_not_blocked() {
        let d = dfa();
        for method in &["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
            assert!(
                d.detect(method, "/upload/file.bak").is_none(),
                "method {method} should not be blocked"
            );
        }
    }

    #[test]
    fn normal_extensions_not_blocked() {
        let d = dfa();
        assert!(d.detect("GET", "/index.html").is_none());
        assert!(d.detect("GET", "/style.css").is_none());
        assert!(d.detect("GET", "/api/v1/users").is_none());
        assert!(d.detect("GET", "/assets/logo.png").is_none());
        assert!(d.detect("GET", "/robots.txt").is_none());
    }

    #[test]
    fn suffix_not_at_end_not_blocked() {
        let d = dfa();
        // .bak in the middle — should not match
        assert!(d.detect("GET", "/file.bak.txt").is_none());
        assert!(d.detect("GET", "/backup.old.gz").is_none());
        assert!(d.detect("GET", "/config.env.encrypted").is_none());
    }

    #[test]
    fn matched_suffix_is_reported() {
        let d = dfa();
        let m = d.detect("GET", "/db/prod.dump").unwrap();
        assert_eq!(m.suffix(), ".dump");

        let m = d.detect("GET", "/.env").unwrap();
        assert_eq!(m.suffix(), ".env");
    }
}

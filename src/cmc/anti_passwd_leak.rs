use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::collections::HashSet;

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

/// Tokens that are structurally distinctive of a Unix /etc/passwd file.
/// Two or more distinct tokens in the same response body trigger a block.
pub const PASSWD_TOKENS: &[&str] = &[
    "root:x:0:0:",
    "daemon:x:",
    "bin:x:",
    "nobody:",
    "/bin/bash",
    "/bin/sh",
    "/bin/false",
    "/usr/sbin/nologin",
    "/sbin/nologin",
];

/// Tokens that are structurally distinctive of a Unix /etc/shadow file.
/// Two or more distinct tokens in the same response body trigger a block.
pub const SHADOW_TOKENS: &[&str] = &[
    "root:$y$",
    "root:$6$",
    "root:$5$",
    "root:$1$",
    "root:!:",
    "daemon:",
    "nobody:",
    ":0:99999:7:::",
];

/// Which file type was detected in the response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakKind {
    Passwd,
    Shadow,
}

/// Result returned when a passwd or shadow leak is detected.
#[derive(Debug, Clone, Copy)]
pub struct PasswdLeakMatch {
    pub kind: LeakKind,
    pub token_a: &'static str,
    pub token_b: &'static str,
    pub match_count: usize,
}

impl PasswdLeakMatch {
    pub fn kind(self) -> LeakKind {
        self.kind
    }
    pub fn token_a(self) -> &'static str {
        self.token_a
    }
    pub fn token_b(self) -> &'static str {
        self.token_b
    }
    pub fn match_count(self) -> usize {
        self.match_count
    }
}

#[derive(Debug, Clone, Default)]
pub struct AntiPasswdLeakCmcBuilder {
    vectorscan_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AntiPasswdLeakCmc {
    passwd: MultiMatcher,
    shadow: MultiMatcher,
}

/// Counts distinct pattern matches in a string; fires when ≥ `threshold`
/// distinct patterns from the static set are found.
#[derive(Debug, Clone)]
struct MultiMatcher {
    ac: AhoCorasick,
    patterns: &'static [&'static str],
    threshold: usize,
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl AntiPasswdLeakCmcBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn vectorscan_enabled(mut self, enabled: bool) -> Self {
        self.vectorscan_enabled = enabled;
        self
    }

    #[must_use] 
    pub fn build(self) -> AntiPasswdLeakCmc {
        AntiPasswdLeakCmc {
            passwd: MultiMatcher::new(PASSWD_TOKENS, 2, self.vectorscan_enabled),
            shadow: MultiMatcher::new(SHADOW_TOKENS, 2, self.vectorscan_enabled),
        }
    }
}

impl MultiMatcher {
    fn new(patterns: &'static [&'static str], threshold: usize, vectorscan_enabled: bool) -> Self {
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(false)
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("static passwd-leak CMC patterns must compile");

        Self {
            ac,
            patterns,
            threshold,
            #[cfg(feature = "vectorscan-engine")]
            vectorscan: vectorscan_enabled
                .then(|| build_vectorscan(patterns))
                .flatten(),
            vectorscan_enabled,
        }
    }

    /// Returns `(distinct_count, first_token, second_token)` when ≥ `threshold`
    /// distinct patterns are found, otherwise `None`.
    fn count_distinct(&self, input: &str) -> Option<(usize, &'static str, &'static str)> {
        #[cfg(feature = "vectorscan-engine")]
        if self.vectorscan_enabled {
            if let Some(db) = &self.vectorscan {
                return self.vectorscan_count(db, input);
            }
        }

        #[cfg(not(feature = "vectorscan-engine"))]
        let _ = self.vectorscan_enabled;

        self.ac_count(input)
    }

    fn ac_count(&self, input: &str) -> Option<(usize, &'static str, &'static str)> {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut first: Option<&'static str> = None;
        let mut second: Option<&'static str> = None;

        for mat in self.ac.find_iter(input) {
            let pid = mat.pattern().as_usize();
            if seen.insert(pid) {
                if first.is_none() {
                    first = self.patterns.get(pid).copied();
                } else if second.is_none() {
                    second = self.patterns.get(pid).copied();
                }
            }
        }

        let count = seen.len();
        if count >= self.threshold {
            Some((count, first?, second?))
        } else {
            None
        }
    }

    #[cfg(feature = "vectorscan-engine")]
    fn vectorscan_count(
        &self,
        db: &BlockDatabase,
        input: &str,
    ) -> Option<(usize, &'static str, &'static str)> {
        let mut scanner = db.create_scanner().ok()?;
        let mut matched: Vec<usize> = Vec::new();

        let _ = scanner.scan(input.as_bytes(), |id, _from, _to, _flags| {
            let idx = id as usize;
            if !matched.contains(&idx) {
                matched.push(idx);
            }
            Scan::Continue
        });

        let count = matched.len();
        if count >= self.threshold {
            let first = self.patterns.get(matched[0]).copied()?;
            let second = self.patterns.get(matched[1]).copied()?;
            Some((count, first, second))
        } else {
            None
        }
    }
}

impl AntiPasswdLeakCmc {
    /// Inspect a response body string.  Returns a `PasswdLeakMatch` when the body
    /// contains ≥ 2 distinct `PASSWD_TOKENS` or ≥ 2 distinct `SHADOW_TOKENS`.
    pub fn detect(&self, input: &str) -> Option<PasswdLeakMatch> {
        if let Some((count, token_a, token_b)) = self.passwd.count_distinct(input) {
            return Some(PasswdLeakMatch {
                kind: LeakKind::Passwd,
                token_a,
                token_b,
                match_count: count,
            });
        }
        if let Some((count, token_a, token_b)) = self.shadow.count_distinct(input) {
            return Some(PasswdLeakMatch {
                kind: LeakKind::Shadow,
                token_a,
                token_b,
                match_count: count,
            });
        }
        None
    }
}

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan(patterns: &[&str]) -> Option<BlockDatabase> {
    let vpatterns = patterns
        .iter()
        .enumerate()
        .map(|(idx, pattern)| {
            Pattern::new(
                pattern.as_bytes().to_vec(),
                Flag::SINGLEMATCH,
                Some(idx as u32),
            )
        })
        .collect::<Vec<_>>();

    BlockDatabase::new(vpatterns).ok()
}

#[cfg(test)]
mod tests {
    use super::{AntiPasswdLeakCmcBuilder, LeakKind};

    fn make_cmc() -> super::AntiPasswdLeakCmc {
        AntiPasswdLeakCmcBuilder::new().build()
    }

    #[test]
    fn detects_passwd_with_two_tokens() {
        let d = make_cmc();
        let body = "root:x:0:0:root:/root:/bin/bash\n\
                    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
        let m = d.detect(body).expect("should detect passwd leak");
        assert!(matches!(m.kind, LeakKind::Passwd));
        assert!(m.match_count >= 2);
    }

    #[test]
    fn single_passwd_token_not_blocked() {
        let d = make_cmc();
        assert!(d.detect("The default shell /bin/bash is commonly used").is_none());
    }

    #[test]
    fn detects_shadow_with_two_tokens() {
        let d = make_cmc();
        let body = "root:$6$somesalt$longhash:19000:0:99999:7:::\n\
                    daemon:*:18858:0:99999:7:::\n";
        let m = d.detect(body).expect("should detect shadow leak");
        assert!(matches!(m.kind, LeakKind::Shadow));
        assert!(m.match_count >= 2);
    }

    #[test]
    fn single_shadow_token_not_blocked() {
        let d = make_cmc();
        assert!(d.detect("daemon: the background service").is_none());
    }

    #[test]
    fn benign_response_allowed() {
        let d = make_cmc();
        assert!(d.detect("Welcome to our site! Please log in.").is_none());
        assert!(d.detect(r#"{"user":"alice","role":"admin"}"#).is_none());
        assert!(d.detect("<html><body><h1>Hello world</h1></body></html>").is_none());
    }

    #[test]
    fn realistic_passwd_dump_blocked() {
        let d = make_cmc();
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
                      nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        let m = d.detect(passwd).expect("full passwd dump must be detected");
        assert!(matches!(m.kind, LeakKind::Passwd));
    }

    #[test]
    fn realistic_shadow_dump_blocked() {
        let d = make_cmc();
        let shadow = "root:$6$salt$hash:19000:0:99999:7:::\n\
                      daemon:*:18858:0:99999:7:::\n\
                      nobody:*:18858:0:99999:7:::\n";
        let m = d.detect(shadow).expect("full shadow dump must be detected");
        assert!(matches!(m.kind, LeakKind::Shadow));
    }

    #[test]
    fn passwd_does_not_fire_on_shadow_only_content() {
        let d = make_cmc();
        // A body with only shadow tokens — must be detected as Shadow, not Passwd
        let shadow_only = "root:$6$salt$hash:19000:0:99999:7:::\ndaemon:*:0:99999:7:::\n";
        if let Some(m) = d.detect(shadow_only) {
            assert!(matches!(m.kind, LeakKind::Shadow));
        }
    }

    #[test]
    fn passwd_takes_priority_when_both_present() {
        let d = make_cmc();
        // Contains tokens from both tables; passwd check runs first.
        let mixed = "root:x:0:0:root:/root:/bin/bash\nroot:$6$salt$hash:19000:0:99999:7:::\n";
        let m = d.detect(mixed).expect("mixed body must be detected");
        assert!(matches!(m.kind, LeakKind::Passwd));
    }
}

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

const LIST_A: &[&str] = &[
    "$gt",
    "$nin",
    "$where",
    "$save",
    "$exists",
    "$remove",
    "$in",
    "$comment",
    "selector",
    "$or",
    "$and",
    "this.password.match",
    "db.stores.mapreduce",
    "db.injection.insert",
    "&&",
    "||",
];

const LIST_B: &[&str] = &[
    "==1",
    "== 1",
    "]=1",
    "] = 1",
    "true",
    "sleep(",
    "logins",
    "admin",
    "pass",
    "user",
    "undefined",
    "date",
    "null",
    "root",
    "new%",
    "%00",
    "{}",
    "success",
    ".insert",
    "while(true)",
    "dropdatabase(",
];

#[derive(Debug, Clone, Default)]
pub struct NoSqlInjectionDfaBuilder {
    vectorscan_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct NoSqlInjectionDfa {
    list_a: LiteralMatcher,
    list_b: LiteralMatcher,
}

#[derive(Debug, Clone, Copy)]
pub struct NoSqlInjectionMatch {
    list_a: &'static str,
    list_b: &'static str,
}

#[derive(Debug, Clone)]
struct LiteralMatcher {
    ac: AhoCorasick,
    patterns: &'static [&'static str],
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl NoSqlInjectionMatch {
    pub fn list_a(self) -> &'static str {
        self.list_a
    }

    pub fn list_b(self) -> &'static str {
        self.list_b
    }
}

impl NoSqlInjectionDfaBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vectorscan_enabled(mut self, enabled: bool) -> Self {
        self.vectorscan_enabled = enabled;
        self
    }

    pub fn build(self) -> NoSqlInjectionDfa {
        NoSqlInjectionDfa {
            list_a: LiteralMatcher::new(LIST_A, self.vectorscan_enabled),
            list_b: LiteralMatcher::new(LIST_B, self.vectorscan_enabled),
        }
    }
}

impl NoSqlInjectionDfa {
    pub fn detect(&self, input: &str) -> Option<NoSqlInjectionMatch> {
        let list_a = self.list_a.find(input)?;
        let list_b = self
            .list_b
            .find(input)
            .or_else(|| detect_numeric_equality(input))?;
        Some(NoSqlInjectionMatch { list_a, list_b })
    }
}

impl LiteralMatcher {
    fn new(patterns: &'static [&'static str], vectorscan_enabled: bool) -> Self {
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("static NoSQL DFA patterns must compile");

        Self {
            ac,
            patterns,
            #[cfg(feature = "vectorscan-engine")]
            vectorscan: vectorscan_enabled
                .then(|| build_vectorscan(patterns))
                .flatten(),
            vectorscan_enabled,
        }
    }

    fn find(&self, input: &str) -> Option<&'static str> {
        #[cfg(feature = "vectorscan-engine")]
        if self.vectorscan_enabled {
            if let Some(db) = &self.vectorscan {
                if let Some(pattern) = vectorscan_find(db, self.patterns, input) {
                    return Some(pattern);
                }
            }
        }

        #[cfg(not(feature = "vectorscan-engine"))]
        let _ = self.vectorscan_enabled;

        self.ac
            .find(input)
            .and_then(|mat| self.patterns.get(mat.pattern().as_usize()).copied())
    }
}

fn detect_numeric_equality(input: &str) -> Option<&'static str> {
    let bytes = input.as_bytes();
    let mut idx = 0usize;

    while idx + 2 <= bytes.len() {
        if bytes[idx] == b'=' && bytes[idx + 1] == b'=' {
            let mut cursor = idx + 2;
            if bytes.get(cursor).copied() == Some(b' ') {
                cursor += 1;
            }
            if bytes
                .get(cursor)
                .copied()
                .is_some_and(|b| matches!(b, b'1'..=b'9'))
            {
                return Some("==[1-9]");
            }
        }
        idx += 1;
    }

    None
}

#[cfg(feature = "vectorscan-engine")]
fn build_vectorscan(patterns: &[&str]) -> Option<BlockDatabase> {
    let patterns = patterns
        .iter()
        .enumerate()
        .map(|(idx, pattern)| {
            Pattern::new(
                pattern.as_bytes().to_vec(),
                Flag::CASELESS | Flag::SINGLEMATCH,
                Some(idx as u32),
            )
        })
        .collect::<Vec<_>>();

    BlockDatabase::new(patterns).ok()
}

#[cfg(feature = "vectorscan-engine")]
fn vectorscan_find(
    db: &BlockDatabase,
    patterns: &'static [&'static str],
    input: &str,
) -> Option<&'static str> {
    let mut scanner = db.create_scanner().ok()?;
    let mut matched_index: Option<usize> = None;
    let _ = scanner.scan(input.as_bytes(), |id, _from, _to, _flags| {
        matched_index = Some(id as usize);
        Scan::Terminate
    });

    matched_index.and_then(|idx| patterns.get(idx).copied())
}

#[cfg(test)]
mod tests {
    use super::NoSqlInjectionDfaBuilder;

    #[test]
    fn requires_one_marker_from_each_list() {
        let dfa = NoSqlInjectionDfaBuilder::new().build();

        assert!(dfa
            .detect(r#"{"user":{"$gt":""},"pass":"admin"}"#)
            .is_some());
        assert!(dfa
            .detect(r#"selector[$where]=this.password.match(/admin/)"#)
            .is_some());
        assert!(dfa.detect(r#"{"$or":[{"role":"root"}]}"#).is_some());
        assert!(dfa.detect(r#"{"$where":"sleep(5000)"}"#).is_some());

        assert!(dfa.detect(r#"{"$gt":""}"#).is_none());
        assert!(dfa.detect(r#"{"user":"admin"}"#).is_none());
    }

    #[test]
    fn detects_numeric_equality_as_list_b() {
        let dfa = NoSqlInjectionDfaBuilder::new().build();

        assert!(dfa.detect(r#"{"$where":"this.age==7"}"#).is_some());
        assert!(dfa.detect(r#"{"$where":"this.age== 9"}"#).is_some());
        assert!(dfa.detect(r#"{"$where":"this.age==0"}"#).is_none());
    }
}

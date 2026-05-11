use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

// ─── Signal pattern tables ────────────────────────────────────────────────────

/// Signal-A text patterns: Java magic byte sequences represented in text form.
/// Binary magic is handled separately via `check_binary_magic`.
pub const SIGNAL_A_TEXT: &[&str] = &[
    "rO0AB",   // base64 prefix for AC ED 00 05 00 (very common in larger blobs)
    "rO0A",    // base64 prefix for AC ED 00 05 (Java stream magic + version)
    "H4sI",    // base64-GZIP prefix (1F 8B encoded)
    "%AC%ED",  // URL-encoded Java magic (uppercase hex)
    "%ac%ed",  // URL-encoded Java magic (lowercase hex)
    "aced",    // ASCII hex of AC ED (decimal: -84 -19)
];

/// Signal-B text patterns: headers announcing a Java serialized object.
pub const SIGNAL_B_TEXT: &[&str] = &[
    "application/x-java-serialized-object",
];

/// Signal-C text patterns: encoded base64 prefixes that appear in serialized blobs.
pub const SIGNAL_C_TEXT: &[&str] = &[
    "rO0AB",  // longest first (avoids subset shadowing in LeftmostFirst mode)
    "rO0A",
    "rO0",
];

/// Binary magic sequences for Signal A (checked against raw bytes, not UTF-8 text).
pub const JAVA_DESER_BINARY_MAGIC: &[(&[u8], &str)] = &[
    (b"\xAC\xED\x00\x05", "ACED0005"),  // Java stream magic + version 5
    (b"\xAC\xED", "ACED"),              // Java stream magic (partial)
    (b"\x1f\x8b", "1F8B"),              // GZIP magic (compressed Java object)
];

// ─── Result types ─────────────────────────────────────────────────────────────

/// Carries the details of a Java deserialization detection.
#[derive(Debug, Clone)]
pub struct JavaDeserMatch {
    pub signal_count: u8,
    pub signal_a: bool,
    pub signal_b: bool,
    pub signal_c: bool,
    pub evidence: String,
}

impl JavaDeserMatch {
    pub fn signal_count(&self) -> u8 {
        self.signal_count
    }
    pub fn evidence(&self) -> &str {
        &self.evidence
    }
    pub fn signals_fired(&self) -> String {
        let mut parts = Vec::new();
        if self.signal_a {
            parts.push("A(magic)");
        }
        if self.signal_b {
            parts.push("B(header)");
        }
        if self.signal_c {
            parts.push("C(prefix)");
        }
        parts.join("+")
    }
}

/// Decision returned by `JavaDeserializeCmc::detect`.
#[derive(Debug, Clone)]
pub enum JavaDeserDecision {
    /// Always block: 3 signals, or 2 signals with `untrust_level >= 60`.
    Block(JavaDeserMatch),
    /// 2 signals but `untrust_level < 60`: log silently, do not block.
    SuspiciousHigh(JavaDeserMatch),
    /// 1 signal and `untrust_level > 80`: log informatively, do not block.
    SuspiciousLow(JavaDeserMatch),
    /// 0 signals, or 1 signal with `untrust_level <= 80`.
    Clean,
}

// ─── Internals ────────────────────────────────────────────────────────────────

/// Single-match Aho-Corasick + optional Vectorscan backend for one signal category.
#[derive(Debug, Clone)]
struct SingleMatcher {
    ac: AhoCorasick,
    patterns: &'static [&'static str],
    #[cfg(feature = "vectorscan-engine")]
    vs: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl SingleMatcher {
    fn new(
        patterns: &'static [&'static str],
        case_insensitive: bool,
        vectorscan_enabled: bool,
        #[cfg(feature = "vectorscan-engine")] vs_caseless: bool,
    ) -> Self {
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(case_insensitive)
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("java_deserialize_detect: static AC patterns must compile");

        #[cfg(feature = "vectorscan-engine")]
        let vs = if vectorscan_enabled {
            build_vs_matcher(patterns, vs_caseless)
        } else {
            None
        };

        Self {
            ac,
            patterns,
            #[cfg(feature = "vectorscan-engine")]
            vs,
            vectorscan_enabled,
        }
    }

    fn first_match(&self, input: &str) -> Option<&'static str> {
        #[cfg(feature = "vectorscan-engine")]
        if self.vectorscan_enabled {
            if let Some(db) = &self.vs {
                return vs_first_pattern(db, input, self.patterns);
            }
        }

        #[cfg(not(feature = "vectorscan-engine"))]
        let _ = self.vectorscan_enabled;

        self.ac
            .find(input)
            .and_then(|m| self.patterns.get(m.pattern().as_usize()).copied())
    }
}

#[cfg(feature = "vectorscan-engine")]
fn build_vs_matcher(patterns: &[&str], caseless: bool) -> Option<BlockDatabase> {
    let vpatterns = patterns
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let flags = if caseless {
                Flag::CASELESS | Flag::SINGLEMATCH
            } else {
                Flag::SINGLEMATCH
            };
            Pattern::new(p.as_bytes().to_vec(), flags, Some(idx as u32))
        })
        .collect::<Vec<_>>();
    BlockDatabase::new(vpatterns).ok()
}

#[cfg(feature = "vectorscan-engine")]
fn vs_first_pattern(
    db: &BlockDatabase,
    input: &str,
    patterns: &'static [&'static str],
) -> Option<&'static str> {
    let mut scanner = db.create_scanner().ok()?;
    let mut first_id: Option<usize> = None;
    let _ = scanner.scan(input.as_bytes(), |id, _from, _to, _flags| {
        first_id.get_or_insert(id as usize);
        Scan::Terminate
    });
    first_id.and_then(|id| patterns.get(id).copied())
}

// ─── CMC ──────────────────────────────────────────────────────────────────────

/// Builder for `JavaDeserializeCmc`.
#[derive(Debug, Clone)]
pub struct JavaDeserializeCmcBuilder {
    untrust_level: u8,
    vectorscan_enabled: bool,
}

impl Default for JavaDeserializeCmcBuilder {
    fn default() -> Self {
        Self {
            untrust_level: 60,
            vectorscan_enabled: false,
        }
    }
}

impl JavaDeserializeCmcBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn untrust_level(mut self, level: u8) -> Self {
        self.untrust_level = level.min(100);
        self
    }

    #[must_use] 
    pub fn vectorscan_enabled(mut self, enabled: bool) -> Self {
        self.vectorscan_enabled = enabled;
        self
    }

    #[must_use] 
    pub fn build(self) -> JavaDeserializeCmc {
        JavaDeserializeCmc {
            signal_a: SingleMatcher::new(
                SIGNAL_A_TEXT,
                false, // case-sensitive: rO0A and H4sI are base64
                self.vectorscan_enabled,
                #[cfg(feature = "vectorscan-engine")]
                false,
            ),
            signal_b: SingleMatcher::new(
                SIGNAL_B_TEXT,
                true, // case-insensitive: HTTP headers
                self.vectorscan_enabled,
                #[cfg(feature = "vectorscan-engine")]
                true,
            ),
            signal_c: SingleMatcher::new(
                SIGNAL_C_TEXT,
                false, // case-sensitive: base64 prefixes
                self.vectorscan_enabled,
                #[cfg(feature = "vectorscan-engine")]
                false,
            ),
            untrust_level: self.untrust_level,
        }
    }
}

/// Detects Java deserialization attack signals across three independent categories.
///
/// Scoring:
/// - 3 signals                              → `Block`
/// - 2 signals, `untrust_level >= 60`       → `Block`
/// - 2 signals, `untrust_level < 60`        → `SuspiciousHigh` (silent log only)
/// - 1 signal,  `untrust_level > 80`        → `SuspiciousLow`  (info log only)
/// - 0 signals, or 1 signal with level ≤ 80 → `Clean`
#[derive(Debug, Clone)]
pub struct JavaDeserializeCmc {
    signal_a: SingleMatcher,
    signal_b: SingleMatcher,
    signal_c: SingleMatcher,
    untrust_level: u8,
}

impl JavaDeserializeCmc {
    /// Inspect `text` (header + body as UTF-8 lossy) and `raw_bytes` (the raw
    /// body) for Java deserialization signals. Returns a `JavaDeserDecision`.
    pub fn detect(&self, text: &str, raw_bytes: &[u8]) -> JavaDeserDecision {
        let (signal_a, ev_a) = self.check_signal_a(text, raw_bytes);
        let (signal_b, ev_b) = self.check_signal_b(text);
        let (signal_c, ev_c) = self.check_signal_c(text);

        let count = u8::from(signal_a) + u8::from(signal_b) + u8::from(signal_c);

        if count == 0 {
            return JavaDeserDecision::Clean;
        }

        let evidence = [ev_a.as_deref(), ev_b, ev_c]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");

        let m = JavaDeserMatch {
            signal_count: count,
            signal_a,
            signal_b,
            signal_c,
            evidence,
        };

        match count {
            3.. => JavaDeserDecision::Block(m),
            2 => {
                if self.untrust_level >= 60 {
                    JavaDeserDecision::Block(m)
                } else {
                    JavaDeserDecision::SuspiciousHigh(m)
                }
            }
            _ => {
                // count == 1
                if self.untrust_level > 80 {
                    JavaDeserDecision::SuspiciousLow(m)
                } else {
                    JavaDeserDecision::Clean
                }
            }
        }
    }

    fn check_signal_a(&self, text: &str, raw_bytes: &[u8]) -> (bool, Option<String>) {
        // Binary magic has priority (most reliable indicator).
        for (magic, label) in JAVA_DESER_BINARY_MAGIC {
            if raw_bytes.windows(magic.len()).any(|w| w == *magic) {
                return (true, Some(format!("binary:0x{label}")));
            }
        }
        // Text-encoded forms (base64, URL-encoded, ASCII hex).
        if let Some(pat) = self.signal_a.first_match(text) {
            return (true, Some(format!("text:{pat}")));
        }
        (false, None)
    }

    fn check_signal_b(&self, text: &str) -> (bool, Option<&'static str>) {
        self.signal_b
            .first_match(text)
            .map_or((false, None), |p| (true, Some(p)))
    }

    fn check_signal_c(&self, text: &str) -> (bool, Option<&'static str>) {
        self.signal_c
            .first_match(text)
            .map_or((false, None), |p| (true, Some(p)))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmc_default() -> JavaDeserializeCmc {
        JavaDeserializeCmcBuilder::new().build()
    }

    fn make_cmc_untrust(level: u8) -> JavaDeserializeCmc {
        JavaDeserializeCmcBuilder::new().untrust_level(level).build()
    }

    // ─── Signal-A (magic) ─────────────────────────────────────────────────

    #[test]
    fn signal_a_raw_binary_fires() {
        let d = make_cmc_default();
        let bytes = b"\xAC\xED\x00\x05some payload";
        let r = d.detect("", bytes);
        // 1 signal (A only) with untrust=60 → Clean
        assert!(matches!(r, JavaDeserDecision::Clean), "single binary signal should not block with untrust=60");
    }

    #[test]
    fn signal_a_base64_text_fires() {
        let d = make_cmc_default();
        // rO0A fires signal A + signal C → 2 signals → Block with untrust=60
        let r = d.detect("rO0AAABwdXI=", b"rO0AAABwdXI=");
        assert!(matches!(r, JavaDeserDecision::Block(_)), "rO0A fires A+C (2 signals) → block at untrust=60");
    }

    #[test]
    fn signal_a_gzip_binary_fires() {
        let d = make_cmc_default();
        let bytes = b"\x1f\x8bsome gzip data";
        let r = d.detect("", bytes);
        assert!(matches!(r, JavaDeserDecision::Clean), "gzip alone should not block at untrust=60");
    }

    #[test]
    fn signal_a_url_encoded_fires_with_header() {
        let d = make_cmc_default();
        // %AC%ED fires signal A; header fires signal B → 2 signals
        let text = "POST /upload HTTP/1.1\nContent-Type: application/x-java-serialized-object\nbody=%AC%EDpayload";
        let r = d.detect(text, b"body=%AC%EDpayload");
        assert!(matches!(r, JavaDeserDecision::Block(_)), "%AC%ED + header → 2 signals → block");
    }

    #[test]
    fn signal_a_ascii_hex_aced_fires() {
        let d = make_cmc_default();
        // "aced" alone is 1 signal A → Clean at untrust=60
        let r = d.detect("data=aced0005", b"data=aced0005");
        assert!(matches!(r, JavaDeserDecision::Clean), "aced alone → 1 signal → no block at untrust=60");
    }

    // ─── Signal-B (headers) ───────────────────────────────────────────────

    #[test]
    fn signal_b_content_type_header_fires() {
        let d = make_cmc_default();
        let text = "POST / HTTP/1.1\nContent-Type: application/x-java-serialized-object\n\nbody";
        let r = d.detect(text, b"body");
        // 1 signal (B) → Clean at untrust=60
        assert!(matches!(r, JavaDeserDecision::Clean), "header alone → 1 signal → no block at untrust=60");
    }

    #[test]
    fn signal_b_accept_header_fires() {
        let d = make_cmc_default();
        let text = "GET / HTTP/1.1\nAccept: application/x-java-serialized-object\n\n";
        let r = d.detect(text, b"");
        assert!(matches!(r, JavaDeserDecision::Clean), "accept header alone → 1 signal → no block at untrust=60");
    }

    #[test]
    fn signal_b_case_insensitive() {
        let d = make_cmc_default();
        let text = "Content-Type: APPLICATION/X-JAVA-SERIALIZED-OBJECT\n\nrO0A";
        let r = d.detect(text, b"rO0A");
        // Header (B) + rO0A (A) + rO0A (C) → 3 signals
        assert!(matches!(r, JavaDeserDecision::Block(_)));
    }

    // ─── Signal-C (encoded prefix) ────────────────────────────────────────

    #[test]
    fn signal_c_ro0_prefix_alone_does_not_block() {
        let d = make_cmc_default();
        // rO0 alone fires C (1 signal) → Clean at untrust=60
        let r = d.detect("payload=rO0==", b"payload=rO0==");
        assert!(matches!(r, JavaDeserDecision::Clean), "rO0 alone → 1 signal → no block at untrust=60");
    }

    #[test]
    fn signal_c_ro0ab_fires_with_header() {
        let d = make_cmc_default();
        let text = "Content-Type: application/x-java-serialized-object\n\nrO0ABQAAAABw";
        let r = d.detect(text, b"rO0ABQAAAABw");
        // B + A (rO0AB matches signal A) + C → 3 signals
        assert!(matches!(r, JavaDeserDecision::Block(_)));
    }

    // ─── Scoring / untrust level ──────────────────────────────────────────

    #[test]
    fn two_signals_block_at_untrust_60() {
        let d = make_cmc_untrust(60);
        // Binary magic (A) + header (B) → 2 signals → Block
        let text = "Content-Type: application/x-java-serialized-object\n\ndata";
        let bytes = b"\xAC\xED\x00\x05data";
        let r = d.detect(text, bytes);
        assert!(matches!(r, JavaDeserDecision::Block(_)), "2 signals at untrust=60 must block");
    }

    #[test]
    fn two_signals_suspicious_high_below_untrust_60() {
        let d = make_cmc_untrust(40);
        let text = "Content-Type: application/x-java-serialized-object\n\ndata";
        let bytes = b"\xAC\xED\x00\x05data";
        let r = d.detect(text, bytes);
        assert!(matches!(r, JavaDeserDecision::SuspiciousHigh(_)), "2 signals at untrust=40 → SuspiciousHigh");
    }

    #[test]
    fn one_signal_suspicious_low_above_untrust_80() {
        let d = make_cmc_untrust(90);
        // Only a header (1 signal)
        let text = "Accept: application/x-java-serialized-object\n\nhello";
        let r = d.detect(text, b"hello");
        assert!(matches!(r, JavaDeserDecision::SuspiciousLow(_)), "1 signal at untrust=90 → SuspiciousLow");
    }

    #[test]
    fn one_signal_clean_at_default_untrust() {
        let d = make_cmc_default(); // untrust=60
        let text = "Accept: application/x-java-serialized-object\n\nhello";
        let r = d.detect(text, b"hello");
        assert!(matches!(r, JavaDeserDecision::Clean), "1 signal at untrust=60 → Clean");
    }

    #[test]
    fn three_signals_always_block() {
        let d = make_cmc_untrust(0); // even untrust=0 should not matter for 3 signals
        let text = "Content-Type: application/x-java-serialized-object\n\nrO0AAABw";
        let bytes = b"\xAC\xED\x00\x05rO0AAABw";
        let r = d.detect(text, bytes);
        assert!(matches!(r, JavaDeserDecision::Block(_)), "3 signals always block regardless of untrust");
    }

    #[test]
    fn clean_benign_request_is_allowed() {
        let d = make_cmc_default();
        let text = "POST /api/login HTTP/1.1\nContent-Type: application/json\n\n{\"user\":\"alice\"}";
        let r = d.detect(text, b"{\"user\":\"alice\"}");
        assert!(matches!(r, JavaDeserDecision::Clean));
    }

    #[test]
    fn h4si_base64_gzip_fires_signal_a() {
        let d = make_cmc_default();
        // H4sI alone is 1 signal (A) → Clean
        let r = d.detect("H4sIAAAAAAAAA", b"H4sIAAAAAAAAA");
        assert!(matches!(r, JavaDeserDecision::Clean), "H4sI alone → 1 signal → no block at untrust=60");
    }

    #[test]
    fn combined_ro0a_and_java_header_blocks() {
        // rO0A fires A + C (2 signals), header fires B (3rd signal) → Block
        let d = make_cmc_default();
        let text = "POST /deserialize HTTP/1.1\nContent-Type: application/x-java-serialized-object\n\nrO0AAABwdXI=";
        let r = d.detect(text, b"rO0AAABwdXI=");
        assert!(matches!(r, JavaDeserDecision::Block(_)));
    }

    #[test]
    fn match_reports_signal_flags_correctly() {
        let d = make_cmc_default();
        let text = "Content-Type: application/x-java-serialized-object\n\nrO0AAABw";
        let bytes = b"\xAC\xED\x00\x05rO0AAABw";
        match d.detect(text, bytes) {
            JavaDeserDecision::Block(m) => {
                assert!(m.signal_a, "binary magic must fire signal A");
                assert!(m.signal_b, "header must fire signal B");
                assert!(m.signal_c, "rO0A must fire signal C");
                assert_eq!(m.signal_count, 3);
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }
}

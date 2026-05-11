use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

#[cfg(feature = "vectorscan-engine")]
use vectorscan::{BlockDatabase, Flag, Pattern, Scan};

const LIST_A: &[&str] = &["entity", "xi:include"];

const LIST_B: &[&str] = &[
    "xxe",
    "system",
    "etc/password",
    "eval",
    "exfil",
    "xmlns:xi",
    "send",
    "doctype",
    "soap",
    "file",
];

#[derive(Debug, Clone, Default)]
pub struct XxeAttackCmcBuilder {
    vectorscan_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct XxeAttackCmc {
    list_a: LiteralMatcher,
    list_b: LiteralMatcher,
}

#[derive(Debug, Clone, Copy)]
pub struct XxeAttackMatch {
    list_a: &'static str,
    list_b: &'static str,
    decoded_utf16: bool,
}

#[derive(Debug, Clone)]
struct LiteralMatcher {
    ac: AhoCorasick,
    patterns: &'static [&'static str],
    #[cfg(feature = "vectorscan-engine")]
    vectorscan: Option<BlockDatabase>,
    vectorscan_enabled: bool,
}

impl XxeAttackMatch {
    pub fn list_a(self) -> &'static str {
        self.list_a
    }

    pub fn list_b(self) -> &'static str {
        self.list_b
    }

    pub fn decoded_utf16(self) -> bool {
        self.decoded_utf16
    }
}

impl XxeAttackCmcBuilder {
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
    pub fn build(self) -> XxeAttackCmc {
        XxeAttackCmc {
            list_a: LiteralMatcher::new(LIST_A, self.vectorscan_enabled),
            list_b: LiteralMatcher::new(LIST_B, self.vectorscan_enabled),
        }
    }
}

impl XxeAttackCmc {
    pub fn detect(&self, input: &str) -> Option<XxeAttackMatch> {
        if let Some(matched) = self.detect_view(input, false) {
            return Some(matched);
        }

        for decoded in utf16_views(input) {
            if let Some(matched) = self.detect_view(&decoded, true) {
                return Some(matched);
            }
        }

        None
    }

    fn detect_view(&self, input: &str, decoded_utf16: bool) -> Option<XxeAttackMatch> {
        let list_a = self.list_a.find(input)?;
        let list_b = self.list_b.find(input)?;
        Some(XxeAttackMatch {
            list_a,
            list_b,
            decoded_utf16,
        })
    }
}

impl LiteralMatcher {
    fn new(patterns: &'static [&'static str], vectorscan_enabled: bool) -> Self {
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("static XXE CMC patterns must compile");

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

fn utf16_views(input: &str) -> Vec<String> {
    let bytes = input.as_bytes();
    if bytes.len() < 8 {
        return Vec::new();
    }

    let mut views = Vec::with_capacity(2);

    if has_utf16_nul_shape(bytes) {
        if let Some(decoded) = decode_utf16_units(bytes, Endian::Little) {
            views.push(decoded);
        }
        if let Some(decoded) = decode_utf16_units(bytes, Endian::Big) {
            views.push(decoded);
        }
    }

    if has_embedded_utf16_nuls(bytes) {
        let stripped = input.replace('\0', "");
        if stripped != input {
            views.push(stripped);
        }
    }

    views
}

fn has_utf16_nul_shape(bytes: &[u8]) -> bool {
    let pairs = bytes.len() / 2;
    if pairs < 4 {
        return false;
    }

    let even_nuls = (0..pairs).filter(|idx| bytes[idx * 2] == 0).count();
    let odd_nuls = (0..pairs).filter(|idx| bytes[idx * 2 + 1] == 0).count();
    even_nuls * 2 >= pairs || odd_nuls * 2 >= pairs
}

fn has_embedded_utf16_nuls(bytes: &[u8]) -> bool {
    #[allow(clippy::naive_bytecount)]
    if bytes.iter().filter(|&&b| b == 0).count() < 4 {
        return false;
    }

    bytes.windows(4).any(|window| {
        matches!(window, [0, first, 0, second] | [first, 0, second, 0]
            if first.is_ascii_graphic() && second.is_ascii_graphic())
    })
}

#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn decode_utf16_units(bytes: &[u8], endian: Endian) -> Option<String> {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        let unit = match endian {
            Endian::Little => u16::from_le_bytes([chunk[0], chunk[1]]),
            Endian::Big => u16::from_be_bytes([chunk[0], chunk[1]]),
        };
        units.push(unit);
    }

    let decoded = String::from_utf16(&units).ok()?;
    let decoded = decoded.trim_start_matches('\u{feff}').to_string();
    let useful_ascii = decoded
        .bytes()
        .filter(|b| matches!(b, b'<' | b'?' | b'!' | b'a'..=b'z' | b'A'..=b'Z'))
        .count();

    (useful_ascii >= 4).then_some(decoded)
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
    use super::XxeAttackCmcBuilder;

    #[test]
    fn requires_one_marker_from_each_list() {
        let cmc = XxeAttackCmcBuilder::new().build();

        assert!(cmc
            .detect(r#"<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#)
            .is_some());
        assert!(cmc
            .detect(r#"<xi:include href="file:///etc/passwd" xmlns:xi="x"/>"#)
            .is_some());

        assert!(cmc.detect(r#"<!ENTITY harmless "value">"#).is_none());
        assert!(cmc.detect(r"<data>file:///etc/passwd</data>").is_none());
    }

    #[test]
    fn detects_utf16le_encoded_payload_after_url_decode() {
        let cmc = XxeAttackCmcBuilder::new().build();
        let utf16le = "<!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let payload = String::from_utf8(utf16le).expect("utf16le ascii bytes are valid utf8");

        let matched = cmc.detect(&payload).expect("utf16le xxe should match");
        assert!(matched.decoded_utf16());
    }

    #[test]
    fn detects_embedded_utf16le_form_value_after_url_decode() {
        let cmc = XxeAttackCmcBuilder::new().build();
        let utf16le = "<!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let payload = format!(
            "payload_test={}",
            String::from_utf8(utf16le).expect("utf16le ascii bytes are valid utf8")
        );

        let matched = cmc
            .detect(&payload)
            .expect("embedded utf16le xxe should match");
        assert!(matched.decoded_utf16());
    }
}

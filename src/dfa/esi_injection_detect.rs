use memchr::memchr_iter;

#[derive(Debug, Clone)]
pub struct EsiInjectionDfaBuilder;
#[derive(Debug, Clone)]
pub struct EsiInjectionDfa;

impl EsiInjectionDfaBuilder {
    pub fn new() -> Self { Self }
    pub fn build(self) -> EsiInjectionDfa { EsiInjectionDfa }
}

const ESI_PATTERNS: [(&[u8], &str); 4] = [
    (b"<esi:include", "<esi:include"),
    (b"<esi:inline", "<esi:inline"),
    (b"<esi:debug", "<esi:debug"),
    (b"<!--esi", "<!--esi"),
];

impl EsiInjectionDfa {
    pub fn detect(&self, input: &str) -> Option<String> {
        let bytes = input.as_bytes();
        for idx in memchr_iter(b'<', bytes) {
            for (pat, label) in ESI_PATTERNS {
                if bytes.len() >= idx + pat.len()
                    && bytes[idx..idx + pat.len()]
                        .iter()
                        .zip(pat.iter())
                        .all(|(a, b)| a.to_ascii_lowercase() == *b)
                {
                    return Some(label.to_string());
                }
            }
        }
        None
    }
}

use memchr::memchr_iter;

#[derive(Debug, Clone)]
pub struct SsiInjectionDfaBuilder;
#[derive(Debug, Clone)]
pub struct SsiInjectionDfa;

impl SsiInjectionDfaBuilder {
    pub fn new() -> Self { Self }
    pub fn build(self) -> SsiInjectionDfa { SsiInjectionDfa }
}

const SSI_KEYWORDS: [(&[u8], &str); 12] = [
    (b"include", "include"),
    (b"exec", "exec"),
    (b"echo", "echo"),
    (b"config", "config"),
    (b"fsize", "fsize"),
    (b"flastmod", "flastmod"),
    (b"printenv", "printenv"),
    (b"set", "set"),
    (b"if", "if"),
    (b"elif", "elif"),
    (b"else", "else"),
    (b"endif", "endif"),
];

fn starts_with_ci(hay: &[u8], pat: &[u8]) -> bool {
    hay.len() >= pat.len()
        && hay.iter()
            .take(pat.len())
            .zip(pat.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

impl SsiInjectionDfa {
    pub fn detect(&self, input: &str) -> Option<String> {
        let bytes = input.as_bytes();
        for idx in memchr_iter(b'<', bytes) {
            if bytes.len() < idx + 5 || &bytes[idx..idx + 5] != b"<!--#" {
                continue;
            }
            if !bytes[idx + 5..].windows(3).any(|w| w == b"-->") {
                continue;
            }
            let after = &bytes[idx + 5..];
            for (kw, label) in SSI_KEYWORDS {
                if starts_with_ci(after, kw) {
                    return Some(format!("<!--#{}", label));
                }
            }
        }
        None
    }
}

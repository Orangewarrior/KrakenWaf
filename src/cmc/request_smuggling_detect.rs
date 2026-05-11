#[derive(Debug, Clone, Default)]
pub struct RequestSmugglingCmcBuilder;
#[derive(Debug, Clone)]
pub struct RequestSmugglingCmc;

#[derive(Debug, Clone, Copy)]
pub struct RequestSmugglingMatch {
    pattern: &'static str,
}

impl RequestSmugglingMatch {
    pub fn pattern(self) -> &'static str {
        self.pattern
    }
}

impl RequestSmugglingCmcBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(self) -> RequestSmugglingCmc {
        RequestSmugglingCmc
    }
}

impl RequestSmugglingCmc {
    pub fn detect(&self, input: &str) -> Option<RequestSmugglingMatch> {
        if has_header_value(input, "transfer-encoding", "chunked") {
            return Some(RequestSmugglingMatch {
                pattern: "transfer-encoding:chunked",
            });
        }

        if has_header_value(input, "x-session-hijack", "true") {
            return Some(RequestSmugglingMatch {
                pattern: "x-session-hijack:true",
            });
        }

        if has_small_content_length(input) {
            return Some(RequestSmugglingMatch {
                pattern: "content-length<=4",
            });
        }

        None
    }
}

fn has_header_value(input: &str, name: &str, expected_value: &str) -> bool {
    let mut start = 0usize;
    while let Some(relative) = input[start..].find(name) {
        let name_idx = start + relative;
        let after_name = name_idx + name.len();

        if !has_header_name_boundary(input.as_bytes(), name_idx, after_name) {
            start = after_name;
            continue;
        }

        let mut cursor = skip_spaces(input.as_bytes(), after_name);
        if input.as_bytes().get(cursor).copied() != Some(b':') {
            start = after_name;
            continue;
        }

        cursor = skip_spaces(input.as_bytes(), cursor + 1);
        if starts_with_token(&input[cursor..], expected_value) {
            return true;
        }
        start = after_name;
    }

    false
}

fn has_small_content_length(input: &str) -> bool {
    let name = "content-length";
    let mut start = 0usize;

    while let Some(relative) = input[start..].find(name) {
        let name_idx = start + relative;
        let after_name = name_idx + name.len();

        if !has_header_name_boundary(input.as_bytes(), name_idx, after_name) {
            start = after_name;
            continue;
        }

        let mut cursor = skip_spaces(input.as_bytes(), after_name);
        if input.as_bytes().get(cursor).copied() != Some(b':') {
            start = after_name;
            continue;
        }

        cursor = skip_spaces(input.as_bytes(), cursor + 1);
        let Some((value, digits)) = parse_decimal_prefix(&input[cursor..]) else {
            start = after_name;
            continue;
        };

        if digits > 0 && value <= 4 && value_is_header_line_terminated(&input[cursor + digits..]) {
            return true;
        }

        start = after_name;
    }

    false
}

fn has_header_name_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start == 0
        || matches!(
            bytes[start - 1],
            b'\r' | b'\n' | b' ' | b'\t' | b'&' | b'?' | b'#' | b';' | b'=' | b'/' | b'\0'
        );
    let after_ok = end < bytes.len() && matches!(bytes[end], b':' | b' ' | b'\t');

    before_ok && after_ok
}

fn skip_spaces(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && matches!(bytes[idx], b' ' | b'\t' | b'\0') {
        idx += 1;
    }
    idx
}

fn starts_with_token(input: &str, expected: &str) -> bool {
    input.starts_with(expected)
        && input
            .as_bytes()
            .get(expected.len())
            .copied()
            .is_none_or(|b| matches!(b, b'\r' | b'\n' | b';' | b',' | b' ' | b'\t' | b'&'))
}

fn parse_decimal_prefix(input: &str) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut digits = 0usize;

    for byte in input.bytes() {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .saturating_mul(10)
            .saturating_add((byte - b'0') as usize);
        digits += 1;
    }

    (digits > 0).then_some((value, digits))
}

fn value_is_header_line_terminated(input: &str) -> bool {
    input
        .as_bytes()
        .first()
        .copied()
        .is_none_or(|b| matches!(b, b'\r' | b'\n' | b' ' | b'\t' | b'&' | b';'))
}

#[cfg(test)]
mod tests {
    use super::RequestSmugglingCmcBuilder;

    #[test]
    fn detects_smuggling_headers_and_body_injections() {
        let cmc = RequestSmugglingCmcBuilder::new().build();

        assert!(cmc
            .detect("get / http/1.1\r\ntransfer-encoding: chunked\r\n\r\n")
            .is_some());
        assert!(cmc.detect("payload=transfer-encoding: chunked").is_some());
        assert!(cmc.detect("payload=x-session-hijack: true").is_some());
        assert!(cmc
            .detect("post / http/1.1\r\ncontent-length: 4\r\n\r\nabcd")
            .is_some());
    }

    #[test]
    fn ignores_larger_content_length_and_non_matching_values() {
        let cmc = RequestSmugglingCmcBuilder::new().build();

        assert!(cmc
            .detect("post / http/1.1\r\ncontent-length: 20\r\n\r\nsafe body")
            .is_none());
        assert!(cmc.detect("payload=transfer-encoding: gzip").is_none());
        assert!(cmc.detect("payload=x-session-hijack: false").is_none());
    }
}

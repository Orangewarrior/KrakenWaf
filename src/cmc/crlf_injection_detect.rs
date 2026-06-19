use aho_corasick::AhoCorasick;

#[derive(Debug, Clone, Default)]
pub struct CrlfInjectionCmcBuilder;

#[derive(Debug, Clone)]
pub struct CrlfInjectionCmc {
    /// Single-pass multi-pattern finders for the escaped and decoded-unicode
    /// line-break token sets. Built once here instead of scanning the input
    /// once per token (the previous `O(input × tokens)` nested-`find` loop).
    escaped_breaks: AhoCorasick,
    unicode_breaks: AhoCorasick,
}

#[derive(Debug, Clone, Copy)]
pub struct CrlfMatch {
    pattern: &'static str,
}

impl CrlfMatch {
    pub fn pattern(self) -> &'static str {
        self.pattern
    }
}

impl CrlfInjectionCmcBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Build the detector, compiling the static line-break pattern sets into
    /// their Aho-Corasick automata.
    ///
    /// # Panics
    /// Panics only if the compile-time-constant `ESCAPED_BREAKS` /
    /// `DECODED_UNICODE_BREAKS` pattern lists fail to compile, which cannot
    /// happen for the fixed inputs in this module.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn build(self) -> CrlfInjectionCmc {
        CrlfInjectionCmc {
            escaped_breaks: AhoCorasick::new(ESCAPED_BREAKS)
                .expect("static CRLF escaped-break patterns must compile"),
            unicode_breaks: AhoCorasick::new(DECODED_UNICODE_BREAKS)
                .expect("static CRLF unicode-break patterns must compile"),
        }
    }
}

const HEADER_NAMES: &[&str] = &[
    "set-cookie",
    "location",
    "content-type",
    "content-length",
    "transfer-encoding",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-original-url",
    "x-rewrite-url",
    "x-custom",
    "x-custom-header",
    "x-xss-protection",
    "content-security-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "refresh",
    "link",
    "x-frame-options",
    "x-powered-by",
    "server",
    "via",
    "cache-control",
    "pragma",
    "expires",
    "last-modified",
    "etag",
    "age",
    "warning",
    "accept-ranges",
    "content-encoding",
    "content-language",
    "content-location",
    "content-md5",
    "content-range",
    "upgrade",
    "connection",
    "proxy-authenticate",
    "www-authenticate",
    "authorization",
    "proxy-authorization",
    "status",
    "host",
    "origin",
    "referer",
    "from",
    "client-ip",
    "cluster-client-ip",
    "forwarded",
    "true-client-ip",
    "x-client-ip",
    "x-host",
    "x-originating-ip",
    "x-real-ip",
    "x-remote-addr",
    "x-remote-ip",
    "base-url",
];

const ESCAPED_BREAKS: &[&str] = &[
    "\\r\\n",
    "\\r",
    "\\n",
    "\\u000d\\u000a",
    "\\u000a",
    "\\u000d",
    "%u000d%u000a",
    "%u000a",
    "%u000d",
    "%250d%250a",
    "%250a",
    "%250d",
    "%25250d%25250a",
    "%%0d0d%%0a0a",
    "%e5%98%8a",
    "%e5%98%8d",
    "%c4%8a",
    "%c4%8d",
    "%e2%80%a8",
    "%e2%80%a9",
    "%c0%8a",
    "%c0%8d",
    "%e0%80%8a",
    "%e0%80%8d",
    "%25e0%2580%258a",
    "%25e0%2580%258d",
];

const DECODED_UNICODE_BREAKS: &[&str] = &["嘊", "嘍", "č", "Ċ", "\u{2028}", "\u{2029}"];

const MULTIPART_PART_HEADER_NAMES: &[&str] = &[
    "content-disposition",
    "content-type",
    "content-transfer-encoding",
];

impl CrlfInjectionCmc {
    pub fn detect(&self, input: &str) -> Option<CrlfMatch> {
        if has_control_line_injection(input) {
            return Some(CrlfMatch {
                pattern: "control-line-header",
            });
        }

        if has_token_line_injection(&self.escaped_breaks, input) {
            return Some(CrlfMatch {
                pattern: "escaped-line-header",
            });
        }

        if has_token_line_injection(&self.unicode_breaks, input) {
            return Some(CrlfMatch {
                pattern: "unicode-line-header",
            });
        }

        None
    }
}

fn has_control_line_injection(input: &str) -> bool {
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let newline_len = if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            2
        } else if bytes[i] == b'\r' || bytes[i] == b'\n' {
            1
        } else {
            i += 1;
            continue;
        };

        if !is_normal_http_framing_break(input, i)
            && line_after_break_is_injected(input, i + newline_len)
        {
            return true;
        }
        i += newline_len;
    }

    false
}

/// Scan `input` once with the multi-pattern `finder` (escaped or decoded
/// line-break tokens) and report whether any match is immediately followed by
/// an injected header/status/markup line. Overlapping iteration preserves the
/// original semantics where shorter break tokens nested inside longer ones were
/// each checked independently.
fn has_token_line_injection(finder: &AhoCorasick, input: &str) -> bool {
    finder
        .find_overlapping_iter(input)
        .any(|m| line_after_break_is_injected(input, m.end()))
}

fn line_after_break_is_injected(input: &str, idx: usize) -> bool {
    let line = &input[idx..];
    let trimmed = trim_line_prefix(line);

    if trimmed.starts_with("http/1.") || trimmed.starts_with("http/2") {
        return true;
    }

    if trimmed.starts_with("<script")
        || trimmed.starts_with("<html")
        || trimmed.starts_with("<body")
        || trimmed.starts_with("<svg")
        || trimmed.starts_with("<img")
        || trimmed.starts_with("<iframe")
        || trimmed.starts_with("<object")
        || trimmed.starts_with("<embed")
        || trimmed.starts_with("<form")
    {
        return true;
    }

    if trimmed.starts_with("0\r")
        || trimmed.starts_with("0\n")
        || trimmed.starts_with("1\r")
        || trimmed.starts_with("1\n")
    {
        return true;
    }

    HEADER_NAMES
        .iter()
        .any(|name| starts_with_header_name_and_separator(trimmed, name))
}

fn is_normal_http_framing_break(input: &str, break_idx: usize) -> bool {
    let prev_start = input[..break_idx].rfind('\n').map_or(0, |idx| idx + 1);
    let prev = input[prev_start..break_idx].trim_matches(['\r', '\n', ' ', '\t']);

    if prev.is_empty() {
        return false;
    }

    if is_request_line(prev) {
        return true;
    }

    // When the WAF inspects a complete request, normal HTTP framing contains
    // newlines between arbitrary valid headers. Treat those as safe only while
    // we are still inside a well-formed header block that began with a valid
    // request line. A CRLF injected into the URI corrupts that first line, so it
    // still fails this check and is detected below.
    if is_inside_normal_request_header_block(input, break_idx) && is_http_header_line(prev) {
        return true;
    }

    if is_multipart_part_header_continuation(input, break_idx, prev) {
        return true;
    }

    HEADER_NAMES
        .iter()
        .any(|name| starts_with_header_name_and_separator(prev, name))
}

fn is_multipart_part_header_continuation(input: &str, break_idx: usize, prev: &str) -> bool {
    if !is_multipart_part_header_line(prev) {
        return false;
    }

    let next = input[break_idx..].trim_start_matches(['\r', '\n', ' ', '\t']);
    match next.lines().next() {
        Some(line) => is_multipart_part_header_line(line),
        // An empty `next` has no header line to continue onto.
        None => false,
    }
}

fn starts_with_header_name_and_separator(line: &str, name: &str) -> bool {
    let Some(rest) = line.strip_prefix(name) else {
        return false;
    };
    rest.starts_with(':') || rest.starts_with("%3a") || rest.starts_with("%253a")
}

fn is_inside_normal_request_header_block(input: &str, break_idx: usize) -> bool {
    let prefix = &input[..break_idx];
    let mut lines = prefix.lines();
    let Some(first) = lines.next() else {
        return false;
    };

    if !is_request_line(first.trim_matches(['\r', ' ', '\t'])) {
        return false;
    }

    for line in lines {
        if line.trim_matches(['\r', ' ', '\t']).is_empty() {
            return false;
        }
    }

    true
}

fn is_http_header_line(line: &str) -> bool {
    let Some((name, _value)) = line.split_once(':') else {
        return false;
    };

    let name = name.trim();
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| {
            matches!(
                b,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
        })
}

fn is_multipart_part_header_line(line: &str) -> bool {
    let Some((name, _value)) = line.split_once(':') else {
        return false;
    };
    let name = name.trim();
    MULTIPART_PART_HEADER_NAMES
        .iter()
        .any(|expected| name.eq_ignore_ascii_case(expected))
}

fn is_request_line(line: &str) -> bool {
    let line = line.to_ascii_lowercase();
    let starts_with_method = [
        "get ", "post ", "put ", "patch ", "delete ", "head ", "options ", "trace ", "connect ",
    ]
    .iter()
    .any(|method| line.starts_with(method));

    starts_with_method
        && (line.ends_with(" http/1.1") || line.ends_with(" http/1.0") || line.ends_with(" http/2"))
}

fn trim_line_prefix(line: &str) -> &str {
    let mut idx = 0usize;
    let bytes = line.as_bytes();
    while idx < bytes.len()
        && matches!(
            bytes[idx],
            b' ' | b'\t' | b'\0' | 0x0b | 0x0c | b'/' | b'.' | b'?' | b'#' | b'&' | b'=' | b';'
        )
    {
        idx += 1;
    }
    &line[idx..]
}

#[cfg(test)]
mod tests {
    use super::CrlfInjectionCmcBuilder;

    #[test]
    fn detects_control_crlf_header_injection() {
        let cmc = CrlfInjectionCmcBuilder::new().build();

        assert!(cmc.detect("value\r\nset-cookie:admin=true").is_some());
        assert!(cmc.detect("value\nlocation:http://evil.test").is_some());
        assert!(cmc.detect("value\r\nhttp/1.1 200 ok\r\n").is_some());
        assert!(cmc
            .detect("value\r\n\r\n<script>alert(1)</script>")
            .is_some());
    }

    #[test]
    fn detects_escaped_and_unicode_crlf_payloads() {
        let cmc = CrlfInjectionCmcBuilder::new().build();

        assert!(cmc.detect(r"value\r\nset-cookie:admin=true").is_some());
        assert!(cmc
            .detect(r"value\u000d\u000alocation:http://evil.test")
            .is_some());
        assert!(cmc.detect("%u000d%u000aset-cookie:admin=true").is_some());
        assert!(cmc
            .detect("%25e0%2580%258d%25e0%2580%258aset-cookie%3aadmin=true")
            .is_some());
        assert!(cmc.detect("嘊嘍set-cookie:admin=true").is_some());
    }

    #[test]
    fn ignores_normal_http_request_framing() {
        let cmc = CrlfInjectionCmcBuilder::new().build();
        let request = "GET /test_get?payload_test=hello HTTP/1.1\r\nHost: localhost\r\nUser-Agent: reqwest\r\n\r\n";

        assert!(cmc.detect(request).is_none());
    }

    #[test]
    fn ignores_common_browser_request_headers() {
        let cmc = CrlfInjectionCmcBuilder::new().build();
        let request = concat!(
            "get /login.php http/1.1\n",
            "host: 127.0.0.1:8443\n",
            "connection: keep-alive\n",
            "upgrade-insecure-requests: 1\n",
            "user-agent: mozilla/5.0\n",
            "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n",
            "sec-fetch-site: none\n",
            "sec-fetch-mode: navigate\n",
            "accept-encoding: gzip, deflate, br\n",
            "accept-language: pt-br,pt;q=0.9,en-us;q=0.8,en;q=0.7\n",
            "cookie: phpSESSID=abc123\n",
            "\n"
        );

        assert!(cmc.detect(request).is_none());
    }

    #[test]
    fn ignores_normal_multipart_part_headers() {
        let cmc = CrlfInjectionCmcBuilder::new().build();
        let request = concat!(
            "post /vulnerabilities/upload/ http/1.1\n",
            "host: localhost\n",
            "content-type: multipart/form-data; boundary=kw\n",
            "\n",
            "content-disposition: form-data; name=\"uploaded\"; filename=\"avatar.png\"\r\n",
            "content-type: image/png\r\n",
            "\r\n",
            "png bytes"
        );

        assert!(cmc.detect(request).is_none());
    }

    #[test]
    fn still_detects_header_injection_after_multipart_part_header() {
        let cmc = CrlfInjectionCmcBuilder::new().build();
        let request = concat!(
            "post /vulnerabilities/upload/ http/1.1\n",
            "host: localhost\n",
            "content-type: multipart/form-data; boundary=kw\n",
            "\n",
            "content-disposition: form-data; name=\"uploaded\"; filename=\"avatar.png\"\r\n",
            "set-cookie: admin=true\r\n",
            "\r\n",
            "png bytes"
        );

        assert!(cmc.detect(request).is_some());
    }

    #[test]
    fn still_detects_crlf_injected_into_request_uri() {
        let cmc = CrlfInjectionCmcBuilder::new().build();
        let request = "get /login.php?next=/home\r\nset-cookie: admin=true http/1.1\nhost: 127.0.0.1:8443\n\n";

        assert!(cmc.detect(request).is_some());
    }
}

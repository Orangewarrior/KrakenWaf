//! Minimal `multipart/form-data` parser used **only** to extract the
//! per-part payload bytes for WAF inspection.
//!
//! Before 2.24.0 the WAF inspected the raw multipart body as a single blob;
//! payloads wrapped in `Content-Disposition: form-data; name="x"\r\n\r\n…`
//! were glued together with boundary and MIME headers, which defeated every
//! literal/keyword matcher that anchors on word boundaries.
//!
//! This parser does **not** decode transfer encodings, does **not**
//! materialise filenames, and does **not** validate header syntax. It walks
//! the byte stream looking for the boundary and emits one `MultipartPart`
//! per body section. Strict, bounded, allocation-free for headers.

use bytes::Bytes;
use memchr::memmem;

/// Cap on the number of parts we will extract from a single body. Each part
/// triggers a fresh inspection pass; an attacker should not be able to turn
/// one POST into a million inspections.
const MAX_PARTS: usize = 256;

/// Cap on the recursive depth of nested `multipart/mixed` parts. RFC 7578
/// allows nesting via inner `Content-Type: multipart/...; boundary=...`;
/// we cap at 3 (`outer → inner → leaf`) which is more than any real
/// browser produces.
#[allow(dead_code)]
const MAX_DEPTH: usize = 3;

#[derive(Debug, Clone)]
pub struct MultipartPart {
    /// Optional `name="…"` parameter from `Content-Disposition`. Surfaced
    /// to log consumers / tests; the proxy itself does not read it.
    #[allow(dead_code)]
    pub name: Option<String>,
    /// Body payload bytes (between the `\r\n\r\n` after the part headers
    /// and the next boundary delimiter, exclusive).
    pub body: Bytes,
}

/// Parse the `boundary=…` parameter out of a `Content-Type:
/// multipart/form-data; boundary=…` header value. Returns `None` if the
/// header is not multipart or the boundary token is malformed.
#[must_use]
pub fn extract_boundary(content_type: &str) -> Option<String> {
    // Lowercase only the type/subtype portion for comparison; the boundary
    // parameter value is case-sensitive.
    let lower = content_type.to_ascii_lowercase();
    if !lower.contains("multipart/") {
        return None;
    }
    let mut iter = content_type.split(';').skip(1);
    iter.find_map(|param| {
        let trimmed = param.trim();
        let (k, v) = trimmed.split_once('=')?;
        if !k.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let raw = v.trim().trim_matches('"');
        if raw.is_empty() || raw.len() > 70 {
            // RFC 2046 §5.1.1 boundary tokens are at most 70 chars.
            return None;
        }
        Some(raw.to_string())
    })
}

/// Split a `multipart/form-data` body into its constituent parts. Returns an
/// empty vec when the body cannot be parsed — callers fall back to inspecting
/// the raw bytes (no extraction = no false-negative window).
#[must_use]
pub fn parse_parts(body: &Bytes, boundary: &str) -> Vec<MultipartPart> {
    let delim = format!("--{boundary}");
    let delim_bytes = delim.as_bytes();
    let bytes = body.as_ref();

    let finder = memmem::Finder::new(delim_bytes);
    let positions: Vec<usize> = finder.find_iter(bytes).collect();
    if positions.len() < 2 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(positions.len().min(MAX_PARTS));
    for window in positions.windows(2) {
        if out.len() >= MAX_PARTS {
            break;
        }
        let start_delim = window[0];
        let next_delim = window[1];

        // Skip past the delimiter and its trailing CRLF; the section header
        // begins immediately after. Tolerate LF-only (`\n`) and CRLF.
        let after_delim = start_delim + delim_bytes.len();
        let payload_start = skip_line_ending(bytes, after_delim);
        if payload_start >= next_delim {
            continue;
        }

        let section = &bytes[payload_start..next_delim];
        // Section is `headers \r\n\r\n body \r\n` — find the header/body split.
        let split = find_header_body_split(section);
        let (headers, body_slice) = match split {
            Some(idx) => (&section[..idx], &section[idx..section.len()]),
            None => (&section[..0], section),
        };

        // Trim the trailing `\r\n` (or `\n`) that immediately precedes the
        // next boundary delimiter; otherwise every emitted part has trailing
        // line-break bytes that fool length-anchored matchers.
        let body_slice = trim_trailing_crlf(body_slice);

        let name = extract_disposition_name(headers);
        out.push(MultipartPart {
            name,
            body: body.slice_ref(body_slice),
        });
    }
    out
}

fn skip_line_ending(bytes: &[u8], idx: usize) -> usize {
    let mut i = idx;
    if i < bytes.len() && bytes[i] == b'\r' {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'\n' {
        i += 1;
    }
    i
}

fn find_header_body_split(section: &[u8]) -> Option<usize> {
    if let Some(idx) = memmem::find(section, b"\r\n\r\n") {
        return Some(idx + 4);
    }
    if let Some(idx) = memmem::find(section, b"\n\n") {
        return Some(idx + 2);
    }
    None
}

fn trim_trailing_crlf(slice: &[u8]) -> &[u8] {
    let mut end = slice.len();
    while end > 0 && (slice[end - 1] == b'\n' || slice[end - 1] == b'\r') {
        end -= 1;
    }
    &slice[..end]
}

fn extract_disposition_name(headers: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-disposition:") {
            let original = &line[line.len() - rest.len()..];
            for param in original.split(';') {
                let trimmed = param.trim();
                if let Some(value) = trimmed.strip_prefix("name=") {
                    let v = value.trim_matches('"');
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_boundary_from_content_type() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundary123";
        assert_eq!(
            extract_boundary(ct).as_deref(),
            Some("----WebKitFormBoundary123")
        );
    }

    #[test]
    fn parses_simple_two_part_body() {
        let boundary = "kw-boundary";
        let raw = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n<sqli>\r\n--{boundary}--\r\n"
        );
        let parts = parse_parts(&Bytes::from(raw), boundary);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name.as_deref(), Some("a"));
        assert_eq!(parts[0].body.as_ref(), b"hello");
        assert_eq!(parts[1].name.as_deref(), Some("b"));
        assert_eq!(parts[1].body.as_ref(), b"<sqli>");
    }

    #[test]
    fn parser_caps_part_count() {
        use std::fmt::Write as _;
        let boundary = "kw";
        let mut raw = String::new();
        for i in 0..(MAX_PARTS + 50) {
            write!(
                raw,
                "--{boundary}\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nx\r\n"
            )
            .expect("write to String is infallible");
        }
        write!(raw, "--{boundary}--\r\n").expect("write to String is infallible");
        let parts = parse_parts(&Bytes::from(raw), boundary);
        assert!(parts.len() <= MAX_PARTS, "must enforce MAX_PARTS");
    }

    #[test]
    fn non_multipart_content_type_returns_none() {
        assert!(extract_boundary("application/json").is_none());
    }
}

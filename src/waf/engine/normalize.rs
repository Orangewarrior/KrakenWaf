use std::borrow::Cow;

const MAX_URL_DECODE_PASSES: usize = 4;

pub(super) fn url_decode_once(input: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => {
                if let (Some(h), Some(l)) = (
                    (input[i + 1] as char).to_digit(16),
                    (input[i + 2] as char).to_digit(16),
                ) {
                    // h and l are each 0–15, so h*16+l is 0–255; cast is safe.
                    #[allow(clippy::cast_possible_truncation)]
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    changed = true;
                    continue;
                }
                out.push(input[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
                changed = true;
            }
            _ => {
                out.push(input[i]);
                i += 1;
            }
        }
    }
    (out, changed)
}

pub(super) fn url_decode(input: &[u8]) -> Vec<u8> {
    let (mut current, mut changed) = url_decode_once(input);
    let mut passes = 1;
    while changed && passes < MAX_URL_DECODE_PASSES {
        let (next, next_changed) = url_decode_once(&current);
        current = next;
        changed = next_changed;
        passes += 1;
    }
    current
}

pub(super) fn normalize_request_bytes(payload: &[u8]) -> Cow<'_, [u8]> {
    let decoded = url_decode(payload);
    if decoded.as_slice() == payload {
        Cow::Borrowed(payload)
    } else {
        Cow::Owned(decoded)
    }
}

/// Returns a window-list over the normalised payload for multi-view matching.
/// The first element is always the full payload; subsequent elements are the
/// `&`/`;`/`?`/newline/NUL separated segments (duplicates of the full string
/// are skipped). Callers MUST match on the first view before iterating so that
/// score accumulation across substring rules works correctly.
pub(super) fn inspection_views(normalized: &str) -> Vec<&str> {
    let mut views = Vec::with_capacity(8);
    if !normalized.is_empty() {
        views.push(normalized);
    }
    for part in normalized.split(['&', ';', '?', '\n', '\r', '\0']) {
        let trimmed = part.trim();
        if !trimmed.is_empty() && trimmed != normalized {
            views.push(trimmed);
        }
    }
    views
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_handles_double_and_triple_encoded_percent() {
        assert_eq!(url_decode(b"%2525"), b"%");
        assert_eq!(url_decode(b"%25252F"), b"/");
        assert_eq!(url_decode(b"%2F"), b"/");
        assert_eq!(url_decode(b"100%"), b"100%");
    }

    #[test]
    fn inspection_views_first_view_is_full_normalized_text() {
        let normalized = "kwaf-score-get-a&kwaf-score-get-b&kwaf-score-get-c";
        let views = inspection_views(normalized);
        assert_eq!(views[0], normalized);
        assert!(
            views.len() > 1,
            "expected the normalized payload to also be split into per-segment views"
        );
    }
}

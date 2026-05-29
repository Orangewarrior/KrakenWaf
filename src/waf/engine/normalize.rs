//! Request normalisation applied before keyword / regex / CMC matching.
//!
//! ## The normalisation contract
//!
//! A WAF inspects a *view* of the request that may differ from what the
//! upstream eventually parses. Every divergence is a potential false negative
//! (the WAF sees something benign, the app sees an attack) or false positive
//! (the reverse). `KrakenWaf`'s contract is therefore deliberately explicit:
//!
//! * **Percent-decoding** — [`url_decode`] decodes `%XX` repeatedly, up to
//!   [`MAX_URL_DECODE_PASSES`] (4) times, stopping early once a pass changes
//!   nothing. This defeats single/double/triple-encoding evasion
//!   (`%252e%252e` → `..`). The cap bounds CPU on pathological inputs; a
//!   payload that only reveals an attack after **5+** decode layers is not
//!   matched on the decoded form, but no mainstream backend decodes that many
//!   times either, and the engine additionally inspects the **raw** form (see
//!   below).
//! * **`+` → space** — applied everywhere, matching `application/x-www-form-
//!   urlencoded` semantics. This is intentionally aggressive: it lets rules
//!   like `union select` match `union+select`. In a URL *path* `+` is literal,
//!   so the decoded view can differ from the path the app sees — to cover both
//!   interpretations the engine inspects the raw form in addition to the
//!   decoded one.
//! * **Multi-form inspection** — the engine never relies on a single view. It
//!   inspects the normalised form, the raw/original form, and (when lossy UTF-8
//!   produced `\u{FFFD}`) a Latin-1 form. See [`as_latin1`].
//! * **Null-byte dual-form** — [`inspection_views`] splits on `\0` so both the
//!   full string and the null-truncated prefix are inspected, defeating
//!   `foo\0../etc/passwd` truncation tricks.
//!
//! What is **not** done here (documented so operators understand the limits):
//! Unicode normalisation (NFKC), overlong-UTF-8 and fullwidth folding, and
//! HTML-entity decoding are not applied. Rules needing those must encode the
//! variants explicitly. The behaviours above are pinned by the unit tests at
//! the bottom of this file so they cannot regress silently.

use std::borrow::Cow;

/// Maximum number of percent-decode passes applied by [`url_decode`]. Bounds
/// CPU on adversarial multi-encoded input while still peeling the
/// single/double/triple-encoding seen in real evasion attempts.
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
///
/// **Null-byte dual-form (AppSec):** splitting on `\0` means both the full
/// form (view[0]) and the null-truncated prefix (a subsequent segment) are
/// always inspected. This defends against `foo\0../etc/passwd` attacks where
/// the C-layer backend truncates at the first NUL.
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

/// Encode raw bytes as a Latin-1 string (1:1 byte→char). Used as a fallback
/// inspection form when `String::from_utf8_lossy` introduces replacement
/// characters (`\u{FFFD}`) that would mask byte-specific attack patterns.
///
/// **UTF-8 dual-form (AppSec):** callers inspect both the UTF-8 lossy form
/// and this Latin-1 form so that neither valid nor invalid-UTF-8 payloads
/// can evade keyword / regex rules.
pub(super) fn as_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
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

    #[test]
    fn plus_decodes_to_space() {
        // `+` → space is applied everywhere so `union+select` matches a
        // space-delimited rule. Pinned because changing it silently would open
        // an evasion.
        assert_eq!(url_decode(b"union+select"), b"union select");
        // A percent-encoded plus (`%2b`) decodes to `+` on the first pass, which
        // the second pass then folds to a space — so an attacker cannot hide a
        // separator by encoding the plus. This multi-pass interaction is part of
        // the documented contract.
        assert_eq!(url_decode(b"a%2bb"), b"a b");
    }

    #[test]
    fn decode_pass_cap_is_four() {
        // A `%` nested five times needs five decode passes; the 4-pass cap must
        // leave exactly one `%25` layer un-peeled rather than loop unbounded.
        assert_eq!(url_decode(b"%2525252525"), b"%25");
        // Four-or-fewer layers still fully resolve.
        assert_eq!(url_decode(b"%2525"), b"%");
    }

    #[test]
    fn normalize_request_bytes_borrows_when_unchanged() {
        // No `%`/`+` present ⇒ zero-copy borrow (hot-path allocation avoided).
        assert!(matches!(normalize_request_bytes(b"plain/path"), Cow::Borrowed(_)));
        assert!(matches!(normalize_request_bytes(b"a%2Fb"), Cow::Owned(_)));
    }

    #[test]
    fn inspection_views_split_on_null_byte() {
        // The null-truncated prefix must be inspected as its own view so
        // `foo\0../etc/passwd` cannot hide behind a C-string truncation.
        let views = inspection_views("foo\0../etc/passwd");
        assert!(views.contains(&"foo"));
        assert!(views.contains(&"../etc/passwd"));
    }

    #[test]
    fn as_latin1_maps_high_bytes_one_to_one() {
        // 0xFF is invalid UTF-8; the Latin-1 fallback maps it to U+00FF rather
        // than the U+FFFD replacement char that would mask a byte pattern.
        assert_eq!(as_latin1(&[0xFF, b'A']), "\u{FF}A");
    }
}

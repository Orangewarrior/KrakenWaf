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
//! * **UTF-16 transcoding** — [`decode_utf16`] recognises UTF-16BE/LE input
//!   (by BOM, or by the interleaved-NUL pattern of ASCII-range text) and
//!   transcodes it to UTF-8 *before* percent-decoding. This closes an evasion
//!   where an attacker hides separators such as `=`/`&` (or any payload) inside
//!   a UTF-16 encoded body that the WAF would otherwise see as opaque bytes but
//!   a UTF-16-aware backend would parse. Because it runs inside
//!   [`normalize_request_bytes`] and [`normalize_str`], **every** CMC module
//!   and rule benefits.
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

/// Minimum byte length before the BOM-less UTF-16 heuristic is considered.
/// Short inputs (e.g. `"a"`) do not carry enough interleaved-NUL signal to
/// distinguish UTF-16 ASCII from incidental NUL bytes, so they are left alone.
const MIN_UTF16_HEURISTIC_LEN: usize = 4;

/// Transcode a UTF-16 byte stream to UTF-8 bytes when the input is recognisably
/// UTF-16, returning `None` otherwise so callers fall through unchanged.
///
/// Two recognisers, in order:
/// 1. **BOM** — a leading `FF FE` (little-endian) or `FE FF` (big-endian) byte
///    order mark. The BOM is consumed and the remainder transcoded.
/// 2. **Interleaved-NUL heuristic** — BOM-less ASCII text encoded as UTF-16
///    has a NUL in every other byte (`A\0B\0…` for LE, `\0A\0B…` for BE). When
///    the buffer is even-length and *every* code unit has its high byte zero on
///    one consistent side (and at least one non-NUL low byte exists), it is
///    treated as that endianness. Requiring the pattern to hold for the whole
///    buffer keeps binary bodies (which contain scattered NULs) from being
///    misread.
///
/// Decoding is lossy (`U+FFFD` for unpaired surrogates) — appropriate for a
/// security inspection view, where the goal is to reveal hidden ASCII rather
/// than to round-trip exactly.
fn decode_utf16(input: &[u8]) -> Option<Vec<u8>> {
    // BOM-led forms take precedence and may be any (even) length.
    if input.len() >= 2 && input.len().is_multiple_of(2) {
        match input[..2] {
            [0xFF, 0xFE] => return Some(transcode_utf16(&input[2..], Endian::Little)),
            [0xFE, 0xFF] => return Some(transcode_utf16(&input[2..], Endian::Big)),
            _ => {}
        }
    }

    // BOM-less interleaved-NUL heuristic for ASCII-range UTF-16 text.
    if input.len() < MIN_UTF16_HEURISTIC_LEN || !input.len().is_multiple_of(2) {
        return None;
    }
    let even_idx_all_nul = input.iter().step_by(2).all(|&b| b == 0);
    let odd_idx_all_nul = input.iter().skip(1).step_by(2).all(|&b| b == 0);
    let has_payload = input.iter().any(|&b| b != 0);
    if !has_payload {
        return None;
    }
    if odd_idx_all_nul && !even_idx_all_nul {
        // low byte first, high byte (NUL) second ⇒ little-endian ASCII.
        return Some(transcode_utf16(input, Endian::Little));
    }
    if even_idx_all_nul && !odd_idx_all_nul {
        // high byte (NUL) first, low byte second ⇒ big-endian ASCII.
        return Some(transcode_utf16(input, Endian::Big));
    }
    None
}

#[derive(Clone, Copy)]
enum Endian {
    Big,
    Little,
}

/// Transcode an even-length UTF-16 byte slice (no BOM) of the given endianness
/// to UTF-8 bytes, lossily. A trailing odd byte (malformed input) is ignored.
fn transcode_utf16(bytes: &[u8], endian: Endian) -> Vec<u8> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| match endian {
            Endian::Big => u16::from_be_bytes([c[0], c[1]]),
            Endian::Little => u16::from_le_bytes([c[0], c[1]]),
        })
        .collect();
    String::from_utf16_lossy(&units).into_bytes()
}

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
    // UTF-16 (BOM or interleaved-NUL ASCII) is transcoded to UTF-8 first so that
    // separators / payloads hidden in a UTF-16 stream are revealed before the
    // percent-decode + `+`→space pass runs over them.
    if let Some(utf8) = decode_utf16(payload) {
        return Cow::Owned(url_decode(&utf8));
    }
    let decoded = url_decode(payload);
    if decoded.as_slice() == payload {
        Cow::Borrowed(payload)
    } else {
        Cow::Owned(decoded)
    }
}

/// Normalise an arbitrary string the same way request payloads are normalised:
/// UTF-16 transcoding (BOM / interleaved-NUL ASCII) → repeated percent-decoding
/// → `+`→space, returned as a UTF-8 `String` (lossy on invalid bytes).
///
/// This is the public entry point CMC modules use when they need a fully
/// decoded view of a single field (e.g. a query string or body) rather than the
/// multi-view pipeline in [`super`]. Keeping it here means every caller shares
/// one decoding contract.
#[must_use]
pub fn normalize_str(raw: &str) -> String {
    let normalized = normalize_request_bytes(raw.as_bytes());
    String::from_utf8_lossy(normalized.as_ref()).into_owned()
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
        assert!(matches!(
            normalize_request_bytes(b"plain/path"),
            Cow::Borrowed(_)
        ));
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

    #[test]
    fn utf16le_bom_is_transcoded() {
        // FF FE BOM + "a=1" little-endian.
        let bytes = [0xFF, 0xFE, b'a', 0, b'=', 0, b'1', 0];
        assert_eq!(decode_utf16(&bytes).as_deref(), Some(b"a=1".as_slice()));
    }

    #[test]
    fn utf16be_bom_is_transcoded() {
        // FE FF BOM + "a=1" big-endian.
        let bytes = [0xFE, 0xFF, 0, b'a', 0, b'=', 0, b'1'];
        assert_eq!(decode_utf16(&bytes).as_deref(), Some(b"a=1".as_slice()));
    }

    #[test]
    fn utf16le_without_bom_is_transcoded_via_heuristic() {
        // "a=b" little-endian, no BOM (low byte then NUL).
        let bytes = [b'a', 0, b'=', 0, b'b', 0];
        assert_eq!(decode_utf16(&bytes).as_deref(), Some(b"a=b".as_slice()));
    }

    #[test]
    fn utf16be_without_bom_is_transcoded_via_heuristic() {
        // "a=b" big-endian, no BOM (NUL then low byte).
        let bytes = [0, b'a', 0, b'=', 0, b'b'];
        assert_eq!(decode_utf16(&bytes).as_deref(), Some(b"a=b".as_slice()));
    }

    #[test]
    fn plain_ascii_is_not_misread_as_utf16() {
        // No interleaved NULs ⇒ heuristic must decline so ASCII is untouched.
        assert_eq!(decode_utf16(b"name=value"), None);
    }

    #[test]
    fn utf16_then_percent_decode_reveals_hidden_separator() {
        // A UTF-16LE body that, once transcoded, contains a percent-encoded `=`
        // and `&` — both encodings must peel so the duplicate is visible.
        // "a%3D1%26A%3D2" in UTF-16LE.
        let raw = "a%3D1%26A%3D2";
        let mut bytes = Vec::new();
        for b in raw.bytes() {
            bytes.push(b);
            bytes.push(0);
        }
        let normalized = normalize_request_bytes(&bytes);
        assert_eq!(normalized.as_ref(), b"a=1&A=2");
    }

    #[test]
    fn normalize_str_matches_byte_pipeline() {
        assert_eq!(normalize_str("a%3Db%26c%3Dd"), "a=b&c=d");
    }
}

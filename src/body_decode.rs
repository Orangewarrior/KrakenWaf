//! Decompression of request and response bodies before WAF inspection.
//!
//! ## Threat model addressed
//!
//! Prior to 2.24.0 the WAF inspected the **raw** bytes carried over the
//! wire. A POST sent with `Content-Encoding: gzip|br|deflate|zstd` passed a
//! compressed payload to every matcher (keywords, regex, vectorscan,
//! libinjection, CMC). Since none of those engines understand the
//! compressed stream the payload was a free-for-all evasion. Trivial PoC:
//!
//! ```sh
//! printf "<sqli>" | gzip | curl -H 'Content-Encoding: gzip' --data-binary @-
//! ```
//!
//! ## Defence
//!
//! `decompress_body_for_inspection` walks the chain of encodings declared by
//! `Content-Encoding:` from **right to left** (per RFC 9110 §8.4), decoding
//! one layer at a time. Two guards bound the work done:
//!
//! * **Absolute cap** (`max_bytes`) — equal to the WAF body buffer cap; once
//!   the running decoded size exceeds it the decoder returns
//!   `DecompressError::TooLarge`.
//! * **Expansion ratio** (`max_ratio`) — protects against zip bombs that
//!   announce a tiny `Content-Length`. A 10 KiB gzip that expands to 4 GiB
//!   trips this guard well before the absolute cap.

use bytes::Bytes;
use std::io::Read;

/// Maximum number of `Content-Encoding` layers we will peel. Pathological
/// chains of `gzip, gzip, gzip, ...` are otherwise a CPU-amplification DoS.
const MAX_DECOMPRESS_LAYERS: usize = 4;

#[derive(Debug)]
pub enum DecompressError {
    /// Encoded body would exceed the configured byte cap when decoded.
    TooLarge,
    /// Encoded body expanded past the allowed ratio.
    Bomb { ratio: u32 },
    /// `Content-Encoding` lists an algorithm we do not implement.
    Unsupported(String),
    /// Too many encoding layers stacked.
    TooManyLayers,
    /// Decoder returned an error on the input bytes.
    Decode(String),
}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "decompressed body exceeds inspection cap"),
            Self::Bomb { ratio } => write!(f, "decompressed body exceeds expansion ratio ({ratio}x)"),
            Self::Unsupported(name) => write!(f, "unsupported Content-Encoding: {name}"),
            Self::TooManyLayers => write!(f, "Content-Encoding chain too long"),
            Self::Decode(err) => write!(f, "decoder error: {err}"),
        }
    }
}

impl std::error::Error for DecompressError {}

/// Parse a `Content-Encoding` header value into an ordered list of layer names
/// (already lowercased and trimmed). The HTTP spec allows comma-separated
/// values and a multi-value list — we accept both and normalise to a single
/// vector ordered as they appear on the wire (innermost-first).
#[must_use]
pub fn parse_content_encoding(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "identity")
        .collect()
}

/// Decompress `payload` using the chain of encodings declared by `encodings`.
/// `encodings` is expected to be ordered innermost-first (i.e. as it appears
/// in `Content-Encoding:`); the chain is peeled from the end so the result
/// is the cleartext that the application would see.
///
/// # Errors
///
/// Returns the appropriate `DecompressError` if any guard is tripped.
pub fn decompress_body_for_inspection(
    payload: &Bytes,
    encodings: &[String],
    max_bytes: usize,
    max_ratio: u32,
) -> Result<Bytes, DecompressError> {
    if encodings.is_empty() {
        return Ok(payload.clone());
    }
    if encodings.len() > MAX_DECOMPRESS_LAYERS {
        return Err(DecompressError::TooManyLayers);
    }

    let original_len = payload.len().max(1);
    let mut current: Vec<u8> = payload.as_ref().to_vec();

    // Peel from outermost (last in list) to innermost (first).
    for encoding in encodings.iter().rev() {
        let decoded = match encoding.as_str() {
            "gzip" | "x-gzip" => gzip_decode(&current, max_bytes)?,
            "deflate" => deflate_decode(&current, max_bytes)?,
            "br" => brotli_decode(&current, max_bytes)?,
            "zstd" => zstd_decode(&current, max_bytes)?,
            other => return Err(DecompressError::Unsupported(other.to_string())),
        };

        // Ratio guard against zip-bomb: comparison vs the *original* compressed
        // input, not the previous layer.
        let ratio = decoded.len() / original_len;
        if u32::try_from(ratio).unwrap_or(u32::MAX) > max_ratio {
            return Err(DecompressError::Bomb { ratio: max_ratio });
        }
        if decoded.len() > max_bytes {
            return Err(DecompressError::TooLarge);
        }
        current = decoded;
    }

    Ok(Bytes::from(current))
}

/// Common bounded-read helper used by every decoder. Returns `TooLarge` as
/// soon as we would exceed `max_bytes` so a malicious stream cannot drive
/// the decoder into multi-GiB allocations.
fn read_bounded<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, DecompressError> {
    let mut out = Vec::with_capacity(4 * 1024);
    // 16 KiB buffer keeps the stack frame small (clippy::large_stack_arrays)
    // and is still enough for a single read call to absorb a full TCP segment.
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|err| DecompressError::Decode(err.to_string()))?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > max_bytes {
            return Err(DecompressError::TooLarge);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn gzip_decode(payload: &[u8], max_bytes: usize) -> Result<Vec<u8>, DecompressError> {
    let mut decoder = flate2::read::MultiGzDecoder::new(payload);
    read_bounded(&mut decoder, max_bytes)
}

fn deflate_decode(payload: &[u8], max_bytes: usize) -> Result<Vec<u8>, DecompressError> {
    // RFC 7230 quirk: real-world senders use either zlib (RFC 1950) or raw
    // DEFLATE under `Content-Encoding: deflate`. Try zlib first; fall back
    // to raw if the header is invalid.
    {
        let mut decoder = flate2::read::ZlibDecoder::new(payload);
        if let Ok(decoded) = read_bounded(&mut decoder, max_bytes) {
            return Ok(decoded);
        }
    }
    let mut decoder = flate2::read::DeflateDecoder::new(payload);
    read_bounded(&mut decoder, max_bytes)
}

fn brotli_decode(payload: &[u8], max_bytes: usize) -> Result<Vec<u8>, DecompressError> {
    let mut decoder = brotli::Decompressor::new(payload, 4 * 1024);
    read_bounded(&mut decoder, max_bytes)
}

fn zstd_decode(payload: &[u8], max_bytes: usize) -> Result<Vec<u8>, DecompressError> {
    let mut decoder = zstd::stream::read::Decoder::new(payload)
        .map_err(|err| DecompressError::Decode(err.to_string()))?;
    read_bounded(&mut decoder, max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip_bytes(input: &[u8]) -> Bytes {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(input).expect("gzip write");
        Bytes::from(encoder.finish().expect("gzip finish"))
    }

    #[test]
    fn parse_content_encoding_normalises() {
        assert_eq!(parse_content_encoding("gzip"), vec!["gzip"]);
        assert_eq!(parse_content_encoding("GZIP, br"), vec!["gzip", "br"]);
        assert_eq!(
            parse_content_encoding("identity, gzip"),
            vec!["gzip"],
            "identity must be stripped"
        );
    }

    #[test]
    fn gzip_payload_is_decoded_for_inspection() {
        let plain = b"<script>alert(1)</script>".to_vec();
        let encoded = gzip_bytes(&plain);
        let out =
            decompress_body_for_inspection(&encoded, &["gzip".to_string()], 1024 * 1024, 32)
                .expect("decode");
        assert_eq!(out.as_ref(), plain.as_slice());
    }

    #[test]
    fn unsupported_encoding_errors_loudly() {
        let payload = Bytes::from_static(b"hello");
        let err = decompress_body_for_inspection(
            &payload,
            &["snappy".to_string()],
            1024,
            32,
        )
        .expect_err("must reject unknown encoding");
        assert!(matches!(err, DecompressError::Unsupported(_)));
    }

    #[test]
    fn too_many_layers_rejected() {
        let payload = Bytes::from_static(b"hello");
        let layers: Vec<String> =
            std::iter::repeat_n("gzip".to_string(), MAX_DECOMPRESS_LAYERS + 1).collect();
        let err = decompress_body_for_inspection(&payload, &layers, 1024, 32)
            .expect_err("must cap layers");
        assert!(matches!(err, DecompressError::TooManyLayers));
    }

    #[test]
    fn zip_bomb_is_detected_before_cap() {
        // 4 KiB of zeros compresses to ≪ 100 bytes; ratio > 32 triggers the guard.
        let plain = vec![0u8; 8 * 1024];
        let encoded = gzip_bytes(&plain);
        assert!(encoded.len() < 200, "compressed too big to be a useful test");
        let err = decompress_body_for_inspection(
            &encoded,
            &["gzip".to_string()],
            1024 * 1024,
            4,
        )
        .expect_err("ratio guard must fire");
        assert!(matches!(err, DecompressError::Bomb { .. }));
    }
}

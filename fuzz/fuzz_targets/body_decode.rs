//! Fuzz the request/response body decompressor (zip-bomb + layer guards).
//!
//! Run with:
//!   cargo fuzz run body_decode
//!
//! Feeds adversarial "compressed" bytes through every supported decoder and
//! verifies the decompressor never panics and always honours the byte cap and
//! expansion-ratio guard rather than allocating unbounded memory.
#![no_main]

use bytes::Bytes;
use krakenwaf::body_decode::{decompress_body_for_inspection, parse_content_encoding};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte selects the encoding chain so the fuzzer reaches every decoder;
    // the remainder is the (adversarial) payload.
    let (sel, payload) = data.split_first().unwrap_or((&0, &[][..]));
    let encoding = match sel % 6 {
        0 => "gzip",
        1 => "deflate",
        2 => "br",
        3 => "zstd",
        4 => "gzip, br",
        _ => "gzip, gzip, gzip, gzip, gzip", // exceeds MAX_DECOMPRESS_LAYERS
    };
    let encodings = parse_content_encoding(encoding);
    let body = Bytes::copy_from_slice(payload);
    // 1 MiB cap, 32x ratio guard — same shape the proxy uses.
    let _ = decompress_body_for_inspection(&body, &encodings, 1 << 20, 32);
});

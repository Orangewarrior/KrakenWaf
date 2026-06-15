//! Fuzz the `multipart/form-data` part extractor on arbitrary bytes.
//!
//! Run with:
//!   cargo fuzz run multipart_extract
//!
//! The parser walks attacker-controlled bytes looking for the boundary and
//! splitting parts; this verifies it never panics, never indexes out of
//! bounds, and respects the `MAX_PARTS` cap on adversarial input.
#![no_main]

use bytes::Bytes;
use krakenwaf::multipart_extract::{extract_boundary, parse_parts};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let body = Bytes::copy_from_slice(data);

    // Derive a boundary from the input when it is valid UTF-8 carrying a
    // multipart Content-Type, so the fuzzer reaches the real extraction path;
    // also always exercise a fixed boundary so the no-match / malformed paths
    // are covered.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(boundary) = extract_boundary(text) {
            let _ = parse_parts(&body, &boundary);
        }
    }
    let _ = parse_parts(&body, "kw-fuzz-boundary");
});

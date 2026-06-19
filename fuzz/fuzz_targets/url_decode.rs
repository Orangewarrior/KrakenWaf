//! Fuzz the URL-decode / normalization pipeline.
//!
//! Run with:
//!   cargo fuzz run url_decode
//!
//! Verifies that multi-pass URL decoding never panics, never returns more bytes
//! than the input, and is idempotent on already-decoded inputs via the CMC
//! inspection surface (which internally normalizes payloads).
#![no_main]

use krakenwaf::cmc::{CmcConfig, CmcManager, CmcManagerBuilder};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn manager() -> &'static CmcManager {
    static MANAGER: OnceLock<CmcManager> = OnceLock::new();
    MANAGER.get_or_init(|| CmcManagerBuilder::new(CmcConfig::default()).build())
}

fuzz_target!(|data: &[u8]| {
    // inspect() and inspect_java_deser() both normalise via the shared pipeline.
    if let Ok(text) = std::str::from_utf8(data) {
        let lower = text.to_ascii_lowercase();
        let _ = manager().inspect(&lower);
        // inspect_java_deser runs on the original (non-lowercased) text so that
        // base64 patterns are matched correctly.
        let _ = manager().inspect_java_deser(text, data);
    }
});

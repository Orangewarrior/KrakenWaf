//! Fuzz the CMC inspection pipeline end-to-end.
//!
//! Run with:
//!   cargo fuzz run cmc_inspect
//!
//! The target builds a CmcManager with all modules enabled and feeds arbitrary
//! bytes through the two main inspection entry-points. Any panic terminates the
//! fuzz run so libFuzzer can report the crashing input.
#![no_main]

use krakenwaf::cmc::{CmcConfig, CmcManagerBuilder};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let config = CmcConfig::default();
    let manager = CmcManagerBuilder::new(config).build();

    // inspect() receives the lowercased, URL-decoded payload string.
    if let Ok(text) = std::str::from_utf8(data) {
        let lower = text.to_ascii_lowercase();
        let _ = manager.inspect(&lower);
        let _ = manager.inspect_java_deser(text, data);
        let _ = manager.inspect_response_body(text);
    }
});

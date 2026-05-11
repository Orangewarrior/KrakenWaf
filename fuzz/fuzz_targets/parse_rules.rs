//! Fuzz the CMC YAML config parser.
//!
//! Run with:
//!   cargo fuzz run parse_rules
//!
//! Feeds arbitrary bytes as a YAML document into the lenient YAML parser used
//! to load `rules/cmc/config.yaml`. Panics on parse errors are bugs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // CmcConfig::from_file requires a filesystem path, so we write to a tempfile.
    if let Ok(text) = std::str::from_utf8(data) {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let _ = tmp.write_all(text.as_bytes());
        // from_file is fallible — panics are the bug, Err results are expected.
        let _ = krakenwaf::cmc::CmcConfig::from_file(tmp.path());
    }
});

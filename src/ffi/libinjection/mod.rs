#![allow(dead_code)]
mod bindings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionKind {
    Sqli,
    Xss,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub kind: DetectionKind,
    pub fingerprint: Option<String>,
}

fn collect_fingerprint(buf: &[core::ffi::c_char]) -> Option<String> {
    // CStr::from_ptr scans memory past the buffer end if the C library omits the
    // null terminator. Find the null byte within our known bounds first, then
    // cast each c_char (i8 or u8 depending on target) to u8 byte-by-byte.
    // libinjection fingerprints are ASCII so the cast is always correct.
    let null_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if null_pos == 0 {
        return None;
    }
    let bytes: Vec<u8> = buf[..null_pos].iter().map(|&c| c.cast_unsigned()).collect();
    let s = String::from_utf8_lossy(&bytes);
    let trimmed = s.trim();
    (!trimmed.is_empty()).then_some(trimmed.to_string())
}

pub fn detect_sqli(input: &[u8]) -> Option<Detection> {
    let mut buf = vec![0 as core::ffi::c_char; 64];
    let matched = unsafe {
        bindings::kwaf_libinjection_sqli(input.as_ptr(), input.len(), buf.as_mut_ptr(), buf.len())
    } != 0;
    matched.then(|| Detection {
        kind: DetectionKind::Sqli,
        fingerprint: collect_fingerprint(&buf),
    })
}

pub fn detect_xss(input: &[u8]) -> Option<Detection> {
    let mut buf = vec![0 as core::ffi::c_char; 64];
    let matched = unsafe {
        bindings::kwaf_libinjection_xss(input.as_ptr(), input.len(), buf.as_mut_ptr(), buf.len())
    } != 0;
    matched.then(|| Detection {
        kind: DetectionKind::Xss,
        fingerprint: collect_fingerprint(&buf).or_else(|| Some("xss-match".into())),
    })
}

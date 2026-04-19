#![allow(dead_code)]
mod bindings;

use std::ffi::CStr;

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
    if buf.is_empty() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().trim().to_string();
    (!value.is_empty()).then_some(value)
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

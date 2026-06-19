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
    let bytes: Vec<u8> = buf[..null_pos]
        .iter()
        .map(|&c| c.to_ne_bytes()[0])
        .collect();
    let s = String::from_utf8_lossy(&bytes);
    let trimmed = s.trim();
    (!trimmed.is_empty()).then_some(trimmed.to_string())
}

#[must_use] 
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

#[must_use]
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

#[cfg(test)]
mod tests {
    use super::{collect_fingerprint, detect_sqli, detect_xss, DetectionKind};

    #[test]
    fn detects_classic_sqli() {
        let d = detect_sqli(b"1' OR '1'='1").expect("sqli detected");
        assert_eq!(d.kind, DetectionKind::Sqli);
        assert!(d.fingerprint.is_some());
    }

    #[test]
    fn detects_classic_xss() {
        let d = detect_xss(b"<script>alert(1)</script>").expect("xss detected");
        assert_eq!(d.kind, DetectionKind::Xss);
    }

    #[test]
    fn benign_input_is_not_flagged() {
        assert!(detect_sqli(b"hello world").is_none());
        assert!(detect_xss(b"hello world").is_none());
    }

    #[test]
    fn empty_input_does_not_panic() {
        // An empty slice yields a dangling-but-aligned pointer with len 0; the C
        // side must treat it as a zero-length buffer rather than reading it.
        assert!(detect_sqli(b"").is_none());
        assert!(detect_xss(b"").is_none());
    }

    #[test]
    fn fingerprint_stops_at_first_nul_within_bounds() {
        // Guards the contract that collect_fingerprint never reads past the NUL
        // terminator the C library writes, even if later bytes hold garbage.
        let mut buf = vec![0 as core::ffi::c_char; 8];
        buf[0] = b's'.cast_signed();
        buf[1] = b'1'.cast_signed();
        // buf[2] stays NUL; trailing bytes are deliberately non-zero garbage.
        buf[3] = 0x7f;
        buf[4] = 0x41;
        assert_eq!(collect_fingerprint(&buf).as_deref(), Some("s1"));
    }
}

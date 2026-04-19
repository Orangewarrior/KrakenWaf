#![allow(dead_code)]
unsafe extern "C" {
    pub fn kwaf_libinjection_sqli(
        data: *const u8,
        len: usize,
        fingerprint_out: *mut core::ffi::c_char,
        fingerprint_out_len: usize,
    ) -> core::ffi::c_int;

    pub fn kwaf_libinjection_xss(
        data: *const u8,
        len: usize,
        fingerprint_out: *mut core::ffi::c_char,
        fingerprint_out_len: usize,
    ) -> core::ffi::c_int;
}


use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/kwaf_libinjection.c");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/kwaf_libinjection.h");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_sqli.c");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_xss.c");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_html5.c");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection.h");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_sqli.h");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_xss.h");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_html5.h");

    cc::Build::new()
        .file("ffi/libinjection/vendor/kwaf_libinjection.c")
        .file("ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_sqli.c")
        .file("ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_xss.c")
        .file("ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_html5.c")
        .include("ffi/libinjection/vendor")
        .include("ffi/libinjection/vendor/libinjection-4.0.0/src")
        .flag_if_supported("-Wno-enum-int-mismatch")
        .flag("-fvisibility=default")
        .warnings(true)
        .compile("kwaf_libinjection");

    println!("cargo:rustc-link-lib=static=kwaf_libinjection");
    println!("cargo:rustc-link-arg=-Wl,--whole-archive");
    println!("cargo:rustc-link-arg=-lkwaf_libinjection");
    println!("cargo:rustc-link-arg=-Wl,--no-whole-archive");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=kwaf_libinjection");
}

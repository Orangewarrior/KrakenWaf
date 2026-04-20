
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/kwaf_libinjection.c");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/kwaf_libinjection.h");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_sqli.c");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_xss.c");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_html5.c");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection.h");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_sqli.h");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_xss.h");
    println!("cargo:rerun-if-changed=ffi/libinjection/vendor/libinjection-4.0.0/src/libinjection_html5.h");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

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

    // cc::Build::compile() emits cargo:rustc-link-lib and cargo:rustc-link-search
    // automatically, but on packages that have both a lib and a bin target the
    // -l flag sometimes does not survive into the final binary link step (a
    // known Cargo edge case with same-package lib→bin native-dep propagation).
    //
    // cargo:rustc-link-arg passes a raw argument directly to the binary linker,
    // bypassing the -l name-resolution path entirely.  Providing the archive by
    // its full path is the most robust option: lld, GNU ld, and the macOS
    // linker all accept a bare archive path as a positional argument.  Without
    // --whole-archive the linker only pulls in symbols that are actually
    // referenced, so there are no duplicate-symbol errors even if the archive
    // also appears via the -l path emitted by compile().
    let archive = out_dir.join("libkwaf_libinjection.a");
    println!("cargo:rustc-link-arg={}", archive.display());
}

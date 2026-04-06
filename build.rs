fn main() {
    if std::env::var_os("CARGO_FEATURE_LIBINJECTION_ENGINE").is_some() {
        let vendor = std::path::PathBuf::from("ffi/libinjection/vendor");
        println!("cargo:rerun-if-changed={}", vendor.join("libinjection_compat.c").display());
        println!("cargo:rerun-if-changed={}", vendor.join("libinjection_compat.h").display());
        cc::Build::new()
            .include(&vendor)
            .file(vendor.join("libinjection_compat.c"))
            .warnings(true)
            .compile("krakenwaf_libinjection");
    }
}

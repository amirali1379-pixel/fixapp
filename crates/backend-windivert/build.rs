use std::path::PathBuf;

fn main() {
    let lib_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../native/windivert/lib");

    println!("cargo:rerun-if-changed={}", lib_dir.display());
    for name in ["WinDivert.lib", "WinDivert.dll", "WinDivert.sys"] {
        println!("cargo:rerun-if-changed={}", lib_dir.join(name).display());
    }

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let import_lib = lib_dir.join("WinDivert.lib");
    if !import_lib.is_file() {
        panic!(
            "WinDivert native bundle is incomplete: missing {}",
            import_lib.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=WinDivert");
}

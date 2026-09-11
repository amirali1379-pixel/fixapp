use std::path::PathBuf;

fn main() {
    let native_lib = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../native/wfp/lib");

    println!("cargo:rerun-if-changed={}", native_lib.display());
    println!("cargo:rustc-link-search=native={}", native_lib.display());

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    // fwpuclnt.lib is a Windows import library used at build time.
    // The corresponding Windows system components are not package assets.
    println!(
        "cargo:rerun-if-changed={}",
        native_lib.join("fwpuclnt.lib").display()
    );
}

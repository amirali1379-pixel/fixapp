use std::path::PathBuf;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let native_lib = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../native/npcap/lib");

    println!("cargo:rerun-if-changed={}", native_lib.display());
    println!("cargo:rerun-if-changed={}", native_lib.join("wpcap.lib").display());
    println!("cargo:rerun-if-changed={}", native_lib.join("Packet.lib").display());

    let wpcap_lib = native_lib.join("wpcap.lib");
    let packet_lib = native_lib.join("Packet.lib");

    if !wpcap_lib.is_file() {
        panic!(
            "Npcap native bundle is incomplete: missing {}",
            wpcap_lib.display()
        );
    }
    if !packet_lib.is_file() {
        panic!(
            "Npcap native bundle is incomplete: missing {}",
            packet_lib.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", native_lib.display());
    println!("cargo:rustc-link-lib=dylib=wpcap");
    println!("cargo:rustc-link-lib=dylib=Packet");
}

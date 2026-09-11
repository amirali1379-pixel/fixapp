use std::path::PathBuf;

fn main() {
    let native_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../native");
    let npcap_lib_dir = native_dir.join("npcap/lib");
    let npcap_runtime_dir = native_dir.join("npcap/runtime");
    let wfp_lib_dir = native_dir.join("wfp/lib");
    let wfp_runtime_dir = native_dir.join("wfp/runtime");
    let windivert_lib_dir = native_dir.join("windivert/lib");
    let windivert_runtime_dir = native_dir.join("windivert/runtime");

    println!("cargo:rerun-if-changed={}", npcap_lib_dir.display());
    for name in ["wpcap.lib", "Packet.lib"] {
        println!("cargo:rerun-if-changed={}", npcap_lib_dir.join(name).display());
    }
    for name in ["wpcap.dll", "Packet.dll"] {
        println!("cargo:rerun-if-changed={}", npcap_runtime_dir.join(name).display());
    }
    println!("cargo:rerun-if-changed={}", wfp_lib_dir.display());
    println!("cargo:rerun-if-changed={}", wfp_lib_dir.join("fwpuclnt.lib").display());
    for name in ["FWPUCLNT.DLL", "FWPKCLNT.SYS"] {
        println!("cargo:rerun-if-changed={}", wfp_runtime_dir.join(name).display());
    }
    println!("cargo:rerun-if-changed={}", windivert_lib_dir.display());
    println!("cargo:rerun-if-changed={}", windivert_lib_dir.join("WinDivert.lib").display());
    for name in ["WinDivert.dll", "WinDivert.sys"] {
        println!("cargo:rerun-if-changed={}", windivert_runtime_dir.join(name).display());
    }

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    println!("cargo:rustc-link-search=native={}", npcap_lib_dir.display());
    println!("cargo:rustc-link-search=native={}", wfp_lib_dir.display());

    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let wpcap_lib = npcap_lib_dir.join("wpcap.lib");
        let fwpuclnt_lib = wfp_lib_dir.join("fwpuclnt.lib");

        if !wpcap_lib.is_file() {
            panic!("Native bundle is incomplete: missing {}", wpcap_lib.display());
        }
        if !fwpuclnt_lib.is_file() {
            panic!("Native bundle is incomplete: missing {}", fwpuclnt_lib.display());
        }

        println!("cargo:rustc-link-lib=dylib=wpcap");
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");

        println!("cargo:rustc-link-lib=dylib=fwpuclnt");
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:fwpuclnt.dll");
    }
}
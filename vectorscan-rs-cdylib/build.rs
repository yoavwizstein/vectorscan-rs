use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = std::env::var("TARGET").unwrap_or_default();

    let hs_def = manifest_dir.join("../vectorscan-rs-sys/vectorscan/hs.def");
    let def_content = fs::read_to_string(&hs_def)
        .expect("Failed to read vectorscan submodule hs.def")
        .replace("LIBRARY hs", "LIBRARY vs");

    let def_path = out_dir.join("vs.def");
    fs::write(&def_path, def_content).expect("Failed to write .def file");

    println!("cargo:rustc-cdylib-link-arg={}", def_path.display());

    if target.contains("windows-gnu") {
        link_mingw_cpp_runtime_statically();
    }

    println!("cargo:rerun-if-changed={}", hs_def.display());
    println!("cargo:rerun-if-changed=build.rs");
}

fn link_mingw_cpp_runtime_statically() {
    // Group handles circular deps between MinGW static archives
    println!("cargo:rustc-cdylib-link-arg=-Wl,-Bstatic");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--start-group");
    println!("cargo:rustc-cdylib-link-arg=-lstdc++");
    println!("cargo:rustc-cdylib-link-arg=-lgcc_eh");
    println!("cargo:rustc-cdylib-link-arg=-lgcc");
    println!("cargo:rustc-cdylib-link-arg=-lssp");
    println!("cargo:rustc-cdylib-link-arg=-lpthread");
    println!("cargo:rustc-cdylib-link-arg=-lmingw32");
    println!("cargo:rustc-cdylib-link-arg=-lmingwex");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--end-group");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-Bdynamic");
    println!("cargo:rustc-cdylib-link-arg=-lmsvcrt");
    println!("cargo:rustc-cdylib-link-arg=-lkernel32");
}

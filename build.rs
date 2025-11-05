use bindgen;
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/processes_trace.bpf.c";
const HDR: &str = "src/bpf/common.h";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate(&out.join("processes_trace.skel.rs"))
        .unwrap();

    bindgen::Builder::default()
        .header(HDR)
        .clang_args(["-I", "src/bpf/vmlinux"])
        .allowlist_type("process")
        .generate()
        .expect("Unable to generate Rust bindings to common.h")
        .write_to_file(out.join("common.rs"))
        .expect("Couldn't write bindings");

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed={HDR}");
}

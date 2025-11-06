use bindgen;
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/processes_trace.bpf.c";
const HDR: &str = "src/bpf/common.h";

fn main() {
    let vmlinux_path = ensure_vmlinux_header();
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    println!("cargo:rerun-if-changed={SRC}");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux_path
                .parent()
                .unwrap_or(vmlinux::include_path_root().join(arch).as_path())
                .as_os_str(),
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

    println!("cargo:rerun-if-changed={HDR}");
}

fn ensure_vmlinux_header() -> PathBuf {
    let vmlinux_h = PathBuf::from("src/bpf/vmlinux.h");

    // Only regenerate if missing or outdated
    if !vmlinux_h.exists() {
        let bpftool_out = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("failed to run bpftool (is it installed?)");

        if !bpftool_out.status.success() {
            panic!(
                "bpftool failed: {}",
                String::from_utf8_lossy(&bpftool_out.stderr)
            );
        }

        std::fs::write(&vmlinux_h, &bpftool_out.stdout).expect("failed to write vmlinux.h");
    }

    vmlinux_h
}

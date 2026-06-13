// SPDX-License-Identifier: MIT

use std::{path::PathBuf, process::Command};
use std::env;

fn main() {
    println!("cargo::rerun-if-changed=src/fw.bpf.c");
    let nix_cflags = env::var("NIX_CFLAGS_COMPILE")
        .expect("$NIX_CFLAGS_COMPILE is not set");
    let mut collected: Vec<_> = nix_cflags.split_whitespace().collect();

    
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let obj = out_dir.join("fw.bpf.o");

    let status = Command::new("bpf-clang")
        .args([
            "-O2",
            "-g",
        ])
        .args(&mut collected)
        .args([
            "-c",
            "src/fw.bpf.c",
            "-o",
        ])
        .arg(&obj)
        .status()
        .expect("failed to compile ebpf .o file");
    
    assert!(status.success());

    println!("cargo:rustc-env=BPF_OBJECT={}", obj.display());
}

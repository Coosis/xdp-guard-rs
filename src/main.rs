// use libbpf_rs::ProgramOutput

use libbpf_rs::ObjectBuilder;
use std::env::var;
use anyhow::{Context, Result};

mod ctypes;

const BPF_OBJ: &str = env!("BPF_OBJECT"); // injected via build.rs as rustc env var

fn main() -> Result<()> {
    let obj = libbpf_rs::ObjectBuilder::default()
        .open_file(BPF_OBJ)
        .with_context(|| "open bpf object failed")?;
    obj.load()
        .with_context(|| "load bpf object failed")?;
    // u32::from_b
    // libbpf_rs::get
    // obj.maps().into_iter().map(|m| m.autocreate)
    println!("Hello, world!");
    Ok(())
}

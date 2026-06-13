// SPDX-License-Identifier: MIT

// use libbpf_rs::ProgramOutput

use std::sync::{Arc, Mutex};

use axum::{Router, routing::{get, post}};
use libbpf_rs::{Link, MapCore, MapFlags, Object};
use anyhow::{Context, Result};
use nix::net::if_::if_nametoindex;

use crate::{ctypes::{fw_meta, fw_ruleset}, helper::as_byte_slice};

mod error;
mod ctypes;
mod helper;
mod service;
mod ruleset;

const BPF_OBJ: &str = env!("BPF_OBJECT"); // injected via build.rs as rustc env var

#[derive(Debug)]
struct AppState {
    pub metadata: ctypes::fw_meta,
    pub obj: Object,
    pub xdp_link: Link,
}

impl AppState {
    fn new(obj: Object, xdp_link: Link) -> Self {
        AppState {
            metadata: ctypes::fw_meta::default(),
            obj,
            xdp_link
        }
    }

    /// must hold mutex
    pub fn update_ruleset(&mut self, new_rule: &fw_ruleset) -> Result<(), error::Error> {
        let nxt = self.metadata.active_ruleset ^ 1;
        let key = as_byte_slice(&nxt);
        self.obj.maps_mut()
            .find(|m| m.name().to_string_lossy() == "rulesets")
            .ok_or(error::Error::MapUpdateErr)?
            .update(key, as_byte_slice(new_rule), MapFlags::ANY)
            .map_err(|_e| error::Error::MapUpdateErr)?;

        let zero: u32 = 0;
        let zk = as_byte_slice(&zero);
        let new_meta = fw_meta { active_ruleset: nxt };
        self.obj.maps_mut()
            .find(|m| m.name().to_string_lossy() == "fw_meta")
            .ok_or(error::Error::MapUpdateErr)?
            .update(zk, as_byte_slice(&new_meta), MapFlags::ANY)
            .map_err(|_e| error::Error::MapUpdateErr)?;
        self.metadata = new_meta;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let bpf_obj = std::env::var("BPF_OBJECT").unwrap_or_else(|_| "fw.bpf.o".to_string());
    let obj = libbpf_rs::ObjectBuilder::default()
        .open_file(bpf_obj)
        .with_context(|| "open bpf object failed")?;
    let obj = obj.load()
        .with_context(|| "load bpf object failed")?;

    let ifname = std::env::args()
        .nth(1)
        .context("usage: <program> <ifname>")?;

    let ifindex = if_nametoindex(ifname.as_str())
        .with_context(|| format!("failed to resolve interface {ifname}"))? as i32;

    let xdp_link = obj
        .progs_mut()
        .find(|p| p.name().to_string_lossy() == "xdp_fw")
        .context("no XDP program named xdp_fw found")?
        .attach_xdp(ifindex)
        .with_context(|| format!("failed to attach XDP program to {ifname}"))?;

    let mut state = AppState::new(obj, xdp_link);

    let init_ruleset = ctypes::fw_ruleset::default();
    let init_ruleset_bytes = as_byte_slice(&init_ruleset);

    let zero: u32 = 0;
    let zk: &[u8] = as_byte_slice(&zero);

    state.obj.maps_mut()
        .find(|m| m.name().to_string_lossy() == "rulesets")
        .ok_or_else(|| anyhow::anyhow!("no rulesets found in object"))?
        .update(zk, init_ruleset_bytes, MapFlags::ANY)
        .with_context(|| "init ruleset failed")?;
        
    let md_bytes: &[u8] = as_byte_slice(&state.metadata);
    state.obj.maps_mut()
        .find(|m| m.name().to_string_lossy() == "fw_meta")
        .ok_or_else(|| anyhow::anyhow!("no fw_meta found in object"))?
        .update(zk, md_bytes, MapFlags::ANY)
        .with_context(|| "init metadata failed")?;

    let app = Router::new()
        .route("/update_rule_toml", post(service::update::handle_toml_ruleset))
        .route("/metrics", get(service::metrics::handle_metrics))
        .with_state(Arc::new(Mutex::new(state)));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8989")
        .await
        .context("listener failed to bound port 8989")?;

    axum::serve(listener, app)
        .await
        .context("serve() failed")?;

    Ok(())
}

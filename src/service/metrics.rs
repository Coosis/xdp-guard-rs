use std::mem::size_of;
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::State;
use libbpf_rs::{MapCore, MapFlags};
use prometheus::{Encoder, Registry, TextEncoder};

use prometheus::process_collector::ProcessCollector;

use crate::ctypes::{fw_stats, MAX_RULES};
use crate::{error::Error, helper::as_byte_slice, AppState};

static PROCESS_REGISTRY: OnceLock<Registry> = OnceLock::new();

pub async fn handle_metrics(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<String, Error> {
    let state = state.lock().unwrap();
    let zero: u32 = 0;
    let key = as_byte_slice(&zero);

    let stats = state.obj.maps()
        .find(|m| m.name().to_string_lossy() == "fw_stats")
        .ok_or(Error::MetricsErr)?
        .lookup_percpu(key, MapFlags::ANY)
        .map_err(|_| Error::MetricsErr)?
        .ok_or(Error::MetricsErr)?;

    let stats = stats.iter()
        .try_fold(fw_stats::default(), |mut acc, cpu| {
            let cpu = parse_fw_stats(cpu)?;
            acc.accepted_packets += cpu.accepted_packets;
            acc.dropped_packets += cpu.dropped_packets;
            acc.rate_limit_hits += cpu.rate_limit_hits;
            Ok::<_, Error>(acc)
        })?;

    let rule_matches = state.obj.maps()
        .find(|m| m.name().to_string_lossy() == "rule_matches")
        .ok_or(Error::MetricsErr)?;

    let mut out = String::new();
    out.push_str("# HELP xdp_guard_accepted_packets_total Packets accepted by xdp-guard.\n");
    out.push_str("# TYPE xdp_guard_accepted_packets_total counter\n");
    out.push_str(&format!("xdp_guard_accepted_packets_total {}\n", stats.accepted_packets));
    out.push_str("# HELP xdp_guard_dropped_packets_total Packets dropped by xdp-guard.\n");
    out.push_str("# TYPE xdp_guard_dropped_packets_total counter\n");
    out.push_str(&format!("xdp_guard_dropped_packets_total {}\n", stats.dropped_packets));
    out.push_str("# HELP xdp_guard_rate_limit_hits_total Packets that hit a token-bucket rate limit.\n");
    out.push_str("# TYPE xdp_guard_rate_limit_hits_total counter\n");
    out.push_str(&format!("xdp_guard_rate_limit_hits_total {}\n", stats.rate_limit_hits));
    out.push_str("# HELP xdp_guard_rule_matches_total Rule matches by rule index.\n");
    out.push_str("# TYPE xdp_guard_rule_matches_total counter\n");

    for idx in 0..MAX_RULES {
        let idx_key = idx as u32;
        let key = as_byte_slice(&idx_key);
        let Some(cpu_values) = rule_matches.lookup_percpu(key, MapFlags::ANY)
            .map_err(|_| Error::MetricsErr)? else {
            continue;
        };
        let matches = cpu_values.iter()
            .try_fold(0u64, |acc, cpu| Ok::<_, Error>(acc + parse_u64(cpu)?))?;
        out.push_str(&format!("xdp_guard_rule_matches_total{{rule=\"{}\"}} {}\n", idx, matches));
    }

    out.push_str(&process_metrics()?);

    Ok(out)
}

fn process_metrics() -> Result<String, Error> {
    let registry = PROCESS_REGISTRY.get_or_init(|| {
        let registry = Registry::new();

        registry.register(Box::new(ProcessCollector::for_self()))
            .expect("process collector registration failed");

        registry
    });

    let mut buf = Vec::new();
    TextEncoder::new()
        .encode(&registry.gather(), &mut buf)
        .map_err(|_| Error::MetricsErr)?;

    String::from_utf8(buf).map_err(|_| Error::MetricsErr)
}

fn parse_fw_stats(bytes: &[u8]) -> Result<fw_stats, Error> {
    if bytes.len() < size_of::<fw_stats>() {
        return Err(Error::MetricsErr);
    }

    Ok(fw_stats {
        accepted_packets: parse_u64(&bytes[0..8])?,
        dropped_packets: parse_u64(&bytes[8..16])?,
        rate_limit_hits: parse_u64(&bytes[16..24])?,
    })
}

fn parse_u64(bytes: &[u8]) -> Result<u64, Error> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| Error::MetricsErr)?;
    Ok(u64::from_ne_bytes(bytes))
}

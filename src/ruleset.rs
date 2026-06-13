// SPDX-License-Identifier: MIT

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::ctypes::{Protocol, fw_rule};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IPMatcher {
    ip4: String,
    mask4: String,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum BucketCountMode {
    Packet,
    Bytes,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenBucketCfg {
    rate_per_sec: u64,
    burst: u64,
    count_mode: BucketCountMode
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortMatcher {
    port_begin: u16,
    port_end: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Block,
    Allow
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ruleset {
    pub default: DefaultAction,
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirewallRule {
    src_ip: Option<IPMatcher>,
    dst_ip: Option<IPMatcher>,

    src_port: Option<PortMatcher>,
    dst_port: Option<PortMatcher>,

    protocol: Option<Protocol>,

    token_bucket: Option<TokenBucketCfg>,

    pub priority: Option<u64>,
    pub action: DefaultAction,
}

impl FirewallRule {
    pub fn empty_rule(&self) -> bool {
        self.src_ip.is_none() &&
            self.dst_ip.is_none() &&
            self.src_port.is_none() &&
            self.dst_port.is_none() &&
            (self.protocol.is_none() || self.protocol == Some(Protocol::Any)) &&
            self.token_bucket.is_none()
    }

    pub fn invalid_rule(&self) -> bool {
        (self.dst_port.is_some()
         && self.protocol != Some(Protocol::Tcp) 
         && self.protocol != Some(Protocol::Udp)) ||

        (self.src_port.is_some()
         && self.protocol != Some(Protocol::Tcp) 
         && self.protocol != Some(Protocol::Udp))
    }

    pub fn to_ctype(&self) -> Result<fw_rule, ()> {
        let mut r = fw_rule::default();
        if let Some(s) = &self.src_ip {
            let addr: Ipv4Addr = s.ip4.parse().map_err(|_| ())?;
            let mask: Ipv4Addr = s.mask4.parse().map_err(|_| ())?;
            let ip_u32 = u32::from(addr);
            let mask_u32 = u32::from(mask);
            r.match_src_ip4(ip_u32, mask_u32);
        }
        if let Some(d) = &self.dst_ip {
            let addr: Ipv4Addr = d.ip4.parse().map_err(|_| ())?;
            let mask: Ipv4Addr = d.mask4.parse().map_err(|_| ())?;
            let ip_u32 = u32::from(addr);
            let mask_u32 = u32::from(mask);
            r.match_dst_ip4(ip_u32, mask_u32);
        }
        if let Some(s) = &self.src_port {
            r.match_src_port(s.port_begin, s.port_end);
        }
        if let Some(d) = &self.dst_port {
            r.match_dst_port(d.port_begin, d.port_end);
        }
        if let Some(p) = &self.protocol {
            r.match_protocol(p.clone());
        }
        if let Some(tb) = &self.token_bucket {
            r.set_token_bucket(
                tb.rate_per_sec,
                tb.burst,
                if tb.count_mode == BucketCountMode::Bytes { true } else { false }
            );
        }
        match self.action {
            DefaultAction::Block => r.default_block(),
            _ => {},
        }
        Ok(r)
    }
}

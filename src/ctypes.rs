use std::mem::{align_of, offset_of, size_of};
use serde::{Deserialize, Serialize};
const MAX_RULES: usize = 32; // WARN: must match header file's value

const RULE_MATCH_DST_IP: u16 =     1 << 0;
const RULE_MATCH_SRC_IP: u16 =     1 << 1;
const RULE_MATCH_DST_PORT: u16 =   1 << 2;
const RULE_MATCH_SRC_PORT: u16 =   1 << 3;
const RULE_USE_TB: u16 =           1 << 4;
const RULE_TB_MODE_PACKET: u16 =   1 << 5;
const RULE_ACTION_BLOCK: u16 =     1 << 15;

#[repr(u8)]
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Any    = 0,
    Icmp   = 1,
    Igmp   = 2,
    Tcp    = 6,
    Udp    = 17,
    Encap  = 41,
    Ospf   = 89,
    Sctp   = 132,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct fw_rule {
	tb_rate_per_sec: u64,
    tb_burst:        u64,
	dst_ip4:         u32,
	dst_mask4:       u32,
	src_ip4:         u32,
	src_mask4:       u32,

	// WARNING: host endian
	dst_port_begin: u16,
	dst_port_end:   u16,
	src_port_begin: u16,
	src_port_end:   u16,

	flags: u16,
	proto: u8,
	_pad: u8,
}

impl fw_rule {
    pub fn new() -> Self {
        fw_rule {
            tb_rate_per_sec: 0,
            tb_burst:        0,
            dst_ip4:         0,
            dst_mask4:       0,
            src_ip4:         0,
            src_mask4:       0,

            // WARNING: host endian
            dst_port_begin: 0,
            dst_port_end:   0,
            src_port_begin: 0,
            src_port_end:   0,

            flags:  0,
            proto:  0,
            _pad: 0,
        }
    }

    /// matches source port \[port_begin, port_end\]
    pub fn match_src_port(&mut self, port_begin: u16, port_end: u16) {
        self.src_port_begin = port_begin;
        self.src_port_end = port_end;
        self.flags |= RULE_MATCH_SRC_PORT;
    }

    /// matches destination port \[port_begin, port_end\]
    pub fn match_dst_port(&mut self, port_begin: u16, port_end: u16) {
        self.dst_port_begin = port_begin;
        self.dst_port_end = port_end;
        self.flags |= RULE_MATCH_DST_PORT;
    }

    pub fn match_src_ip4(&mut self, ip: u32, mask: u32) {
        self.src_ip4 = ip.to_be();
        self.src_mask4 = mask.to_be();
        self.flags |= RULE_MATCH_SRC_IP;
    }

    pub fn match_dst_ip4(&mut self, ip: u32, mask: u32) {
        self.dst_ip4 = ip.to_be();
        self.dst_mask4 = mask.to_be();
        self.flags |= RULE_MATCH_DST_IP;
    }

    pub fn match_protocol(&mut self, protocol: Protocol) {
        self.proto = (protocol as u8).to_be();
    }

    pub fn default_block(&mut self) {
        self.flags |= RULE_ACTION_BLOCK;
    }

    pub fn set_token_bucket(&mut self, rate_per_sec: u64, burst: u64, count_bytes: bool) {
        self.tb_rate_per_sec = rate_per_sec;
        self.tb_burst = burst;
        self.flags |= RULE_USE_TB;
        if !count_bytes {
            self.flags |= RULE_TB_MODE_PACKET
        }
    }
}

#[repr(C)]
pub struct fw_ruleset {
	rule_cnt: u32,
	flags: u32,
	rules: [fw_rule; MAX_RULES]
}

impl fw_ruleset {
    pub fn from_rules(rules: Vec<fw_rule>, default_block: bool) -> Self {
        let mut rules_buf: [fw_rule; MAX_RULES] = [fw_rule::default(); MAX_RULES];
        for i in 0..rules.len() {
            if i >= MAX_RULES { break; }
            rules_buf[i] = rules[i];
        }
        let cnt = if rules.len() > MAX_RULES { MAX_RULES as u32 } else { rules.len() as u32 };
        Self {
            rule_cnt: cnt,
            flags: if default_block { 1 } else { 0 },
            rules: rules_buf,
        }
    }
}

impl Default for fw_ruleset {
    fn default() -> Self {
        Self { rule_cnt: 0, flags: 0, rules: [fw_rule::default(); MAX_RULES] }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fw_meta {
    pub active_ruleset: u32,
}

const _: () = {
    assert!(size_of::<fw_rule>() == 48);
    assert!(align_of::<fw_rule>() == 8);

	assert!(offset_of!(fw_rule, tb_rate_per_sec) == 0);
    assert!(offset_of!(fw_rule, tb_burst) == 8);
	assert!(offset_of!(fw_rule, dst_ip4) == 16);
	assert!(offset_of!(fw_rule, dst_mask4) == 20);
	assert!(offset_of!(fw_rule, src_ip4) == 24);
	assert!(offset_of!(fw_rule, src_mask4) == 28);
	assert!(offset_of!(fw_rule, dst_port_begin) == 32);
	assert!(offset_of!(fw_rule, dst_port_end) == 34);
	assert!(offset_of!(fw_rule, src_port_begin) == 36);
	assert!(offset_of!(fw_rule, src_port_end) == 38);
	assert!(offset_of!(fw_rule, flags) == 40);
	assert!(offset_of!(fw_rule, proto) == 42);
	assert!(offset_of!(fw_rule, _pad) == 43);

    assert!(size_of::<fw_ruleset>() == (8 + MAX_RULES * size_of::<fw_rule>()));
    assert!(align_of::<fw_ruleset>() == 8);

    assert!(size_of::<fw_meta>() == 4);
    assert!(align_of::<fw_meta>() == 4);
};

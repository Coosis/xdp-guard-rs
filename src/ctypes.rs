const MAX_RULES: usize = 32; // WARN: must match header file's value

#[repr(C)]
struct fw_rule {
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
	tb_idx: u8,
}

#[repr(C)]
struct fw_ruleset {
	rule_cnt: u32,
	flags: u32,
	rules: [fw_rule; MAX_RULES]
}

#[repr(C)]
struct fw_meta {
    active_ruleset: u32,
}

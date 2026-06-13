#include <linux/bpf.h>

struct tb_state {
	__u64 tokens;
	__u64 last_ns;
};

#define RULE_MATCH_DST_IP     (1 << 0)
#define RULE_MATCH_SRC_IP     (1 << 1)
#define RULE_MATCH_DST_PORT   (1 << 2)
#define RULE_MATCH_SRC_PORT   (1 << 3)
#define RULE_USE_TB           (1 << 4)
#define RULE_TB_MODE_PACKET   (1 << 5)
#define RULE_ACTION_BLOCK     (1 << 15)

#define RULE_PROTO_ANY   0
#define RULE_PROTO_ICMP  1
#define RULE_PROTO_IGMP  2
#define RULE_PROTO_TCP   6
#define RULE_PROTO_UDP   17
#define RULE_PROTO_ENCAP 41
#define RULE_PROTO_OSPF  89
#define RULE_PROTO_SCTP  132

struct fw_rule {
	// token bucket config
	__u64 tb_rate_per_sec;
    __u64 tb_burst;

	// ip/cidr rules, big endian to reduce number of instructions needed to compare
	__u32 dst_ip4;
	__u32 dst_mask4;
	__u32 src_ip4;
	__u32 src_mask4;

	// ports, only make sense when proto = tcp/udp, ignored on other protocols
	// WARNING: must be host endian for range comparisons
	__u16 dst_port_begin;
	__u16 dst_port_end;
	__u16 src_port_begin;
	__u16 src_port_end;

	__u16 flags;
	// protocol(use ip header's protocol number directly)
	__u8 proto;
	__u8 _pad;
};

#define NUM_GENERATIONS 3
#define MAX_RULES 32
#define RULESET_DEFAULT_BLOCK (1 << 0)
struct fw_ruleset {
	__u32 rule_cnt;
	__u32 flags;
	struct fw_rule rules[MAX_RULES];
};

struct fw_meta {
    __u32 active_ruleset;
};

#define OFFSETOF(type, member) __builtin_offsetof(type, member)
#define STATIC_ASSERT _Static_assert

STATIC_ASSERT(sizeof(struct fw_rule) == 48, "fw_rule size changed"); // 44 + alignment = 48
STATIC_ASSERT(__alignof__(struct fw_rule) == 8, "fw_rule alignment changed"); // __u64 should be 8 bytes-aligned

STATIC_ASSERT(OFFSETOF(struct fw_rule, tb_rate_per_sec) == 0,  "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, tb_burst)        == 8,  "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, dst_ip4)         == 16, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, dst_mask4)       == 20, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, src_ip4)         == 24, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, src_mask4)       == 28, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, dst_port_begin)  == 32, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, dst_port_end)    == 34, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, src_port_begin)  == 36, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, src_port_end)    == 38, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, flags)           == 40, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, proto)           == 42, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_rule, _pad)             == 43, "bad offset");

STATIC_ASSERT(sizeof(struct tb_state) == 16, "tb_state size changed");
STATIC_ASSERT(__alignof__(struct tb_state) == 8, "tb_state alignment changed");

STATIC_ASSERT(OFFSETOF(struct tb_state, tokens) == 0, "bad offset");
STATIC_ASSERT(OFFSETOF(struct tb_state, last_ns) == 8, "bad offset");

STATIC_ASSERT(sizeof(struct fw_ruleset) == 8 + MAX_RULES * sizeof(struct fw_rule), "fw_ruleset size changed");
STATIC_ASSERT(__alignof__(struct fw_ruleset) == 8, "fw_ruleset alignment changed");

STATIC_ASSERT(OFFSETOF(struct fw_ruleset, rule_cnt) == 0, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_ruleset, flags) == 4, "bad offset");
STATIC_ASSERT(OFFSETOF(struct fw_ruleset, rules) == 8, "bad offset");

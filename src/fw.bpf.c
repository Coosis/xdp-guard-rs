#include "fw.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NUM_GENERATIONS 3
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_GENERATIONS);
    __type(key, __u32);
    __type(value, struct fw_ruleset);
} rulesets SEC(".maps");

#define MAX_TBS 8
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_TBS);
    __type(key, __u32);
    __type(value, struct tb_state);
} tb_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fw_meta);
} fw_meta SEC(".maps");

#define RULE_NOMATCH 0
#define RULE_MATCH_ALLOW 1
#define RULE_MATCH_TB_DENY 2
// if a rule has RULE_USE_TB, it only matches while the bucket has enough tokens;
// if the bucket is empty, the rule is treated as not matched and evaluation continues.
static __always_inline int match_rule(
		struct fw_rule *rule,
		struct iphdr *ip_head,
		void *data_end,
		__u64 data_sz // only used when tb is turned on + count packet bytes
		) {
	if(rule == NULL) return RULE_NOMATCH;
	// is rule empty?
	if(!( (rule->flags & RULE_MATCH_SRC_IP) 
				|| (rule->flags & RULE_MATCH_DST_IP)
				|| (rule->flags & RULE_MATCH_SRC_PORT)
				|| (rule->flags & RULE_MATCH_DST_PORT)
				|| (rule->flags & RULE_USE_TB)
				|| (rule->proto != RULE_PROTO_ANY)
		)) { /* nothing needs matching, ignore */ return RULE_NOMATCH; }

	// ignore if want to match port & not tcp & not udp
	if ((rule->flags & (RULE_MATCH_SRC_PORT | RULE_MATCH_DST_PORT)) &&
			rule->proto != RULE_PROTO_TCP &&
			rule->proto != RULE_PROTO_UDP) {
		return RULE_NOMATCH;
	}

	// past this point, there's at least one thing to match;
	// if any fail, check returns early to avoid more checks
	// NOTE: rule already have big endian inside, no conversion needed;
	// this is done to avoid conversion on-the-fly for speed benefits

	// src ip?
	if(rule->flags & RULE_MATCH_SRC_IP) {
		if( (ip_head->saddr & rule->src_mask4) != rule->src_ip4 ) return RULE_NOMATCH;
	}

	// dst ip?
	if(rule->flags & RULE_MATCH_DST_IP) {
		if( (ip_head->daddr & rule->dst_mask4) != rule->dst_ip4 ) return RULE_NOMATCH;
	}

	// protocols
	if(rule->proto != RULE_PROTO_ANY) {
		// must match protocol
		if(rule->proto != ip_head->protocol) return RULE_NOMATCH; // wrong protocol

		// only tcp & udp need port matching
		if(rule->proto == RULE_PROTO_TCP || rule->proto == RULE_PROTO_UDP) {
			__u32 ihl_bytes = ip_head->ihl * 4;
			if (ihl_bytes < sizeof(struct iphdr)) return RULE_NOMATCH; // what the heck??
			if( ((void *)ip_head) + ihl_bytes + 4 > data_end ) return RULE_NOMATCH; // not enough data for ports

			void *proto_head = ( (void *)ip_head ) + ihl_bytes;

			if(rule->flags & RULE_MATCH_SRC_PORT) {
				__u16 src_port = bpf_ntohs(*(__be16 *)proto_head);
				if( src_port < rule->src_port_begin || src_port > rule->src_port_end ) return RULE_NOMATCH;
			}
			if(rule->flags & RULE_MATCH_DST_PORT) {
				__u16 dst_port = bpf_ntohs(*((__be16 *)proto_head + 1));
				if( dst_port < rule->dst_port_begin || dst_port > rule->dst_port_end ) return RULE_NOMATCH;
			}
		}
	}

	// token bucket update if necessary
	if(rule->flags & RULE_USE_TB) {
		__u32 tb_idx = rule->tb_idx;
		if(tb_idx >= MAX_TBS) return RULE_NOMATCH; // possible corrupted rule, skip
		struct tb_state *state = bpf_map_lookup_elem((void *)&tb_state, &tb_idx);
		if(state == NULL) return RULE_NOMATCH; // possible corrupted rule, skip

		__u64 now = bpf_ktime_get_ns();
		if (state->last_ns == 0) { // avoid comparing with boot time accidently
			state->tokens = rule->tb_burst;
			state->last_ns = now;
		}
		__u64 elapsed = now - state->last_ns;
		state->last_ns = now;

		__u64 add = elapsed * rule->tb_rate_per_sec / 1000000000ULL;
		__u64 tokens = state->tokens + add;
		if (tokens < state->tokens)
			tokens = rule->tb_burst;
		if (tokens > rule->tb_burst)
			tokens = rule->tb_burst;

		__u64 cost = 0;
		if(rule->flags & RULE_TB_MODE_PACKET) cost = 1;
		else cost = data_sz;

		if(tokens >= cost) {
			state->tokens = tokens - cost;
			return RULE_MATCH_ALLOW;
		}
		state->tokens = tokens;
		return RULE_MATCH_TB_DENY;
	}

	return RULE_MATCH_ALLOW; // all checks passed
}

SEC("xdp") int xdp_fw(struct xdp_md *ctx) {
	__u32 zero = 0;
	struct fw_meta *fwm = bpf_map_lookup_elem((void *)&fw_meta, &zero);
	if(fwm == NULL) return XDP_PASS;

	__u32 active = fwm->active_ruleset;
	if (active >= NUM_GENERATIONS)
		return XDP_PASS;
	struct fw_ruleset *rules = bpf_map_lookup_elem((void *)&rulesets, &active);
	if(rules == NULL) return XDP_PASS;

	// parsing
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if( (void *)(eth + 1) > data_end ) return XDP_PASS; // not enough data even for eth header
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS; // not ethernet + ip, ignore

	struct iphdr *ip_head = (void *)(eth + 1);
	// must have ip header, otherwise ignore
	if((void *)(ip_head + 1) > data_end) return XDP_PASS;

	// ignore if not ivp4
	if(ip_head->version != 4) return XDP_PASS;

	__u32 rule_cnt = rules->rule_cnt;
	if (rule_cnt > MAX_RULES)
		rule_cnt = MAX_RULES;

	#pragma unroll
	for(__u32 i = 0; i < MAX_RULES; i++) {
		if(i >= rule_cnt) break;
		int result = match_rule(&rules->rules[i], ip_head, data_end, data_end - data);
		if(result == RULE_MATCH_ALLOW) {
			if(rules->rules[i].flags & RULE_ACTION_BLOCK) return XDP_DROP;
			else return XDP_PASS;
		}
		// result = RULE_NOMATCH | RULE_MATCH_TB_DENY,
		// both skip rule
	}

	bpf_printk("myxdp hit\n");
	// TODO! prometheus stats?
	int def_action = (rules->flags & RULESET_DEFAULT_BLOCK) ? XDP_DROP : XDP_PASS;
	return def_action;
}

char LICENSE[] SEC("license") = "GPL";


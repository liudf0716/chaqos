// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_skb_utils.h"
#include "qosify-bpf.h"

#define INET_ECN_MASK 3

#define FLOW_CHECK_INTERVAL	((u32)((1000000000ULL) >> 24))
#define FLOW_TIMEOUT		((u32)((30ULL * 1000000000ULL) >> 24))
#define FLOW_BULK_TIMEOUT	5

#define EWMA_SHIFT		12

const volatile static uint32_t module_flags = 0;

struct flow_bucket {
	__u32 last_update;
	__u32 pkt_len_avg;
	__u32 pkt_count;
	__u32 bulk_timeout;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct qosify_config);
	__uint(max_entries, 1);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 1 << 16);
} tcp_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 1 << 16);
} udp_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct flow_bucket);
	__uint(max_entries, QOSIFY_FLOW_BUCKETS);
} flow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, 1);
	__uint(key_size, sizeof(struct in_addr));
	__type(value, struct qosify_ip_map_val);
	__uint(max_entries, 100000);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, 1);
	__uint(key_size, sizeof(struct in6_addr));
	__type(value, struct qosify_ip_map_val);
	__uint(max_entries, 100000);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct qosify_class);
	__uint(max_entries, QOSIFY_MAX_CLASS_ENTRIES +
			    QOSIFY_DEFAULT_CLASS_ENTRIES);
} class_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, struct in_addr);
	__type(value, struct qosify_ip_stats_val);
	__uint(max_entries, 100000);
} ipv4_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, struct in6_addr);
	__type(value, struct qosify_ip_stats_val);
	__uint(max_entries, 100000);
} ipv6_stats_map SEC(".maps");

static struct qosify_config *get_config(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&config, &key);
}

static __always_inline __u32 cur_time(void)
{
	__u32 val = bpf_ktime_get_ns() >> 24;

	if (!val)
		val = 1;

	return val;
}

static __always_inline __u32 ewma(__u32 *avg, __u32 val)
{
	if (*avg)
		*avg = (*avg * 3) / 4 + (val << EWMA_SHIFT) / 4;
	else
		*avg = val << EWMA_SHIFT;

	return *avg >> EWMA_SHIFT;
}

static __always_inline __u8 dscp_val(struct qosify_dscp_val *val, bool ingress)
{
	__u8 ival = val->ingress;
	__u8 eval = val->egress;

	return ingress ? ival : eval;
}

static __always_inline void
ipv4_change_dsfield(struct __sk_buff *skb, __u32 offset,
		    __u8 mask, __u8 value, bool force)
{
	struct iphdr *iph;
	__u32 check;
	__u8 dsfield;

	iph = skb_ptr(skb, offset, sizeof(*iph));
	if (!iph)
		return;

	check = bpf_ntohs(iph->check);
	if ((iph->tos & mask) && !force)
		return;

	dsfield = (iph->tos & mask) | value;
	if (iph->tos == dsfield)
		return;

	check += iph->tos;
	if ((check + 1) >> 16)
		check = (check + 1) & 0xffff;
	check -= dsfield;
	check += check >> 16;
	iph->check = bpf_htons(check);
	iph->tos = dsfield;
}

static __always_inline void
ipv6_change_dsfield(struct __sk_buff *skb, __u32 offset,
		    __u8 mask, __u8 value, bool force)
{
	struct ipv6hdr *ipv6h;
	__u16 *p;
	__u16 val;

	ipv6h = skb_ptr(skb, offset, sizeof(*ipv6h));
	if (!ipv6h)
		return;

	p = (__u16 *)ipv6h;
	if (((*p >> 4) & mask) && !force)
		return;

	val = (*p & bpf_htons((((__u16)mask << 4) | 0xf00f))) | bpf_htons((__u16)value << 4);
	if (val == *p)
		return;

	*p = val;
}

static void
parse_l4proto(struct qosify_config *config, struct skb_parser_info *info,
	      bool ingress, __u8 *out_val)
{
	struct udphdr *udp;
	__u32 src, dest, key;
	__u8 *value;
	__u8 proto = info->proto;

	udp = skb_info_ptr(info, sizeof(*udp));
	if (!udp)
		return;

	if (config && (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)) {
		*out_val = config->dscp_icmp;
		return;
	}

	src = READ_ONCE(udp->source);
	dest = READ_ONCE(udp->dest);
	if (ingress)
		key = src;
	else
		key = dest;

	if (proto == IPPROTO_TCP) {
		value = bpf_map_lookup_elem(&tcp_ports, &key);
	} else {
		if (proto != IPPROTO_UDP)
			key = 0;

		value = bpf_map_lookup_elem(&udp_ports, &key);
	}

	if (value)
		*out_val = *value;
}

static __always_inline bool
check_flow_bulk(struct qosify_flow_config *config, struct __sk_buff *skb,
		struct flow_bucket *flow, __u8 *out_val)
{
	bool trigger = false;
	__s32 delta;
	__u32 time;
	int segs = 1;
	bool ret = false;

	if (!config->bulk_trigger_pps)
		return false;

	time = cur_time();
	if (!flow->last_update)
		goto reset;

	delta = time - flow->last_update;
	if ((u32)delta > FLOW_TIMEOUT)
		goto reset;

	if (skb->gso_segs)
		segs = skb->gso_segs;
	flow->pkt_count += segs;
	if (flow->pkt_count > config->bulk_trigger_pps) {
		flow->bulk_timeout = config->bulk_trigger_timeout + 1;
		trigger = true;
	}

	if (delta >= FLOW_CHECK_INTERVAL) {
		if (flow->bulk_timeout && !trigger)
			flow->bulk_timeout--;

		goto clear;
	}

	goto out;

reset:
	flow->pkt_len_avg = 0;
clear:
	flow->pkt_count = 1;
	flow->last_update = time;
out:
	if (flow->bulk_timeout) {
		*out_val = config->dscp_bulk;
		return true;
	}

	return false;
}

static __always_inline bool
check_flow_prio(struct qosify_flow_config *config, struct __sk_buff *skb,
		struct flow_bucket *flow, __u8 *out_val)
{
	int cur_len = skb->len;

	if (flow->bulk_timeout)
		return false;

	if (!config->prio_max_avg_pkt_len)
		return false;

	if (skb->gso_segs > 1)
		cur_len /= skb->gso_segs;

	if (ewma(&flow->pkt_len_avg, cur_len) <= config->prio_max_avg_pkt_len) {
		*out_val = config->dscp_prio;
		return true;
	}

	return false;
}

static __always_inline bool
check_flow(struct qosify_flow_config *config, struct __sk_buff *skb,
	   __u8 *out_val)
{
	struct flow_bucket flow_data;
	struct flow_bucket *flow;
	__u32 hash;
	bool ret = false;

	if (!config)
		return false;

	if (!config->prio_max_avg_pkt_len && !config->bulk_trigger_pps)
		return false;

	hash = bpf_get_hash_recalc(skb);
	flow = bpf_map_lookup_elem(&flow_map, &hash);
	if (!flow) {
		memset(&flow_data, 0, sizeof(flow_data));
		bpf_map_update_elem(&flow_map, &hash, &flow_data, BPF_ANY);
		flow = bpf_map_lookup_elem(&flow_map, &hash);
		if (!flow)
			return false;
	}

	ret |= check_flow_bulk(config, skb, flow, out_val);
	ret |= check_flow_prio(config, skb, flow, out_val);

	return ret;
}

static __always_inline __u32
calc_rate_estimator(struct qosify_ip_stats_val *val, bool ingress)
{
#define	SMOOTH_VALUE	10
	__u32 now = cur_time();
	__u32 est_slot = now / RATE_ESTIMATOR;
	__u32 rate = 0;
	__u64 cur_bytes = 0;
	__u32 delta = RATE_ESTIMATOR - (now % RATE_ESTIMATOR);
	__u32 ratio = RATE_ESTIMATOR * SMOOTH_VALUE / delta;

	if (val->est_slot == est_slot) {
		rate = val->stats[ingress].prev_s_bytes;
		cur_bytes = val->stats[ingress].cur_s_bytes;
	} else if (val->est_slot == est_slot - 1) {
		rate = val->stats[ingress].cur_s_bytes;
	} else {
		return 0;
	}

	rate = rate * SMOOTH_VALUE / ratio;
	rate += cur_bytes;

	return rate * 8 / RATE_ESTIMATOR;
}

static __always_inline void
rate_estimator(struct qosify_ip_stats_val *val, __u32 est_slot, __u32 len, bool ingress)
{
	if (val->est_slot == est_slot) {
		val->stats[ingress].cur_s_bytes += len;
	} else {
		if (val->est_slot == est_slot - 1) {
			val->stats[ingress].prev_s_bytes = val->stats[ingress].cur_s_bytes;
		} else {
			val->stats[ingress].prev_s_bytes = 0;
		}
		val->stats[ingress].cur_s_bytes = 0;
		val->est_slot = est_slot;
	}
}

static __always_inline struct qosify_ip_map_val *
parse_ipv4(struct qosify_config *config, struct skb_parser_info *info,
	   bool ingress, __u8 *out_val)
{
	struct iphdr *iph;
	__u8 ipproto;
	int hdr_len;
	void *key;
	struct qosify_ip_stats_val *val = NULL;
	__u32 now = cur_time();
	struct in_addr addr;
	struct qosify_ip_stats_val new_val;
	__builtin_memset(&addr, 0, sizeof(addr));
	__builtin_memset(&new_val, 0, sizeof(new_val));

	iph = skb_parse_ipv4(info, sizeof(struct udphdr));
	if (!iph)
		return NULL;

	parse_l4proto(config, info, ingress, out_val);

	if (ingress) {
		key = &iph->saddr;
		addr.s_addr = iph->saddr;
	} else {
		key = &iph->daddr;
		addr.s_addr = iph->daddr;
	}

	val = bpf_map_lookup_elem(&ipv4_stats_map, &addr);
	if (val) {
		rate_estimator(val, now / RATE_ESTIMATOR, info->skb->len, ingress);
	} else {
		new_val.stats[ingress].cur_s_bytes = info->skb->len;
		bpf_map_update_elem(&ipv4_stats_map, &addr, &new_val, BPF_ANY);
	}

	return bpf_map_lookup_elem(&ipv4_map, key);
}

static __always_inline struct qosify_ip_map_val *
parse_ipv6(struct qosify_config *config, struct skb_parser_info *info,
	   bool ingress, __u8 *out_val)
{
	struct ipv6hdr *iph;
	__u8 ipproto;
	void *key;
	struct qosify_ip_stats_val *val = NULL;
	__u32 now = cur_time();
	struct in6_addr addr;
	struct qosify_ip_stats_val new_val;
	__builtin_memset(&addr, 0, sizeof(addr));
	__builtin_memset(&new_val, 0, sizeof(new_val));

	iph = skb_parse_ipv6(info, sizeof(struct udphdr));
	if (!iph)
		return NULL;

	if (ingress) {
		memcpy(&addr, &iph->saddr, sizeof(addr));
		key = &iph->saddr;
	} else {
		memcpy(&addr, &iph->daddr, sizeof(addr));
		key = &iph->daddr;
	}

	val = bpf_map_lookup_elem(&ipv6_stats_map, &addr);
	if (val) {
		rate_estimator(val, now / RATE_ESTIMATOR, info->skb->len, ingress);
	} else {
		new_val.stats[ingress].cur_s_bytes = info->skb->len;
		bpf_map_update_elem(&ipv6_stats_map, &addr, &new_val, BPF_ANY);
	}

	parse_l4proto(config, info, ingress, out_val);

	return bpf_map_lookup_elem(&ipv6_map, key);
}

static __always_inline int
dscp_lookup_class(uint8_t *dscp, bool ingress, struct qosify_class **out_class,
		  bool counter)
{
	struct qosify_class *class;
	__u8 fallback_flag;
	__u32 key;

	if (!(*dscp & QOSIFY_DSCP_CLASS_FLAG))
		return 0;

	fallback_flag = *dscp & QOSIFY_DSCP_FALLBACK_FLAG;
	key = *dscp & QOSIFY_DSCP_VALUE_MASK;
	class = bpf_map_lookup_elem(&class_map, &key);
	if (!class)
		return -1;

	if (!(class->flags & QOSIFY_CLASS_FLAG_PRESENT))
		return -1;

	if (counter)
	    class->packets++;
	*dscp = dscp_val(&class->val, ingress);
	*dscp |= fallback_flag;
	*out_class = class;

	return 0;
}

SEC("tc")
int classify(struct __sk_buff *skb)
{
	struct skb_parser_info info;
	bool ingress = module_flags & QOSIFY_INGRESS;
	struct qosify_config *config;
	struct qosify_class *class = NULL;
	struct qosify_ip_map_val *ip_val;
	__u32 iph_offset;
	__u8 dscp = 0;
	void *iph;
	bool force;
	int type;

	config = get_config();
	if (!config)
		return TC_ACT_UNSPEC;

	skb_parse_init(&info, skb);
	if (module_flags & QOSIFY_IP_ONLY) {
		type = info.proto = skb->protocol;
	} else if (skb_parse_ethernet(&info)) {
		skb_parse_vlan(&info);
		skb_parse_vlan(&info);
		type = info.proto;
	} else {
		return TC_ACT_UNSPEC;
	}

	iph_offset = info.offset;
	if (type == bpf_htons(ETH_P_IP))
		ip_val = parse_ipv4(config, &info, ingress, &dscp);
	else if (type == bpf_htons(ETH_P_IPV6))
		ip_val = parse_ipv6(config, &info, ingress, &dscp);
	else
		return TC_ACT_UNSPEC;

	if (ip_val) {
		if (!ip_val->seen)
			ip_val->seen = 1;
		dscp = ip_val->dscp;
	}

	if (dscp_lookup_class(&dscp, ingress, &class, true))
		return TC_ACT_UNSPEC;

	if (class) {
		if (check_flow(&class->config, skb, &dscp) &&
		    dscp_lookup_class(&dscp, ingress, &class, false))
			return TC_ACT_UNSPEC;
	}

	dscp &= GENMASK(5, 0);
	dscp <<= 2;
	force = !(dscp & QOSIFY_DSCP_FALLBACK_FLAG);

	if (type == bpf_htons(ETH_P_IP))
		ipv4_change_dsfield(skb, iph_offset, INET_ECN_MASK, dscp, force);
	else if (type == bpf_htons(ETH_P_IPV6))
		ipv6_change_dsfield(skb, iph_offset, INET_ECN_MASK, dscp, force);

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";

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
#include <linux/bpf.h>
#include <net/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "bpf_skb_utils.h"
#include "qosify-bpf.h"
#include "jhash.h"
#include "builtins.h"
#include "chadpi.h"

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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct qosify_ipv4_mask_config);
	__uint(max_entries, 10);
} ipv4_mask_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct qosify_ipv6_mask_config);
	__uint(max_entries, 10);
} ipv6_mask_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, struct in_addr);
	__type(value, struct qosify_traffic_stats_val);
	__uint(max_entries, 2000);
} ipv4_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, struct in6_addr);
	__type(value, struct qosify_traffic_stats_val);
	__uint(max_entries, 2000);
} ipv6_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, struct qosify_flowv4_keys);
	__type(value, struct qosify_conn_stats);
	__uint(max_entries, 100000);
} flow_table_v4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, struct qosify_flowv6_keys);
	__type(value, struct qosify_conn_stats);
	__uint(max_entries, 100000);
} flow_table_v6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct qosify_traffic_stats_val);
	__uint(max_entries, DPI_MAX_NUM);
} dpi_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct qosify_dpi_match_pattern);
	__uint(max_entries, DPI_MAX_NUM);
} dpi_match_map SEC(".maps");

static struct qosify_config *get_config(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&config, &key);
}

static struct qosify_ipv4_mask_config *get_ipv4_mask(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ipv4_mask_map, &key);
}

static struct qosify_ipv6_mask_config *get_ipv6_mask(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ipv6_mask_map, &key);
}

static __always_inline __u32
hash_tuple4(struct qosify_flowv4_keys *keys)
{
	__u32 hash = 0;

	hash = jhash_3words(keys->src_ip, keys->dst_ip, keys->src_port, 0);
	hash = jhash_2words(keys->dst_port, keys->proto, hash);

	return hash;
}

static __always_inline __u32 cur_time(void)
{
	__u32 val = bpf_ktime_get_ns() >> 24;

	if (!val)
		val = 1;

	return val;
}

static __always_inline __u32 cur_time_sec(void)
{
	__u32 val = bpf_ktime_get_ns() / 1000000000;

	if (!val)
		val = 1;

	return val;
}

static __always_inline __u32 bits2mask(__u32 bits)
{
	return (bits? 0xffffffffU << (32 - bits) : 0);
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
		__bpf_memzero(&flow_data, sizeof(flow_data));
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
calc_rate_estimator(struct qosify_traffic_stats_val *val, bool ingress)
{
#define	SMOOTH_VALUE	10
	__u32 now = cur_time_sec();
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
rate_estimator(struct qosify_traffic_stats_val *val, __u32 est_slot, __u32 len, bool ingress)
{
	if (val->est_slot == est_slot) {
		val->stats[ingress].cur_s_bytes += len;
		//__sync_fetch_and_add(&val->stats[ingress].total_bytes, len);
	} else {
		if (val->est_slot == est_slot - 1) {
			val->stats[ingress].prev_s_bytes = val->stats[ingress].cur_s_bytes;
		} else {
			val->stats[ingress].prev_s_bytes = 0;
		}
		val->stats[ingress].cur_s_bytes = 0;
		val->est_slot = est_slot;
	}

	val->stats[ingress].total_bytes += len;
	val->stats[ingress].total_packets++;
}

static __always_inline int
dpi_match_scan(const __u8 *payload, const __u8 *pattern, __u32 pattern_len, __u32 payload_len)
{
#define MAX_SCAN_LEN 1000
	__u16 i;
	__u16 len;
	if (pattern_len > MAX_PATTERN_LEN)
		pattern_len = MAX_PATTERN_LEN;
	if (pattern_len > payload_len)
		return 1;
	len = payload_len - pattern_len;
	if (len > MAX_SCAN_LEN)
		len = MAX_SCAN_LEN;
	
	for (i = 0; i < len; i++) {
		if (__bpf_memcmp(payload + i, pattern, pattern_len) == 0)
			return 0;
	}

	return 1;
}


static __always_inline long 
dpi_match_iterator_cb(__u32 index, void *ctx)
{
	struct qosify_dpi_match_pattern *pattern = bpf_map_lookup_elem(&dpi_match_map, &index);
	struct dpi_match_ctx *match_ctx = (struct dpi_match_ctx *)ctx;
	if (!pattern || pattern->dpi_id == 0) {
		bpf_printk("dpi_match_iterator_cb: end of pattern \n");
		return 1; // stop the loop
	}

	
	if (pattern->proto != match_ctx->proto || (!pattern->dport && pattern->dport != match_ctx->dport))
		return 0;
	
	if ((!pattern->start && pattern->start >= match_ctx->payload_len)||
		(!pattern->end && pattern->end > match_ctx->payload_len) ||
		pattern->pattern_len > match_ctx->payload_len)
		return 0;

	if (dpi_match_scan(match_ctx->payload + pattern->start,
		pattern->pattern, pattern->pattern_len,
		pattern->end? pattern->end : match_ctx->payload_len ) == 0) {
		match_ctx->dpi_id = pattern->dpi_id;
		bpf_printk("dpi_match_iterator_cb: match found %d \n", pattern->dpi_id);
		return 1; // stop the loop
	}

	return 0;
}

static  __u16
dpi_engine_match(__u8 proto, __u16 dport, __u8 *payload, __u32 payload_len, bool ingress)
{
	__u32 count = DPI_MAX_NUM;
	struct dpi_match_ctx ctx;
	__bpf_memzero(&ctx, sizeof(ctx));
	ctx.proto = proto;
	ctx.dport = dport;
	ctx.payload = payload;
	ctx.payload_len = payload_len;
	ctx.ingress = ingress;

	int ret = bpf_loop(count, dpi_match_iterator_cb, &ctx, 0);
	if (ret < 0)
		bpf_printk("dpi_engine_match: bpf_loop failed %d\n", ret);
	
	if (ctx.dpi_id == 0 && !ingress) {
		bpf_printk("dpi_engine_match: dpi_id not found, try to match extension\n");
		bpf_printk("dpi_engine_match: proto %d, dport %d, payload_len %d\n", proto, bpf_htons(dport), payload_len);
		ctx.dpi_id = dpi_match_extension(proto, bpf_htons(dport), payload, payload_len, ingress);
	}
		
	return ctx.dpi_id;
}

static __always_inline __u8
check_tcp_finish(struct tcphdr *tcph)
{
	// if tcp packet is finish the connection then return 1
	if (tcph->fin || tcph->rst)
		return 1;

	return 0;
}

static __always_inline void
dpi4_engine(struct iphdr *iph, struct skb_parser_info *info, bool ingress, __u32 now)
{
	struct qosify_flowv4_keys keys;
	struct qosify_conn_stats *stats;
	struct qosify_traffic_stats_val *dpi_val;
	const __u8 *payload = NULL;
	__u32 payload_len = 0;
	__u32 key = 0;
	__u8 dpi_max_check = 0;
	__u32 dpi_id = 0;

	__bpf_memzero(&keys, sizeof(keys));
	keys.proto = iph->protocol;
	keys.dst_ip = ingress? iph->saddr : iph->daddr;
	keys.src_ip = ingress? iph->daddr : iph->saddr;
	if(iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = skb_parse_tcp(info);
		if (!tcph)
			return;
		keys.dst_port = ingress? tcph->source : tcph->dest;
		keys.src_port = ingress? tcph->dest : tcph->source;
		if (check_tcp_finish(tcph)) {
			if (bpf_map_lookup_elem(&flow_table_v4_map, &keys))
				bpf_map_delete_elem(&flow_table_v4_map, &keys);
			return;
		}
		payload = skb_info_ptr(info, MIN_TCP_PAYLOAD_LEN);
		if (!payload)
			return;
		payload_len = info->skb->len - info->offset;
		dpi_max_check = 2;
	} else if(iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = skb_parse_udp(info);
		if (!udph)
			return;
		keys.dst_port = ingress? udph->source : udph->dest;
		keys.src_port = ingress? udph->dest : udph->source;
		payload = skb_info_ptr(info, MIN_UDP_PAYLOAD_LEN);
		if (!payload)
			return;
		payload_len = info->skb->len - info->offset;
		dpi_max_check = 3;
		return;
	} else {
		return;
	}

	if (payload_len == 0) {
		return;
	}
	
	stats = bpf_map_lookup_elem(&flow_table_v4_map, &keys);
	if (stats) {
		bpf_printk("dpi4_engine: %d %d %d\n", keys.src_ip, ntohs(keys.dst_port), keys.proto);
		bpf_printk("stats->dpi_id %d, stats->dpi_pkt_num %d ingress %d\n", stats->dpi_id, stats->dpi_pkt_num, ingress);
		if (!stats->dpi_id && stats->dpi_pkt_num >= dpi_max_check){
			stats->dpi_id = dpi_last_match(keys.proto, keys.dst_port, payload, payload_len, ingress);
		} else if (!stats->dpi_id) {
			stats->dpi_id = dpi_engine_match(keys.proto, keys.dst_port, payload, payload_len, ingress);
			stats->dpi_pkt_num++;
		}
		rate_estimator(&stats->val, now, info->skb->len, ingress);
		stats->last_seen = now;
		bpf_map_update_elem(&flow_table_v4_map, &keys, stats, BPF_ANY);
		dpi_id = stats->dpi_id;
	} else {
		struct qosify_conn_stats new_stats;
		__bpf_memzero(&new_stats, sizeof(new_stats));
		bpf_printk("dpi4_engine: new conn %d %d %d\n", keys.src_ip, ntohs(keys.dst_port), keys.proto);
		new_stats.val.est_slot = now;
		new_stats.val.stats[ingress].cur_s_bytes = info->skb->len;
		new_stats.val.stats[ingress].total_bytes = info->skb->len;
		new_stats.val.stats[ingress].total_packets = 1;

		new_stats.dpi_id = dpi_engine_match(keys.proto, keys.dst_port, payload, payload_len, ingress);
		new_stats.dpi_pkt_num++;
		new_stats.last_seen = now;

		bpf_map_update_elem(&flow_table_v4_map, &keys, &new_stats, BPF_ANY);
		dpi_id = new_stats.dpi_id;
	}

	
	dpi_val = bpf_map_lookup_elem(&dpi_stats_map, &dpi_id);
	if (dpi_val) {
		bpf_printk("dpi4_engine: dpi_id %d, payload_len %d ingress %d\n", dpi_id, info->skb->len, ingress);
		rate_estimator(dpi_val, now, info->skb->len, ingress);
		bpf_map_update_elem(&dpi_stats_map, &dpi_id, dpi_val, BPF_ANY);
	} else {
		struct qosify_traffic_stats_val new_val;
		__bpf_memzero(&new_val, sizeof(new_val));
		bpf_printk("dpi4_engine: new dpi_id %d payload_len %d ingress %d\n", dpi_id, payload_len, ingress);
		new_val.stats[ingress].cur_s_bytes = info->skb->len;
		new_val.stats[ingress].total_bytes = info->skb->len;
		new_val.stats[ingress].total_packets = 1;
		bpf_map_update_elem(&dpi_stats_map, &dpi_id, &new_val, BPF_ANY);
	}
}

static __always_inline struct qosify_ip_map_val *
parse_ipv4(struct qosify_config *config, struct skb_parser_info *info,
	   bool ingress, __u8 *out_val, bool dpi)
{
	struct iphdr *iph;
	__u8 ipproto;
	int hdr_len;
	void *key;
	struct qosify_traffic_stats_val *val = NULL;
	__u32 now = cur_time_sec() / RATE_ESTIMATOR;
	struct in_addr addr;
	struct qosify_traffic_stats_val new_val;
	struct qosify_ipv4_mask_config *mask = get_ipv4_mask();
	__u32 addr_masked;

	__bpf_memzero(&addr, sizeof(addr));
	__bpf_memzero(&new_val, sizeof(new_val));

	iph = skb_parse_ipv4(info, sizeof(struct udphdr));
	if (!iph)
		return NULL;

	if (!ingress) {
		key = &iph->saddr;
		addr.s_addr = iph->saddr;
	} else {
		key = &iph->daddr;
		addr.s_addr = iph->daddr;
	}

	if (!dpi) {
		parse_l4proto(config, info, ingress, out_val);
		return bpf_map_lookup_elem(&ipv4_map, key);
	}

	if (!mask) {
		bpf_printk("no mask\n");
		return NULL;
	}

	addr_masked = addr.s_addr & htonl(bits2mask(mask->prefix));
	if (addr_masked != mask->ip4)
		return NULL;

	dpi4_engine(iph, info, ingress, now);

	val = bpf_map_lookup_elem(&ipv4_stats_map, &addr);
	if (val) {
		rate_estimator(val, now, info->skb->len, ingress);
		bpf_map_update_elem(&ipv4_stats_map, &addr, val, BPF_ANY);
	} else {
		new_val.stats[ingress].cur_s_bytes = info->skb->len;
		new_val.stats[ingress].total_bytes = info->skb->len;
		new_val.stats[ingress].total_packets = 1;
		bpf_map_update_elem(&ipv4_stats_map, &addr, &new_val, BPF_ANY);
	}

	return bpf_map_lookup_elem(&ipv4_map, key);
}

static __always_inline struct qosify_ip_map_val *
parse_ipv6(struct qosify_config *config, struct skb_parser_info *info,
	   bool ingress, __u8 *out_val, bool dpi)
{
	struct ipv6hdr *iph;
	__u8 ipproto;
	void *key;
	struct qosify_traffic_stats_val *val = NULL;
	__u32 now = cur_time();
	struct in6_addr addr;
	struct qosify_traffic_stats_val new_val;
	struct qosify_ipv6_mask_config *mask = get_ipv6_mask();

	__bpf_memzero(&addr, sizeof(addr));
	__bpf_memzero(&new_val, sizeof(new_val));

	iph = skb_parse_ipv6(info, sizeof(struct udphdr));
	if (!iph)
		return NULL;

	if (!ingress) {
		__bpf_memcpy(&addr, &iph->saddr, sizeof(addr));
		key = &iph->saddr;
	} else {
		__bpf_memcpy(&addr, &iph->daddr, sizeof(addr));
		key = &iph->daddr;
	}

	if (!dpi) {
		parse_l4proto(config, info, ingress, out_val);
		return bpf_map_lookup_elem(&ipv6_map, key);
	}

	if (!mask) {
		return NULL;
	}

	val = bpf_map_lookup_elem(&ipv6_stats_map, &addr);
	if (val) {
		rate_estimator(val, now / RATE_ESTIMATOR, info->skb->len, ingress);
		bpf_map_update_elem(&ipv6_stats_map, &addr, val, BPF_ANY);
	} else {
		new_val.stats[ingress].cur_s_bytes = info->skb->len;
		new_val.stats[ingress].total_bytes = info->skb->len;
		new_val.stats[ingress].total_packets = 1;
		bpf_map_update_elem(&ipv6_stats_map, &addr, &new_val, BPF_ANY);
	}

	return NULL;
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
	if (!config) {
		return TC_ACT_UNSPEC;
	}

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
		ip_val = parse_ipv4(config, &info, ingress, &dscp, false);
	else if (type == bpf_htons(ETH_P_IPV6))
		ip_val = parse_ipv6(config, &info, ingress, &dscp, false);
	else {
		return TC_ACT_UNSPEC;
	}

	if (ip_val) {
		if (!ip_val->seen)
			ip_val->seen = 1;
		dscp = ip_val->dscp;
	}

	if (dscp_lookup_class(&dscp, ingress, &class, true)) {
		return TC_ACT_UNSPEC;
	}

	if (class) {
		if (check_flow(&class->config, skb, &dscp) &&
		    dscp_lookup_class(&dscp, ingress, &class, false)) {
			return TC_ACT_UNSPEC;
		}
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

SEC("tc/egress")
int chadpi_egress(struct __sk_buff *skb)
{
	struct skb_parser_info info;
	bool ingress = 0;
	struct qosify_config *config;
	__u32 iph_offset;
	int type;

	config = get_config();
	if (!config) {
		bpf_printk("no config\n");
		return TC_ACT_OK;
	}

	skb_parse_init(&info, skb);
	if (skb_parse_ethernet(&info)) {
		skb_parse_vlan(&info);
		skb_parse_vlan(&info);
		type = info.proto;
	} else {
		bpf_printk("no eth, egress %d\n", ingress);
		return TC_ACT_OK;
	}

	iph_offset = info.offset;
	if (type == bpf_htons(ETH_P_IP))
		parse_ipv4(config, &info, ingress, NULL, true);
	else if (type == bpf_htons(ETH_P_IPV6))
		parse_ipv6(config, &info, ingress, NULL, true);
	else {
		bpf_printk("no ip, egress %d\n", ingress);
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

SEC("tc/ingress")
int chadpi_ingress(struct __sk_buff *skb)
{
	struct skb_parser_info info;
	bool ingress = 1;
	struct qosify_config *config;
	__u32 iph_offset;
	int type;

	config = get_config();
	if (!config) {
		bpf_printk("no config\n");
		return TC_ACT_OK;
	}

	skb_parse_init(&info, skb);
	if (skb_parse_ethernet(&info)) {
		skb_parse_vlan(&info);
		skb_parse_vlan(&info);
		type = info.proto;
	} else {
		bpf_printk("no eth, ingress %d\n", ingress);
		return TC_ACT_OK;
	}

	iph_offset = info.offset;
	if (type == bpf_htons(ETH_P_IP))
		parse_ipv4(config, &info, ingress, NULL, true);
	else if (type == bpf_htons(ETH_P_IPV6))
		parse_ipv6(config, &info, ingress, NULL, true);
	else {
		bpf_printk("no ip, ingress %d\n", ingress);
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

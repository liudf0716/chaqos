// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BPF_QOSIFY_H
#define __BPF_QOSIFY_H

#define QOSIFY_MAX_CLASS_ENTRIES	16
#define QOSIFY_DEFAULT_CLASS_ENTRIES	2

#ifndef QOSIFY_FLOW_BUCKET_SHIFT
#define QOSIFY_FLOW_BUCKET_SHIFT	13
#endif

#define QOSIFY_FLOW_BUCKETS		(1 << QOSIFY_FLOW_BUCKET_SHIFT)

/* rodata per-instance flags */
#define QOSIFY_INGRESS			(1 << 0)
#define QOSIFY_IP_ONLY			(1 << 1)

#define QOSIFY_DSCP_VALUE_MASK		((1 << 6) - 1)
#define QOSIFY_DSCP_FALLBACK_FLAG	(1 << 6)
#define QOSIFY_DSCP_CLASS_FLAG		(1 << 7)

#define QOSIFY_CLASS_FLAG_PRESENT	(1 << 0)

#define RATE_ESTIMATOR 				(4)

#define MIN_TCP_PAYLOAD_LEN 20
#define MIN_UDP_PAYLOAD_LEN 8
#define MAX_PATTERN_LEN 32
#define DPI_MAX_NUM		1024

enum {
	EGRESS,
	INGRESS,
	DIRECTION_MAX,
};

struct qosify_dscp_val {
	uint8_t ingress;
	uint8_t egress;
};

/* global config data */

struct qosify_flow_config {
	uint8_t dscp_prio;
	uint8_t dscp_bulk;

	uint8_t bulk_trigger_timeout;
	uint16_t bulk_trigger_pps;

	uint16_t prio_max_avg_pkt_len;
};

struct qosify_config {
	uint8_t dscp_icmp;
};

struct qosify_ip_map_val {
	uint8_t dscp; /* must be first */
	uint8_t seen;
};

struct qosify_class {
	struct qosify_flow_config config;

	struct qosify_dscp_val val;

	uint8_t flags;

	uint64_t packets;
};

struct qosify_ipv4_mask_config {
	uint32_t ip4;
	uint32_t prefix;
};

struct qosify_ipv6_mask_config {
	uint8_t	ip6[16];
	uint32_t prefix;
};

struct pkt_stats {
	uint32_t cur_s_bytes;
	uint32_t prev_s_bytes;
	uint64_t total_bytes;
	uint64_t total_packets;
};

struct qosify_traffic_stats_val {
	struct pkt_stats stats[DIRECTION_MAX];
	uint32_t est_slot;
};

struct qosify_flowv4_keys {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
};

struct qosify_flowv6_keys {
	uint32_t src_ip[4];
	uint32_t dst_ip[4];
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
};

struct qosify_conn_stats {
	struct qosify_traffic_stats_val val;
	uint16_t dpi_id;
	uint16_t dpi_pkt_num;
	uint64_t last_seen;
};

struct qosify_dpi_list {
	uint16_t dpi_id;
	uint16_t dpi_pkt_num;
};

struct qosify_dpi_match_pattern {
	uint16_t dpi_id;
	uint16_t dport;
	uint8_t proto;
	uint8_t start;
	uint8_t end;
	uint8_t pattern_len;
	uint8_t pattern[MAX_PATTERN_LEN];
};

struct dpi_match_ctx {
	__u8 proto;
	__u16 dport;
	bool ingress;
	__u16 dpi_id;
	struct skb_parser_info *info;
};

#endif

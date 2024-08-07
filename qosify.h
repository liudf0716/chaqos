// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __QOS_CLASSIFY_H
#define __QOS_CLASSIFY_H

#include <stdbool.h>
#include <regex.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "qosify-bpf.h"

#include <libubox/utils.h>
#include <libubox/avl.h>
#include <libubox/blobmsg.h>
#include <libubox/ulog.h>

#include <netinet/in.h>

#define CLASSIFY_PROG_PATH	"/lib/bpf/qosify-bpf.o"
#define CLASSIFY_PIN_PATH	"/sys/fs/bpf/qosify"
#define CLASSIFY_DATA_PATH	"/sys/fs/bpf/qosify_data"

#define QOSIFY_DNS_IFNAME "ifb-dns"

#define QOSIFY_PRIO_BASE	0x110
#define QOSIFY_PRIO_CHADPI_BASE	0x100

enum qosify_map_id {
	CL_MAP_TCP_PORTS,
	CL_MAP_UDP_PORTS,
	CL_MAP_IPV4_ADDR,
	CL_MAP_IPV6_ADDR,
	CL_MAP_CLASS,
	CL_MAP_CONFIG,
	CL_MAP_IPV4_STATS,
	CL_MAP_IPV6_STATS,
	CL_MAP_IPV4_MASK,
	CL_MAP_IPV6_MASK,
	CL_MAP_TABLE_V4,
	CL_MAP_TABLE_V6,
	CL_MAP_DPI_MATCH,
	CL_MAP_DPI_STATS,
	CL_MAP_DNS,
	__CL_MAP_MAX,
};

struct qosify_map_data {
	enum qosify_map_id id;

	bool file : 1;
	bool user : 1;

	uint8_t dscp;
	uint8_t file_dscp;

	union {
		uint32_t port;
		struct in_addr ip;
		struct in6_addr ip6;
		struct {
			uint32_t seq : 30;
			uint32_t only_cname : 1;
			const char *pattern;
			regex_t regex;
		} dns;
	} addr;
};

struct qosify_map_entry {
	struct avl_node avl;

	uint32_t timeout;

	struct qosify_map_data data;
};


extern int qosify_map_timeout;
extern int qosify_active_timeout;
extern struct qosify_config config;
extern struct qosify_flow_config flow_config;

int qosify_run_cmd(char *cmd, bool ignore_error);

int qosify_loader_init(void);
const char *qosify_get_program(uint32_t flags, int *fd);
const int qosify_get_chadpi_program(bool egress);

int qosify_map_init(void);
int qosify_map_dscp_value(const char *val, uint8_t *dscp);
int qosify_map_load_file(const char *file);
void __qosify_map_set_entry(struct qosify_map_data *data);
int qosify_map_set_entry(enum qosify_map_id id, bool file, const char *str,
			 uint8_t dscp);
void qosify_map_reload(void);
void qosify_map_clear_files(void);
void qosify_map_gc(void);
void qosify_map_dump(struct blob_buf *b);
void qosify_map_stats(struct blob_buf *b, bool reset);
void qosify_map_set_dscp_default(enum qosify_map_id id, uint8_t val);
void qosify_map_reset_config(void);
void qosify_map_update_config(void);
void qosify_map_set_classes(struct blob_attr *val);
int qosify_map_lookup_dns_entry(char *host, bool cname, uint8_t *dscp, uint32_t *seq);
int qosify_map_add_dns_host(char *host, const char *addr, const char *type, int ttl);
int qosify_map_set_ipv4_mask(char *ip4, uint32_t prefix);
int qosify_map_set_ipv6_mask(char *ip6, uint32_t prefix);
int qosify_map_add_dpi_match(struct qosify_dpi_match_pattern *dpi_match);

void qosify_map_show_ip4_stats(struct blob_buf *b);
void qosify_map_show_ip6_stats(struct blob_buf *b);
void qosify_map_show_table_v4(struct blob_buf *b);
void qosify_map_show_table_v6(struct blob_buf *b);
void qosify_map_show_dpi_stats(struct blob_buf *b);
void qosify_map_show_dpi_match(struct blob_buf *b);
void qosify_show_l7_proto(struct blob_buf *b);

void qosify_net_mask_config_update(struct blob_attr *attr);
void qosify_map_clear_list(enum qosify_map_id id);
int map_parse_flow_config(struct qosify_flow_config *cfg, struct blob_attr *attr,
			  bool reset);
int map_fill_dscp_value(uint8_t *dest, struct blob_attr *attr, bool reset);

int qosify_iface_init(void);
void qosify_iface_config_update(struct blob_attr *ifaces, struct blob_attr *devs);
void qosify_iface_check(void);
void qosify_iface_status(struct blob_buf *b);
void qosify_iface_get_devices(struct blob_buf *b);
void qosify_iface_stop(void);

int qosify_dns_init(void);
void qosify_dns_stop(void);

int qosify_ubus_init(void);
void qosify_ubus_stop(void);
int qosify_ubus_check_interface(const char *name, char *ifname, int ifname_len);
void qosify_ubus_update_bridger(bool shutdown);

#endif

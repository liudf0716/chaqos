// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#include <libubus.h>

#include "qosify.h"

static struct blob_buf b;

static int
qosify_ubus_add_array(struct blob_attr *attr, uint8_t val, enum qosify_map_id id)
{
	struct blob_attr *cur;
	int rem;

	if (blobmsg_check_array(attr, BLOBMSG_TYPE_STRING) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_for_each_attr(cur, attr, rem)
		qosify_map_set_entry(id, false, blobmsg_get_string(cur), val);

	return 0;
}

static int
qosify_ubus_set_files(struct blob_attr *attr)
{
	struct blob_attr *cur;
	int rem;

	if (blobmsg_check_array(attr, BLOBMSG_TYPE_STRING) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	qosify_map_clear_files();

	blobmsg_for_each_attr(cur, attr, rem)
		qosify_map_load_file(blobmsg_get_string(cur));

	qosify_map_gc();

	return 0;
}


enum {
	CL_ADD_DSCP,
	CL_ADD_TIMEOUT,
	CL_ADD_IPV4,
	CL_ADD_IPV6,
	CL_ADD_TCP_PORT,
	CL_ADD_UDP_PORT,
	CL_ADD_DNS,
	__CL_ADD_MAX
};

static const struct blobmsg_policy qosify_add_policy[__CL_ADD_MAX] = {
	[CL_ADD_DSCP] = { "dscp", BLOBMSG_TYPE_STRING },
	[CL_ADD_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
	[CL_ADD_IPV4] = { "ipv4", BLOBMSG_TYPE_ARRAY },
	[CL_ADD_IPV6] = { "ipv6", BLOBMSG_TYPE_ARRAY },
	[CL_ADD_TCP_PORT] = { "tcp_port", BLOBMSG_TYPE_ARRAY },
	[CL_ADD_UDP_PORT] = { "udp_port", BLOBMSG_TYPE_ARRAY },
	[CL_ADD_DNS] = { "dns", BLOBMSG_TYPE_ARRAY },
};


static int
qosify_ubus_reload(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	qosify_map_reload();
	return 0;
}


static int
qosify_ubus_add(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int prev_timemout = qosify_map_timeout;
	struct blob_attr *tb[__CL_ADD_MAX];
	struct blob_attr *cur;
	uint8_t dscp = 0xff;
	int ret;

	blobmsg_parse(qosify_add_policy, __CL_ADD_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!strcmp(method, "add")) {
		if ((cur = tb[CL_ADD_DSCP]) == NULL ||
		    qosify_map_dscp_value(blobmsg_get_string(cur), &dscp))
			return UBUS_STATUS_INVALID_ARGUMENT;

		if ((cur = tb[CL_ADD_TIMEOUT]) != NULL)
			qosify_map_timeout = blobmsg_get_u32(cur);
	}

	if ((cur = tb[CL_ADD_IPV4]) != NULL &&
	    (ret = qosify_ubus_add_array(cur, dscp, CL_MAP_IPV4_ADDR) != 0))
		return ret;

	if ((cur = tb[CL_ADD_IPV6]) != NULL &&
	    (ret = qosify_ubus_add_array(cur, dscp, CL_MAP_IPV6_ADDR) != 0))
		return ret;

	if ((cur = tb[CL_ADD_TCP_PORT]) != NULL &&
	    (ret = qosify_ubus_add_array(cur, dscp, CL_MAP_TCP_PORTS) != 0))
		return ret;

	if ((cur = tb[CL_ADD_UDP_PORT]) != NULL &&
	    (ret = qosify_ubus_add_array(cur, dscp, CL_MAP_UDP_PORTS) != 0))
		return ret;

	if ((cur = tb[CL_ADD_DNS]) != NULL &&
	    (ret = qosify_ubus_add_array(cur, dscp, CL_MAP_DNS) != 0))
		return ret;

	qosify_map_timeout = prev_timemout;

	return 0;
}

enum {
	CL_CONFIG_RESET,
	CL_CONFIG_FILES,
	CL_CONFIG_TIMEOUT,
	CL_CONFIG_DSCP_UDP,
	CL_CONFIG_DSCP_TCP,
	CL_CONFIG_DSCP_ICMP,
	CL_CONFIG_INTERFACES,
	CL_CONFIG_DEVICES,
	CL_CONFIG_CLASSES,
	CL_CONFIG_NET_MASK,
	__CL_CONFIG_MAX
};

static const struct blobmsg_policy qosify_config_policy[__CL_CONFIG_MAX] = {
	[CL_CONFIG_RESET] = { "reset", BLOBMSG_TYPE_BOOL },
	[CL_CONFIG_FILES] = { "files", BLOBMSG_TYPE_ARRAY },
	[CL_CONFIG_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
	[CL_CONFIG_DSCP_UDP] = { "dscp_default_udp", BLOBMSG_TYPE_STRING },
	[CL_CONFIG_DSCP_TCP] = { "dscp_default_tcp", BLOBMSG_TYPE_STRING },
	[CL_CONFIG_DSCP_ICMP] = { "dscp_icmp", BLOBMSG_TYPE_STRING },
	[CL_CONFIG_INTERFACES] = { "interfaces", BLOBMSG_TYPE_TABLE },
	[CL_CONFIG_DEVICES] = { "devices", BLOBMSG_TYPE_TABLE },
	[CL_CONFIG_CLASSES] = { "classes", BLOBMSG_TYPE_TABLE },
	[CL_CONFIG_NET_MASK] = { "masks", BLOBMSG_TYPE_TABLE },
};

static int
qosify_ubus_config(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__CL_CONFIG_MAX];
	struct blob_attr *cur;
	uint8_t dscp;
	bool reset = false;
	int ret;

	blobmsg_parse(qosify_config_policy, __CL_CONFIG_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if ((cur = tb[CL_CONFIG_RESET]) != NULL)
		reset = blobmsg_get_bool(cur);

	if (reset)
		qosify_map_reset_config();

	if ((cur = tb[CL_CONFIG_CLASSES]) != NULL || reset)
		qosify_map_set_classes(cur);

	if ((cur = tb[CL_CONFIG_TIMEOUT]) != NULL)
		qosify_map_timeout = blobmsg_get_u32(cur);

	if ((cur = tb[CL_CONFIG_FILES]) != NULL &&
	    (ret = qosify_ubus_set_files(cur) != 0))
		return ret;

	if ((cur = tb[CL_CONFIG_NET_MASK]) != NULL) {
		qosify_net_mask_config_update(tb[CL_CONFIG_NET_MASK]);
	}

	if (map_parse_flow_config(&flow_config, msg, reset) ||
	    map_fill_dscp_value(&config.dscp_icmp, tb[CL_CONFIG_DSCP_ICMP], reset))
		return UBUS_STATUS_INVALID_ARGUMENT;

	map_fill_dscp_value(&dscp, tb[CL_CONFIG_DSCP_UDP], true);
	if (dscp != 0xff)
		qosify_map_set_dscp_default(CL_MAP_UDP_PORTS, dscp);

	map_fill_dscp_value(&dscp, tb[CL_CONFIG_DSCP_TCP], true);
	if (dscp != 0xff)
		qosify_map_set_dscp_default(CL_MAP_TCP_PORTS, dscp);

	qosify_map_update_config();

	qosify_iface_config_update(tb[CL_CONFIG_INTERFACES], tb[CL_CONFIG_DEVICES]);

	qosify_iface_check();

	return 0;
}


static int
qosify_ubus_dump(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_map_dump(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_status(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_iface_status(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_get_stats(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	static const struct blobmsg_policy policy =
		{ "reset", BLOBMSG_TYPE_BOOL };
	struct blob_attr *tb;
	bool reset = false;

	blobmsg_parse(&policy, 1, &tb, blobmsg_data(msg), blobmsg_len(msg));

	reset = tb && blobmsg_get_u8(tb);

	blob_buf_init(&b, 0);
	qosify_map_stats(&b, reset);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_check_devices(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	qosify_iface_check();

	return 0;
}

enum {
	CL_DNS_HOST_NAME,
	CL_DNS_HOST_TYPE,
	CL_DNS_HOST_ADDR,
	CL_DNS_HOST_TTL,
	__CL_DNS_HOST_MAX
};

static const struct blobmsg_policy qosify_dns_policy[__CL_DNS_HOST_MAX] = {
	[CL_DNS_HOST_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[CL_DNS_HOST_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[CL_DNS_HOST_ADDR] = { "address", BLOBMSG_TYPE_STRING },
	[CL_DNS_HOST_TTL] = { "ttl", BLOBMSG_TYPE_INT32 },
};

static int
__qosify_ubus_add_dns_host(struct blob_attr *msg)
{
	struct blob_attr *tb[__CL_DNS_HOST_MAX];
	struct blob_attr *cur;
	uint32_t ttl = 0;

	blobmsg_parse(qosify_dns_policy, __CL_DNS_HOST_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[CL_DNS_HOST_NAME] || !tb[CL_DNS_HOST_TYPE] ||
	    !tb[CL_DNS_HOST_ADDR])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if ((cur = tb[CL_DNS_HOST_TTL]) != NULL)
		ttl = blobmsg_get_u32(cur);

	if (qosify_map_add_dns_host(blobmsg_get_string(tb[CL_DNS_HOST_NAME]),
				    blobmsg_get_string(tb[CL_DNS_HOST_ADDR]),
				    blobmsg_get_string(tb[CL_DNS_HOST_TYPE]),
				    ttl))
		return UBUS_STATUS_INVALID_ARGUMENT;

	return 0;
}

static int
qosify_ubus_add_dns_host(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	return __qosify_ubus_add_dns_host(msg);
}

enum {
	CL_MASK_TYPE,
	CL_MASK_IPV4,
	CL_MASK_IPV6,
	CL_MASK_PREFIX,
	__CL_MASK_MAX
};

static const struct blobmsg_policy qosify_mask_policy[__CL_MASK_MAX] = {
	[CL_MASK_TYPE] = { "type", BLOBMSG_TYPE_INT32 },
	[CL_MASK_IPV4] = { "ipv4", BLOBMSG_TYPE_STRING },
	[CL_MASK_IPV6] = { "ipv6", BLOBMSG_TYPE_STRING },
	[CL_MASK_PREFIX] = { "prefix", BLOBMSG_TYPE_INT32 },
};

static int
qosify_ubus_add_mask(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct blob_attr *tb[__CL_MASK_MAX];
	uint32_t type = 0;

	blobmsg_parse(qosify_mask_policy, __CL_MASK_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[CL_MASK_TYPE] || (!tb[CL_MASK_IPV4] && !tb[CL_MASK_IPV6]) || !tb[CL_MASK_PREFIX])
		return UBUS_STATUS_INVALID_ARGUMENT;

	type = blobmsg_get_u32(tb[CL_MASK_TYPE]);
	if (type == 4) {
		if (qosify_map_set_ipv4_mask(blobmsg_get_string(tb[CL_MASK_IPV4]),
					     blobmsg_get_u32(tb[CL_MASK_PREFIX])))
			return UBUS_STATUS_INVALID_ARGUMENT;

		qosify_map_clear_list(CL_MAP_IPV4_STATS);
	} else if (type == 6) {
		if (qosify_map_set_ipv6_mask(blobmsg_get_string(tb[CL_MASK_IPV6]),
					     blobmsg_get_u32(tb[CL_MASK_PREFIX])))
			return UBUS_STATUS_INVALID_ARGUMENT;

		qosify_map_clear_list(CL_MAP_IPV6_STATS);
	} else {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return 0;
}

static int
qosify_ubus_show_ip4_stats(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_map_show_ip4_stats(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_show_ip6_stats(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_map_show_ip6_stats(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_show_table_v4(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_map_show_table_v4(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_show_table_v6(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_map_show_table_v6(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_show_dpi_stats(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_map_show_dpi_stats(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_show_dpi_match(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_map_show_dpi_match(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

enum {
	CL_DPI_PATTERN_DPI_ID,
	CL_DPI_PATTERN_DPORT,
	CL_DPI_PATTERN_PROTO,
	CL_DPI_PATTERN_START,
	CL_DPI_PATTERN_END,
	CLI_DPI_PATTERN_PATTERN_LEN,
	CL_DPI_PATTERN_PATTERN,
	__CL_DPI_PATTERN_MAX
};

static const struct blobmsg_policy qosify_dpi_match_policy[] = {
	[CL_DPI_PATTERN_DPI_ID] = { "dpi_id", BLOBMSG_TYPE_INT32 },
	[CL_DPI_PATTERN_DPORT] = { "dport", BLOBMSG_TYPE_INT32 },
	[CL_DPI_PATTERN_PROTO] = { "proto", BLOBMSG_TYPE_INT32 },
	[CL_DPI_PATTERN_START] = { "start", BLOBMSG_TYPE_INT32 },
	[CL_DPI_PATTERN_END] = { "end", BLOBMSG_TYPE_INT32 },
	[CLI_DPI_PATTERN_PATTERN_LEN] = { "pattern_len", BLOBMSG_TYPE_INT32 },
	[CL_DPI_PATTERN_PATTERN] = { "pattern", BLOBMSG_TYPE_STRING },
};

static int
qosify_ubus_add_dpi_match(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct blob_attr *tb[__CL_DPI_PATTERN_MAX];
	struct blob_attr *cur;
	struct qosify_dpi_match_pattern pattern = {};
	int ret;

	blobmsg_parse(qosify_dpi_match_policy, __CL_DPI_PATTERN_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[CL_DPI_PATTERN_DPI_ID] || !tb[CL_DPI_PATTERN_DPORT] ||
	    !tb[CL_DPI_PATTERN_PROTO] || !tb[CL_DPI_PATTERN_START] ||
	    !tb[CL_DPI_PATTERN_END] || !tb[CLI_DPI_PATTERN_PATTERN_LEN] ||
	    !tb[CL_DPI_PATTERN_PATTERN]) {
		return UBUS_STATUS_NO_DATA;
	}

	pattern.dpi_id = blobmsg_get_u32(tb[CL_DPI_PATTERN_DPI_ID]);
	pattern.dport = htons((uint16_t)blobmsg_get_u32(tb[CL_DPI_PATTERN_DPORT]));
	pattern.proto = blobmsg_get_u32(tb[CL_DPI_PATTERN_PROTO]);
	pattern.start = blobmsg_get_u32(tb[CL_DPI_PATTERN_START]);
	pattern.end = blobmsg_get_u32(tb[CL_DPI_PATTERN_END]);
	pattern.pattern_len = blobmsg_get_u32(tb[CLI_DPI_PATTERN_PATTERN_LEN]);

	cur = tb[CL_DPI_PATTERN_PATTERN];
	const char *pattern_str = blobmsg_get_string(cur);
	if (pattern.pattern_len != strlen(pattern_str))
		pattern.pattern_len = strlen(pattern_str);

	if (pattern.pattern_len > MAX_PATTERN_LEN) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memcpy(pattern.pattern, pattern_str, pattern.pattern_len);

	ret = qosify_map_add_dpi_match(&pattern);
	if (ret) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	return 0;
}

static int
qosify_ubus_show_all_stats(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_map_show_ip4_stats(&b);
	qosify_map_show_ip6_stats(&b);
	qosify_map_show_table_v4(&b);
	qosify_map_show_table_v6(&b);
	qosify_map_show_dpi_stats(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
qosify_ubus_show_l7_proto(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	qosify_show_l7_proto(&b);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static const struct ubus_method qosify_methods[] = {
	UBUS_METHOD_NOARG("reload", qosify_ubus_reload),
	UBUS_METHOD("add", qosify_ubus_add, qosify_add_policy),
	UBUS_METHOD_MASK("remove", qosify_ubus_add, qosify_add_policy,
			 ((1 << __CL_ADD_MAX) - 1) & ~(1 << CL_ADD_DSCP)),
	UBUS_METHOD("config", qosify_ubus_config, qosify_config_policy),
	UBUS_METHOD_NOARG("dump", qosify_ubus_dump),
	UBUS_METHOD_NOARG("status", qosify_ubus_status),
	UBUS_METHOD_NOARG("get_stats", qosify_ubus_get_stats),
	UBUS_METHOD("add_dns_host", qosify_ubus_add_dns_host, qosify_dns_policy),
	UBUS_METHOD_NOARG("check_devices", qosify_ubus_check_devices),
	UBUS_METHOD("mask", qosify_ubus_add_mask, qosify_mask_policy),
	UBUS_METHOD_NOARG("show_ip4_stats", qosify_ubus_show_ip4_stats),
	UBUS_METHOD_NOARG("show_ip6_stats", qosify_ubus_show_ip6_stats),
	UBUS_METHOD_NOARG("show_table4", qosify_ubus_show_table_v4),
	UBUS_METHOD_NOARG("show_table6", qosify_ubus_show_table_v6),
	UBUS_METHOD_NOARG("show_dpi_stats", qosify_ubus_show_dpi_stats),
	UBUS_METHOD_NOARG("show_dpi_match", qosify_ubus_show_dpi_match),
	UBUS_METHOD("dpi_match", qosify_ubus_add_dpi_match, qosify_dpi_match_policy),
	UBUS_METHOD_NOARG("show_all_stats", qosify_ubus_show_all_stats),
	UBUS_METHOD_NOARG("show_l7_proto", qosify_ubus_show_l7_proto),
};

static struct ubus_object_type qosify_object_type =
	UBUS_OBJECT_TYPE("qosify", qosify_methods);

static struct ubus_object qosify_object = {
	.name = "qosify",
	.type = &qosify_object_type,
	.methods = qosify_methods,
	.n_methods = ARRAY_SIZE(qosify_methods),
};

static void
qosify_subscribe_dnsmasq(struct ubus_context *ctx)
{
	static struct ubus_subscriber sub = {
		.cb = qosify_ubus_add_dns_host,
	};
	uint32_t id;

	if (!sub.obj.id &&
	    ubus_register_subscriber(ctx, &sub))
		return;

	if (ubus_lookup_id(ctx, "dnsmasq.dns", &id))
		return;

	ubus_subscribe(ctx, &sub, id);
}

static void
qosify_ubus_event_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
		     const char *type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy =
		{ "path", BLOBMSG_TYPE_STRING };
	struct blob_attr *attr;
	const char *path;

	blobmsg_parse(&policy, 1, &attr, blobmsg_data(msg), blobmsg_len(msg));

	if (!attr)
		return;

	path = blobmsg_get_string(attr);
	if (!strcmp(path, "dnsmasq.dns"))
		qosify_subscribe_dnsmasq(ctx);
	else if (!strcmp(path, "bridger"))
		qosify_ubus_update_bridger(false);
}


static void
ubus_connect_handler(struct ubus_context *ctx)
{
	static struct ubus_event_handler ev = {
		.cb = qosify_ubus_event_cb
	};

	ubus_add_object(ctx, &qosify_object);
	ubus_register_event_handler(ctx, &ev, "ubus.object.add");
	qosify_subscribe_dnsmasq(ctx);
}

static struct ubus_auto_conn conn;

void qosify_ubus_update_bridger(bool shutdown)
{
	struct ubus_request req;
	uint32_t id;
	void *c;

	if (ubus_lookup_id(&conn.ctx, "bridger", &id))
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", "qosify");
	c = blobmsg_open_array(&b, "devices");
	if (!shutdown)
		qosify_iface_get_devices(&b);
	blobmsg_close_array(&b, c);

	ubus_invoke_async(&conn.ctx, id, "set_blacklist", b.head, &req);
}

int qosify_ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);

	return 0;
}

void qosify_ubus_stop(void)
{
	qosify_ubus_update_bridger(true);
	ubus_auto_shutdown(&conn);
}

struct iface_req {
	char *name;
	int len;
};

static void
netifd_if_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct iface_req *ifr = req->priv;
	enum {
		IFS_ATTR_UP,
		IFS_ATTR_DEV,
		__IFS_ATTR_MAX
	};
	static const struct blobmsg_policy policy[__IFS_ATTR_MAX] = {
		[IFS_ATTR_UP] = { "up", BLOBMSG_TYPE_BOOL },
		[IFS_ATTR_DEV] = { "l3_device", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__IFS_ATTR_MAX];

	blobmsg_parse(policy, __IFS_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[IFS_ATTR_UP] || !tb[IFS_ATTR_DEV])
		return;

	if (!blobmsg_get_bool(tb[IFS_ATTR_UP]))
		return;

	snprintf(ifr->name, ifr->len, "%s", blobmsg_get_string(tb[IFS_ATTR_DEV]));
}

int qosify_ubus_check_interface(const char *name, char *ifname, int ifname_len)
{
	struct iface_req req = { ifname, ifname_len };
	char *obj_name = "network.interface.";
	uint32_t id;

#define PREFIX "network.interface."
	obj_name = alloca(sizeof(PREFIX) + strlen(name) + 1);
	sprintf(obj_name, PREFIX "%s", name);
#undef PREFIX

	ifname[0] = 0;

	if (ubus_lookup_id(&conn.ctx, obj_name, &id))
		return -1;

	blob_buf_init(&b, 0);
	ubus_invoke(&conn.ctx, id, "status", b.head, netifd_if_cb, &req, 1000);

	if (!ifname[0])
		return -1;

	return 0;
}

// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <unistd.h>
#include <errno.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>

#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>

#include <libubox/vlist.h>
#include <libubox/avl-cmp.h>
#include <libubox/uloop.h>

#include "qosify.h"

static void interface_update_cb(struct vlist_tree *tree,
				struct vlist_node *node_new,
				struct vlist_node *node_old);

static VLIST_TREE(devices, avl_strcmp, interface_update_cb, true, false);
static VLIST_TREE(interfaces, avl_strcmp, interface_update_cb, true, false);
static int socket_fd;
static struct nl_sock *rtnl_sock;

#define APPEND(_buf, _ofs, _format, ...) _ofs += snprintf(_buf + _ofs, sizeof(_buf) - _ofs, _format, ##__VA_ARGS__)

struct qosify_iface_config {
	struct blob_attr *data;

	bool ingress;
	bool egress;
	bool nat;
	bool host_isolate;
	bool autorate_ingress;

	const char *bandwidth_up;
	const char *bandwidth_down;
	const char *mode;
	const char *common_opts;
	const char *ingress_opts;
	const char *egress_opts;
};


struct qosify_iface {
	struct vlist_node node;

	char ifname[IFNAMSIZ];
	bool active;

	bool device;
	struct blob_attr *config_data;
	struct qosify_iface_config config;
};

enum {
	IFACE_ATTR_BW_UP,
	IFACE_ATTR_BW_DOWN,
	IFACE_ATTR_INGRESS,
	IFACE_ATTR_EGRESS,
	IFACE_ATTR_MODE,
	IFACE_ATTR_NAT,
	IFACE_ATTR_HOST_ISOLATE,
	IFACE_ATTR_AUTORATE_IN,
	IFACE_ATTR_INGRESS_OPTS,
	IFACE_ATTR_EGRESS_OPTS,
	IFACE_ATTR_OPTS,
	__IFACE_ATTR_MAX
};

static inline const char *qosify_iface_name(struct qosify_iface *iface)
{
	return iface->node.avl.key;
}

static void
iface_config_parse(struct blob_attr *attr, struct blob_attr **tb)
{
	static const struct blobmsg_policy policy[__IFACE_ATTR_MAX] = {
		[IFACE_ATTR_BW_UP] = { "bandwidth_up", BLOBMSG_TYPE_STRING },
		[IFACE_ATTR_BW_DOWN] = { "bandwidth_down", BLOBMSG_TYPE_STRING },
		[IFACE_ATTR_INGRESS] = { "ingress", BLOBMSG_TYPE_BOOL },
		[IFACE_ATTR_EGRESS] = { "egress", BLOBMSG_TYPE_BOOL },
		[IFACE_ATTR_MODE] = { "mode", BLOBMSG_TYPE_STRING },
		[IFACE_ATTR_NAT] = { "nat", BLOBMSG_TYPE_BOOL },
		[IFACE_ATTR_HOST_ISOLATE] = { "host_isolate", BLOBMSG_TYPE_BOOL },
		[IFACE_ATTR_AUTORATE_IN] = { "autorate_ingress", BLOBMSG_TYPE_BOOL },
		[IFACE_ATTR_INGRESS_OPTS] = { "ingress_options", BLOBMSG_TYPE_STRING },
		[IFACE_ATTR_EGRESS_OPTS] = { "egress_options", BLOBMSG_TYPE_STRING },
		[IFACE_ATTR_OPTS] = { "options", BLOBMSG_TYPE_STRING },
	};

	blobmsg_parse(policy, __IFACE_ATTR_MAX, tb, blobmsg_data(attr), blobmsg_len(attr));
}

static bool
iface_config_equal(struct qosify_iface *if1, struct qosify_iface *if2)
{
	struct blob_attr *tb1[__IFACE_ATTR_MAX], *tb2[__IFACE_ATTR_MAX];
	int i;

	iface_config_parse(if1->config_data, tb1);
	iface_config_parse(if2->config_data, tb2);

	for (i = 0; i < __IFACE_ATTR_MAX; i++) {
		if (!!tb1[i] != !!tb2[i])
			return false;

		if (!tb1[i])
			continue;

		if (blob_raw_len(tb1[i]) != blob_raw_len(tb2[i]))
			return false;

		if (memcmp(tb1[i], tb2[i], blob_raw_len(tb1[i])) != 0)
			return false;
	}

	return true;
}

static const char *check_str(struct blob_attr *attr)
{
	const char *str = blobmsg_get_string(attr);

	if (strchr(str, '\''))
		return NULL;

	return str;
}

static void
iface_config_set(struct qosify_iface *iface, struct blob_attr *attr)
{
	struct qosify_iface_config *cfg = &iface->config;
	struct blob_attr *tb[__IFACE_ATTR_MAX];
	struct blob_attr *cur;

	iface_config_parse(attr, tb);

	memset(cfg, 0, sizeof(*cfg));

	/* defaults */
	cfg->mode = "diffserv4";
	cfg->ingress = true;
	cfg->egress = true;
	cfg->host_isolate = true;
	cfg->autorate_ingress = false;
	cfg->nat = !iface->device;

	if ((cur = tb[IFACE_ATTR_BW_UP]) != NULL)
		cfg->bandwidth_up = check_str(cur);
	if ((cur = tb[IFACE_ATTR_BW_DOWN]) != NULL)
		cfg->bandwidth_down = check_str(cur);
	if ((cur = tb[IFACE_ATTR_MODE]) != NULL)
		cfg->mode = check_str(cur);
	if ((cur = tb[IFACE_ATTR_OPTS]) != NULL)
		cfg->common_opts = check_str(cur);
	if ((cur = tb[IFACE_ATTR_EGRESS_OPTS]) != NULL)
		cfg->egress_opts = check_str(cur);
	if ((cur = tb[IFACE_ATTR_INGRESS_OPTS]) != NULL)
		cfg->ingress_opts = check_str(cur);
	if ((cur = tb[IFACE_ATTR_INGRESS]) != NULL)
		cfg->ingress = blobmsg_get_bool(cur);
	if ((cur = tb[IFACE_ATTR_EGRESS]) != NULL)
		cfg->egress = blobmsg_get_bool(cur);
	if ((cur = tb[IFACE_ATTR_NAT]) != NULL)
		cfg->nat = blobmsg_get_bool(cur);
	if ((cur = tb[IFACE_ATTR_HOST_ISOLATE]) != NULL)
		cfg->host_isolate = blobmsg_get_bool(cur);
	if ((cur = tb[IFACE_ATTR_AUTORATE_IN]) != NULL)
		cfg->autorate_ingress = blobmsg_get_bool(cur);
}

static const char *
interface_ifb_name(struct qosify_iface *iface)
{
	static char ifname[IFNAMSIZ + 1] = "ifb-";
	int len = strlen(iface->ifname);

	if (len + 4 < IFNAMSIZ) {
		snprintf(ifname + 4, IFNAMSIZ - 4, "%s", iface->ifname);

		return ifname;
	}

	ifname[4] = iface->ifname[0];
	ifname[5] = iface->ifname[1];
	snprintf(ifname + 6, IFNAMSIZ - 6, "%s", iface->ifname + len - (IFNAMSIZ + 6) - 1);

	return ifname;
}

static int
prepare_qdisc_cmd(char *buf, int len, const char *dev, bool add, const char *type)
{
	return snprintf(buf, len, "tc qdisc %s dev '%s' %s",
			add ? "add" : "del", dev, type);
}

static int
prepare_filter_cmd(char *buf, int len, const char *dev, int prio, bool add, bool egress)
{
	return snprintf(buf, len, "tc filter %s dev '%s' %sgress prio %d",
			add ? "add" : "del", dev, egress ? "e" : "in", prio);
}

static int
cmd_add_chadpi_bpf_filter(const char *ifname, int prio, bool egress)
{
	struct tcmsg tcmsg = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = if_nametoindex(ifname),
	};
	struct nl_msg *msg;
	struct nlattr *opts;
	int prog_fd = -1;
	char name[32] = {0};

	prog_fd = qosify_get_chadpi_program(egress);
	if (prog_fd < 0)
		return -1;

	if (egress) {
		tcmsg.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
		snprintf(name, sizeof(name), "qosify_chadpi_egress");
	} else {
		tcmsg.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
		snprintf(name, sizeof(name), "qosify_chadpi_ingress");
	}

	tcmsg.tcm_info = TC_H_MAKE(prio << 16, htons(ETH_P_ALL));

	msg = nlmsg_alloc_simple(RTM_NEWTFILTER, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);
	nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
	nla_put_string(msg, TCA_KIND, "bpf");

	opts = nla_nest_start(msg, NLA_F_NESTED | TCA_OPTIONS);
	nla_put_u32(msg, TCA_BPF_FD, prog_fd);
	nla_put_string(msg, TCA_BPF_NAME, name);
	nla_nest_end(msg, opts);

	nl_send_auto_complete(rtnl_sock, msg);
	nlmsg_free(msg);

	return nl_wait_for_ack(rtnl_sock);
}

static int
cmd_add_bpf_filter(const char *ifname, int prio, bool egress, bool eth)
{
	struct tcmsg tcmsg = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = if_nametoindex(ifname),
	};
	struct nl_msg *msg;
	struct nlattr *opts;
	const char *suffix;
	int prog_fd = -1;
	char name[32];

	suffix = qosify_get_program(!egress * QOSIFY_INGRESS + !eth * QOSIFY_IP_ONLY, &prog_fd);
	if (!suffix)
		return -1;

	snprintf(name, sizeof(name), "qosify_%s", suffix);

	if (egress)
		tcmsg.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
	else
		tcmsg.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);

	tcmsg.tcm_info = TC_H_MAKE(prio << 16, htons(ETH_P_ALL));

	msg = nlmsg_alloc_simple(RTM_NEWTFILTER, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);
	nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
	nla_put_string(msg, TCA_KIND, "bpf");

	opts = nla_nest_start(msg, TCA_OPTIONS);
	nla_put_u32(msg, TCA_BPF_FD, prog_fd);
	nla_put_string(msg, TCA_BPF_NAME, name);
	nla_put_u32(msg, TCA_BPF_FLAGS, TCA_BPF_FLAG_ACT_DIRECT);
	nla_put_u32(msg, TCA_BPF_FLAGS_GEN, TCA_CLS_FLAGS_SKIP_HW);
	nla_nest_end(msg, opts);

	nl_send_auto_complete(rtnl_sock, msg);
	nlmsg_free(msg);

	return nl_wait_for_ack(rtnl_sock);
}

static int
cmd_add_qdisc(struct qosify_iface *iface, const char *ifname, bool egress, bool eth)
{
	struct qosify_iface_config *cfg = &iface->config;
	const char *bw = egress ? cfg->bandwidth_up : cfg->bandwidth_down;
	const char *dir_opts = egress ? cfg->egress_opts : cfg->ingress_opts;
	char buf[512];
	int ofs;

	ofs = prepare_qdisc_cmd(buf, sizeof(buf), ifname, true, "clsact");
	qosify_run_cmd(buf, true);

	ofs = prepare_qdisc_cmd(buf, sizeof(buf), ifname, true, "root cake");
	if (bw)
		APPEND(buf, ofs, " bandwidth %s", bw);

	APPEND(buf, ofs, " %s %sgress", cfg->mode, egress ? "e" : "in");
	if (!egress && cfg->autorate_ingress)
		APPEND(buf, ofs, " autorate-ingress");

	if (cfg->host_isolate)
		APPEND(buf, ofs, " %snat dual-%shost",
			cfg->nat ? "" : "no",
			egress ? "src" : "dst");
	else
		APPEND(buf, ofs, " flows");

	APPEND(buf, ofs, " %s %s",
	       cfg->common_opts ? cfg->common_opts : "",
	       dir_opts ? dir_opts : "");

	return qosify_run_cmd(buf, false);
}

static int
cmd_add_ingress(struct qosify_iface *iface, bool eth)
{
	const char *ifbdev = interface_ifb_name(iface);
	char buf[256];
	int prio = QOSIFY_PRIO_BASE;
	int chadpi_prio = QOSIFY_PRIO_CHADPI_BASE;
	int ofs;

	cmd_add_chadpi_bpf_filter(iface->ifname, chadpi_prio, false);

	cmd_add_bpf_filter(iface->ifname, prio++, false, eth);

	ofs = prepare_filter_cmd(buf, sizeof(buf), iface->ifname, prio++, true, false);
	APPEND(buf, ofs, " protocol ip u32 match ip sport 53 0xffff "
			 "flowid 1:1 action mirred egress redirect dev " QOSIFY_DNS_IFNAME);
	qosify_run_cmd(buf, false);

	ofs = prepare_filter_cmd(buf, sizeof(buf), iface->ifname, prio++, true, false);
	APPEND(buf, ofs, " protocol 802.1Q u32 offset plus 4 match ip sport 53 0xffff "
			 "flowid 1:1 action mirred egress redirect dev " QOSIFY_DNS_IFNAME);
	qosify_run_cmd(buf, false);

	ofs = prepare_filter_cmd(buf, sizeof(buf), iface->ifname, prio++, true, false);
	APPEND(buf, ofs, " protocol ipv6 u32 match ip6 sport 53 0xffff "
			 "flowid 1:1 action mirred egress redirect dev " QOSIFY_DNS_IFNAME);
	qosify_run_cmd(buf, false);

	ofs = prepare_filter_cmd(buf, sizeof(buf), iface->ifname, prio++, true, false);
	APPEND(buf, ofs, " protocol ipv6 u32 offset plus 4 match ip6 sport 53 0xffff "
			 "flowid 1:1 action mirred egress redirect dev " QOSIFY_DNS_IFNAME);
	qosify_run_cmd(buf, false);


	if (!iface->config.ingress)
		return 0;

	snprintf(buf, sizeof(buf), "ip link add '%s' type ifb", ifbdev);
	qosify_run_cmd(buf, false);

	cmd_add_qdisc(iface, ifbdev, false, eth);

	snprintf(buf, sizeof(buf), "ip link set dev '%s' up", ifbdev);
	qosify_run_cmd(buf, false);

	ofs = prepare_filter_cmd(buf, sizeof(buf), iface->ifname, prio++, true, false);
	APPEND(buf, ofs, " protocol all u32 match u32 0 0 flowid 1:1"
			 " action mirred egress redirect dev '%s'", ifbdev);
	return qosify_run_cmd(buf, false);
}

static int cmd_add_egress(struct qosify_iface *iface, bool eth)
{
	if (!iface->config.egress)
		return 0;

	cmd_add_qdisc(iface, iface->ifname, true, eth);

	if (cmd_add_chadpi_bpf_filter(iface->ifname, QOSIFY_PRIO_CHADPI_BASE, true))
		return -1;

	return cmd_add_bpf_filter(iface->ifname, QOSIFY_PRIO_BASE, true, eth);
}

static void
interface_clear_qdisc(struct qosify_iface *iface)
{
	char buf[64];
	int i;

	prepare_qdisc_cmd(buf, sizeof(buf), iface->ifname, false, "root");
	qosify_run_cmd(buf, true);

	prepare_filter_cmd(buf, sizeof(buf), iface->ifname, QOSIFY_PRIO_CHADPI_BASE, false, false);
	qosify_run_cmd(buf, true);

	prepare_filter_cmd(buf, sizeof(buf), iface->ifname, QOSIFY_PRIO_CHADPI_BASE, false, true);
	qosify_run_cmd(buf, true);
	
	for (i = 0; i < 6; i++) {
		prepare_filter_cmd(buf, sizeof(buf), iface->ifname, QOSIFY_PRIO_BASE + i, false, false);
		qosify_run_cmd(buf, true);
	}

	prepare_filter_cmd(buf, sizeof(buf), iface->ifname, QOSIFY_PRIO_BASE, false, true);
	qosify_run_cmd(buf, true);

	snprintf(buf, sizeof(buf), "ip link del '%s'", interface_ifb_name(iface));
	qosify_run_cmd(buf, true);
}

static void
interface_start(struct qosify_iface *iface)
{
	struct ifreq ifr = {};
	bool eth;

	if (!iface->ifname[0] || iface->active)
		return;

	ULOG_INFO("start interface %s\n", iface->ifname);

	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name));
	if (ioctl(socket_fd, SIOCGIFHWADDR, &ifr) < 0) {
		ULOG_ERR("ioctl(SIOCGIFHWADDR, %s) failed: %s\n", iface->ifname, strerror(errno));
		return;
	}

	eth = ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER;

	interface_clear_qdisc(iface);
	cmd_add_egress(iface, eth);
	cmd_add_ingress(iface, eth);

	iface->active = true;
}

static void
interface_stop(struct qosify_iface *iface)
{
	if (!iface->ifname[0] || !iface->active)
		return;

	ULOG_INFO("stop interface %s\n", iface->ifname);
	iface->active = false;

	interface_clear_qdisc(iface);
}

static void
interface_set_config(struct qosify_iface *iface, struct blob_attr *config)
{
	iface->config_data = blob_memdup(config);
	iface_config_set(iface, iface->config_data);
	interface_start(iface);
}

static void
interface_update_cb(struct vlist_tree *tree,
		    struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct qosify_iface *if_new = NULL, *if_old = NULL;

	if (node_new)
		if_new = container_of(node_new, struct qosify_iface, node);
	if (node_old)
		if_old = container_of(node_old, struct qosify_iface, node);

	if (if_new && if_old) {
		if (!iface_config_equal(if_old, if_new)) {
			interface_stop(if_old);
			free(if_old->config_data);
			interface_set_config(if_old, if_new->config_data);
		}

		free(if_new);
		return;
	}

	if (if_old) {
		interface_stop(if_old);
		free(if_old->config_data);
		free(if_old);
	}

	if (if_new)
		interface_set_config(if_new, if_new->config_data);
}

static void
interface_create(struct blob_attr *attr, bool device)
{
	struct qosify_iface *iface;
	const char *name = blobmsg_name(attr);
	int name_len = strlen(name);
	char *name_buf;

	if (strchr(name, '\''))
		return;

	if (name_len >= IFNAMSIZ)
		return;

	if (blobmsg_type(attr) != BLOBMSG_TYPE_TABLE)
		return;

	iface = calloc_a(sizeof(*iface), &name_buf, name_len + 1);
	strcpy(name_buf, blobmsg_name(attr));
	iface->config_data = attr;
	iface->device = device;
	vlist_add(device ? &devices : &interfaces, &iface->node, name_buf);
}

void qosify_iface_config_update(struct blob_attr *ifaces, struct blob_attr *devs)
{
	struct blob_attr *cur;
	int rem;

	vlist_update(&devices);
	blobmsg_for_each_attr(cur, devs, rem)
		interface_create(cur, true);
	vlist_flush(&devices);

	vlist_update(&interfaces);
	blobmsg_for_each_attr(cur, ifaces, rem)
		interface_create(cur, false);
	vlist_flush(&interfaces);
}

static void
qosify_iface_check_device(struct qosify_iface *iface)
{
	const char *name = qosify_iface_name(iface);
	int ifindex;

	ifindex = if_nametoindex(name);
	if (!ifindex) {
		interface_stop(iface);
		iface->ifname[0] = 0;
	} else {
		snprintf(iface->ifname, sizeof(iface->ifname), "%s", name);
		interface_start(iface);
	}
}

static void
qosify_iface_check_interface(struct qosify_iface *iface)
{
	const char *name = qosify_iface_name(iface);
	char ifname[IFNAMSIZ];

	if (qosify_ubus_check_interface(name, ifname, sizeof(ifname)) == 0) {
		snprintf(iface->ifname, sizeof(iface->ifname), "%s", ifname);
		interface_start(iface);
	} else {
		interface_stop(iface);
		iface->ifname[0] = 0;
	}
}

static void qos_iface_check_cb(struct uloop_timeout *t)
{
	struct qosify_iface *iface;

	vlist_for_each_element(&devices, iface, node)
		qosify_iface_check_device(iface);
	vlist_for_each_element(&interfaces, iface, node)
		qosify_iface_check_interface(iface);
	qosify_ubus_update_bridger(false);
}

void qosify_iface_check(void)
{
	static struct uloop_timeout timer = {
		.cb = qos_iface_check_cb,
	};

	uloop_timeout_set(&timer, 10);
}

static void
__qosify_iface_status(struct blob_buf *b, struct qosify_iface *iface)
{
	void *c;

	c = blobmsg_open_table(b, qosify_iface_name(iface));
	blobmsg_add_u8(b, "active", iface->active);
	if (iface->ifname[0])
		blobmsg_add_string(b, "ifname", iface->ifname);
	blobmsg_add_u8(b, "egress", iface->config.egress);
	blobmsg_add_u8(b, "ingress", iface->config.ingress);
	blobmsg_close_table(b, c);

}

void qosify_iface_status(struct blob_buf *b)
{
	struct qosify_iface *iface;
	void *c;

	c = blobmsg_open_table(b, "devices");
	vlist_for_each_element(&devices, iface, node)
		__qosify_iface_status(b, iface);
	blobmsg_close_table(b, c);

	c = blobmsg_open_table(b, "interfaces");
	vlist_for_each_element(&interfaces, iface, node)
		__qosify_iface_status(b, iface);
	blobmsg_close_table(b, c);
}

static int
qosify_nl_error_cb(struct sockaddr_nl *nla, struct nlmsgerr *err,
		   void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) err - 1;
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
	struct nlattr *attrs;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);
	int len = nlh->nlmsg_len;
	const char *errstr = "(unknown)";

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	attrs = (void *) ((unsigned char *) nlh + ack_len);
	len -= ack_len;

	nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb[NLMSGERR_ATTR_MSG])
		errstr = nla_data(tb[NLMSGERR_ATTR_MSG]);

	ULOG_ERR("Netlink error(%d): %s\n", err->error, errstr);

	return NL_STOP;
}

static void
__qosify_iface_get_device(struct blob_buf *b, struct qosify_iface *iface)
{
	if (!iface->ifname[0] || !iface->active)
		return;

	blobmsg_add_string(b, NULL, iface->ifname);
}

void qosify_iface_get_devices(struct blob_buf *b)
{
	struct qosify_iface *iface;

	vlist_for_each_element(&devices, iface, node)
		__qosify_iface_get_device(b, iface);
	vlist_for_each_element(&interfaces, iface, node)
		__qosify_iface_get_device(b, iface);
}

int qosify_iface_init(void)
{
	int fd, opt;

	socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (socket < 0)
		return -1;

	rtnl_sock = nl_socket_alloc();
	if (!rtnl_sock)
		return -1;

	if (nl_connect(rtnl_sock, NETLINK_ROUTE))
		return -1;

	nl_cb_err(nl_socket_get_cb(rtnl_sock), NL_CB_CUSTOM,
		  qosify_nl_error_cb, NULL);

	fd = nl_socket_get_fd(rtnl_sock);
	opt = 1;
	setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &opt, sizeof(opt));

	opt = 1;
	setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &opt, sizeof(opt));

	return 0;
}

void qosify_iface_stop(void)
{
	struct qosify_iface *iface;

	vlist_for_each_element(&interfaces, iface, node)
		interface_stop(iface);
	vlist_for_each_element(&devices, iface, node)
		interface_stop(iface);

	nl_socket_free(rtnl_sock);
}


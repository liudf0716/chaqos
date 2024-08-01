#ifndef __CHAQOS_DPI_H
#define __CHAQOS_DPI_H

#define CHADPI_L7_UNKNOWN 0xffff

enum chaqos_dpi_l7_proto_t {
    CHADPI_L7_VIDEO_DOUYIN = 1001,
    CHADPI_L7_VIDEO_KUAISHOU,
    CHADPI_L7_VIDEO_IQIYI,
    CHADPI_L7_VIDEO_YOUKU,
    CHADPI_L7_VIDEO_MANGO,
    CHADPI_L7_VIDEO_XIGUA,
    CHADPI_L7_VIDEO_MIGU,
    CHADPI_L7_VIDEO_CCTV,
    CHADPI_L7_VIDEO_1905,
    CHADPI_L7_VIDEO_TENCENT_VIDEO,
    CHADPI_L7_VIDEO_BILIBILI,
    CHADPI_L7_VIDEO_XHS,
    CHADPI_L7_VIDEO_PPTV,
    CHADPI_L7_VIDEO_WASU,
    CHADPI_L7_VIDEO_SOHU,
    CHADPI_L7_VIDEO_LETV,
    CHADPI_L7_VIDEO_WEIBO,
    CHADPI_L7_VIDEO_DOUYU,
    CHADPI_L7_MSG_WECHAT = 2001,
    CHADPI_L7_MSG_QQ,
    CHADPI_L7_MSG_DINGTALK,
    CHADPI_L7_SHOPPING_TAOBAO = 3001,
    CHADPI_L7_SHOPPING_JD,
    CHADPI_L7_SHOPPING_PINDUODUO,
    CHAPPI_L7_WAIMAI_MEITUAN = 4001,
    CHADPI_L7_WAIMAI_ELEME,
    CHADPI_L7_WAIMAI_DAZHONG,
    CHADPI_L7_ERSHOU_XIANYU = 5001,
    CHADPI_L7_ERSHOU_ZHUANZHUAN,
    CHADPI_L7_FTP = 10000,
    CHADPI_L7_SSH,
    CHADPI_L7_TELNET,
    CHADPI_L7_SMTP,
    CHADPI_L7_DNS,
    CHADPI_L7_DHCP,
    CHADPI_L7_TFTP,
    CHADPI_L7_HTTP,
    CHADPI_L7_POP3,
    CHADPI_L7_NTP,
    CHADPI_L7_NETBIOS,
    CHADPI_L7_IMAP,
    CHADPI_L7_SNMP,
    CHADPI_L7_LDAP,
    CHADPI_L7_HTTPS,
    CHADPI_L7_SMB,
    CHADPI_L7_SMTPS,
    CHADPI_L7_DNS_OVER_TLS,
    CHADPI_L7_IMAPS,
    CHADPI_L7_POP3S,
    CHADPI_L7_NFS,
    CHADPI_L7_RDP,
    CHADPI_L7_XMPP,
    CHADPI_L7_APPLE_PUSH,
    CHADPI_L7_GOOGLE_CLOUD_MESSAGING,
    CHADPI_L7_MDNS,
    CHADPI_L7_LLMNR,
    CHADPI_L7_QUIC,
    CHADPI_L7_TCP,
    CHADPI_L7_UDP,
};

static __always_inline __u16
dpi_match_extension(__u8 proto, __u16 dport, __u8 *payload, __u32 payload_len, bool ingress)
{
	if (proto == IPPROTO_TCP) {
		switch (dport) {
		case 443:
			return CHADPI_L7_HTTPS;
		case 80:
			return CHADPI_L7_HTTP;
		case 22:
			return CHADPI_L7_SSH;
		case 21:
			return CHADPI_L7_FTP;
		case 23:
			return CHADPI_L7_TELNET;
		case 25:
			return CHADPI_L7_SMTP;
		case 53:
			return CHADPI_L7_DNS;
		case 67:
		case 68:
			return CHADPI_L7_DHCP;
		case 69:
			return CHADPI_L7_TFTP;
		case 110:
			return CHADPI_L7_POP3;
		case 123:
			return CHADPI_L7_NTP;
		case 137:
		case 138:
		case 139:
			return CHADPI_L7_NETBIOS;
		case 143:
			return CHADPI_L7_IMAP;
		case 161:
		case 162:
			return CHADPI_L7_SNMP;
		case 389:
			return CHADPI_L7_LDAP;
		
		case 445:
			return CHADPI_L7_SMB;
		case 465:
		case 587:
			return CHADPI_L7_SMTPS;
		case 853:
			return CHADPI_L7_DNS_OVER_TLS;
		case 993:
			return CHADPI_L7_IMAPS;
		case 995:
			return CHADPI_L7_POP3S;
		case 2049:
			return CHADPI_L7_NFS;
		case 3389:
			return CHADPI_L7_RDP;
		case 5222:
			return CHADPI_L7_XMPP;
		case 5223:
			return CHADPI_L7_APPLE_PUSH;
		case 5228:
			return CHADPI_L7_GOOGLE_CLOUD_MESSAGING;
		case 5353:
			return CHADPI_L7_MDNS;
		case 5355:
			return CHADPI_L7_LLMNR;
		default:
			return CHADPI_L7_TCP;
		}
	}

	if (proto == IPPROTO_UDP) {
		switch (dport)
		{
		case 53:
			return CHADPI_L7_DNS;
		case 67:
		case 68:
			return CHADPI_L7_DHCP;
		case 443:
			return CHADPI_L7_QUIC;
		case 853:
			return CHADPI_L7_DNS_OVER_TLS;
		case 3389:
			return CHADPI_L7_RDP;
		case 5353:
			return CHADPI_L7_MDNS;
		case 5355:
			return CHADPI_L7_LLMNR;
		default:
			return CHADPI_L7_UDP;
		}
	}

	return CHADPI_L7_UNKNOWN;
}

#endif
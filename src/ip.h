/*
 * Copyright (c) 2007-2012, Paul Meng (mirnshi@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
**/

#ifndef _IP_H_
#define _IP_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MTU          1500
#define IPV6_MMTU    1280

#define ETH_ALEN 6
#define ETHERTYPE_IP	0x0800	/* IP */
#define ETHERTYPE_ARP	0x0806	/* Address resolution */
struct ethdr {
	u_char  dst[ETH_ALEN];	/* destination eth addr */
	u_char  src[ETH_ALEN];	/* source ether addr    */
	u_short type;		/* packet type ID field */
};
typedef struct ethdr ethdr;

#define ARPHRD_ETHER	1	/* ethernet hardware format */
#define ARPOP_REQUEST	1	/* request to resolve address */
#define ARPOP_REPLY	2	/* response to previous request */

struct  arphdr {
	u_short hrd;			/* format of hardware address */
	u_short pro;			/* format of protocol address */
	u_char  hln;			/* length of hardware address */
	u_char  pln;			/* length of protocol address */
	u_short op;			/* one of: */
	u_char sea[ETH_ALEN];
	u_char sip[4];
	u_char dea[ETH_ALEN];
	u_char dip[4];
};
typedef struct arphdr arphdr;

struct iphdr {
	u_int   ihl:4,		/* ip header length, should be 20 bytes */
			ver:4;	/* version */
	u_char  tos;		/* type of service */
	u_short len;		/* ip packet length */
	u_short id;		/* identification */
	u_short frag;		/* fragment offset field */
	u_char  ttl;		/* time to live */
#define TTL	64
	u_char  proto;		/* protocol */
	u_short cksum;		/* checksum */
	u_int   sip;
	u_int   dip;		/* source and dest address */
};
typedef struct iphdr iphdr;

#define IPDF 0x4000
#define IPMF 0x2000

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8 
#endif
#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif
#ifndef ICMP_TIMXCEED
#define ICMP_TIMXCEED 11
#endif
#ifndef ICMP_UNREACH
#define ICMP_UNREACH 3
#endif
#ifndef ICMP_UNREACH_PORT
#define ICMP_UNREACH_PORT 3
#endif

#ifndef ICMP_REDIRECT
#define ICMP_REDIRECT 5
#define ICMP_REDIRECT_NET 0
#endif

struct icmphdr 
{ 
	u_char type;		/* echo or echo reply */
	u_char code;		/* type sub code */
	u_short cksum;
	u_short id;
	u_short seq;
}; 
typedef struct icmphdr icmphdr;

struct icmprdr 
{ 
	u_char type;		/* echo or echo reply */
	u_char code;		/* type sub code */
	u_short cksum;
	u_int ip;
	u_char data[0];
}; 

typedef struct icmprdr icmprdr;

struct icmpthdr 
{ 
	icmphdr b;
	u_int timestamp;
}; 
typedef struct icmpthdr icmpthdr;

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_TCP
#define	IPPROTO_TCP	6
#endif

struct ipovly {
	u_char	ih_x1[9];		/* (unused) */
	u_char	ih_pr;			/* protocol */
	u_short	ih_len;			/* protocol length */
	struct	in_addr ih_src;		/* source internet address */
	struct	in_addr ih_dst;		/* destination internet address */
};

typedef struct {
	u_short sport;
	u_short dport;
	u_short len;
	u_short cksum;
} udphdr;

struct udpiphdr {
	struct ipovly	ui_i;		/* overlaid ip structure */
	udphdr	ui_u;		/* udp header */
};

#define	ui_x1		ui_i.ih_x1
#define	ui_pr		ui_i.ih_pr
#define	ui_len		ui_i.ih_len
#define	ui_src		ui_i.ih_src
#define	ui_dst		ui_i.ih_dst
#define	ui_sport	ui_u.sport
#define	ui_dport	ui_u.dport
#define	ui_ulen		ui_u.len
#define	ui_sum		ui_u.cksum

typedef struct udpiphdr udpiphdr;

struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	u_int	th_seq;			/* sequence number */
	u_int	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80
#define	TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define	PRINT_TH_FLAGS	"\20\1FIN\2SYN\3RST\4PUSH\5ACK\6URG\7ECE\10CWR"

	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

typedef struct tcphdr tcphdr;
struct tcpiphdr {
	struct	ipovly ti_i;		/* overlaid ip structure */
	struct	tcphdr ti_t;		/* tcp header */
};
typedef struct tcpiphdr tcpiphdr;
#define	ti_x1		ti_i.ih_x1
#define	ti_pr		ti_i.ih_pr
#define	ti_len		ti_i.ih_len
#define	ti_src		ti_i.ih_src
#define	ti_dst		ti_i.ih_dst
#define	ti_sport	ti_t.th_sport
#define	ti_dport	ti_t.th_dport
#define	ti_seq		ti_t.th_seq
#define	ti_ack		ti_t.th_ack
#define	ti_x2		ti_t.th_x2
#define	ti_off		ti_t.th_off
#define	ti_flags	ti_t.th_flags
#define	ti_win		ti_t.th_win
#define	ti_sum		ti_t.th_sum
#define	ti_urp		ti_t.th_urp


#define TCPOPT_MAXSEG           2
#define TCPOLEN_MAXSEG          4
#define TCPOPT_WINDOW           3
#define TCPOLEN_WINDOW          3
#define TCPOPT_TIMESTAMP        8
#define TCPOLEN_TIMESTAMP       10

#define PKT_MAXSIZE 1520
#define ARP_PSIZE 64
#define ICMP_PSIZE 128
#define UDP_PSIZE 128

/* define ipv6 */
#define ETHER_MAP_IPV6_MULTICAST(ip6addr, enaddr)                   \
{                                                                   \
	(enaddr)[0] = 0x33;                                         \
	(enaddr)[1] = 0x33;                                         \
	(enaddr)[2] = ((u_char *)ip6addr)[12];                      \
	(enaddr)[3] = ((u_char *)ip6addr)[13];                      \
	(enaddr)[4] = ((u_char *)ip6addr)[14];                      \
	(enaddr)[5] = ((u_char *)ip6addr)[15];                      \
}

#define ETHERTYPE_IPV6	0x86DD	/* IP */

typedef struct {
	union {
		u_char	_a8[16];
		u_short	_a16[8];
		u_int	_a32[4];
	} uaddr;
} ip6;
#define addr8 uaddr._a8
#define addr16 uaddr._a16
#define addr32 uaddr._a32

#define IN6_IS_MULTICAST(a)	((a)->addr8[0] == 0xff)

typedef struct {
	union {
		struct ip6_hdrctl {
			u_int ip6_un1_flow;	/* 20 bits of flow-ID */
			u_short ip6_un1_plen;	/* payload length */
			u_char  ip6_un1_nxt;	/* next header */
			u_char  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		u_char ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	ip6 src;	/* source address */
	ip6 dst;	/* destination address */
} ip6hdr;

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

#define IPV6_VERSION		0x60
#define IPV6_VERSION_MASK	0xf0

#define IPV6_ADDR_INT32_ONE     0x01000000
#define IPV6_ADDR_INT32_TWO     0x02000000
#define IPV6_ADDR_INT32_MNL     0x000001ff
#define IPV6_ADDR_INT32_MLL     0x000002ff
#define IPV6_ADDR_INT32_SMP     0xffff0000
#define IPV6_ADDR_INT16_ULL     0x80fe
#define IPV6_ADDR_INT16_USL     0xc0fe
#define IPV6_ADDR_INT16_MLL     0x02ff

#define IP6EQ(s, d) (!memcmp((s)->addr8, (d)->addr8, 16))

typedef struct {
	u_int8_t	type;	/* type field */
	u_int8_t	code;	/* code field */
	u_int16_t	cksum;	/* checksum field */
	union {
		u_int32_t	icmp6_un_data32[1]; /* type-specific field */
		u_int16_t	icmp6_un_data16[2]; /* type-specific field */
		u_int8_t	icmp6_un_data8[4];  /* type-specific field */
	} icmp6_dataun;
} icmp6hdr;

#define icmp6_data32 icmp6_dataun.icmp6_un_data32
#define icmp6_data16 icmp6_dataun.icmp6_un_data16
#define icmp6_data8  icmp6_dataun.icmp6_un_data8
#define icmp6_pptr	icmp6_data32[0]		/* parameter prob */
#define icmp6_mtu	icmp6_data32[0]		/* packet too big */
#define icmp6_id	icmp6_data16[0]		/* echo request/reply */
#define icmp6_seq	icmp6_data16[1]		/* echo request/reply */

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8 
#endif
#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif
#ifndef ICMP_TIMXCEED
#define ICMP_TIMXCEED 11
#endif
#ifndef ICMP_UNREACH
#define ICMP_UNREACH 3
#endif
#ifndef ICMP_UNREACH_PORT
#define ICMP_UNREACH_PORT 3
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6          58
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST		128	/* echo service */
#endif
#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY		129	/* echo reply */
#endif
#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH		1	/* dest unreachable, codes: */
#endif
#ifndef ICMP6_TIME_EXCEEDED
#define ICMP6_TIME_EXCEEDED		3	/* time exceeded, code: */
#endif
#ifndef ICMP6_DST_UNREACH_NOPORT
#define ICMP6_DST_UNREACH_NOPORT	4	/* port unreachable */
#endif

typedef struct tcpcb6 {
	u_int timeout;
	ip6	sip;
	ip6 dip;
	u_int sport;
	u_int dport;
	u_int ack;
	u_int seq;
	u_short winsize;
	u_char	flags;  /* my flags */
	u_char	rflags; /* remote tcp flags */
} tcpcb6;

#ifndef ND_ROUTER_SOLICIT
#define ND_ROUTER_SOLICIT		133	/* router solicitation */
#define ND_ROUTER_ADVERT		134	/* router advertisement */
#define ND_NEIGHBOR_SOLICIT		135	/* neighbor solicitation */
#define ND_NEIGHBOR_ADVERT		136	/* neighbor advertisement */
#define ND_REDIRECT			137	/* redirect */
#endif

typedef struct {
	icmp6hdr hdr;
	ip6 target;
} ndhdr;

typedef struct {
	u_char type;
	u_char len;
	u_char mac[6];
} ndopt;
#define nd_na_flags	hdr.icmp6_data32[0]
#define ND_NA_FLAG_OVERRIDE		0x20

typedef struct {
	icmp6hdr	hdr;
	u_int		reachable;
	u_int		retransmit;
} ndrahdr;

#define nd_ra_curhoplimit	hdr.icmp6_data8[0]
#define nd_ra_router_lifetime hdr.icmp6_data16[1]
#define ND_RA_FLAG_MANAGED	0x80
#define ND_RA_FLAG_OTHER	0x40
#define ND_RA_FLAG_HA		0x20

#define DMP_MAC    1
#define DMP_RAW    2
#define DMP_DETAIL 4
#define DMP_ALL    0x80

struct packet; /* defined in queue.h */

typedef struct sesscb {
	int sock;
	u_int timeout;
	u_int sn;
	u_int waittime;
	u_char smac[6];
	u_char dmac[6];
	u_int sip;
	u_int dip;
	u_int rdip;
	ip6 sip6;
	ip6 dip6;
	ip6 rdip6;
	u_int sport;
	u_int dport;
	u_int ipid;
	int proto;
	int dsize;
	int rdsize;
	u_int ack;
	u_int seq;
	u_int rack;
	u_int rseq;
	u_short winsize;
	u_char	flags;  /* my flags */
	u_char	rflags; /* remote tcp flags */
	u_char ttl;
	u_char rttl;
	u_short rmss; /* TCP MSS */
	int aproto;
	u_char icmptype;
	u_char icmpcode;
	int mtu;
	int frag;
	char *data;
} sesscb;

void encap_ehead(char *mbuf, const u_char *sea, const u_char *dea, const u_short type);
void swap_ehead(char *mbuf);

u_short cksum(register unsigned short *buffer, register int size);
u_short cksum_fixup(u_short cksum, u_short old, u_short new, u_short udp);
u_short cksum6(ip6hdr *ip, u_char nxt, int len);

int dmp_packet(const struct packet *m, const int flag);

int etherIsZero(u_char *mac);
int etherIsMulticast(u_char *mac);

int sameNet(u_long ip1, u_long ip2, int cidr);
int sameNet6(char *s, char *d, int cidr);

void swap_ip6head(struct packet *m);

int getCIDR(u_long mask);

const char *icmpTypeCode2String(int ipv, u_int8_t type, u_int8_t code);

char *ip6tostr(const u_char *ip6);

#define PRINT_MAC(x) \
    printf("%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", (x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5]);
#endif

/* end of file */

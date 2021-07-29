/*
 * Copyright (c) 2007-2015, Paul Meng (mirnshi@gmail.com)
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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "vpcs.h"
#include "packets6.h"
#include "utils.h"
#include "ip.h"
#include "frag6.h"

static struct packet *icmp6Reply(pcs *, struct packet *, char type, char code);
static struct packet *udp6Reply(struct packet *m0);
static void fix_dmac6(pcs *pc, struct packet *m);
static struct packet* nb_sol(pcs *pc, ip6 *dst);
static void save_mtu6(pcs *pc, struct packet *m);

static int sub_nbsol(pcs *pc, struct packet *m);
static int sub_nbadv(pcs *pc, struct packet *m);
static int sub_udp(pcs *pc, struct packet *m);

static int save_nb_adv(pcs *pc, struct packet *m);

/* static void xxpreh(char *e, int c); */
extern int tcp6(pcs *pc, struct packet *m);

extern u_int time_tick;
/*
 * ipv6 stack
 *
 * code: PKT_UP, send to up layer
 *       PKT_ENQ, in out queue
 *       PKT_DROP, drop the packet
 */
int upv6(pcs *pc, struct packet **m0)
{
	struct packet *m = *m0;
	ethdr *eh;
	ip6hdr *ip;
	icmp6hdr *icmp;
	struct packet *p = NULL;
	
	eh = (ethdr *)(m->data);
	
	if (etherIsMulticast(eh->src))
		return PKT_DROP;
		
	if (eh->type != htons(ETHERTYPE_IPV6))
		return PKT_DROP;
	
	ip = (ip6hdr *)(eh + 1);
	if ((ip->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return PKT_DROP;
	
	/* too big, send ICMP with the code ICMP6_PACKET_TOO_BIG */
	if (ntohs(ip->ip6_plen) + sizeof(ip6hdr) > pc->mtu) {
		p = icmp6Reply(pc, m, ICMP6_PACKET_TOO_BIG, 0);
		if (p) {
			fix_dmac6(pc, p);
			enq(&pc->oq, p);
		}
		return PKT_ENQ;
	}
	
	/* fragment */
	if (ip6ehdr(ip, m->len - sizeof(ethdr), IPPROTO_FRAGMENT) > 0) {
		m = ipreass6(m);
		if (m == NULL)
			return PKT_ENQ;
		else
			*m0 = m;
		ip = (ip6hdr *)(m->data + sizeof(ethdr));
	}
		
	if (ip->ip6_nxt == IPPROTO_ICMPV6) {
		icmp = (icmp6hdr *)(ip + 1);
		
		/* neighbor solicitation */
		if (icmp->type == ND_NEIGHBOR_SOLICIT)
			return sub_nbsol(pc, m);
		
		if (icmp->type == ICMP6_ECHO_REQUEST) {
			swap_ip6head(m);
		
			icmp = (icmp6hdr *)(ip + 1);
			icmp->type = ICMP6_ECHO_REPLY;
			icmp->cksum = cksum_fixup(icmp->cksum, 
			    ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY, 0);
			swap_ehead(m->data);
			
			/* push m into the background output queue 
			   which is watched by pth_output */
			enq(&pc->bgoq, m);

			return PKT_ENQ;
		}

		if (icmp->type == ND_ROUTER_ADVERT) {
			return sub_nbadv(pc, m);
		}
		/* neighbor advertisement */
		if (icmp->type == ND_NEIGHBOR_ADVERT) {
			save_nb_adv(pc, m);
			return PKT_DROP;
		}
		
		if (icmp->type == ICMP6_PACKET_TOO_BIG)
			save_mtu6(pc, m);
		
		switch (icmp->type) {
			case ICMP6_ECHO_REPLY:
			case ICMP6_TIME_EXCEEDED:
			case ICMP6_DST_UNREACH:
			case ICMP6_PACKET_TOO_BIG:
				return PKT_UP;
			default:
				break;
		}
	}
	
	switch (ip->ip6_nxt) {
		case IPPROTO_UDP:
			return sub_udp(pc, m);
		case IPPROTO_TCP:
			return tcp6(pc, m);
		default:
			return PKT_DROP;
	}

	return PKT_UP;
}


int sub_udp(pcs *pc, struct packet *m)
{
	ethdr *eh;
	ip6hdr *ip;
	udphdr *ui;	
	struct packet *p;

	eh = (ethdr *)(m->data);
	ip = (ip6hdr *)(eh + 1);
	
	ui = (udphdr *)(ip + 1);
	
	if (IN6_IS_MULTICAST(&(ip->dst)))
		return PKT_DROP;
		
	/* udp echo reply */	
	char *data = ((char*)(ui + 1));
	if (memcmp(data, eh->dst, 6) == 0)
		return PKT_UP;
	
	p = (ip->ip6_hlim != 1) ? udp6Reply(m) :
	    icmp6Reply(pc, m, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT);
		
	/* push m into the background output queue 
	   which is watched by pth_output */
	if (p != NULL)
		enq(&pc->bgoq, p);

	/* anyway tell caller to drop this packet */
	return PKT_DROP;		
}

int sub_nbsol(pcs *pc, struct packet *m)
{
	ethdr *eh;
	ip6hdr *ip;
	ndhdr *nshdr;
	ndopt *nsopt;
	ip6 *tip6 = NULL;
	
	eh = (ethdr *)(m->data);
	ip = (ip6hdr *)(eh + 1);
	nshdr = (ndhdr *)(ip + 1);
	nsopt = (ndopt *)(nshdr + 1);
	
	if (eh->dst[0] != 0x33 || 
	    eh->dst[1] != 0x33 ||
	    eh->dst[2] != 0xff ||
	    ip->ip6_hlim != 255 ||
	    ip->dst.addr16[0] != IPV6_ADDR_INT16_MLL ||
	    ip->dst.addr32[1] != 0 ||
	    ip->dst.addr32[2] != IPV6_ADDR_INT32_ONE ||
	    ip->dst.addr8[12] != 0xff) {
		return PKT_DROP;
	}
	
	if (eh->dst[3] != pc->ip6.ip.addr8[13] ||
	    eh->dst[4] != pc->ip6.ip.addr8[14] ||
	    eh->dst[5] != pc->ip6.ip.addr8[15] ||
	    ip->dst.addr32[3] != (pc->ip6.ip.addr32[3] | 0xff)) {
		if (eh->dst[3] != pc->link6.ip.addr8[13] ||
		    eh->dst[4] != pc->link6.ip.addr8[14] ||
		    eh->dst[5] != pc->link6.ip.addr8[15] ||
		    ip->dst.addr32[3] != (pc->link6.ip.addr32[3] | 0xff)) {
			return PKT_DROP;
		} else
			tip6 = &pc->link6.ip;	
	} else
		tip6 = &pc->ip6.ip;			

	/* send advertisement */
	memcpy(ip->dst.addr8, ip->src.addr8, 16);
	memcpy(ip->src.addr8, tip6->addr8, 16);
		
	nshdr->hdr.type = ND_NEIGHBOR_ADVERT;
	nshdr->hdr.code = 0;
	nshdr->nd_na_flags = ND_RA_FLAG_OTHER | ND_RA_FLAG_HA;
	nsopt->type = 2;
	memcpy(nsopt->mac, pc->ip4.mac, ETH_ALEN);
		
	nshdr->hdr.cksum = 0;
	nshdr->hdr.cksum = cksum6(ip, IPPROTO_ICMPV6, ntohs(ip->ip6_plen));
	
	memcpy(eh->dst, eh->src, ETH_ALEN);
	memcpy(eh->src, pc->ip4.mac, ETH_ALEN);	

	enq(&pc->oq, m);
	
	return PKT_ENQ;
}

int sub_nbadv(pcs *pc, struct packet *m)
{
	ethdr *eh;
	ip6hdr *ip;
	icmp6hdr *icmp;
	int setMtu = 0, setMac = 0;
	u_int32_t mtu = 0;
	char *p = NULL, *mac = NULL;
	ndrahdr *ndr = NULL;
	
	eh = (ethdr *)(m->data);
	ip = (ip6hdr *)(eh + 1);
	icmp = (icmp6hdr *)(ip + 1);
	ndr = (ndrahdr *)(ip + 1);
	
	/*  icmp6_data8[0]
	 *  |7654 3210|
	 *   |||
	 *   ||Override flag, update link address if 1
	 *   |Solicited flag, response to NS if 1
	 *   Router flag if 1
	 */
	 
	if (ip->src.addr8[0] != 0xfe || ip->src.addr8[1] != 0x80 ||
	    icmp->icmp6_data8[0] != ND_RA_FLAG_OTHER) {
		return PKT_DROP;
	}

	/*
	 * TLD (Type, Length, Data)
	 * Type, Length: 8 bits
	 *  1 = Source link-layer
	 *      Length = 1, Data: Ethernet 48 bit MAC
	 *  2 = Target link-layer
	 *      Length = 1, Data: Ethernet 48 bit MAC
	 *  3 = Prefix Informationr
	 *      Length = 4, 
	 *      Data: Prefix Length 8 bit
	 *            1-bit on-link flag
	 *            1-bit autonomous address-configuration flag, this 
	 *              prefix can be used for stateless autoconfiguration.
	 *            6-bits reserved
	 *            32-bits the prefix valid lifetime in seconds
	 *            32-bits stateless address remain preferred lifetime
	 *            32-bits reserved
	 *            128-bits Prefix of the ip address
	 *  4 = Redirected Header
	 *      Length: multiple of 8 octets in range 1 to 161
	 *      Data: 48-bits Set to zero and ignored by receiver.
	 *            variable octet IP Header + Data, not exceed 1280 octets.
	 *  5 = MTU
	 *      Length = 1
	 *      Data: 16-bits reserved
	 *            32-bits mtu
	 */
	
	for (p = (char *)(ndr + 1);
	    p < ((char*)icmp + ntohs(ip->ip6_plen));
	    p += *(p + 1) * 8)
	{
		/* link-layer address */
		if (*p == 1 && *(p + 1) == 1)
			mac = p + 2;
		/* mtu */
		else if (*p == 5 && *(p + 1) == 1)
			mtu = ntohl(*(u_int32_t *)(p + 4));
		/* prefix */
		else if (*p == 3 && *(p + 1) == 4) {
			if (pc->ip6.cidr == 0) {
				memcpy(pc->ip6.ip.addr8, p + 16, 16);
				pc->ip6.cidr = *(p + 2);

				pc->ip6.ip.addr8[15] = pc->ip4.mac[5];
				pc->ip6.ip.addr8[14] = pc->ip4.mac[4];
				pc->ip6.ip.addr8[13] = pc->ip4.mac[3];
				pc->ip6.ip.addr8[12] = 0xfe;
				pc->ip6.ip.addr8[11] = 0xff;
				pc->ip6.ip.addr8[10] = pc->ip4.mac[2];
				pc->ip6.ip.addr8[9]  = pc->ip4.mac[1];
				pc->ip6.ip.addr8[8]  = (pc->ip4.mac[0] &0x20) ?
				    pc->ip4.mac[0] & 0xef : (pc->ip4.mac[0] | 0x20);

				pc->ip6.type = IP6TYPE_EUI64;
				setMtu = 1;
			}
			if (sameNet6((char *)pc->ip6.ip.addr8, p + 16, pc->ip6.cidr))
				setMac = 1;
		}
	}

	if (setMtu != 0 && mtu != 0)
		pc->mtu = mtu;
	if (setMac != 0 && mac != NULL)
		memcpy(pc->ip6.gmac, mac, 6);

	return PKT_DROP;	
}

void send6(pcs *pc, struct packet *m)
{
	ethdr *eh = (ethdr *)(m->data);
	ip6hdr *ip;
	
	if (eh->type != htons(ETHERTYPE_IPV6)) {
		del_pkt(m);
		return;
	}
	
	fix_dmac6(pc, m);
	
	ip = (ip6hdr *)(eh + 1);
	m = ipfrag6(m, findmtu6(pc, &ip->dst));
	
	enq(&pc->oq, m);
}

int response6(struct packet *m, sesscb *sesscb)
{
	ethdr *eh;
	ip6hdr *ip;

	eh = (ethdr *)(m->data);
	ip = (ip6hdr *)(eh + 1);
	
	if (ip->ip6_nxt == IPPROTO_ICMPV6) {
		icmp6hdr *icmp = (icmp6hdr *)(ip + 1);
		if (icmp->type == ICMP6_DST_UNREACH || 
		    icmp->type == ICMP6_TIME_EXCEEDED || 
		    icmp->type == ICMP6_DST_UNREACH_NOPORT ||
		    icmp->type == ICMP6_PACKET_TOO_BIG) {
			
			if (icmp->type == ICMP6_PACKET_TOO_BIG)
				sesscb->mtu = ntohl(icmp->icmp6_mtu);
			sesscb->icmptype = icmp->type;
			sesscb->icmpcode = icmp->code;
			sesscb->rttl = ip->ip6_hlim;
			memcpy(sesscb->rdip6.addr8, ip->src.addr8, 16);
			
			return IPPROTO_ICMPV6;
		}
	}
	
	if (!IP6EQ(&(sesscb->dip6), &(ip->src)))
		return 0;
			
	if (ip->ip6_nxt == IPPROTO_ICMPV6 && sesscb->proto == IPPROTO_ICMPV6) {
		icmp6hdr *icmp = (icmp6hdr *)(ip + 1);
		
		sesscb->icmptype = icmp->type;
		sesscb->icmpcode = icmp->code;
		
		sesscb->rttl = ip->ip6_hlim;
		memcpy(sesscb->rdip6.addr8, ip->src.addr8, 16);
		
		if (ntohs(icmp->icmp6_seq) == sesscb->sn) {
			return IPPROTO_ICMPV6;
		}

		return 0;
	} 
	
	if (ip->ip6_nxt == IPPROTO_UDP) {
		udphdr *ui = (udphdr *)(ip + 1);
		char *data = ((char*)(ui + 1));
	
		if (memcmp(data, eh->dst, 6) == 0) {
			sesscb->rttl = ip->ip6_hlim;
			return IPPROTO_UDP;
		}
		return 0;
	}
	if (ip->ip6_nxt == IPPROTO_TCP) {
		struct tcphdr *th = (struct tcphdr *)(ip + 1);
		char *data = ((char*)(th + 1));
		
		sesscb->rseq = ntohl(th->th_seq);
		sesscb->rack = ntohl(th->th_ack);
		sesscb->rflags = th->th_flags;
		sesscb->rttl = ip->ip6_hlim;
		sesscb->rdsize = ntohs(ip->ip6_plen) - sizeof(iphdr) - (th->th_off << 2);
		sesscb->data = NULL;

		/* try to get MSS from options */
		if (sesscb->flags == TH_SYN && sesscb->rdsize > 0 &&
		    sesscb->rflags == (TH_SYN | TH_ACK)) {
			int i = 0;

			while (data[i] == 0x1 && i < sesscb->rdsize) i++;
			
			for (;i < sesscb->rdsize;) {
				if (data[i] == TCPOPT_MAXSEG && 
				    data[i + 1] == TCPOLEN_MAXSEG) {
					sesscb->rmss = (data[i + 2] << 8) + data[i + 3];
					break;
				}
				i += data[i + 1];
			}
		} else {
			sesscb->data = ((char*)(ip + 1)) + (th->th_off << 2);
		}
		
		return IPPROTO_TCP;
	}
	
	return 0;
}

struct packet *packet6(pcs *pc) //sesscb *sesscb)
{
	sesscb *sesscb = &pc->mscb;
	int dlen = 0, len = 0, i;
	struct packet *m = NULL;
	ethdr *eh;
	ip6hdr *ip;
	
	if (sesscb->dsize < 60000)
		dlen = sesscb->dsize;

	len = sizeof(ethdr) + sizeof(ip6hdr);
	switch (sesscb->proto) {
		case IPPROTO_ICMPV6:
			len += sizeof(icmp6hdr) + dlen;
			break;
		case IPPROTO_UDP:
			if (dlen < 6)
				dlen = 6;
			len += sizeof(udphdr) + dlen;
			break;
		case IPPROTO_TCP:
			if (sesscb->flags != (TH_ACK | TH_PUSH))
				dlen = 0;
			if (sesscb->flags == TH_SYN) {
				/* mss(2 + 2), nop(1 + 1), timestamp ( 2 + 8), 
				 * nop(1), winscale (2 + 1)*/
				dlen = 4 + 2 + 2 + 8 + 1 + 3;	
			} else {
				dlen = dlen + 2 + 2 + 8;
			}
			
			if (sesscb->rmss != 0 && dlen > sesscb->rmss)
				dlen = sesscb->rmss - sizeof(ethdr) - 
				    sizeof(iphdr) - sizeof(tcphdr);
				
			len += sizeof(tcphdr) + dlen;
				
			break;
	}
	
	m = new_pkt(len);
	if (m == NULL)
		return NULL;
	
	eh = (ethdr *)(m->data);
	memcpy(eh->src, sesscb->smac, 6);
	memcpy(eh->dst, sesscb->dmac, 6);
	eh->type = htons(ETHERTYPE_IPV6);

	ip = (ip6hdr *)(eh + 1);
	ip->ip6_flow = 0;
	ip->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip->ip6_vfc |= IPV6_VERSION;
	ip->ip6_nxt = sesscb->proto;
	ip->ip6_hlim = sesscb->ttl;
	ip->ip6_plen = htons((u_short)(len - sizeof(ethdr) - sizeof(ip6hdr)));
	
	memcpy(ip->src.addr8, sesscb->sip6.addr8, 16);
	memcpy(ip->dst.addr8, sesscb->dip6.addr8, 16);
	
	if (sesscb->proto == IPPROTO_ICMPV6) {
		icmp6hdr *icmp = (icmp6hdr *)(ip + 1);
		icmp->type = ICMP6_ECHO_REQUEST;
		icmp->icmp6_id = sesscb->ipid;
		icmp->icmp6_seq = htons(sesscb->sn);
		
		/* append payload data */
		for (i = 0; i < dlen; i++)
			m->data[sizeof(ethdr) + sizeof(ip6hdr) + 
			    sizeof(icmp6hdr) + i] = i % 0xff;
	
		icmp->cksum = 0;
		icmp->cksum = cksum6(ip, IPPROTO_ICMPV6, len - 
		    sizeof(ethdr) - sizeof(ip6hdr));
		
	} else if (sesscb->proto == IPPROTO_UDP) {
		udphdr *ui = (udphdr *)(ip + 1);
		char *data = ((char*)(ui + 1));
		
		ui->sport = htons(sesscb->sport);
		ui->dport = htons(sesscb->dport);
		ui->len = htons(len - sizeof(ethdr) - sizeof(ip6hdr));
		
		memcpy(data, sesscb->smac, 6);	
		for (i = 6; i < dlen; i++)
			data[i] = i + sizeof(udphdr);
		
		ui->cksum = 0;
		ui->cksum = cksum6(ip, IPPROTO_UDP, len - 
		    sizeof(ethdr) - sizeof(ip6hdr));
	} else if (sesscb->proto == IPPROTO_TCP) {
		struct tcphdr *th = (struct tcphdr *)(ip + 1);
		char *data = ((char*)(th + 1));
		u_int t = htonl(time(0));
		int optlen = 0;
		
		th->th_sport = htons(sesscb->sport);
		th->th_dport = htons(sesscb->dport);
		th->th_ack = htonl(sesscb->ack);
		th->th_seq = htonl(sesscb->seq);
		th->th_win = htons(sesscb->winsize);
		th->th_flags = sesscb->flags;
		
		if (sesscb->flags == TH_SYN) {
			/* mss 1460 */
			*data++ = TCPOPT_MAXSEG;
			*data++ = TCPOLEN_MAXSEG;
			*data++ = 0x5;
			*data++ = 0xb4;
			/* align */
			*data++ = 0x1;
			*data++ = 0x1;
			/* timestamp */
			*data++ = TCPOPT_TIMESTAMP;
			*data++ = TCPOLEN_TIMESTAMP;
			memcpy(data, (char *)&t, 4);
			data += 8;
			/* align */
			*data++ = 0x1;
			*data++ = TCPOPT_WINDOW;
			*data++ = TCPOLEN_WINDOW;
			*data++ = 1;
		} else {
			/* align */
			*data++ = 0x1;
			*data++ = 0x1;
			/* timestamp */
			*data++ = TCPOPT_TIMESTAMP;
			*data++ = TCPOLEN_TIMESTAMP;
			memcpy(data, (char *)&t, 4);
			data += 8;
		}
		
		optlen = data - (char*)(th + 1);
		th->th_off = (sizeof(tcphdr) + optlen) >> 2;
		
		/* fill the data */
		for (i = optlen; i < dlen; i++) {
			if ((i % 2) == 0)
				*data++ = 0xd;
			else
				*data++ = 0xa;
		}

		th->th_sum = 0;
		th->th_sum = cksum6(ip, IPPROTO_TCP, len - 
		    sizeof(ethdr) - sizeof(ip6hdr));
	}
	
	if ((sesscb->frag & IPF_FRAG) == IPF_FRAG)
		m = ipfrag6(m, findmtu6(pc, &(sesscb->dip6)));
	
	return m;
	
}

/*-----------------------------------------------------------------------
 *
 * internal functions
 *
 *-----------------------------------------------------------------------*/

struct packet *icmp6Reply(pcs *pc, struct packet *m0, char icmptype, char icmpcode)
{
	ethdr *eh, *eh0;
	ip6hdr *ip, *ip0;
	icmp6hdr *icmp;
	struct packet *m;	
	int hlen;
	int plen;
	
	plen = m0->len - sizeof(ethdr);
	
	if (sizeof(ip6hdr) + sizeof(icmp6hdr) + plen > IPV6_MMTU)
		plen = IPV6_MMTU - sizeof(ip6hdr) - sizeof(icmp6hdr);
	
	hlen = sizeof(ethdr) + sizeof(ip6hdr) + sizeof(icmp6hdr) + plen;
	
	m = new_pkt(hlen);
	if (m == NULL)
		return NULL;
	
	hlen = hlen - sizeof(ethdr) - sizeof(ip6hdr);
	
	eh = (ethdr *)(m->data);
	eh0 = (ethdr *)(m0->data);
	
	memcpy(eh->src, eh0->dst, ETH_ALEN);
	memcpy(eh->dst, eh0->src, ETH_ALEN);
	eh->type = eh0->type;
	
	ip = (ip6hdr *)(eh + 1);
	ip0 = (ip6hdr *)(eh0 + 1);
	ip->ip6_flow = 0;
	ip->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip->ip6_vfc |= IPV6_VERSION;
	ip->ip6_nxt = IPPROTO_ICMPV6;
	ip->ip6_hlim = TTL;
	ip->ip6_plen = htons(sizeof(icmp6hdr) + (u_short)plen);
	
	memcpy(ip->src.addr8, ip0->dst.addr8, 16);
	memcpy(ip->dst.addr8, ip0->src.addr8, 16);
	
	icmp = (icmp6hdr *)(ip + 1);
	icmp->type = icmptype; //ICMP6_DST_UNREACH;
	icmp->code = icmpcode; //ICMP6_DST_UNREACH_NOPORT;
	switch (icmptype) {
		case ICMP6_PACKET_TOO_BIG:
			icmp->icmp6_mtu = htonl(pc->mtu);
			break;
		default:
			icmp->icmp6_id = time(0) & 0xffff;
			icmp->icmp6_seq = htons(1);
			break;
	}

	memcpy((char *)(icmp + 1), m0->data + sizeof(ethdr), plen);
	icmp->cksum = 0;
	icmp->cksum = cksum6(ip, IPPROTO_ICMPV6, hlen);

	return m;
}

struct packet *udp6Reply(struct packet *m0)
{
	ethdr *eh;
	ip6hdr *ip;
	udphdr *ui;
	struct packet *m;
	
	m = new_pkt(m0->len);
	if (m == NULL)
		return NULL;
	
	copy_pkt(m, m0);
	
	eh = (ethdr *)(m->data);
	ip = (ip6hdr *)(eh + 1);
	ui = (udphdr *)(ip + 1);
	
	swap_ehead(m->data);
	swap_ip6head(m);

	ip->ip6_hlim = TTL;

	ui->sport ^= ui->dport;
	ui->dport ^= ui->sport;
	ui->sport ^= ui->dport;

	ui->cksum = 0;
	ui->cksum = cksum6(ip, IPPROTO_UDP, ntohs(ui->len));
			
	return m;	
}

/*
 * find neighbor
 *
 * return the mac
 *   NULL, not found
 *
 */
u_char *nbDiscovery(pcs *pc, ip6 *dst)
{
	int i, j;
	static u_char mac[ETH_ALEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};	
	int waittime = 1000;
	struct timeval tv;
	
	/* linklocal address */
	if (dst->addr16[0] == IPV6_ADDR_INT16_ULL) {
		mac[0] = (dst->addr8[8] ^ 0x2);
		mac[1] = dst->addr8[9];
		mac[2] = dst->addr8[10];
		mac[3] = dst->addr8[13];
		mac[4] = dst->addr8[14];
		mac[5] = dst->addr8[15];
		
		return mac;	
	}
	
	/* find router */
	if (!sameNet6((char *)pc->ip6.ip.addr8, (char *)dst->addr8, pc->ip6.cidr) &&
		dst->addr16[0] != IPV6_ADDR_INT16_ULL) {
		
		gettimeofday(&(tv), (void*)0);
		while (!timeout(tv, waittime)) {
			struct packet *m;
			
			if (memcmp(pc->ip6.gmac, (const char *)mac, ETH_ALEN) != 0)
				return (pc->ip6.gmac);
			
			m = nbr_sol(pc);
			if (m == NULL) {
				printf("out of memory\n");
				return NULL;
			}
			enq(&pc->oq, m);
			delay_ms(10);
		}
		return NULL;
	} else {
		/* search neightbor cache */
		for (i = 0; i < POOL_SIZE; i++) {
			if (sameNet6((char *)pc->ipmac6[i].ip.addr8, 
			    (char *)dst->addr8, 128))
				return (pc->ipmac6[i].mac);
		}
	}
	
	/* find neighbor */
	i = 0;
	j = -1;
	while ((i++ < 3) &&  (j == -1)){
		struct packet *m;
		
		m = nb_sol(pc, dst);	
		
		if (m == NULL) {
			printf("out of memory\n");
			return NULL;
		}
		enq(&pc->oq, m);
		
		gettimeofday(&(tv), (void*)0);
		while (!timeout(tv, waittime)) {
			delay_ms(1);
			for (i = 0; i < POOL_SIZE; i++) {
				if (sameNet6((char *)pc->ipmac6[i].ip.addr8, 
				    (char *)dst->addr8, 128))
					return (pc->ipmac6[i].mac);
			}
		}
	}
	return NULL;
}

/* 
 * generate neighbor router solicitation packet
 */
struct packet* nbr_sol(pcs *pc)
{
	ethdr *eh;
	ip6hdr *ip;
	icmp6hdr *icmp;
	struct packet *m;	
	int len;

	len = sizeof(ethdr) + sizeof(ip6hdr) + sizeof(icmp6hdr);
	m = new_pkt(len);
	if (m == NULL)
		return NULL;
	len = sizeof(icmp6hdr);

	eh = (ethdr *)(m->data);
	memcpy(eh->src, pc->ip4.mac, ETH_ALEN);
	eh->type = htons(ETHERTYPE_IPV6);

	ip = (ip6hdr *)(eh + 1);
	ip->ip6_flow = 0;
	ip->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip->ip6_vfc |= IPV6_VERSION;
	ip->ip6_nxt = IPPROTO_ICMPV6;
	ip->ip6_hlim = 255;
	
	memcpy(ip->src.addr8, pc->ip6.ip.addr8, 16);
	/* format destination ip */
	ip->dst.addr16[0] = IPV6_ADDR_INT16_MLL;
	ip->dst.addr16[1] = 0;
	ip->dst.addr32[1] = 0;
	ip->dst.addr32[2] = 0;
	ip->dst.addr32[3] = IPV6_ADDR_INT32_TWO;
	
	/* rewrite eh->dst */
	eh->dst[0] = 0x33;
	eh->dst[1] = 0x33;
	eh->dst[5] = 2;
	
	icmp = (icmp6hdr *)(ip + 1);
	icmp->type = ND_ROUTER_SOLICIT;
	icmp->code = 0;

	len = sizeof(icmp6hdr);
	ip->ip6_plen = htons((u_short)len);
	icmp->cksum = 0;
	
	icmp->cksum = cksum6(ip, IPPROTO_ICMPV6, len);

	return m;
}

/* generate neighbor solicitation packet
 */
struct packet* nb_sol(pcs *pc, ip6 *dst)
{
	ethdr *eh;
	ip6hdr *ip;
	ndhdr *nshdr;
	ndopt *nsopt;
	struct packet *m;	
	int len;
	
	len = sizeof(ethdr) + sizeof(ip6hdr) + sizeof(ndhdr) + sizeof(ndopt);
	
	m = new_pkt(len);
	if (m == NULL)
		return NULL;
	
	len = sizeof(ndhdr) + sizeof(ndopt);
	
	eh = (ethdr *)(m->data);
	memcpy(eh->src, pc->ip4.mac, ETH_ALEN);
	eh->type = htons(ETHERTYPE_IPV6);

	ip = (ip6hdr *)(eh + 1);
	ip->ip6_flow = 0;
	ip->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip->ip6_vfc |= IPV6_VERSION;
	ip->ip6_nxt = IPPROTO_ICMPV6;
	ip->ip6_hlim = 255;
	
	if (dst->addr16[0] == IPV6_ADDR_INT16_ULL)
		memcpy(ip->src.addr8, pc->link6.ip.addr8, 16);
	else
		memcpy(ip->src.addr8, pc->ip6.ip.addr8, 16);

	/* format destination ip */
	ip->dst.addr16[0] = IPV6_ADDR_INT16_MLL;
	ip->dst.addr16[1] = 0;
	ip->dst.addr32[1] = 0;
	ip->dst.addr32[2] = IPV6_ADDR_INT32_ONE;
	ip->dst.addr32[3] = dst->addr32[3];
	ip->dst.addr8[12] = 0xff;
	
	/* rewrite eh->dst */
	eh->dst[0] = 0x33;
	eh->dst[1] = 0x33;
	eh->dst[2] = ip->dst.addr8[12];
	eh->dst[3] = ip->dst.addr8[13];
	eh->dst[4] = ip->dst.addr8[14];
	eh->dst[5] = ip->dst.addr8[15];
	
	nshdr = (ndhdr *)(ip + 1);
	nshdr->hdr.type = ND_NEIGHBOR_SOLICIT;
	nshdr->hdr.code = 0;
	nshdr->nd_na_flags = 0;
	memcpy(nshdr->target.addr8, dst->addr8, 16);
	
	/* append neighbor solicitation option */
	nsopt = (ndopt*)(nshdr + 1);
	nsopt->type = 1;
	nsopt->len = 1;
	memcpy(nsopt->mac, pc->ip4.mac, ETH_ALEN);
	
	len = sizeof(ndhdr) + sizeof(ndopt);
	ip->ip6_plen = htons((u_short)len);
	nshdr->hdr.cksum = 0;
	
	nshdr->hdr.cksum = cksum6(ip, IPPROTO_ICMPV6, len);

	return m;
}

int save_nb_adv(pcs *pc, struct packet *m)
{
	ethdr *eh;
	ip6hdr *ip;
	ndhdr *nshdr;
	ndopt *nsopt;
	int i;

	eh = (ethdr *)(m->data);
	
	if (eh->type != htons(ETHERTYPE_IPV6))
		return -1;

	if (memcmp(eh->dst, pc->ip4.mac, ETH_ALEN))
		return -1;

	ip = (ip6hdr *)(eh + 1);

	if ((!IP6EQ(&(pc->ip6.ip), &(ip->dst)) && 
	    !IP6EQ(&(pc->link6.ip), &(ip->dst))) || IP6EQ(&ip->dst, &ip->src))
		return -1;

	nshdr = (ndhdr *)(ip + 1);
	nsopt = (ndopt *)(nshdr + 1);
	
	if (nshdr->hdr.type != ND_NEIGHBOR_ADVERT)
		return -1;

	/* shoule check sum field
	 * ...
	 */

	/* not Target Link-Layer Address */
	if (nsopt->type != 2)
		return -1;

	i = 0;
	while (i < POOL_SIZE) {
		if (IP6EQ(&pc->ipmac6[i].ip, &ip->src) &&
		    (time_tick - pc->ipmac6[i].timeout <= 120))
			break;

		if (pc->ipmac6[i].timeout == 0 || 
		    (time_tick - pc->ipmac6[i].timeout > 120)) {
			memcpy(pc->ipmac6[i].mac, nsopt->mac, ETH_ALEN);
			memcpy(pc->ipmac6[i].ip.addr8, ip->src.addr8, 
			    sizeof(ip->src.addr8));
			
			pc->ipmac6[i].timeout = time_tick;
			pc->ipmac6[i].cidr = 128;
			break;
		}
		i++;
	}

	if (i == POOL_SIZE) {
		i = 0;
		memcpy(pc->ipmac6[i].mac, nsopt->mac, ETH_ALEN);
		memcpy(pc->ipmac6[i].ip.addr8, ip->src.addr8, 16);
		pc->ipmac6[i].timeout = time_tick;
	}

	return i;
}

void fix_dmac6(pcs *pc, struct packet *m)
{
	u_char *p;
	ethdr *eh;
	ip6hdr *ip;
	
	eh = (ethdr *)(m->data);	
	ip = (ip6hdr *)(eh + 1);
	
	p = nbDiscovery(pc, &ip->dst);
	if (p)
		memcpy(eh->dst, p, 6);
	
}

int ip6ehdr(ip6hdr *ip, int plen, int hdrtype)
{
	int nxt, off;
	ip6eh *eh;
	
	nxt = ip->ip6_nxt;
	off = sizeof(ip6hdr);
	while (off < plen) {
		if (nxt == hdrtype)
			return off;
		eh = (ip6eh *)(((char *)ip) + off);
		switch (nxt) {
			case IPPROTO_AH:
				off = (eh->len) << 2;
				break;
			default:
				off += (eh->len + 1) << 3;
				break;
		}
		nxt = eh->nxt;
	}
	return 0;
}

void save_mtu6(pcs *pc, struct packet *m)
{
	icmp6hdr *icmp;
	ip6hdr *ip = NULL, *ip0 = NULL;
	int i, n;

	ip = (ip6hdr *)(m->data + sizeof(ethdr));
	if ((ip->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return;

	n = ip6ehdr(ip, m->len - sizeof(ethdr), IPPROTO_ICMPV6);
	if (n == 0)
		return;

	icmp = (icmp6hdr *)((char *)ip + n);
	if (icmp->type != ICMP6_PACKET_TOO_BIG)
		return;

	ip0 = (ip6hdr *)(m->data + sizeof(ethdr) + 
	    sizeof(ip6hdr) + sizeof(icmp6hdr));
	
	for (i = 0, n = -1; i < POOL_SIZE; i++) {
		if (IP6EQ(&ip0->dst, &pc->ip6mtu[i].ip)) {
			pc->ip6mtu[i].mtu = ntohl(icmp->icmp6_mtu);
			pc->ip6mtu[i].timeout = time_tick;
			return;
		}
		if ((n < 0) && 
		    (time_tick - pc->ip6mtu[i].timeout > POOL_TIMEOUT))
			n = i;
	}

	if (n >= 0) {
		pc->ip6mtu[n].mtu = ntohl(icmp->icmp6_mtu);
		pc->ip6mtu[n].timeout = time_tick;
		memcpy(pc->ip6mtu[n].ip.addr8, ip0->dst.addr8, 16);
	}
}

int findmtu6(pcs *pc, ip6 *src)
{
	int i;
	
	for (i = 0; i < POOL_SIZE; i++) {
		if (time_tick - pc->ip6mtu[i].timeout > POOL_TIMEOUT)
			continue;
		if (IP6EQ(src, &pc->ip6mtu[i].ip))
			return pc->ip6mtu[i].mtu;
	}
	return pc->mtu;
}

/* end of file */

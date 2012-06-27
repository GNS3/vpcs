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

static struct packet *icmp6Reply(struct packet *m);
static struct packet *udp6Reply(struct packet *m0);

static struct packet* nb_sol(pcs *pc, ip6 *dst);
static int nb_adv(pcs *pc, struct packet *m, ip6 *dst);

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
int upv6(pcs *pc, struct packet *m)
{
	ethdr *eh;
	ip6hdr *ip;
	icmp6hdr *icmp;
	ip6 *tip6 = NULL;

	eh = (ethdr *)(m->data);
	
	if (etherIsMulticast(eh->src)) 
		return PKT_DROP;
		
	if (eh->type != htons(ETHERTYPE_IPV6)) 
		return PKT_DROP;
	
	ip = (ip6hdr *)(eh + 1);
	if ((ip->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) 
		return PKT_DROP;
		
	if (ip->ip6_nxt == IPPROTO_ICMPV6) {
		icmp = (icmp6hdr *)(ip + 1);
		
		/* neighbor solicitation */
		if (icmp->type == ND_NEIGHBOR_SOLICIT) {
			ndhdr *nshdr;
			ndopt *nsopt;
			
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
		
		if (icmp->type == ICMP6_ECHO_REQUEST) {
			swap_ip6head(m);
		
			icmp = (icmp6hdr *)(ip + 1);
			icmp->type = ICMP6_ECHO_REPLY;
			icmp->cksum = cksum_fixup(icmp->cksum, 
			    ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY, 0);
			swap_ehead(m->data);
			enq(&pc->oq, m);
			
			return PKT_ENQ;	
		}

		if (icmp->type == ND_ROUTER_ADVERT) {
			char *p = NULL, *mac = NULL;
			ndrahdr *ndr = (ndrahdr *)(ip + 1);
			
			/*  icmp6_data8[0]
			 *  |7654 3210|
			 *   |||
			 *   ||Override flag, update link address if 1
			 *   |Solicited flag, response to NS if 1
			 *   Router flag if 1
			 */
			 
			if (ip->src.addr8[0] != 0xfe ||
			    ip->src.addr8[1] != 0x80 ||
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
			
			p = (char *)(ndr + 1);
			
			/* link-layer address */
			if (*p == 1 && *(p + 1) == 1) {
				mac = p + 2;
				p += 8;
			}
			/* mtu, skip it*/
			if (*p == 5 && *(p + 1) == 1) {
				p += 8;
			}
			/* prefix */
			if (*p == 3 && *(p + 1) == 4) {
				int cidr;
				cidr = 	*(p + 2);
				if (pc->ip6.cidr == 0) {
					memcpy(pc->ip6.ip.addr8, p + 16, 16);
					pc->ip6.cidr = cidr;
					
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
				} 
				if (sameNet6((char *)pc->ip6.ip.addr8, p + 16, pc->ip6.cidr)) {
					memcpy(pc->ip6.gmac, mac, 6);						
				}
			}
			return PKT_DROP;
		}
		/* neighbor advertisement */
		if (icmp->type == ND_NEIGHBOR_ADVERT) {
			return PKT_UP;		
		}
		if (icmp->type == ICMP6_ECHO_REPLY) {
			return PKT_UP;
		}
		if (icmp->type == ICMP6_TIME_EXCEEDED || icmp->type == ICMP6_DST_UNREACH) {
			return PKT_UP;
		}
	}
	
	if (ip->ip6_nxt == IPPROTO_UDP) {
		udphdr *ui;
		ui = (udphdr *)(ip + 1);
		
		if (IN6_IS_MULTICAST(&(ip->dst)))
			return PKT_DROP;
			
		/* udp echo reply */	
		char *data = ((char*)(ui + 1));
		if (memcmp(data, eh->dst, 6) == 0)
			return PKT_UP;
		else {
			struct packet *p;
			if (ip->ip6_hlim == 1)
				p = icmp6Reply(m);
			else
				p = udp6Reply(m);
			if (p != NULL)
				enq(&pc->oq, p);
		}

		/* anyway tell caller to drop this packet */
		return PKT_DROP;	
	} else if (ip->ip6_nxt == IPPROTO_TCP) {
		return tcp6(pc, m);
	} else {
		//printf("get %x\n", ip->ip6_nxt);
		return PKT_DROP;
	}

	return PKT_UP;
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
		    icmp->type == ICMP6_DST_UNREACH_NOPORT) {
			
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
		if (sesscb->flags == TH_SYN && sesscb->rflags == (TH_SYN | TH_ACK) && 
			sesscb->rdsize > 0) {
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

struct packet *packet6(sesscb *sesscb)
{
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
			    sizeof(icmp6hdr) + i] = i;
    	
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
	return m;
	
}

/*-----------------------------------------------------------------------
 *
 * internal functions
 *
 *-----------------------------------------------------------------------*/

struct packet *icmp6Reply(struct packet *m0)
{
	ethdr *eh, *eh0;
	ip6hdr *ip, *ip0;
	icmp6hdr *icmp;
	struct packet *m;	
	int hlen;
	int plen;
	
	plen = m0->len - sizeof(ethdr);
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
	ip->ip6_plen = htons((u_short)hlen);
	
	memcpy(ip->src.addr8, ip0->dst.addr8, 16);
	memcpy(ip->dst.addr8, ip0->src.addr8, 16);
	
	icmp = (icmp6hdr *)(ip + 1);
	icmp->type = ICMP6_DST_UNREACH;
	icmp->code = ICMP6_DST_UNREACH_NOPORT;
	icmp->icmp6_id = time(0) & 0xffff;
	icmp->icmp6_seq = htons(1);

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
		for (i = 0; i < NB_SIZE; i++) {
			if (sameNet6((char *)pc->ipmac6[i].ip.addr8, 
			    (char *)dst->addr8, 128))
				return (pc->ipmac6[i].mac);
		}
	}
	
	/* find neighbor */
	i = 0;
	j = -1;
	while ((i++ < 3) &&  (j == -1)){
		struct packet *p;
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
			while ((p = deq(&pc->iq)) != NULL && (j == -1)) {
				j = nb_adv(pc, p, dst);
				free(p);
			}
		}			
	}
	if (i > 3)
		return NULL;
	return (pc->ipmac6[j].mac);
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

/*
 * resolve neighbor advertisement
 *
 * if valid, put ip/mac into ip pool, return the record position in the pool
 * else return -1
 */
int nb_adv(pcs *pc, struct packet *m, ip6 *dst)
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
	    !IP6EQ(&(pc->link6.ip), &(ip->dst))) || !IP6EQ(dst, &ip->src))
		return -1;

	nshdr = (ndhdr *)(ip + 1);
	nsopt = (ndopt *)(nshdr + 1);
	
	if (nshdr->hdr.type != ND_NEIGHBOR_ADVERT)
		return -1;

	/* shoule check sum field
	 * ...
	 */
	if (!IP6EQ(dst, &nshdr->target))
		return -1;

	/* not Target Link-Layer Address */
	if (nsopt->type != 2)
		return -1;

	i = 0;
	while (i < NB_SIZE) {
		if (memcmp(pc->ipmac6[i].ip.addr8, ip->src.addr8, 16) == 0 &&
		    (time_tick - pc->ipmac6[i].timeout <= 120))
			break;
			
		if (pc->ipmac6[i].timeout == 0 || 
		    (time_tick - pc->ipmac6[i].timeout > 120)) {
			memcpy(pc->ipmac6[i].mac, nsopt->mac, ETH_ALEN);
			memcpy(pc->ipmac6[i].ip.addr8, ip->src.addr8, 16);
			pc->ipmac6[i].timeout = time_tick;
			pc->ipmac6[i].cidr = 128;
			break;
		}
		i++;
	}

	if (i == NB_SIZE) {
		i = 0;
		memcpy(pc->ipmac6[i].mac, nsopt->mac, ETH_ALEN);
		memcpy(pc->ipmac6[i].ip.addr8, ip->src.addr8, 16);
		pc->ipmac6[i].timeout = time_tick;
	}

	return i;
}

/* end of file */

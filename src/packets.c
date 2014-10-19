/*
 * Copyright (c) 2007-2014, Paul Meng (mirnshi@gmail.com)
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
#include <ctype.h> /* isprint */
#include <unistd.h> /* usleep */
#include <string.h>
#include <sys/time.h>

#include "packets.h"
#include "vpcs.h"
#include "utils.h"

#define IPFRG_MAXHASH  (1 << 10)
#define IPFRG_HASHMASK (IPFRG_MAXHASH - 1)
#define IPFRG_HASH(x,y) \
        (((((x) & 0xF) | ((((x) >> 8) & 0xF) << 4)) ^ (y)) & IPFRG_HASHMASK)
        
static struct packet *arp(pcs *pc, u_int dip);
static struct packet *udpReply(struct packet *m0);
static struct packet *icmpReply(struct packet *m0, char icmptype);
static void save_eaddr(pcs *pc, u_int addr, u_char *mac);
extern int upv6(pcs *pc, struct packet *m);
extern int tcp(pcs *pc, struct packet *m);

static void free_ipfrag(struct ipfrag_head *head, struct ipfrag *fp);
static void free_packet(struct packet *m);
static struct ipfrag *new_ipfrag(struct packet *m, iphdr *ip);
static struct packet *defrag_pkt(struct packet **);

extern u_int time_tick;
static struct ipfrag_head ipfrag_hash[IPFRG_MAXHASH];

/*
 * ipv4 stack
 *
 * code: PKT_UP, send to up layer
 *       PKT_ENQ, in out queue
 *       PKT_DROP, drop the packet
 */
int upv4(pcs *pc, struct packet **m0)
{
	struct packet *m = *m0;
	struct packet *p = NULL;
	ethdr *eh = (ethdr *)(m->data);
	u_int *si, *di;
	
	if (eh->type == htons(ETHERTYPE_IPV6))
		return upv6(pc, m);
		
	/* not ipv4 or arp */
	if ((eh->type != htons(ETHERTYPE_IP)) && 
	    (eh->type != htons(ETHERTYPE_ARP))) 
		return PKT_DROP;
		
	if (etherIsMulticast(eh->src)) 
		return PKT_DROP;

	if (memcmp(eh->dst, pc->ip4.mac, ETH_ALEN) == 0 &&
	    ((u_short*)m->data)[6] == htons(ETHERTYPE_IP)) {
		iphdr *ip = (iphdr *)(eh + 1);
		
		if (ip->frag & (IP_MF | IP_OFFMASK)) {
			m = ipreass(m);
			if (m == NULL)
				return PKT_ENQ;
			else
				*m0 = m;
			ip = (iphdr *)(m->data + sizeof(ethdr));
		}
		
		/* ping me, reply */
		if (ip->proto == IPPROTO_ICMP) {
			icmphdr *icmp = (icmphdr *)(ip + 1);
			
			if (ip->dip != pc->ip4.ip)
				return PKT_DROP;
			
			/* other type will be sent to application */
			if (icmp->type != ICMP_ECHO)
				return PKT_UP;

			p = icmpReply(m, ICMP_ECHOREPLY);
			if (p != NULL) {
				fix_dmac(pc, p);
				if (pc->ip4.flags & IPF_FRAG) {
					p = ipfrag(p, pc->ip4.mtu);
				}
				enq(&pc->oq, p);
			}
			return PKT_ENQ;
		} else if (ip->proto == IPPROTO_UDP) {
			udpiphdr *ui;
			char *data = NULL;
			ui = (udpiphdr *)ip;
			
			if (IN_MULTICAST(ip->dip))
				return PKT_DROP;
			
			/* dhcp packet */
			if (ui->ui_sport == htons(67) && ui->ui_dport == htons(68)) 
				return PKT_UP;
			
			if (ip->dip != pc->ip4.ip)
				return PKT_DROP;
				
			/* dns response */
			if (ui->ui_sport == htons(53))
				return PKT_UP;
						
			data = ((char*)(ui + 1));
			
			/* udp echo reply */	
			if (memcmp(data, eh->dst, ETH_ALEN) == 0)
				return PKT_UP;
			else {
				struct packet *p;
				if (ip->ttl == 1)
					p = icmpReply(m, ICMP_UNREACH);
				else
					p = udpReply(m);
				
				if (p != NULL) {
					fix_dmac(pc, p);
					if (pc->ip4.flags & IPF_FRAG) {
						p = ipfrag(p, pc->ip4.mtu);
					}
					enq(&pc->oq, p);
				}
			}			
			/* anyway tell caller to drop this packet */
			return PKT_DROP;
		} else if (ip->proto == IPPROTO_TCP) {
			if (ip->dip != pc->ip4.ip)
				return PKT_DROP;
			return tcp(pc, m);	
		}	

	} else if (eh->type == htons(ETHERTYPE_ARP)) {
		arphdr *ah = (arphdr *)(eh + 1);
		si = (u_int *)ah->sip;
		di = (u_int *)ah->dip;
			
		/* arp reply */
		if (ah->op == htons(ARPOP_REQUEST) && 
		    di[0] == pc->ip4.ip) {
			save_eaddr(pc, si[0], ah->sea);
				
			ah->op = htons(ARPOP_REPLY);
			memcpy(ah->dea, ah->sea, ETH_ALEN);
			memcpy(ah->sea, pc->ip4.mac, ETH_ALEN);
					
			di[0] = si[0];
			si[0] = pc->ip4.ip;
					
			encap_ehead(m->data, pc->ip4.mac, eh->src, 
			    ETHERTYPE_ARP);
	
			enq(&pc->oq, m);
				
			return PKT_ENQ;
		} else if (ah->op == htons(ARPOP_REPLY) && 	
		    sameNet(di[0], pc->ip4.ip, pc->ip4.cidr)) {
		    	save_eaddr(pc, si[0], ah->sea);
		}
		
		return PKT_DROP;
	} else if (strncmp((const char *)eh->dst, (const char *)pc->ip4.mac, 
	    ETH_ALEN) != 0)
		return PKT_DROP;
	
	return PKT_UP;
}

int response(struct packet *m, sesscb *sesscb)
{
	ethdr *eh;
	iphdr *ip;

	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	
	/* tracerouter response */
	if (ip->proto == IPPROTO_ICMP) {
		icmphdr *icmp = (icmphdr *)(ip + 1);
		/* redirect for network */
		if (icmp->type == ICMP_REDIRECT) {
			if (icmp->code == ICMP_REDIRECT_NET) {
				icmprdr *rdr = (icmprdr *)icmp;
				
				sesscb->icmptype = icmp->type;
				sesscb->icmpcode = icmp->code;
				/* should check sum */
				sesscb->rdip = rdr->ip;	
				/* should check data */
				return IPPROTO_ICMP;
			}
		}
		if (icmp->type == ICMP_UNREACH || icmp->type == ICMP_TIMXCEED) {
			sesscb->icmptype = icmp->type;
			sesscb->icmpcode = icmp->code;
			sesscb->rttl = ip->ttl;
			sesscb->rdip = ip->sip;
			
			return IPPROTO_ICMP;
		}
	}
	
	if (ip->sip != sesscb->dip)
		return 0;
	
	if (ip->proto == IPPROTO_ICMP && sesscb->proto == IPPROTO_ICMP) {
		icmphdr *icmp = (icmphdr *)(ip + 1);
		sesscb->icmptype = icmp->type;
		sesscb->icmpcode = icmp->code;
		sesscb->rttl = ip->ttl;
		sesscb->rdip = ip->sip;
		sesscb->rdsize = ntohs(ip->len)  - (ip->ihl << 2);
		if (ntohs(icmp->seq) == sesscb->sn) {
			return IPPROTO_ICMP;
		}
		return 0;
	}
			
	if (ip->proto == IPPROTO_UDP && sesscb->proto == IPPROTO_UDP) {
		udpiphdr *ui = (udpiphdr *)ip;	
		char *data = ((char*)(ui + 1));
		if (memcmp(data, eh->dst, 6) == 0) {
			sesscb->rdsize = ntohs(ip->len)  - (ip->ihl << 2);
			sesscb->rttl = ip->ttl;
			return IPPROTO_UDP;
		}
		
		return 0;
	}
	
	if (ip->proto == IPPROTO_TCP && sesscb->proto == IPPROTO_TCP) {
		tcpiphdr *ti = (tcpiphdr *)ip;		
		char *data = ((char*)(ti + 1));
		
		sesscb->rseq = ntohl(ti->ti_seq);
		sesscb->rack = ntohl(ti->ti_ack);
		sesscb->rflags = ti->ti_flags;
		sesscb->rttl = ip->ttl;
		sesscb->data = NULL;
		sesscb->rdsize = ntohs(ip->len) - (ip->ihl << 2) - 
		    (ti->ti_off << 2);
		
		
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
			sesscb->data = ((char*)(ip + 1)) + (ti->ti_off << 2);
		}
		return IPPROTO_TCP;
	}
	return 0;
}

int arpResolve(pcs *pc, u_int ip, u_char *dmac)
{
	int i, c;
	struct packet *m;
	int waittime = 1000;
	struct timeval tv;
		
	c = 0;

	for (i = 0; i < ARP_SIZE; i++) {
		if (pc->ipmac4[i].ip == ip && 
		    (time_tick - pc->ipmac4[i].timeout) <= 120 &&
		    !etherIsZero(pc->ipmac4[i].mac)) {
			memcpy(dmac, pc->ipmac4[i].mac, ETH_ALEN);
			return 1;
		}
	}

	while (c++ < 3){
		m = arp(pc, ip);
		if (m == NULL) {
			printf("out of memory\n");
			return 0;
		}
		enq(&pc->oq, m);
		gettimeofday(&(tv), (void*)0);
		while (!timeout(tv, waittime)) {
			delay_ms(1);
			for (i = 0; i < ARP_SIZE; i++) {
				if (pc->ipmac4[i].ip == ip && 
				    (time_tick - pc->ipmac4[i].timeout) <= 120 &&
				    !etherIsZero(pc->ipmac4[i].mac)) {
					memcpy(dmac, pc->ipmac4[i].mac, ETH_ALEN);
					return 1;
				}
			}	
		}
	}
	return 0;
}

struct packet *packet(sesscb *sesscb)
{
	ethdr *eh;
	iphdr *ip;
	int i;
	struct packet *m;
	int dlen = 0; /* the size of payload */
	int hdr_len = 0;
	char b[9];
	
	dlen = sesscb->dsize;

	switch (sesscb->proto) {
		case IPPROTO_ICMP:
			hdr_len = sizeof(iphdr) + sizeof(icmphdr);
			break;
		case IPPROTO_UDP:
			hdr_len = sizeof(iphdr) + sizeof(udphdr);
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
			
			hdr_len = sizeof(iphdr) + sizeof(tcphdr);
			break;
	}
		
	m = new_pkt(sizeof(ethdr) + hdr_len + dlen);
	
	if (m == NULL)
		return NULL;

	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	
	ip->ver = 4;
	ip->ihl = sizeof *ip >> 2;
	ip->len = htons(hdr_len + dlen);
	ip->id = htons(sesscb->ipid++);
	if (!sesscb->frag)
		ip->frag = htons(IP_DF);
	ip->ttl = sesscb->ttl;
	ip->proto = sesscb->proto;
	ip->sip = sesscb->sip;
	ip->dip = sesscb->dip;
	
	if (sesscb->proto == IPPROTO_ICMP) {
		icmphdr *icmp = (icmphdr *)(ip + 1);
		char *data = ((char*)(icmp + 1));
		
		icmp->seq = htons(sesscb->sn);
		icmp->cksum = 0;
		icmp->type = ICMP_ECHO;
		icmp->code = 0;
		icmp->id = time(0) & 0xffff;
		
		for (i = 0; i < dlen; i++)
			data[i] = (i + sizeof(icmphdr)) & 0xff;
		
		icmp->cksum = cksum((unsigned short *) (icmp), 
		    hdr_len + dlen - sizeof(iphdr));
	} else if (sesscb->proto == IPPROTO_UDP) {
		udpiphdr *ui = (udpiphdr *)ip;
		char *data = ((char*)(ui + 1));
		
		ui->ui_sport = htons(sesscb->sport);
		ui->ui_dport = htons(sesscb->dport);
		ui->ui_ulen = htons(hdr_len + dlen - sizeof(iphdr));
		ui->ui_sum = 0;
		
		/* this's my footprint */
		if (sesscb->data != NULL) {
			memcpy(data, sesscb->data, dlen);
		} else {
			memcpy(data, sesscb->smac, 6);	
			for (i = 6; i < dlen; i++)
				data[i] = (i + sizeof(udphdr)) & 0xff;
		}
				
		bcopy(((struct ipovly *)ip)->ih_x1, b, 9);
		bzero(((struct ipovly *)ip)->ih_x1, 9);
		
		ui->ui_len = ui->ui_ulen;
		ui->ui_sum = cksum((u_short*)ui, hdr_len + dlen);
		
		bcopy(b, ((struct ipovly *)ip)->ih_x1, 9);
		
	} else if (sesscb->proto == IPPROTO_TCP) {
		tcpiphdr *ti = (tcpiphdr *)ip;
		char *data = ((char*)(ti + 1));
		u_int t = htonl(time(0));
		int optlen = 0;
		
		ti->ti_sport = htons(sesscb->sport);
		ti->ti_dport = htons(sesscb->dport);
		ti->ti_len = htons(hdr_len + dlen - sizeof(iphdr));
		ti->ti_ack = htonl(sesscb->ack);
		ti->ti_seq = htonl(sesscb->seq);
		ti->ti_win = htons(sesscb->winsize);
		ti->ti_sum = 0;
		ti->ti_flags = sesscb->flags;
		
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
		
		optlen = data - (char*)(ti + 1);
		ti->ti_off = (sizeof(tcphdr) + optlen) >> 2;
		
		/*  
	 	 * TELNET protcol 
	 	 *               IAC: 0xff
	 	 *      option code
	 	 *              WILL: 0xfb
	 	 *             WON't: 0xfc
	 	 *                DO: 0xfd
	 	 *             DON'T: 0xfe
	 	 * command
	 	 *              ECHO: 0x01
	 	 * SUPPRESS-GO-AHEAD: 0x03
	 	 *     TERMINAL-TYPE: 0x18
	 	 *              NAWS: 0x1f
	 	 */

		/* fill the data */
		for (i = optlen; i < dlen; i++) {
			if ((i % 2) == 0)
				*data++ = 0xd;
			else
				*data++ = 0xa;
		}
		
		bcopy(((struct ipovly *)ip)->ih_x1, b, 9);
		bzero(((struct ipovly *)ip)->ih_x1, 9);
		
		ti->ti_sum = cksum((u_short*)ti, hdr_len + dlen);
		bcopy(b, ((struct ipovly *)ip)->ih_x1, 9);
	}
	
	encap_ehead(m->data, sesscb->smac, sesscb->dmac, ETHERTYPE_IP);
	
	/* maybe fragmentation failed, let's do cksum first */
	ip->cksum = 0;
	ip->cksum = cksum((u_short *)ip, sizeof(iphdr));
		
	if (sesscb->frag)
		ipfrag(m, sesscb->mtu);
	
	return m;
}

struct packet *arp(pcs *pc, u_int dip)
{
	ethdr *eh;
	arphdr *ah;
	struct packet *m;
	u_int *si, *di;
	u_char broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	
	m = new_pkt(ARP_PSIZE);
	if (m == NULL)
		return NULL;

	eh = (ethdr *)(m->data);
	ah = (arphdr *)(eh + 1);

	ah->hrd = htons(ARPHRD_ETHER);
	ah->pro = htons(ETHERTYPE_IP);
	ah->hln = 6;
	ah->pln = 4;
	ah->op = htons(ARPOP_REQUEST);
	
	si = (u_int *)ah->sip;
	di = (u_int *)ah->dip;
	si[0] = pc->ip4.ip;
	di[0] = dip;

	memcpy(ah->dea, broadcast, ETH_ALEN);
	memcpy(ah->sea, pc->ip4.mac, ETH_ALEN);
	
	encap_ehead(m->data, pc->ip4.mac, broadcast, ETHERTYPE_ARP);
	
	return m;
}

struct packet *udpReply(struct packet *m0)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	struct packet *m;
	
	m = new_pkt(m0->len);
	if (m == NULL)
		return NULL;
	
	copy_pkt(m, m0);
	
	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	ui = (udpiphdr *)ip;
		
	ip->dip ^= ip->sip;
	ip->sip ^= ip->dip;
	ip->dip ^= ip->sip;
	
	ui->ui_sport ^= ui->ui_dport;
	ui->ui_dport ^= ui->ui_sport;
	ui->ui_sport ^= ui->ui_dport;
	
	ip->cksum = cksum_fixup(ip->cksum, ip->ttl, TTL, 0);
	ip->ttl = TTL;
	
	swap_ehead(m->data);
	return m;	
}

struct packet *icmpReply(struct packet *m0, char icmptype)
{
	struct packet *m = NULL;
	ethdr *eh = NULL;
	iphdr *ip = NULL;
	icmphdr *icmp = NULL;
	
	if (icmptype == ICMP_ECHOREPLY) {
		m = m0;

		eh = (ethdr *)(m->data);
		ip = (iphdr *)(eh + 1);
		icmp = (icmphdr *)(ip + 1);
			
		u_short old_sum;
		u_char old_ttl;
		
		old_ttl = ip->ttl;
		old_sum = icmp->cksum;
		
		icmp->type = ICMP_ECHOREPLY;
		icmp->cksum = cksum_fixup(icmp->cksum, ICMP_ECHO, ICMP_ECHOREPLY, 0);

		ip->dip ^= ip->sip;
		ip->sip ^= ip->dip;
		ip->dip ^= ip->sip;

		ip->ttl = TTL;
		
		ip->cksum = cksum_fixup(cksum_fixup(cksum_fixup(ip->cksum, 
		    old_ttl, ip->ttl, 0), ICMP_ECHO, ICMP_ECHOREPLY, 0),
		    old_sum, icmp->cksum, 0);
	
		swap_ehead(m->data);
		
		return m;	
	} 
	
	if (icmptype == ICMP_UNREACH) {
		int len, len0;
    	
		eh = (ethdr *)(m0->data);
		ip = (iphdr *)(eh + 1);
		
		len0 = ntohs(ip->len);
		if (len0 > 44)
			len0 = 44;

		len = sizeof(ethdr) + sizeof(iphdr) + sizeof(icmphdr) + len0;

		m = new_pkt(len);
		if (m == NULL)
			return NULL;
		
		/* get original etherhdr and iphdr */
		memcpy(m->data, m0->data, sizeof(ethdr) + sizeof(iphdr));
    	
		eh = (ethdr *)(m->data);
		ip = (iphdr *)(eh + 1);
		icmp = (icmphdr *)(ip + 1);
    	
	    	/* copy the origial part */
		memcpy((char*)(icmp + 1), (char *)(m0->data + sizeof(ethdr)), len0);

		ip->len = htons(len - sizeof(ethdr));
		ip->id = time(0) & 0xffff;
		ip->frag = htons(0x4000);
		ip->ttl = TTL;
		ip->proto = IPPROTO_ICMP;
		ip->cksum = 0;
		ip->dip ^= ip->sip;
		ip->sip ^= ip->dip;
		ip->dip ^= ip->sip;
		
		icmp->seq = htons(1);
		icmp->cksum = 0;
		icmp->type = ICMP_UNREACH;
		icmp->code = ICMP_UNREACH_PORT;
		icmp->id = time(0) & 0xffff;
			
		icmp->cksum = cksum((unsigned short *) (icmp), sizeof(icmphdr) + len0);
		
		ip->cksum = cksum((u_short *)ip, sizeof(iphdr));
		
		swap_ehead(m->data);
    	
		return m;
	}
	
	return NULL;
}

static void 
save_eaddr(pcs *pc, u_int addr, u_char *mac)
{
	int i;
	
	if (!sameNet(addr, pc->ip4.ip, pc->ip4.cidr))
		return;
	
	i = 0;
	while (i < ARP_SIZE) {
		if (time_tick - pc->ipmac4[i].timeout <= 120 &&
			pc->ipmac4[i].ip == addr) {
			pc->ipmac4[i].timeout = time_tick;
			break;
		}
		if (pc->ipmac4[i].timeout == 0 || 
		    time_tick - pc->ipmac4[i].timeout > 120) {
			pc->ipmac4[i].ip = addr;
			memcpy(pc->ipmac4[i].mac, mac, ETH_ALEN);
			pc->ipmac4[i].timeout = time_tick;
			break;
		}
		i++;
	}
}

void
fix_dmac(pcs *pc, struct packet *m)
{
	ethdr *eh = NULL;
	iphdr *ip = NULL;
	u_char mac[6];
	
	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	
	if (sameNet(ip->dip, pc->ip4.ip, pc->ip4.cidr))
		return;
		
	if (arpResolve(pc, pc->ip4.gw, mac))
		memcpy(eh->dst, mac, sizeof(mac));
}

struct packet *
ipfrag(struct packet *m0, int mtu)
{
	struct packet *m = NULL, *mh = NULL;
	iphdr *ip = NULL, *ip0 = NULL;
	int hlen, len, off, elen, flen, last;
	int nfrags;
	
	elen = sizeof(ethdr) + sizeof(iphdr);
	
	ip0 = (iphdr *)(m0->data + sizeof(ethdr));
	if (ntohs(ip0->len) <= mtu)
		return m0;
		
	hlen = ip0->ihl << 2;
	len = (mtu - hlen) & ~7; /* payload in fragment */
	ip0->len = ntohs(ip0->len);

	/* too small, let it alone */
	if (len < 8)
		return m0;
	
	flen = len;
	off = hlen + len;
	
	mh = m0;
	last = 0;
	for (nfrags = 1; off < ip0->len; off += len, nfrags++) {
		if (off + len >= ip0->len) {
			last = 1;
			m = new_pkt(elen + ip0->len - off);
		} else
			m = new_pkt(elen + len);

		if (m == NULL) 
			goto ipfrag_err;

		/* ether and ip head */
		memcpy(m->data, m0->data, elen);
		memcpy(m->data + elen, m0->data + sizeof(ethdr) + off, len);
		ip = (iphdr *)(m->data + sizeof(ethdr));
		ip->frag = ((off -hlen) >> 3);
	
		if (!last) {
			ip->frag |= IP_MF;
			ip->len = htons(len + sizeof(iphdr));
		} else
			ip->len = htons(sizeof(iphdr) + ip0->len - off);		
		ip->frag = htons(ip->frag);
		ip->cksum = 0;
		ip->cksum = cksum((u_short *)ip, sizeof(iphdr));
		m->next = NULL;
		mh->next = m;
		mh = m;
	}
	m0->len = elen + flen;
	ip0->len = htons(len + sizeof(iphdr));
	ip0->frag = htons(IP_MF);
	ip0->cksum = 0;
	ip0->cksum = cksum((u_short *)ip0, sizeof(iphdr));

	return m0;
	
ipfrag_err:
	for (m = mh->next; m; m = mh) {
		mh = m->next;
		del_pkt(m);
	}
	
	return m0;
}

/* 
 * return NULL, the packet is a piece, expired, or invalid.
 * return packet, all of pieces have been arrived and reassembled.
 */
struct packet *
ipreass(struct packet *m)
{
	ethdr *eh = (ethdr *)(m->data);
	iphdr *ip = (iphdr *)(eh + 1);
	iphdr *ip0;
	struct ipfrag *fp = NULL;
	struct ipfrag_head *qh;
	struct packet *m0 = NULL, *m2 = NULL;
	u_short hash, off, off0;
	int next;

	
	hash = IPFRG_HASH(ip->sip, ip->id);
	qh = &ipfrag_hash[hash];
	
	pthread_mutex_lock(&(qh->locker));
	
	ip->frag = ntohs(ip->frag);
	for (fp = qh->head; fp; fp = fp->next) {
		if (time_tick - fp->expired > 30) {
			free_packet(fp->m);
			free_ipfrag(qh, fp);
			continue;
		}
		
		if (ip->id != fp->id || 
		    ip->sip != fp->sip ||
		    ip->dip != fp->dip ||
		    ip->proto != fp->proto)
			continue;
		
		/* a fragment is existed */
	    	if ((ip->frag & IP_MF) == IP_MF)
			fp->flags |= FF_HEAD;
		else if ((ip->frag & (~IP_OFFMASK)) == 0)
			fp->flags |= FF_TAIL;

		off = ip->frag << 3;
		if (off == 0 && (ip->frag & IP_MF)) {
			if (!ip->len || (ip->len & 0x7) != 0) {
				del_pkt(m);
				free_packet(fp->m);
			 	free_ipfrag(qh, fp);
				goto ret_null;
			}
			m->next = fp->m;
			fp->m = m;
		} else {
			/* Find a segment, insertion sort on singly linked list
			 */
			m2 = NULL;
			for (m0 = fp->m; m0; m2 = m0, m0 = m0->next) {
				ip0 = (iphdr *)(m0->data + sizeof(ethdr));
				off0 = ip0->frag << 3;
				if (off0 > off)
					break;	
			}
			if (m2) {
				m->next = m2->next;
				m2->next = m;
			} else {
				m->next = fp->m;
				fp->m = m;
			}
		}	
		fp->nfrags++;
		/* too many fragments */
		if (fp->nfrags > 16) {
			free_packet(fp->m);
		 	free_ipfrag(qh, fp);
			goto ret_null;
		}
		/* the head and tail are arrived, scan the chain 
		 * Note: overlap is invalid here.
		 */
		if (fp->flags == (FF_TAIL | FF_HEAD)) {		
			for (next = 0, m0 = fp->m; m0; m0 = m0->next) {
				ip0 = (iphdr *)(m0->data + sizeof(ethdr));
				off0 = ip0->frag << 3;			
				if (next < off0)
					goto ret_null;			
				/* the last fragment */
				if ((ip0->len & 0x7) != 0) {					
					m = fp->m;
					free_ipfrag(qh, fp);
					/* copy to single packet buffer
					 * free the old buffer
					 */	
					m = defrag_pkt(&m);
					goto ret;
				}
				next += ip0->len;
			}
		}
		goto ret_null;
	}
	/* new fragment */
	fp = new_ipfrag(m, ip);	
	if (qh->head == NULL) {
		qh->head = fp;
		qh->tail = fp;
	} else {
		fp->prev = qh->tail;
		qh->tail->next = fp;
		qh->tail = fp;
	}
	
ret_null:
	pthread_mutex_unlock(&(qh->locker));	
	return NULL;

ret:		
	pthread_mutex_unlock(&(qh->locker));
	return m;	
}

static struct packet *defrag_pkt(struct packet **m0)
{
	struct packet *m, *mh, *m2;
	iphdr *ip;
	int len;
	int elen;
	int off;
	
	mh = *m0;	
	len = 0;
	while (mh) {
		ip = (iphdr *)(mh->data + sizeof(ethdr));
				
		len += ntohs(ip->len) - sizeof(iphdr);
		mh = mh->next;
	}		
	m = new_pkt(len + sizeof(iphdr) + sizeof(ethdr));
	if (m == NULL)
		return mh;

	mh = *m0;
	memcpy(m->data, mh->data, mh->len);
	ip = (iphdr *)(m->data + sizeof(ethdr));
	ip->len = ntohs(len + sizeof(iphdr));
	off = mh->len;
	elen = sizeof(ethdr) + sizeof(iphdr);
	m2 = mh;
	mh = mh->next;
	del_pkt(m2);
	while (mh) {
		len = mh->len - elen;
		memcpy(m->data + off, mh->data + elen, len);
		off += len;
		m2 = mh;
		mh = mh->next;
		del_pkt(m2);
	}
	ip->frag = 0;
	ip->cksum = 0;
	ip->cksum = cksum((u_short *)ip, sizeof(iphdr));
	
	return m;
}

static void
free_packet(struct packet *m)
{
	struct packet *m0;
	
	while (m) {
		m0 = m->next;
		del_pkt(m);
		m = m0;
	}
}

static void
free_ipfrag(struct ipfrag_head *qh, struct ipfrag *fp)
{
	if (fp == qh->head)
		qh->head = fp->next;
	else
		fp->prev->next = fp->next;
	free(fp);
}

static struct ipfrag *
new_ipfrag(struct packet *m, iphdr *ip)
{
	struct ipfrag *fp;
	
	fp = (struct ipfrag *)malloc(sizeof(struct ipfrag));
	if (!fp)
		return NULL;

	memset(fp, 0, sizeof(struct ipfrag));
	
	fp->expired = time_tick;
	fp->nfrags = 1;
	fp->proto = ip->proto;
	fp->id = ip->id;
	fp->sip = ip->sip;
	fp->dip = ip->dip;
	fp->m = m;
	m->next = NULL;
	if ((ip->frag & IP_MF) == IP_MF)
		fp->flags = FF_HEAD;
	else if ((ip->frag & (~IP_OFFMASK)) == 0)
		fp->flags = FF_TAIL;
		
	return fp;
}

void init_ipfrag(void)
{
	int i;
	
	memset(ipfrag_hash, 0, sizeof(struct ipfrag_head) * IPFRG_MAXHASH);
	for (i = 0; i < IPFRG_MAXHASH; i++)
		pthread_mutex_init(&(ipfrag_hash[i].locker), NULL);
	
}

#if 0
static void xxpreh(char *e, int c)
{
	int i;
	
	for (i = 0; i < c; i++) {
		printf("%2.2x ", *(e + i));
		if (i % 16 == 0) printf("\n");
	}
	return;
}
#endif

/* end of file */

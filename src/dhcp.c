/*
 * Copyright (c) 2007-2011, Paul Meng (mirnshi@gmail.com)
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
#include <sys/socket.h>
#include <netinet/in.h>
#include "packets.h"
#include "vpcs.h"
#include "dhcp.h"

struct packet * dhcp4_discover(pcs *pc)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	dhcp4_hdr *dh;
	int i;
	
	struct packet *m;
	char b[9];
	u_char bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		
	m = new_pkt(DHCP4_PSIZE);
	if (m == NULL)
		return NULL;
	
	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	ui = (udpiphdr *)ip;
	dh = (dhcp4_hdr*)(ui + 1);
	
	dh->op = 1;
	dh->htype = 1;
	dh->hlen = 6;
	dh->hops = 0;
	dh->xid = pc->ip4.dhcp.xid;
	dh->secs = 0;
	dh->flags = 0;
	dh->ciaddr = 0;
	dh->yiaddr = 0;
	dh->siaddr = 0;
	dh->giaddr = 0;
	memcpy(dh->chaddr, pc->ip4.mac, 6);
	
	i = 0;
	((int*)(&dh->options[i]))[0] = htonl(0x63825363);
	i += sizeof(int);
	dh->options[i++] = DHO_DHCP_MESSAGE_TYPE;
	dh->options[i++] = 1;
	dh->options[i++] = DHCPDISCOVER;
	
	dh->options[i++] = DHO_HOST_NAME;
	dh->options[i++] = 5;
	dh->options[i++] = 'v';
	dh->options[i++] = 'p';
	dh->options[i++] = 'c';
	dh->options[i++] = 's';
	dh->options[i++] = pc->id + '1';
	
	dh->options[i++] = DHO_DHCP_CLIENT_IDENTIFIER;
	dh->options[i++] = 7;
	memcpy(&dh->options[i], pc->ip4.mac, 6);
	i += 6;
	dh->options[i] = DHO_END;
	
	ui->ui_sport = htons(68);
	ui->ui_dport = htons(67);
	ui->ui_ulen = htons(sizeof(dhcp4_hdr) + sizeof(udphdr));
	ui->ui_sum = 0;
	
	ip->ver = 4;
	ip->ihl = sizeof *ip >> 2;
	ip->tos = 0x10;
	ip->len = htons(sizeof(udpiphdr) + sizeof(dhcp4_hdr));
	ip->id = 0;
	ip->ttl = 16;
	ip->proto = IPPROTO_UDP;
	ip->cksum = 0;
	ip->sip = 0;
	ip->dip = 0xffffffff;

	bcopy(((struct ipovly *)ip)->ih_x1, b, 9);
	bzero(((struct ipovly *)ip)->ih_x1, 9);
	ui->ui_len = ui->ui_ulen;
	ui->ui_sum = cksum((u_short*)ui,  sizeof(udpiphdr) + sizeof(dhcp4_hdr));
	bcopy(b, ((struct ipovly *)ip)->ih_x1, 9);

	ip->cksum = 0;
	ip->cksum = cksum((u_short *)ip, sizeof(iphdr));
	
	encap_ehead(m->data, pc->ip4.mac, bcast, ETHERTYPE_IP);
	m->len = sizeof(ethdr) + sizeof(udpiphdr) + sizeof(dhcp4_hdr);
	
	return m;
}

struct packet * dhcp4_request(pcs *pc)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	dhcp4_hdr *dh;
	int i;
	struct packet *m;
	char b[9];
		
	m = new_pkt(DHCP4_PSIZE);
	if (m == NULL)
		return NULL;
	
	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	ui = (udpiphdr *)ip;
	dh = (dhcp4_hdr*)(ui + 1);
	
	dh->op = 1;
	dh->htype = 1;
	dh->hlen = 6;
	dh->hops = 0;
	dh->xid = pc->ip4.dhcp.xid;
	dh->secs = 0;
	dh->flags = 0;
	dh->ciaddr = pc->ip4.dhcp.ip;
	dh->yiaddr = 0;
	dh->siaddr = 0;
	dh->giaddr = 0;
	memcpy(dh->chaddr, pc->ip4.mac, 6);
	
	i = 0;
	((int*)(&dh->options[i]))[0] = htonl(0x63825363);
	i += sizeof(int);
	dh->options[i++] = DHO_DHCP_MESSAGE_TYPE;
	dh->options[i++] = 1;
	dh->options[i++] = DHCPREQUEST;
	
	dh->options[i++] = DHO_DHCP_PARAMETER_REQUEST_LIST;
	dh->options[i++] = 2;
	dh->options[i++] = DHO_SUBNET_MASK;
	dh->options[i++] = DHO_ROUTERS;
	
	dh->options[i++] = DHO_DHCP_SERVER_IDENTIFIER;
	dh->options[i++] = 4;
	((int*)(&dh->options[i]))[0] = pc->ip4.dhcp.svr;
	i += sizeof(int);
	
	dh->options[i++] = DHO_DHCP_REQUESTED_ADDRESS;
	dh->options[i++] = 4;
	((int*)(&dh->options[i]))[0] = pc->ip4.dhcp.ip;
	i += sizeof(int);
	
	dh->options[i++] = DHO_HOST_NAME;
	dh->options[i++] = 5;
	dh->options[i++] = 'v';
	dh->options[i++] = 'p';
	dh->options[i++] = 'c';
	dh->options[i++] = 's';
	dh->options[i++] = pc->id + '1';
	
	dh->options[i++] = DHO_DHCP_CLIENT_IDENTIFIER;
	dh->options[i++] = 7;
	memcpy(&dh->options[i], pc->ip4.mac, 6);
	i += 6;
	dh->options[i] = DHO_END;
		
	ui->ui_sport = htons(68);
	ui->ui_dport = htons(67);
	ui->ui_ulen = htons(sizeof(dhcp4_hdr) + sizeof(udphdr));
	ui->ui_sum = 0;
	
	ip->ver = 4;
	ip->ihl = sizeof *ip >> 2;
	ip->tos = 0x10;
	ip->len = htons(sizeof(udpiphdr) + sizeof(dhcp4_hdr));
	ip->id = 0;
	ip->ttl = 16;
	ip->proto = IPPROTO_UDP;
	ip->cksum = 0;
	ip->sip = 0;
	ip->dip = 0xffffffff;

	bcopy(((struct ipovly *)ip)->ih_x1, b, 9);
	bzero(((struct ipovly *)ip)->ih_x1, 9);
	ui->ui_len = ui->ui_ulen;
	ui->ui_sum = cksum((u_short*)ui,  sizeof(udpiphdr) + sizeof(dhcp4_hdr));
	bcopy(b, ((struct ipovly *)ip)->ih_x1, 9);

	ip->cksum = 0;
	ip->cksum = cksum((u_short *)ip, sizeof(iphdr));
	
	encap_ehead(m->data, pc->ip4.mac, pc->ip4.dhcp.smac, ETHERTYPE_IP);
	m->len = sizeof(ethdr) + sizeof(udpiphdr) + sizeof(dhcp4_hdr);

	return m;
}

int isDhcp4_Offer(pcs *pc, struct packet *m)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	dhcp4_hdr *dh;
	u_char *p;
	u_int magic;
	
	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	ui = (udpiphdr *)ip;
	dh = (dhcp4_hdr*)(ui + 1);
	
	if (dh->xid == pc->ip4.dhcp.xid && dh->op == 2) {
		pc->ip4.dhcp.svr = ip->sip;
		pc->ip4.dhcp.ip = dh->yiaddr;
		memcpy(pc->ip4.dhcp.smac, eh->src, 6);
		p = dh->options;
		magic = ((long*)(p))[0];
		if (magic == htonl(0x63825363)) {
			p += 4;
			while (*p != DHO_END && p - dh->options < DHCP_OPTION_LEN) {
				if (*p == DHO_SUBNET_MASK && *(p + 1) == 4) {
					pc->ip4.dhcp.netmask = ((int*)(p + 2))[0];
					p += 6;
					continue;
				} else if (*p == DHO_ROUTERS && *(p + 1) == 4) {
					pc->ip4.dhcp.gw = ((int*)(p + 2))[0];
					p += 6;
					continue;
				} else {
					p++;		/* skip op code */
					p += *(p) + 1;	/* add op offset(length) */
				}
			}
		}
		return 1;
	} else
		return 0;
}

int isDhcp4_packer(pcs *pc, struct packet *m)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	dhcp4_hdr *dh;
	u_char *p;
	u_int magic;
	
	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	ui = (udpiphdr *)ip;
	dh = (dhcp4_hdr*)(ui + 1);
	
	if (dh->xid == pc->ip4.dhcp.xid && dh->op == 2) {
		pc->ip4.ip = dh->yiaddr;
		p = dh->options;
		magic = ((long*)(p))[0];
		if (magic == htonl(0x63825363)) {
			p += 4;
			while (*p != DHO_END && p - dh->options < DHCP_OPTION_LEN) {
				if (*p == DHO_SUBNET_MASK && *(p + 1) == 4) {
					pc->ip4.cidr = getCIDR(ntohl(((int*)(p + 2))[0]));
					p += 6;
					continue;
				} else if (*p == DHO_ROUTERS && *(p + 1) == 4) {
					pc->ip4.gw = ((int*)(p + 2))[0];
					p += 6;
					continue;
				} else if (*p == DHO_DHCP_LEASE_TIME && *(p + 1) == 4) {
					pc->ip4.lease += ((int*)(p + 2))[0];
					p += 6;
					continue;
				} else {
					p++;		/* skip op code */
					p += *(p) + 1;	/* add op offset(length) */
				}
			}
				
		}
		return 1;
	} else
		return 0;
}
/* end of file */

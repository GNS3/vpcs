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
#include <sys/socket.h>
#include <netinet/in.h>
#include "packets.h"
#include "vpcs.h"
#include "dhcp.h"

struct packet * dhcp4_discover(pcs *pc, int renew)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	dhcp4_hdr *dh;
	int i, k;
	
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
	k = strlen(pc->xname);
	dh->options[i++] = k;
	strncpy((char *)(dh->options + i), pc->xname, k);
	i += k;

	
	dh->options[i++] = DHO_DHCP_CLIENT_IDENTIFIER;
	dh->options[i++] = 7;
	/* using hardware address as my identifier */
	dh->options[i++] = 1;
	memcpy(&dh->options[i], pc->ip4.mac, 6);
	i += 6;
	
	if (renew && pc->ip4.dhcp.ip) {
		dh->options[i++] = DHO_DHCP_REQUESTED_ADDRESS;
		dh->options[i++] = 4;
		((int*)(&dh->options[i]))[0] = pc->ip4.dhcp.ip;
		i += sizeof(int);
	}
		
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
	int i, k;
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
	
	dh->options[i++] = DHO_DHCP_SERVER_IDENTIFIER;
	dh->options[i++] = 4;
	((int*)(&dh->options[i]))[0] = pc->ip4.dhcp.svr;
	i += sizeof(int);
	
	dh->options[i++] = DHO_DHCP_REQUESTED_ADDRESS;
	dh->options[i++] = 4;
	((int*)(&dh->options[i]))[0] = pc->ip4.dhcp.ip;
	i += sizeof(int);
	
	dh->options[i++] = DHO_DHCP_CLIENT_IDENTIFIER;
	dh->options[i++] = 7;
	/* using hardware address as my identifier */
	dh->options[i++] = 1;
	memcpy(&dh->options[i], pc->ip4.mac, 6);
	i += 6;
	
	dh->options[i++] = DHO_HOST_NAME;
	k = strlen(pc->xname);
	dh->options[i++] = k;
	strncpy((char *)(dh->options + i), pc->xname, k);
	i += k;
	
	dh->options[i++] = DHO_DHCP_PARAMETER_REQUEST_LIST;
	dh->options[i++] = 4;
	dh->options[i++] = DHO_SUBNET_MASK;
	dh->options[i++] = DHO_ROUTERS;
	dh->options[i++] = DHO_DNS;
	dh->options[i++] = DHO_DOMAIN;

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

struct packet * dhcp4_release(pcs *pc)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	dhcp4_hdr *dh;
	int i, k;
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
	dh->secs = pc->ip4.dhcp.lease;
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
	dh->options[i++] = DHCPRELEASE;
	
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
	k = strlen(pc->xname);
	dh->options[i++] = k;
	strncpy((char *)(dh->options + i), pc->xname, k);
	i += k;
	
	dh->options[i++] = DHO_DHCP_CLIENT_IDENTIFIER;
	dh->options[i++] = 7;
	/* using hardware address as my identifier */
	dh->options[i++] = 1;
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
	ip->sip = pc->ip4.dhcp.ip;
	ip->dip = pc->ip4.dhcp.svr;

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
	
	if (dh->xid != pc->ip4.dhcp.xid || dh->op != 2)
		return 0;
	
	/* offer for me */
	p = dh->options;
	magic = ((long*)(p))[0];
	/* invalid magic */
	if (magic != htonl(0x63825363))
		return 0;
	
	pc->ip4.dhcp.svr = ip->sip;
	pc->ip4.dhcp.ip = dh->yiaddr;
	memcpy(pc->ip4.dhcp.smac, eh->src, 6);
	
	/* options */
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
		} else if (*p == DHO_DNS) {
			if (*(p + 1) == 4) {
				pc->ip4.dhcp.dns[0] = ((int*)(p + 2))[0];
				p += 6;
			} else if (*(p + 1) >= 8) {
				pc->ip4.dhcp.dns[0] = ((int*)(p + 2))[0];
				pc->ip4.dhcp.dns[1] = ((int*)(p + 2))[1];
				p += *(p + 1) + 2;
			}
			continue;
		} else if (*p == DHO_DHCP_SERVER_IDENTIFIER && *(p + 1) == 4) {
			pc->ip4.dhcp.svr = ((int*)(p + 2))[0];
			p += 6;
			continue;
		} else {
			p++;		/* skip op code */
			p += *(p) + 1;	/* add op offset(length) */
		}
	}
	
	return 1;
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
		memset(&(pc->ip4.dhcp), 0, sizeof(pc->ip4.dhcp));

		pc->ip4.dhcp.svr = ip->sip;
		memcpy(pc->ip4.dhcp.smac, eh->src, 6);

		pc->ip4.ip = dh->yiaddr;
		pc->ip4.dhcp.ip = pc->ip4.ip;

		p = dh->options;
		magic = ((long*)(p))[0];
		if (magic == htonl(0x63825363)) {
			pc->ip4.dhcp.renew = 0;
			pc->ip4.dhcp.rebind = 0;
			p += 4;
			while (*p != DHO_END && p - dh->options < DHCP_OPTION_LEN) {
				if (*p == DHO_SUBNET_MASK && *(p + 1) == 4) {
					pc->ip4.dhcp.netmask = ((int*)(p + 2))[0];
					pc->ip4.cidr = getCIDR(ntohl(((int*)(p + 2))[0]));
					p += 6;
					continue;
				} else if (*p == DHO_ROUTERS && *(p + 1) == 4) {
					pc->ip4.gw = ((int*)(p + 2))[0];
					pc->ip4.dhcp.gw = pc->ip4.gw;
					p += 6;
					continue;
				} else if (*p == DHO_DHCP_LEASE_TIME && *(p + 1) == 4) {
					pc->ip4.lease = ntohl(((int*)(p + 2))[0]);
					pc->ip4.dhcp.lease = pc->ip4.lease;
					p += 6;
					continue;
				} else if (*p == DHO_DHCP_RENEWAL_TIME && *(p + 1) == 4) {
					pc->ip4.dhcp.renew = ntohl(((int*)(p + 2))[0]);
					p += 6;
					continue;
				} else if (*p == DHO_DHCP_REBIND_TIME && *(p + 1) == 4) {
					pc->ip4.dhcp.rebind = ntohl(((int*)(p + 2))[0]);
					p += 6;
					continue;
				} else if (*p == DHO_DNS) {
					if (*(p + 1) == 4) {
						pc->ip4.dhcp.dns[0] = ((int*)(p + 2))[0];
						pc->ip4.dns[0] = pc->ip4.dhcp.dns[0];
						p += 6;
					} else if (*(p + 1) >= 8) {
						pc->ip4.dhcp.dns[0] = ((int*)(p + 2))[0];
						pc->ip4.dhcp.dns[1] = ((int*)(p + 2))[1];
						pc->ip4.dns[0] = pc->ip4.dhcp.dns[0];
						pc->ip4.dns[1] = pc->ip4.dhcp.dns[1];	
						p += *(p + 1) + 2;
					}
					continue;
				} else if (*p == DHO_DOMAIN) {
					memset(pc->ip4.dhcp.domain, 0, sizeof(pc->ip4.dhcp.domain));
					memcpy(pc->ip4.dhcp.domain, p + 2, *(p + 1));
					strcpy(pc->ip4.domain, pc->ip4.dhcp.domain);
					p += *(p + 1) + 2;
					continue;
				} else if (*p == DHO_DHCP_SERVER_IDENTIFIER && *(p + 1) == 4) {
					pc->ip4.dhcp.svr = ((int*)(p + 2))[0];
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

int dmp_dhcp(pcs *pc, const struct packet *m)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	dhcp4_hdr *dh;
	int direct = 0;
	int i, j, k;
	struct in_addr in;
	u_char opcode;
	char *msg_type[8] = {
		"Discover",
		"Offer",
		"Request",
		"Decline",
		"Ack",
		"Nak",
		"Release",
		"Inform"};
	
	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	if (ip->proto != IPPROTO_UDP)
		return 0;
		
	ui = (udpiphdr *)ip;
	dh = (dhcp4_hdr*)(ui + 1);
	
	/* incoming */
	if (memcmp(eh->dst, pc->ip4.mac, 6) == 0)
		direct = 1;
	
	/* to dhcp server */
	if (direct == 0) {
		if (ui->ui_sport != htons(68) ||
		    ui->ui_dport != htons(67))
			return 0;
	} else {
		if (ui->ui_dport != htons(68) ||
		    ui->ui_sport != htons(67))
			return 0;
	}

	printf("Opcode: %d (%s)\n", dh->op, (dh->op == 1 ? "REQUEST" : "REPLY"));
	in.s_addr = dh->ciaddr;
	printf("Client IP Address: %s\n", inet_ntoa(in));
	in.s_addr = dh->yiaddr;
	printf("Your IP Address: %s\n", inet_ntoa(in));
	in.s_addr = dh->siaddr;
	printf("Server IP Address: %s\n", inet_ntoa(in));
	in.s_addr = dh->giaddr;
	printf("Gateway IP Address: %s\n", inet_ntoa(in));
	printf("Client MAC Address: ");
	PRINT_MAC(dh->chaddr);
	printf("\n");
	
	/* skip magic */
	i = sizeof(int);
	opcode = dh->options[i];
	while (opcode != DHO_END && i < DHCP_OPTION_LEN) {
		switch (opcode) {
		case DHO_DHCP_MESSAGE_TYPE:
			printf("Option %d: Message Type = ", DHO_DHCP_MESSAGE_TYPE);
			k = dh->options[i + 1];
			j = dh->options[i + 2];
			if (j > 0 && j < 9) 
				printf("%s\n", msg_type[j - 1]);
			else
				printf("Unknown\n");
			i += k + 2;
			break;
		case DHO_HOST_NAME:
			printf("Option %d: Host Name = ", DHO_HOST_NAME);
			k = dh->options[i + 1];
			for (j = 0; j < k; j++)
				printf("%c", dh->options[i + 2 + j]);
			printf("\n");
			i += k + 2;
			break;
		case DHO_DHCP_CLIENT_IDENTIFIER:
			printf("Option %d: Client Identifier = ", DHO_DHCP_CLIENT_IDENTIFIER);
			k = dh->options[i + 1];
			if (dh->options[i + 2] == 1) {
				printf("Hardware Type=Ethernet MAC Address = ");
				PRINT_MAC(&(dh->options[i + 3]));
				printf("\n");
			} else
				printf("Unknow type ");
			i += k + 2;
			break;
		case DHO_DHCP_SERVER_IDENTIFIER:
			in.s_addr = ((int*)(&dh->options[i + 2]))[0];
			printf("Option %d: DHCP Server = %s\n", 
			    DHO_DHCP_SERVER_IDENTIFIER, inet_ntoa(in));
			i += 6;
			break;
		case DHO_DHCP_REQUESTED_ADDRESS:
			in.s_addr = ((int*)(&dh->options[i + 2]))[0];
			printf("Option %d: Requested IP Address = %s\n", 
			    DHO_DHCP_REQUESTED_ADDRESS, inet_ntoa(in));
			i += 6;
			break;
		case DHO_DHCP_LEASE_TIME:
			j = ((int*)(&dh->options[i + 2]))[0];
			printf("Option %d: Lease Time = %d\n", 
			    DHO_DHCP_LEASE_TIME, ntohl(j));
			i += 6;
			break;
		case DHO_DHCP_RENEWAL_TIME:
			j = ((int*)(&dh->options[i + 2]))[0];
			printf("Option %d: Renewal Time = %d\n", 
			    DHO_DHCP_RENEWAL_TIME, ntohl(j));
			i += 6;
			break;
		case DHO_DHCP_REBIND_TIME:
			j = ((int*)(&dh->options[i + 2]))[0];
			printf("Option %d: Rebinding Time = %d\n", 
			    DHO_DHCP_REBIND_TIME, ntohl(j));
			i += 6;
			break;
		case DHO_SUBNET_MASK:
			printf("Option %d: Subnet Mask = %d.%d.%d.%d\n", 
			    DHO_SUBNET_MASK, 
			    dh->options[i + 2],
			    dh->options[i + 3],
			    dh->options[i + 4],
			    dh->options[i + 5]);
			i += 6;
			break;
		case DHO_ROUTERS:
			in.s_addr = ((int*)(&dh->options[i + 2]))[0];
			printf("Option %d: Router = %s\n", 
			    DHO_ROUTERS, inet_ntoa(in));
			i += 6;
			break;
		case DHO_DNS:
			k = dh->options[i + 1];
			printf("Option %d: DNS Server = ", DHO_DNS);
			j = 0;
			while (k >= (j + 1)* 4) {
				in.s_addr = ((int*)(&dh->options[i + 2 + j * 4]))[0];
				printf("%s ", inet_ntoa(in));
				j++;
			}
			printf("\n");
			i += k + 2;
			break;
		case DHO_DOMAIN:
			printf("Option %d: Domain = ", DHO_DOMAIN);
			k = dh->options[i + 1];
			for (j = 0; j < k; j++)
				printf("%c", dh->options[i + 2 + j]);
			printf("\n");
			i += k + 2;
			break;
		case DHO_TFTP_SERVER:
			in.s_addr = ((int*)(&dh->options[i + 2]))[0];
			printf("Option %d: TFTP Server Address = %s\n", 
			    DHO_TFTP_SERVER, inet_ntoa(in));
			i += 5;
			break;
		default:
			k = dh->options[i + 1];
			i += k + 2;
			break;
		}
		
		opcode = dh->options[i];
	}
	printf("\n");
	
	return 0;	
}

int dhcp_renew(pcs *pc)
{
	struct packet *m;
	struct packet *p;
	int i;
	int ok;
	
	pc->ip4.dhcp.xid = rand();	
	/* request */
	i = 0;
	ok = 0;
	while (i++ < 3 && !ok) {
		m = dhcp4_request(pc);
		if (m == NULL) {
			sleep(1);
			continue;	
		}

		enq(&pc->oq, m);
		sleep(1);
		
		while ((p = deq(&pc->bgiq)) != NULL && !ok) {
			ok = isDhcp4_packer(pc, p);
			free(p);
		}
		
		i++;
	}
	if (ok) {
		if (pc->ip4.dhcp.renew == 0)
			pc->ip4.dhcp.renew = pc->ip4.dhcp.lease / 2;
		if (pc->ip4.dhcp.rebind == 0)
			pc->ip4.dhcp.rebind = pc->ip4.dhcp.lease * 7 / 8;
		return 1;
	}
	return 0;	
}

int dhcp_rebind(pcs *pc)
{
	int ts[3] = {1, 3, 9};
	struct packet *m;
	struct packet *p;
	int i;
	int ok;
	
	pc->ip4.dhcp.xid = rand();	
	/* request */
	i = 0;
	ok = 0;
	while (i < 3 && !ok) {
		m = dhcp4_discover(pc, 0);
		if (m == NULL) {
			sleep(1);
			continue;	
		}
		enq(&pc->oq, m);
		sleep(ts[i]);
		
		while ((p = deq(&pc->bgiq)) != NULL && !ok) {
			ok = isDhcp4_Offer(pc, p);
			free(p);
		}
	}
	if (!ok)
		return 0;

	/* request */
	i = 0;
	ok = 0;
	while (i < 3 && !ok) {	
		m = dhcp4_request(pc);
		if (m == NULL) {
			sleep(1);
			continue;	
		}

		enq(&pc->oq, m);
		sleep(1);
		
		while ((p = deq(&pc->bgiq)) != NULL && !ok) {
			ok = isDhcp4_packer(pc, p);
			free(p);
		}
	}
	if (ok) {
		if (pc->ip4.dhcp.renew == 0)
			pc->ip4.dhcp.renew = pc->ip4.dhcp.lease / 2;
		if (pc->ip4.dhcp.rebind == 0)
			pc->ip4.dhcp.rebind = pc->ip4.dhcp.lease * 7 / 8;
		return 1;
	}
	return 0;
}

int dhcp_enq(pcs *pc, const struct packet *m)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	dhcp4_hdr *dh;
	
	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	ui = (udpiphdr *)ip;
	dh = (dhcp4_hdr*)(ui + 1);
	
	if (pc->bgjobflag && dh->xid == pc->ip4.dhcp.xid) {
		enq(&pc->bgiq, (struct packet *)m);
		return 1;
	}
	return 0;
}
/* end of file */

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
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "ip.h"
#include "queue.h"

u_long ip_masks[33] = {
	0x0, 
	0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
	0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
	0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
	0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
	0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
	0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
	0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0,
	0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF
};

void swap_ehead(char *mbuf)
{
	u_char mac[6];
	ethdr *eh;
	eh = (ethdr *)mbuf;
	memcpy(mac, eh->dst, ETH_ALEN);
	memcpy(eh->dst, eh->src, ETH_ALEN);
	memcpy(eh->src, mac, ETH_ALEN);	
}

void encap_ehead(char *mbuf, const u_char *sea, const u_char *dea, const u_short type)
{
	ethdr *eh;
	eh = (ethdr *)mbuf;
	memcpy(eh->dst, dea, ETH_ALEN);
	memcpy(eh->src, sea, ETH_ALEN);	
	eh->type = htons(type);
}

u_short cksum(register unsigned short *buffer, register int size) 
{ 
	register unsigned long cksum = 0; 
	
	while (size > 1) { 
	  cksum += *buffer++; 
	  size -= sizeof(unsigned short); 
	} 
	 
	if (size) 
		cksum += *(unsigned char *) buffer; 
	
	cksum = (cksum >> 16) + (cksum & 0xffff); 
	cksum += (cksum >> 16);
	
	return (unsigned short) (~cksum); 
} 

u_short cksum_fixup(u_short cksum, u_short old, u_short new, u_short udp)
{
	u_long l = 0;

	if (udp && !cksum) 
		return (0x0000);
	
	l = cksum + old - new;
	l = (l >> 16) + (l & 0xffff);
	l = l & 0xffff;
	
	if (udp && !l) 
		return (0xFFFF);
		
	return (l);
}

u_short cksum6(ip6hdr *ip, u_char nxt, int len)
{
	int sum = 0;
	u_short *w;
	union {
		u_short phs[4];
		struct {
			u_int	ph_len;
			u_char	ph_zero[3];
			u_char	ph_nxt;
		} ph;
	} uph;
	
	memset(&uph, 0, 8);
	uph.ph.ph_len = htonl(len);
	uph.ph.ph_nxt = nxt;
	
	sum += uph.phs[0];  sum += uph.phs[1];
	sum += uph.phs[2];  sum += uph.phs[3];
	
	w = (u_short *)&(ip->src);
	sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
	sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
	
	w = (u_short *)&(ip->dst);
	sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
	sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
	
	w = (u_short *)(ip + 1);

	while (len > 1) { 
		sum += *w++; 
		len -= sizeof(u_short); 
	}
	if (len) sum += *(unsigned char *) w;
	
	sum = (sum >> 16) + (sum & 0xffff); 
	sum += (sum >> 16); 
	
	return (u_short) (~sum);	
}

int sameNet(u_long ip1, u_long ip2, int cidr)
{
#if 0
	printf("%lx--%lx\n%lx--%lx\n", ip1, ip2, 
		ip_masks[cidr] & ntohl(ip1),
		ip_masks[cidr] & ntohl(ip2));
#endif

	if ((ip_masks[cidr] & ntohl(ip1)) == (ip_masks[cidr] & ntohl(ip2)))
		return 1;
	else
		return 0;
}

int sameNet6(char *s, char *d, int cidr)
{
	int b;
	int i;
	
	b = cidr / 8;
	
	i = 0;
	while (i < b) {
		if (s[i] != d[i])
			return 0;
		i++;
	}
	b = 8 - cidr % 8;
	if ((s[i] >> b) != (d[i] >> b))
		return 0;
	
	return 1;
}

int getCIDR(u_long mask)
{
	int i;
	for (i = 0; i < 33; i++) {
		if (ip_masks[i] ==  mask)
			return i;
	}
	// should not be here
	return 0;	
}

void swap_ip6head(struct packet *m)
{
	ip6 ip0;
	ip6hdr *ip;
	
	ip = (ip6hdr *)(m->data + sizeof(ethdr));
	memcpy(ip0.addr8, ip->dst.addr8, 16);
	memcpy(ip->dst.addr8, ip->src.addr8, 16);
	memcpy(ip->src.addr8, ip0.addr8, 16);
}

int etherIsZero(u_char *mac) 
{
	u_char zero[ETH_ALEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};	
	if (!strncmp((const char *)mac, (const char *)zero, 6))
		return 1;
	else
		return 0;
}

int etherIsMulticast(u_char *mac) 
{
	u_char broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};	
	if (!strncmp((const char *)mac, (const char *)broadcast, 6))
		return 1;
	else
		return 0;
}

int dmp_packet(const struct packet *m, const int flag)
{
	int i, j, pos0, pos1;
	char x0[96], x1[17];
	u_char *p = (u_char *)m->data;
	int len = m->len;
	int left;
	
	if (flag == 0)
		return flag;

	printf("\n");
	
	if (flag == 2) {
		for (j = 6; j < 12; j++)
			printf("%2.2x:", *(p + j));
		
		printf("\b -> ");
		
		for (j = 0; j < 6; j++)
			printf("%2.2x:", *(p + j));
			
		printf("\b \n");
	}
	
	len -= 14;
	p += 14;
		
	i = 0;
	while (i < len) {
		pos0 = pos1 = 0;
		left = 40;
		for (j = i; (j < i + 16 && j < len); j += 2) {
			
			pos0 += sprintf(x0 + pos0, "%2.2x", *(p + j));
			left -= 2;
			if (isprint(*(p + j)))
				pos1 += sprintf(x1 + pos1, "%c", *(p + j));
			else
				pos1 += sprintf(x1 + pos1, ".");
			
			pos0 += sprintf(x0 + pos0, "%2.2x ", *(p + j + 1));
			left -= 3;
			if (isprint(*(p + j + 1)))
				pos1 += sprintf(x1 + pos1, "%c", *(p + j + 1));
			else
				pos1 += sprintf(x1 + pos1, ".");
		}

		for (pos1 = 0; pos1 < left; pos1++)
			pos0 += sprintf(x0 + pos0, " ");
		printf("%s   %s\n", x0, x1);
		i += (j - i);
	}
	printf("\n");
	return flag;
}

const char *icmpTypeCode2String(int ipv, u_int8_t type, u_int8_t code)
{
	const char *DestUnreach[] = {
		"Destination network unreachable",
		"Destination host unreachable",
		"Destination protocol unreachable",
		"Destination port unreachable",
		"Fragmentation required, and DF flag set",
		"Source route failed",
		"Destination network unknown",
		"Destination host unknown",
		"Source host isolated",
		"Network administratively prohibited",
		"Host administratively prohibited",
		"Network unreachable for TOS",
		"Host unreachable for TOS",
		"Communication administratively prohibited"};
	
	const char *Redirect[] = {
		"Redirect Datagram for the Network",
		"Redirect Datagram for the Host",
		"Redirect Datagram for the TOS & network",
		"Redirect Datagram for the TOS & host"};
	
	const char *TimeExceed[] = {
		"TTL expired in transit",
		"Fragment reassembly time exceeded"};
		
	const char *Dest6Unreach[] = {
		"No route to destination",
		"Communication with destination administratively prohibited",
		"Beyond scope of source address",
		"Address unreachable",
		"Port unreachable",
		"Source address failed ingress/egress policy",
		"Reject route to destination"};
	const char *Time6Exceed[] = {
		"Hop limit exceeded in transit",
		"Fragment reassembly time exceeded"};
	
	const char *empty = "";	
	
	if (ipv == 4) {
		switch (type) {
			case 3:
				if (code <= 13)
					return DestUnreach[code];
				break;
			case 5:
				if (code <= 3)
					return Redirect[code];
				break;
			case 11:
				if (code <= 1)
					return TimeExceed[code];
				break;
			default:
				break;
		}
	} else if (ipv == 6) {
		switch (type) {
			case 1:
				if (code <= 6)
					return Dest6Unreach[code];
				break;
			case 3:
				if (code <= 1)
					return Time6Exceed[code];
				break;
			default:
				break;
		}
	}

	return empty;
}
/* end of file */

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
#include <string.h>
#include <ctype.h>

#include "ip.h"
#include "dump.h"
#include "dns.h"

static void dmp_ip(void *dat);
static void dmp_ip6(void *dat);
static void dmp_arp(void *dat);
static void dmp_dns(void *dat);
static char *dmp_dns_timestr(u_int s);

int dmp_packet(const struct packet *m, const int flag)
{
	int i, j, pos0, pos1;
	char x0[96], x1[17];
	u_char *p = (u_char *)m->data;
	int len = m->len;
	int left;
	ethdr *eh = (ethdr *)m->data;
	int cr = 0;

	if (flag == 0)
		return flag;

	if (flag & DMP_MAC) {
		printf("\n");
		printf("\033[33m");
		cr = 1;
		PRINT_MAC(p + 6);
		printf(" -> ");
		PRINT_MAC(p);
		printf("\n");
	}	
	len -= 14;
	p += 14;
	
	if (flag & DMP_RAW) {	
		i = 0;
		if (!cr) {
			printf("\n");
			printf("\033[33m");
			cr = 1;
		}
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
	}
	if (flag & DMP_DETAIL) {
		if (!cr) {
			printf("\n");
			printf("\033[33m");
			cr = 1;
		}
		
		if (eh->type == htons(ETHERTYPE_IP))
			dmp_ip(eh + 1);
		else if (eh->type == htons(ETHERTYPE_IPV6))
			dmp_ip6(eh + 1);
		else if (eh->type == htons(ETHERTYPE_ARP))
			dmp_arp(eh + 1);
	}
	if (cr)
		printf("\033[0m");
	
	return 1;
}

static void dmp_arp(void *dat)
{
	arphdr *ah = (arphdr *)dat;	
	struct in_addr in;
	u_char broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u_int *si, *di;
	
	printf("ARP, OpCode: %d (%s)", ntohs(ah->op), 
	    ((ntohs(ah->op) == ARPOP_REQUEST) ? "Request" : "Reply"));
	
	si = (u_int *)ah->sip;
	di = (u_int *)ah->dip;
	if (si[0] == di[0] && di[0] != 0)
		printf("    Gratuitous ARP");    	
	printf("\nEther Address: ");
	PRINT_MAC(ah->sea);
	printf(" -> ");
	if (memcmp(ah->dea, broadcast, ETH_ALEN) == 0)
		printf("Broadcast");
	else
		PRINT_MAC(ah->dea);
	printf("\n");
	
	if ((ntohs(ah->op) == ARPOP_REQUEST)) { 
		in.s_addr = di[0];
		printf("Who has %s? Tell ", inet_ntoa(in));
		in.s_addr = si[0];
		printf("%s", inet_ntoa(in));
	} else if ((ntohs(ah->op) == ARPOP_REPLY)) {
		in.s_addr = si[0];
		printf("%s is at ", inet_ntoa(in));
		PRINT_MAC(ah->sea);
	}
	printf("\n");
}

static void dmp_ip(void *dat)
{
	iphdr *iph = (iphdr *)dat;
	icmphdr *icmp = (icmphdr *)(iph + 1);
	udphdr *uh = (udphdr *)(iph + 1);
	tcphdr *th = (tcphdr *)(iph + 1);
	u_char *data;
	struct in_addr in;
	
	printf("IPv%d, id: %x, length: %d, ttl: %d, sum: %4.4x", iph->ver, 
	    ntohs(iph->id), ntohs(iph->len), iph->ttl, ntohs(iph->cksum));
	
	if (ntohs(iph->frag) == IPDF)
		printf(", DF");
	if (ntohs(iph->frag) == IPMF)
		printf(", MF");
		
	in.s_addr = iph->sip;
	printf("\nAddress: %s -> ", inet_ntoa(in));
	in.s_addr = iph->dip;
	printf("%s\n", inet_ntoa(in));
	
	if (iph->proto == IPPROTO_ICMP) {
		printf("Proto: icmp, ");
		printf("type: %d, ", icmp->type);
		printf("code: %d\n", icmp->code);
		printf("Desc: %s\n", icmpTypeCode2String(iph->ver, icmp->type, icmp->code));
	} else if (iph->proto == IPPROTO_UDP) {
		printf("Proto: udp, len: %d, sum: %4.4x\n", ntohs(uh->len), ntohs(uh->cksum));
		printf("Port: %d -> %d\n", ntohs(uh->sport), ntohs(uh->dport));
		
		if (ntohs(uh->sport) == 53 || ntohs(uh->dport) == 53)
			return dmp_dns(dat);
			
		if (ntohs(uh->sport) == ntohs(uh->dport) && 
		    ntohs(uh->sport) == 520 && iph->dip == 0x90000e0) {
		    	data = (u_char *)(uh + 1);
			printf("Desc: RIP%d %s message\n", *(data + 1),
			    (*data == 1) ? "request" : "response");
		}
		
	} else if (iph->proto == IPPROTO_TCP) {
		printf("Proto: tcp, sum: %4.4x, ack: %8.8x, seq: %8.8x, ", 
		    ntohs(th->th_sum), ntohl(th->th_ack), ntohl(th->th_seq));
		printf("flags: ");
		if (th->th_flags & TH_FIN)
			printf("F");
		if (th->th_flags & TH_SYN)
			printf("S");
		if (th->th_flags & TH_RST)
			printf("R");
		if (th->th_flags & TH_PUSH)
			printf("P");
		if (th->th_flags & TH_ACK)
			printf("A");
		if (th->th_flags & TH_URG)
			printf("U");
		if (th->th_flags & TH_ECE)
			printf("E");
		if (th->th_flags & TH_CWR)
			printf("C");	
		printf("\n");

		printf("Port: %d -> %d\n", ntohs(th->th_sport), ntohs(th->th_dport));
	}
}

static void dmp_ip6(void *dat)
{
	ip6hdr *iph = (ip6hdr *)dat;
	icmp6hdr *icmp = (icmp6hdr *)(iph + 1);
	udphdr *uh = (udphdr *)(iph + 1);
	tcphdr *th = (tcphdr *)(iph + 1);
	u_char *data;
	char *p;
	
	printf("IPv6, flowid: %x, length: %d, ttl: %d\n", 
	    ntohl(iph->ip6_flow & IPV6_FLOWLABEL_MASK), ntohs(iph->ip6_plen), iph->ip6_hlim);
	
	p = ip6tostr(iph->src.addr8);
	printf("Address: %s -> ", p);
	p = ip6tostr(iph->dst.addr8);
	printf("%s\n", p);
	
	if (iph->ip6_nxt == IPPROTO_ICMPV6) {
		printf("Proto: icmp, ");
		printf("type: %d, ", icmp->type);
		printf("code: %d\n", icmp->code);
		printf("Desc: %s\n", icmpTypeCode2String(6, icmp->type, icmp->code));
	} else if (iph->ip6_nxt == IPPROTO_UDP) {
		printf("Proto: udp, len: %d, sum: %4.4x\n", ntohs(uh->len), ntohs(uh->cksum));
		printf("Port: %d -> %d\n", ntohs(uh->sport), ntohs(uh->dport));
		if (ntohs(uh->sport) == ntohs(uh->dport) && ntohs(uh->sport) == 521 &&
		    iph->dst.addr32[0] == IPV6_ADDR_INT32_MLL &&
		    iph->dst.addr32[1] == 0 && iph->dst.addr32[2] == 0 &&
		    iph->dst.addr32[3] == 0x09000000) {
		    	data = (u_char *)(uh + 1);
			printf("Desc: RIP%d %s message\n", *(data + 1),
			    (*data == 1) ? "request" : "response");
		}
	} else if (iph->ip6_nxt == IPPROTO_TCP) {
		printf("Proto: tcp, sum: %4.4x, ack: %8.8x, seq: %8.8x, ", 
		    ntohs(th->th_sum), ntohl(th->th_ack), ntohl(th->th_seq));
		printf("flags: ");
		if (th->th_flags & TH_FIN)
			printf("F");
		if (th->th_flags & TH_SYN)
			printf("S");
		if (th->th_flags & TH_RST)
			printf("R");
		if (th->th_flags & TH_PUSH)
			printf("P");
		if (th->th_flags & TH_ACK)
			printf("A");
		if (th->th_flags & TH_URG)
			printf("U");
		if (th->th_flags & TH_ECE)
			printf("E");
		if (th->th_flags & TH_CWR)
			printf("C");	
		printf("\n");

		printf("Port: %d -> %d\n", ntohs(th->th_sport), ntohs(th->th_dport));
	}
}

void
dmp_dns(void *dat)
{
	iphdr *iph = (iphdr *)dat;
	udphdr *uh = (udphdr *)(iph + 1);
	int iplen;	
	char *p, *q;
	dnshdr *dh;
	u_short *sp;	
	char name[256];
	int i, j;
	int rlen;
	u_char c;
	u_short ptr, type, classt;
	u_int ttl;
	struct in_addr in;
	const char *rcode[6] = {
		"No error",
		"Format error",
		"Server failure",
		"Name error",
		"Not implement",
		"Refused"};
	const char *typestr[16] = {"A", "NS", "MD", "MF", "CNAME", "SOA", "MB", 
		"MG", "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT"};
	const char *classtr[4] = {"IN", "CS", "CH", "HS"};
	/* make gcc happy */
	union u_dnsflags {
		u_short flags;
		dnsflags dflags;
	} u_dnsflags;
	dnsflags *dflags;
	
	iplen = ntohs(iph->len);
	dh = (dnshdr *)(uh + 1);
	
	printf("DNS: QueryID = %x", dh->id);
	if (ntohs(uh->dport) == 53) {
		printf(", QueryFlags = %x\n", dh->flags);
		p = (char *)(dh + 1);
		i = j = 0;
		name[0] = '\0';
		while (p + j - (char *)iph < iplen) {
			i = *(p + j);
			strncat(name, (char *)(p + j + 1), i);
			j += i + 1;
			if (*(p + j) == '\0')
				break;
			strcat(name, ".");	
		}
		printf("     Host: %s", name);
		p += j + 1;
		type = *(u_short *)(p);
		classt = *((u_short *)(p) + 1);
		if (type == 0x0100)
			printf(", type = %s", typestr[0]);
		if (classt == 0x0100)
			printf(", class = IN");
		printf("\n");
	} else if (ntohs(uh->sport) == 53){
		printf(", RespFlags = %x, ", dh->flags);
		u_dnsflags.flags = dh->flags;
		dflags = &u_dnsflags.dflags;
		if (dflags->rc != 0) {
			if (dflags->rc)
				printf("rc: %s", rcode[dflags->rc]);
			else
				printf("rc: %d", dflags->rc);
		}
		printf("\n");
		printf("     Query = %d, Answer = %d, Auth = %d, Add = %d\n", 
		    ntohs(dh->query), ntohs(dh->answer), ntohs(dh->author), ntohs(dh->addition));
			
		p = (char *)(dh + 1);
		j = dmp_dns_rname(p, (char *)iph + iplen, name);
		printf("     QueryHost: %s", name);
		
		p += j + 1;
		type = *(u_short *)(p);
		classt = *((u_short *)(p) + 1);
		if (type == 0x0100)
			printf(", type = %s", typestr[0]);
		if (classt == 0x0100)
			printf(", class = IN");	
		printf("\n");
		
		p += 4;
		
		/* unpack record */
		while (p - (char *)iph < iplen) {
			sp = (u_short *)p;
			ptr = ntohs(*sp);
			
			if ((ptr & 0xc000) == 0xc000) {
				q = (char *)(dh) + (ptr & 0x3fff);
				dmp_dns_rname(q, (char *)iph + iplen, name);
				printf("     RR: name = %s\n", name);
			} else {
				printf("     Only support compression scheme\n");
				return;
			}
			sp ++;
			p += 2; 

			type = ntohs(*sp);
			classt = ntohs(*(sp + 1));
			ttl = ntohl(*((u_int *)(sp + 4)));
			if (type < 1 || type > 16)
				printf("         Invalid type (%d)", type);
			else
				printf("         type = %s", typestr[type - 1]);
				
			if (classt < 1 || classt > 4)
				printf(", Invalid class (%d)", classt);	
			else	
				printf(", class = %s", classtr[classt - 1]);
			
			printf(", TTL = %d", ttl);
			
			p += 2 + 2 + 4;
			sp = (u_short *)p;
			rlen = ntohs(*sp);
			if (type == 1 && rlen == 4) {
				in.s_addr = ((u_int *)(p + 2))[0];
				printf(", addr = %s", inet_ntoa(in));
			} else if (type == 2) {
				/* ns */	
				i = j = 0;
				memset(name, 0, sizeof(name));
				q = p + 2;
				c = *(q + j);
				while (j < rlen) {
					strncat(name, (char *)(q + j + 1), c);
					j += i + 1;
					c = *(q + j);
					if (*(q + j) == '\0' || c > 64)
						break;
					strcat(name, ".");	
				}
				printf("\n         ns = %s", name);
			} else if (type == 5) {
				/* cname */
				printf(", data length = %d\n", rlen);
				printf("         Cname: ");

				/* output cname name */
				q = p + 2;
				c = *q;
				i = 0;
				while (1) {
					q++;
					for (j = 0; j < c; j++, i++)
						printf("%c", *(q + j));
					q += c;
					c = *q;
					if (c == 0 || c > 64)
						break;
					printf(".");
					i++;
				}
				if (i + 1 < rlen && c > 64) {
					sp = (u_short *)q;
					dmp_dns_rname((char *)(dh) + (ntohs(*sp) & 0x3fff), 
					    (char *)iph + iplen, name);
					printf(".%s", name);
				}
			} else if (type == 6) {
				printf(", data length = %d\n", rlen);
				printf("         Name server: ");

				/* output ns server name */
				q = p + 2;
				c = *q;
				while (1) {
					q++;
					for (j = 0; j < c; j++)
						printf("%c", *(q + j));
					q += c;
					c = *q;
					if (c > 64)
						break;
					printf(".");
				}
				dmp_dns_rname((char *)(dh) + (ptr & 0x3fff), (char *)iph + iplen, name);
				printf(".%s\n", name);
				
				sp = (u_short *)q;
				/* output mail server name */
				printf("         Responsible Mailbox: ");
				q = q + 2;
				c = *q;
				while (1) {
					q++;
					for (j = 0; j < c; j++)
						printf("%c", *(q + j));
					q += c;
					c = *q;
					if (c > 64)
						break;
					printf(".");
				}
				dmp_dns_rname((char *)(dh) + (ntohs(*sp) & 0x3fff), (char *)iph + iplen, name);
				printf(".%s\n", name);
				
				/*output serial number */
				q = q + 2;
				printf("         Serial number: %x\n", ntohl(((u_int *)q)[0]));
				printf("         Refresh interval: %s\n", 
				    dmp_dns_timestr(((u_int *)q)[1]));
				printf("         Retry interval: %s\n", 
				    dmp_dns_timestr(((u_int *)q)[2]));
				printf("         Expiration time: %s\n", 
				    dmp_dns_timestr(((u_int *)q)[3]));
				printf("         Minimum TTL: %s", 
				    dmp_dns_timestr(((u_int *)q)[4]));
			}
			p += 2 + rlen;
			printf("\n");
		} /* while */
	} /* if */
}


static char *
dmp_dns_timestr(u_int s)
{
	static char buf[64];
	int off = 0;
	
	buf[0] = '\0';
	s = ntohl(s);
	if (s / (3600 * 24)) {
		off += snprintf(buf + off, sizeof(buf), "%d days", s / (3600 * 24));
		s -= (s / (3600 * 24)) * (3600 * 24);
	}
	
	if (s / (3600)) {
		off += snprintf(buf + off, sizeof(buf), "%d hours", s / (3600));
		s -= (s / (3600)) * (3600);
	}
	
	if (s / (60)) {
		off += snprintf(buf + off, sizeof(buf), "%d minutes", s / (60));
		s -= (s / (60)) * (60);
	}
	if (s) {
		off += snprintf(buf + off, sizeof(buf), "%d minutes", s / (60));
	}
	
	return buf;
}


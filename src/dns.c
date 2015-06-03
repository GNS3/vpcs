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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "packets.h"
#include "vpcs.h"
#include "utils.h"
#include "dns.h"
#include "inet6.h"

extern int ctrl_c;

static int fmtstring(const char *name, char *buf);
static int dnsrequest(u_short id, const char *name, int type, char *data, int *namelen);
static int dnsparse(struct packet *m, u_short id, char *data, int dlen, u_char *ip);
static int ip2str(u_char *ip, char *str);

int hostresolv(pcs *pc, char *name, char *ipstr)
{
	sesscb cb;
	struct packet *m;
	char data[512];
	char *pdn = NULL;
	int dlen;
	u_int gip;
	struct in_addr in;
	struct timeval tv;
	int ok;
	int namelen;
	int i;
	u_char mac[ETH_ALEN];
	char dname[64];
	u_short magicid;
	int reqcnt = 0;
	int atype = 1;
	u_char ip[20];
	
	if (!strchr(name, '.')) {
		if (pc->ip4.domain[0] != '\0')
			snprintf(dname, sizeof(dname), "%s.%s", name, pc->ip4.domain);
		else if (pc->ip4.dhcp.domain[0] != '\0')
			snprintf(dname, sizeof(dname), "%s.%s", name, pc->ip4.dhcp.domain);
	} else
		snprintf(dname, sizeof(dname), "%s", name);
reqry:	
	if (reqcnt > 3)
		return 0;

	magicid = random();
	dlen = dnsrequest(magicid, dname, atype, data, &namelen);
	if (dlen == 0) 
		return 0;

	if (sameNet(cb.dip, pc->ip4.ip, pc->ip4.cidr))
		gip = cb.dip;
	else {
		if (pc->ip4.gw == 0) {
			printf("No gateway found\n");
			return 0;
		} else
		
		gip = pc->ip4.gw;
	}

  	if (!arpResolve(pc, gip, mac)) {
		in.s_addr = gip;
		printf("host (%s) not reachable\n", inet_ntoa(in));
		return 0;
	}

	pdn = data + sizeof(dnshdr);
	for (i = 0; i < 2; i++) {
		if (pc->ip4.dns[i] == 0)
			continue;
		
		/* save old control block */
		memcpy(&cb, &pc->mscb, sizeof(sesscb));
		pc->mscb.data = data;
		pc->mscb.dsize = dlen;
		pc->mscb.proto = IPPROTO_UDP;
		pc->mscb.mtu = pc->mtu;
		pc->mscb.ipid =  time(0) & 0xffff;
		pc->mscb.ttl = TTL;
		pc->mscb.sip = pc->ip4.ip;
		pc->mscb.dip = pc->ip4.dns[i];
		pc->mscb.sport = (random() % (65000 - 1024)) + 1024;
		pc->mscb.dport = 53;
		memcpy(pc->mscb.smac, pc->ip4.mac, ETH_ALEN);
		memcpy(pc->mscb.dmac, mac, ETH_ALEN);
	
		m = packet(pc);
		/* restore control block */
		memcpy(&pc->mscb, &cb, sizeof(sesscb));
		if (m == NULL) {
			printf("out of memory\n");
			return 0;
		}
		gettimeofday(&(tv), (void*)0);
		enq(&pc->oq, m);
		while (!timeout(tv, 1000) && !ctrl_c) {
			delay_ms(1);
			ok = 0;		
			while ((m = deq(&pc->iq)) != NULL && !ok) {
				ok = dnsparse(m, magicid, pdn, namelen, ip);
				free(m);
			}
			if (ok == 2) {
				//printf("%s ->> %s\n", dname, pdn);
				//strcpy(dname, pdn);
				reqcnt++;
				goto reqry;
			}
			if (ok == 6) {
				//printf("%s ->> AAAA\n", dname);
				//strcpy(dname, pdn);
				reqcnt++;
				atype = 28;
				goto reqry;
			}
			if (ok) {
				strcpy(name, pdn);
				ip2str(ip, ipstr);
				return 1;
			}
		}
	}
	return 0;
}

static int fmtstring(const char *name, char *buf)
{
	char *s, *r;
	int len = 0;
	char c;
	
	if (name == NULL || name[0] == '.' || strstr(name, "..") || 
	    !strchr(name, '.') || strlen(name) > MAX_DNS_NAME)
		return 0;
	
	memset(buf, 0, MAX_DNS_NAME);
	strcpy(buf + 1, name);
	
	s = buf + 1;
	while (*s != '\0') {
		if (*s == '.')
			*s = '\0';
		s++;
	}
	
	s = buf;
	r = buf + 1;
	while (*r) {
		c = strlen(r);
		*s = c;
		len += c + 1;
		s = r + c;
		r = s + 1;
	}
	/* prefix and '\0' at end of the string */
        return len + 1;
}

static int dnsrequest(u_short id, const char *name, int type, char *data, int *namelen)
{
	u_char buf[256];	
	dnshdr dh;
	int dlen = sizeof(dnshdr);
	int i;
	
	memset(&dh, 0, sizeof(dnshdr));
	dh.id = id;
	dh.flags = 0x0001; /* QR|OC|AA|TC|RD -  RA|Z|RCODE  */
	dh.query = htons(0x0001); /* one query */
	  	
  	memcpy(data, (void *)&dh, sizeof(dnshdr));
  	
  	/* query name */
  	memset(buf, 0, sizeof(buf));
  	i = fmtstring(name, (char *)buf);
  	if (i == 0)
  		return 0;
  	*namelen = i;
  	memcpy(data + dlen, buf, i);
  	dlen += i;
  	
  	/* A record */
  	data[dlen++] = 0x00;
  	data[dlen++] = type;
  	/* IN class */
  	data[dlen++] = 0x00;
  	data[dlen++] = 0x01;
  	
	return dlen;
}

/* very simple DNS answer parser 
 * only search A record if exist, get IP address 
 * return 1 if host name was resolved.
 */
static int dnsparse(struct packet *m, u_short magicid, char *data, int dlen, u_char *cip)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	u_char *p;
	dnshdr *dh;
	u_short *sp;
	int rlen;
	int iplen;
	int i, j;
	u_char c;
	
	const char *rcode[6] = {
		"No error",
		"Format error",
		"Server failure",
		"Name error",
		"Not implement",
		"Refused"};
		

	eh = (ethdr *)(m->data);
	ip = (iphdr *)(eh + 1);
	ui = (udpiphdr *)ip;
	iplen = ntohs(ip->len);

	dh = (dnshdr *)(ui + 1);
	if (dh->id != magicid)
		return 0;

	/* invalid name or answer */
	if ((dh->flags & 0x8081) != 0x8081) {
		c = (dh->flags >> 8) & 0xf;
		if (c == 0)
			return 0;
		printf("DNS server return: ");
		if (c < 6)
			printf("%s\n", rcode[c]);
		else
			printf("error: %d\n", c);
			 
		return 0;
	}
		
	if (dh->query == 0)
		return 0;
	
	/* No Error, answer is zero, try AAAA */
	if (dh->answer == 0)
		return 6;

	p = (u_char *)(dh + 1);
	
	/* extract domain name */
	c = 0;
	i = 0;
	data[0] = '\0';
	while (p + c - (u_char *)ip < iplen) {
		i = *(p + c);
		strncat(data, (char *)(p + c + 1), i);
		c += i + 1;
		if (*(p + c) == '\0')
			break;
		strcat(data, ".");	
	}
	
	/* skip type and class */
	p += c + 5;
	
	/* skip offset pointer, 
	 * normal is 0xc00c, 11 00000000001100, 11-pointer, 0c-offset from dnshdr 
	*/
	p += 2;
	while (p - (u_char *)ip < iplen) {
		sp = (u_short *)p;
		/* A/AAAA record */
		if ((*sp == 0x0100 || *sp == 0x1c00) && *(sp + 1) == 0x0100) {
			p += 2 + 2 + 4;
			sp = (u_short *)p;
			if (*sp == 0x0400 || *sp == 0x1000) {
				memcpy(cip + 1, p + 2, ntohs(*sp));
				cip[0] = ntohs(*sp);
				return 1;
			}
		} else if (*sp == 0x0500) {
			/* cname */
			/* skip type2, class2, ttl4 */
			p += 2 + 2 + 4;
			rlen = ntohs(*((u_short *)p));
			p = p + 2;
			c = *p;
			i = 0;
			data[i] = '\0';
			
			while (1) {
				p++;
				for (j = 0; j < c; j++)
					i += sprintf(data + i, "%c", *(p + j));
				p += c;
				c = *p;
				if (c == 0 || c > 64)
					break;
				i += sprintf(data + i, ".");
			}
			if (c > 64) {
				sp = (u_short *)p;
				i += sprintf(data + i, ".");
				dmp_dns_rname((char *)(dh) + (ntohs(*sp) & 0x3fff), 
				    (char *)ip + iplen, data + i);
			}
			/* tell caller retry again */
			return 2;
		} else  {
			/* skip type2, class2, ttl4, rlen2 */
			p += 2 + 2 + 4;
			sp = (u_short *)p;
			rlen = ntohs(*sp);
			p += rlen + 2;
			/* skip pointer */
			p += 2;
		}
	}
	return 0;
}

int ip2str(u_char *ip, char *str)
{
	struct in6_addr ipaddr;
	char buf[INET6_ADDRSTRLEN + 1];
	
	if (*ip == 4)
		sprintf(str, "%d.%d.%d.%d", ip[1], ip[2], ip[3], ip[4]);
	else if (*ip == 16) {
		memset(buf, 0, sizeof(buf));
		memcpy(ipaddr.s6_addr, ip + 1, 16);
		vinet_ntop6(AF_INET6, &ipaddr, buf, INET6_ADDRSTRLEN + 1);
		sprintf(str, "%s", buf);
	}
	
	return 0;
}

int
dmp_dns_rname(char *s, char *se, char *name)
{
	int i;
	u_char c;

	name[0] = '\0';	
	c = *s;
	i = 0;
	while (s < se) {
		strncat(name, (char *)(s + i + 1), c);
		i += c + 1;
		c = *(s + i);
		if (*(s + i) == '\0' || c > 64)
			break;
		strcat(name, ".");	
	}
	return i;
}
/* end of file */

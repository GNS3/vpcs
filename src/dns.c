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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "packets.h"
#include "vpcs.h"
#include "utils.h"
#include "dns.h"

extern int ctrl_c;

static int fmtstring(const char *name, char *buf);
static int dnsrequest(const char *name, char *data, int *namelen);
static int dnsparse(struct packet *m, const char *data, int dlen, u_int *ip);

int hostresolv(pcs *pc, const char *name, u_int *ip)
{
	sesscb cb;
	struct packet *m;
	char data[512];
	int dlen;
	u_int gip;
	struct in_addr in;
	struct timeval tv;
	int ok;
	int namelen;
	int i;
	u_char mac[ETH_ALEN];
	char dname[64];
	
	if (!strchr(name, '.')) {
		if (pc->ip4.domain[0] != '\0')
			snprintf(dname, sizeof(dname), "%s.%s", name, pc->ip4.domain);
		else if (pc->ip4.dhcp.domain[0] != '\0')
			snprintf(dname, sizeof(dname), "%s.%s", name, pc->ip4.dhcp.domain);
	} else
		snprintf(dname, sizeof(dname), "%s", name);
		
	dlen = dnsrequest(dname, data, &namelen);
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

	for (i = 0; i < 2; i++) {
		if (pc->ip4.dns[i] == 0)
			continue;
	
	  	memset(&cb, 0, sizeof(sesscb));
	  	cb.data = data;
	  	cb.dsize = dlen;
	  	cb.proto = IPPROTO_UDP;
	  	cb.mtu = pc->ip4.mtu;
	  	cb.ipid =  time(0) & 0xffff;
	  	cb.ttl = TTL;
	  	cb.sip = pc->ip4.ip;
	  	cb.dip = pc->ip4.dns[i];
	  	cb.sport = (random() % (65000 - 1024)) + 1024;
		cb.dport = 53;
		memcpy(cb.smac, pc->ip4.mac, ETH_ALEN);
		memcpy(cb.dmac, mac, ETH_ALEN);
	
		m = packet(&cb);
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
				ok = dnsparse(m, data + sizeof(dnshdr), namelen, ip);
				free(m);
			}
			if (ok)
				return 1;
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

static int dnsrequest(const char *name, char *data, int *namelen)
{
	u_char buf[256];	
	dnshdr dh;
	int dlen = sizeof(dnshdr);
	int i;
	
	memset(&dh, 0, sizeof(dnshdr));
	dh.id = DNS_MAGIC;
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
  	data[dlen++] = 0x01;
  	/* IN class */
  	data[dlen++] = 0x00;
  	data[dlen++] = 0x01;
  	
	return dlen;
}

/* very simple DNS answer parser 
 * only search A record if exist, get IP address 
 * return 1 if host name was resolved.
 */
static int dnsparse(struct packet *m, const char *data, int dlen, u_int *cip)
{
	ethdr *eh;
	iphdr *ip;
	udpiphdr *ui;
	u_char *p;

	dnshdr *dh;
	u_short *sp;
	int rlen;
	int iplen;
	int c;
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
	if (dh->id != 0x424c)
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
		
	if (dh->query == 0 || dh->answer == 0)
		return 0;	
		
	p = (u_char *)(dh + 1);

	/* not my query */
	if (memcmp(p, data, dlen))
		return 0;

	/* skip type and class */
	p += dlen + 4;
	
	/* skip offset pointer, 
	 * normal is 0xc00c, 11 00000000001100, 11-pointer, 0c-offset from dnshdr 
	*/
	p += 2;
	while (p - (u_char *)ip < iplen) {
		sp = (u_short *)p;
		/* A record */
		if (*sp == 0x0100 && *(sp + 1) == 0x0100) {
			p += 2 + 2 + 4;
			sp = (u_short *)p;
			if (*sp == 0x0400) {
				*cip = ((u_int *)(p + 2))[0];
				return 1;
			}
		} else {
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
/* end of file */

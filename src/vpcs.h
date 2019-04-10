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

#ifndef _VPC_H_
#define _VPC_H_

#include "queue.h"
#include "globle.h"
#include "ip.h"

#define MAX_LEN  (128)

typedef struct {
	u_char mac[6];
	u_int ip;
	int timeout;
} ipmac;

typedef struct {
	u_int svr;
	u_char smac[6];
	u_int timetick;
	u_int lease;
	u_int renew;
	u_int rebind;
	u_int ip;
	u_int netmask;
	u_int gw;
	u_int xid;
	u_int dns[2];
	char domain[64];
} dhcp;

typedef struct {
	int timeout;
	ip6	ip;
	int cidr;
	u_char mac[6];
} ip6mac;

typedef struct {
	int timeout;
	ip6 ip;
	u_int32_t mtu;
} ip6mtu;

typedef struct {
	ip6	ip;		/* local host ip6 */
	int cidr;		/* local host ip6 netmask */
	int type;		/* 1:eui-64 2:locallink */
#define IP6TYPE_NONE 0	
#define IP6TYPE_EUI64 1
#define IP6TYPE_LOCALLINK 2
	u_char gmac[6];		/* destination host mac */
	ip6 dns[2];		/* local host ip6 */
} hipv6;
	
typedef struct {
	int dynip;              /* dynamic IP (dhcp) */
	u_int ip;		/* local host ip */
	int cidr;		/* local host ip netmask */
	u_char mac[6];		/* local host mac */
	u_int gw;		/* default gateway ip */
	u_char gmac[6];		/* destination host mac */
	dhcp dhcp;				
	u_int lease;		/* dhcp lease time */
	u_int dns[2];		/* dns server */
	char domain[64];	/* search domain name */
	int flags;
#define IPF_FRAG 0x1
} hipv4;

#define MAX_NAMES_LEN	(12)
#define MAX_SESSIONS	1000
#define POOL_SIZE	32
#define POOL_TIMEOUT	120

typedef struct {
	int id;				/* pc id */
	char xname[MAX_NAMES_LEN + 1];	/* pc name */
	pthread_t outid;		/* ip output pthread id */
	pthread_t rpid;			/* reader pthread id */
	pthread_t wpid;			/* writer pthread id */	
	int dmpflag;			/* dump flag */
	FILE *dmpfile;			/* dump file pointer */
	int bgjobflag;			/* backgroun job flag */
	int fd;				/* device handle */
	int rfd;			/* client handle if in the udp mode		 */	
	int lport;			/* local udp port */
	int rport;			/* remote udp port */
	u_int rhost;			/* remote host */
	struct pq bgiq;			/* background input queue */
	struct pq bgoq;			/* background output queue */
	struct pq iq;			/* queue */
	struct pq oq;			/* queue */
	pthread_mutex_t locker;		/* mutex */
	sesscb mscb;			/* opened by app */
	sesscb sesscb[MAX_SESSIONS];	/* tcp session pool */
	tcpcb6 tcpcb6[MAX_SESSIONS];	/* tcp6 session pool */
	ipmac ipmac4[POOL_SIZE];	/* arp pool */
	ip6mac ipmac6[POOL_SIZE];	/* neighbor pool */
	ip6mtu ip6mtu[POOL_SIZE];	/* mtu6 record */
	hipv4 ip4;
	int ip6auto;
	hipv6 ip6;
	hipv6 link6;
	int mtu;
} pcs;

struct echoctl {
	int enable;
	int fgcolor;
	int bgcolor;
};

pcs vpc[MAX_NUM_PTHS];

#define delay_ms(s) usleep(s * 1000)

void parse_cmd(char *cmdstr);

#endif

/* end of file */

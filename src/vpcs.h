/*
 * Copyright (c) 2007-2013, Paul Meng (mirnshi@gmail.com)
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

#define ARP_SIZE 10
#define NB_SIZE 10

typedef struct {
	u_int svr;
	u_char smac[6];
	u_int lease;
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
	ip6	ip;			/* local host ip6 */
	int cidr;			/* local host ip6 netmask */
	int type;			/* 1:eui-64 2:locallink */
#define IP6TYPE_NONE 0	
#define IP6TYPE_EUI64 1
#define IP6TYPE_LOCALLINK 2
	u_char gmac[6];			/* destination host mac */
	int mtu;
} hipv6;
	
typedef struct {
	int dynip;              /* dynamic IP (dhcp) */
	u_int ip;		/* local host ip */
	int cidr;		/* local host ip netmask */
	u_char mac[6];		/* local host mac */
	u_long gw;		/* default gateway ip */
	u_char gmac[6];		/* destination host mac */
	dhcp dhcp;				
	u_int lease;		/* dhcp lease time */
	u_int dns[2];		/* dns server */
	char domain[64];	/* search domain name */
	int mtu;
} hipv4;

#define MAX_NAMES_LEN	(6)	
typedef struct {
	int id;				/* pc id */
	char xname[MAX_NAMES_LEN + 1];	/* pc name */
	pthread_t rpid;                 /* reader pthread id */
	pthread_t wpid;                 /* writer pthread id */	
	int dmpflag;			/* dump flag */
	//int sock;			/* a command is running (socket is opened) */
	int fd;				/* device handle */
	int rfd;			/* client handle if in the udp mode		 */	
	int lport;			/* local udp port */
	int rport;			/* remote udp port */
	u_int rhost;			/* remote host */
	struct pq iq;			/* queue	 */
	struct pq oq;			/* queue */
	pthread_mutex_t locker;		/* mutex */
	sesscb mscb;			/* opened by app */
	sesscb sesscb[NUM_PTHS];	/* tcp session pool */
	tcpcb6 tcpcb6[NUM_PTHS];	/* tcp6 session pool */
	ipmac ipmac4[ARP_SIZE];		/* arp pool */
	ip6mac ipmac6[NB_SIZE];		/* neighbor pool */
	hipv4 ip4;
	int ip6auto;
	hipv6 ip6;
	hipv6 link6;
} pcs;

pcs vpc[NUM_PTHS];

#define delay_ms(s) usleep(s * 1000)

void parse_cmd(char *cmdstr);

#endif

/* end of file */

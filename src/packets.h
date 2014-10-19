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

#ifndef _PACKETS_H_
#define _PACKETS_H_

#include "vpcs.h"
#include "ip.h"

struct ipfrag {
	struct ipfrag *prev;
	struct ipfrag *next;
	u_int  expired;
	u_int  flags:4,         /* first and last fragments */
	       nfrags:4;        /* count of fragments */
#define FF_HEAD 1
#define FF_TAIL  2
	u_char  proto;            /* protocol of this fragment */
	u_short id;           /* sequence id for reassembly */
	u_int sip;
	u_int dip;
	struct packet *m;          /* to ip headers of fragments */
};

struct ipfrag_head {
	struct ipfrag *head;
	struct ipfrag *tail;
	pthread_mutex_t locker;
};

#define PAYLOAD56 56

void init_ipfrag(void);
struct packet *ipreass(struct packet *m);
struct packet *ipfrag(struct packet *m0, int mtu);

struct packet *packet(sesscb *sesscb);
int upv4(pcs *pc, struct packet **pkt);
int response(struct packet *pkt, sesscb *sesscb);
int arpResolve(pcs *pc, u_int ip, u_char *dmac);
int host2ip(pcs *pc, const char *name, u_int *ip);
void fix_dmac(pcs *pc, struct packet *m);

#endif

/* end of file */

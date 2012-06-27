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

#ifndef _PACKETS6_H_
#define _PACKETS6_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "vpcs.h"
#include "ip.h"

#define ETHER_MAP_IPV6_MULTICAST(ip6addr, enaddr)                       \
/* struct       in6_addr *ip6addr; */                                   \
/* u_char       enaddr[ETHER_ADDR_LEN]; */                              \
{                                                                       \
        (enaddr)[0] = 0x33;                                             \
        (enaddr)[1] = 0x33;                                             \
        (enaddr)[2] = ((u_char *)ip6addr)[12];                          \
        (enaddr)[3] = ((u_char *)ip6addr)[13];                          \
        (enaddr)[4] = ((u_char *)ip6addr)[14];                          \
        (enaddr)[5] = ((u_char *)ip6addr)[15];                          \
}


int upv6(pcs *pc, struct packet *m);

struct packet *packet6(sesscb *sesscb);

int response6(struct packet *pkt, sesscb *sesscb);
struct packet *tcp6Reply(struct packet *m0, sesscb *cb);
int tr6Reply(struct packet *m, ip6 *mip, ip6 *dip);

u_char *nbDiscovery(pcs *pc, ip6 *dst);
struct packet* nbr_sol(pcs *pc);

#endif

/* end of file */

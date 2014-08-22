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

#ifndef _DHCP_H_
#define _DHCP_H_
                                
#define DHCP_SNAME_LEN          (64)
#define DHCP_FILE_LEN           (128)
#define DHCP_OPTION_LEN		(128)

typedef struct dhcp4_packet {
	char  op;				
	char  htype;				/* ether:1 */
	char  hlen;				/* hardware address length:6 */
	char  hops;				/* number of relay agent, same lan:0 */
	u_int xid;				/* transaction id */
	u_short secs;				/* seconds since client start */
	u_short flags;				/* flags: 0 */
	u_int ciaddr;				/* client ip */
	u_int yiaddr;				/* your client ip */
	u_int siaddr;				/* server ip */
	u_int giaddr;				/* relay server ip */
	u_char chaddr[16];			/* client hardware address */
	char sname[DHCP_SNAME_LEN];		/* Server name */
	char file[DHCP_FILE_LEN];		/* file name */
	u_char options[DHCP_OPTION_LEN];	/* dummny options */
} dhcp4_hdr;

#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNAK         6
#define DHCPRELEASE     7
#define DHCPINFORM      8

#define DHO_PAD                         0
#define DHO_SUBNET_MASK                 1
#define DHO_TIME_OFFSET                 2
#define DHO_ROUTERS                     3
#define DHO_DNS                         6
#define DHO_HOST_NAME                   12
#define DHO_DOMAIN                      15
#define DHO_DHCP_REQUESTED_ADDRESS      50
#define DHO_DHCP_LEASE_TIME             51
#define DHO_DHCP_MESSAGE_TYPE           53
#define DHO_DHCP_SERVER_IDENTIFIER      54
#define DHO_DHCP_PARAMETER_REQUEST_LIST 55
#define DHO_DHCP_MESSAGE                56
#define DHO_DHCP_RENEWAL_TIME           58
#define DHO_DHCP_REBIND_TIME            59
#define DHO_DHCP_CLIENT_IDENTIFIER      61
#define DHO_TFTP_SERVER                 150

#define DHO_END                         255

#define DHCP4_PSIZE (512)

struct packet * dhcp4_discover(pcs *pc, int renew);
struct packet * dhcp4_request(pcs *pc);
struct packet * dhcp4_renew(pcs *pc);
struct packet * dhcp4_release(pcs *pc);
int isDhcp4_Offer(pcs *pc, struct packet *m);
int isDhcp4_packer(pcs *pc, struct packet *m);

int dmp_dhcp(pcs *pc, const struct packet *m);

int dhcp_renew(pcs *pc);
int dhcp_rebind(pcs *pc);
int dhcp_enq(pcs *pc, const struct packet *m);


#endif
/* end of file */

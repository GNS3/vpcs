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
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "globle.h"
#include "command6.h"
#include "utils.h"
#include "vpcs.h"
#include "dev.h"
#include "packets6.h"
#include "queue.h"
#include "tcp.h"
#include "help.h"

extern int pcid;
extern int devtype;
extern int ctrl_c;
extern u_int time_tick;
extern int num_pths;

int run_net6(char *cmdstr);

#include "inet6.h"
extern int vinet_pton6(int af, const char * __restrict src, void * __restrict dst);
extern const char *vinet_ntop6(int af, const void *src, char *dst, socklen_t cnt);

/* ping host , char *cmdstr*/
int run_ping6(int argc, char **argv)
{
	pcs *pc = &vpc[pcid];
	struct in6_addr ipaddr;
	struct packet *m = NULL;
	int i;
	char *p;
	char proto_seq[16];
	int count = 5;

	printf("\n");
	
	i = 2;
	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "-c")) {
			if ((i + 1) < argc && digitstring(argv[i + 1]))
				count = atoi(argv[i + 1]);
			break;
		}
	}
	
	if (vinet_pton6(AF_INET6, argv[1], &ipaddr) != 1) {
		printf("Invalid address: %s\n", argv[1]);
		return 0;
	}
	
	memcpy(pc->mscb.dip6.addr8, ipaddr.s6_addr, 16);
	if (pc->mscb.dip6.addr16[0] != IPV6_ADDR_INT16_ULL)
		memcpy(pc->mscb.sip6.addr8, pc->ip6.ip.addr8, 16);
	else
		memcpy(pc->mscb.sip6.addr8, pc->link6.ip.addr8, 16);
		
	/* ping self, discard options */	
	if (IP6EQ(&pc->mscb.sip6, &pc->mscb.dip6)) {
		i = 1;
		while (i < 6) {
			printf("%s icmp_seq=%d ttl=%d time=0.001 ms\n", 
			    argv[1], i++, pc->mscb.ttl);
			delay_ms(1);
		}
		return 1;
	}
	
	/* find destination */
	p = (char*)nbDiscovery(pc, &pc->mscb.dip6);	
	if (p == NULL) {
		printf("host (%s) not reachable\n", argv[1]);
		return 0;
	}
	memcpy(pc->mscb.dmac, p, 6);
	
	if (pc->mscb.proto == IPPROTO_ICMP) {
		pc->mscb.proto = IPPROTO_ICMPV6;
		strcpy(proto_seq, "icmp6_seq");
	} else if (pc->mscb.proto == IPPROTO_TCP) {
		strcpy(proto_seq, "tcp6_seq");
	} else if (pc->mscb.proto == IPPROTO_UDP) {
		strcpy(proto_seq, "udp6_seq");
	}	

	if (pc->mscb.proto == IPPROTO_TCP && pc->mscb.flags == 0) {	
		i = 0;
		while ((i++ < count || count == -1) && !ctrl_c) {
			struct timeval ts0, ts;
			int usec;
			int k;
			int dsize = pc->mscb.dsize;
			int traveltime = 1;
			
			if (i > 1) {
				printf("wait %dms\n", pc->mscb.waittime);
				delay_ms(pc->mscb.waittime);
			}

			/* clear the input queue */
			while ((m = deq(&pc->iq)) != NULL);
			/* connect the remote */
			gettimeofday(&(ts), (void*)0);
			k = tcp_open(pc, IPV6_VERSION);
			
			/* restore data size */
			pc->mscb.dsize = dsize;
			
			gettimeofday(&(ts0), (void*)0);
			usec = (ts0.tv_sec - ts.tv_sec) * 1000000 + ts0.tv_usec - ts.tv_usec;
			if (usec < 0)
				usec = 0;
			if (k == 0) {
				printf("Connect   %d@%s timeout\n", pc->mscb.dport, argv[1]);
				continue;
			} else if (k == 2) {
				char buf[INET6_ADDRSTRLEN + 1];
				
				memset(buf, 0, sizeof(buf));
				vinet_ntop6(AF_INET6, &pc->mscb.rdip6, buf, INET6_ADDRSTRLEN + 1);
				
				printf("*%s %s=%d ttl=%d time=%.3f ms", 
				    buf, proto_seq, i++, pc->mscb.rttl, usec / 1000.0);
						
				
				printf(" (ICMP type:%d, code:%d, %s)\n", 
				    pc->mscb.icmptype, pc->mscb.icmpcode,
				    icmpTypeCode2String(6, pc->mscb.icmptype, pc->mscb.icmpcode));

				continue;
			} else if (k == 3) {
				printf("Connect   %d@%s RST returned\n", pc->mscb.dport, argv[1]);
				continue;	
			}
			
			printf("Connect   %d@%s seq=%d ttl=%d time=%.3f ms\n", 
			    pc->mscb.dport, argv[1], i, pc->mscb.rttl, usec / 1000.0);
			
			traveltime = 0.6 * usec / 1000;
			/* send data */
			delay_ms(traveltime);		
			gettimeofday(&(ts), (void*)0);
			k = tcp_send(pc, IPV6_VERSION);
			if (k == 0) {
				printf("SendData  %d@%s timeout\n", pc->mscb.dport, argv[1]);
				continue;
			}
			
			gettimeofday(&(ts0), (void*)0);
			usec = (ts0.tv_sec - ts.tv_sec) * 1000000 + ts0.tv_usec - ts.tv_usec;
			if (usec < 0)
				usec = 0;
			printf("SendData  %d@%s seq=%d ttl=%d time=%.3f ms\n", 
			    pc->mscb.dport, argv[1], i, pc->mscb.rttl, usec / 1000.0);
			
			/* close */
			if (k != 2)
				delay_ms(traveltime);
			
			gettimeofday(&(ts), (void*)0);
			k = tcp_close(pc, IPV6_VERSION);
			if (k == 0) {
				printf("Close     %d@%s timeout\n", pc->mscb.dport, argv[1]);
				continue;
			}
			
			gettimeofday(&(ts0), (void*)0);
			usec = (ts0.tv_sec - ts.tv_sec) * 1000000 + ts0.tv_usec - ts.tv_usec;
			if (usec < 0)
				usec = 0;
			printf("Close     %d@%s seq=%d ttl=%d time=%.3f ms\n", 
			    pc->mscb.dport, argv[1], i, pc->mscb.rttl, usec / 1000.0);

		}
	} else {
		i = 1;
		while ((i <= count || count == -1) && !ctrl_c) {
			struct packet *p;
			struct timeval tv;
			int usec;
			int respok = 0;

			if (i > 1)
				delay_ms(pc->mscb.waittime);
			
		new_mtu6:
			pc->mscb.sn = i;
			pc->mscb.timeout = time_tick;
				
			m = packet6(pc);
			
			if (m == NULL) {
				printf("out of memory\n");
				return false;
			}
			
			gettimeofday(&(tv), (void*)0);
			enq(&pc->oq, m);
		
			while (!timeout(tv, pc->mscb.waittime) && !ctrl_c) {
				delay_ms(1);
				respok = 0;	
				
				while ((p = deq(&pc->iq)) != NULL && !respok && 
				    !timeout(tv, pc->mscb.waittime) && !ctrl_c) {
					
					pc->mscb.icmptype = pc->mscb.icmpcode = 0; 
					respok = response6(p, &pc->mscb);
					usec = (p->ts.tv_sec - tv.tv_sec) * 1000000 +
					    p->ts.tv_usec - tv.tv_usec;
					if (usec < 0)
						usec = 0;	
					del_pkt(p);
					
					if (respok == 0)
						continue;
					
					tv.tv_sec = 0;

					if ((pc->mscb.proto == IPPROTO_ICMPV6 && 
					    pc->mscb.icmptype == ICMP6_ECHO_REPLY) ||
					    (pc->mscb.proto == IPPROTO_UDP && respok == IPPROTO_UDP)||
					    (pc->mscb.proto == IPPROTO_TCP && respok == IPPROTO_TCP)) {
						printf("%s %s=%d ttl=%d time=%.3f ms\n", argv[1], 
						    proto_seq, i++, pc->mscb.rttl, usec / 1000.0);
						break;
					}
						
					if (respok == IPPROTO_ICMPV6) {
						char buf[INET6_ADDRSTRLEN + 1];
						
						memset(buf, 0, sizeof(buf));
						vinet_ntop6(AF_INET6, &pc->mscb.rdip6, buf, 
						    INET6_ADDRSTRLEN + 1);
						
						printf("*%s %s=%d ttl=%d time=%.3f ms", 
						    buf, proto_seq, i, pc->mscb.rttl, usec / 1000.0);

						if (pc->mscb.icmptype == ICMP6_PACKET_TOO_BIG) {
							printf(" (new MTU %d)\n", pc->mscb.mtu);
							goto new_mtu6;
						}
						
						printf(" (ICMP type:%d, code:%d, %s)\n", 
						    pc->mscb.icmptype, pc->mscb.icmpcode,
						    icmpTypeCode2String(6, pc->mscb.icmptype, pc->mscb.icmpcode));
						i++;
						break;
					}
				}
			}
			if (!respok && !ctrl_c)
				printf("%s %s=%d timeout\n", argv[1], proto_seq, i++);
		} 
	}
	return 1;
}

int ipauto6(void)
{
	struct packet *m = NULL;
	char buf6[INET6_ADDRSTRLEN + 1];
	struct in6_addr ipaddr;
	int n = 100;
	
	m = nbr_sol(&vpc[pcid]);
	vpc[pcid].ip6auto = 1;
	if (m != NULL)
		enq(&vpc[pcid].oq, m);
	do {
		usleep(10000);
		if (vpc[pcid].ip6.ip.addr32[0] != 0 || vpc[pcid].ip6.ip.addr32[1] != 0 || 
		    vpc[pcid].ip6.ip.addr32[2] != 0 || vpc[pcid].ip6.ip.addr32[3] != 0) {	
			memset(buf6, 0, INET6_ADDRSTRLEN + 1);
			memcpy(ipaddr.s6_addr, vpc[pcid].ip6.ip.addr8, 16);
			vinet_ntop6(AF_INET6, &ipaddr, buf6, INET6_ADDRSTRLEN + 1);
			printf("GLOBAL SCOPE      : %s/%d\n", buf6, vpc[pcid].ip6.cidr);
			printf("ROUTER LINK-LAYER : ");
			PRINT_MAC(vpc[pcid].ip6.gmac);
			printf("\n");
			return 1;
		}
	} while (--n > 0);
	
	printf("No router answered ICMPv6 Router Solicitation\n");
	return 1;
}

int run_ipset6(int argc, char **argv)
{
	char buf[INET6_ADDRSTRLEN + 1];
	pcs *pc = &vpc[pcid];
	struct in6_addr ipaddr;
	int hasMask = 0;
	struct packet *m;
	int eui64 = 0;
	
	switch (argc) {
		case 1:
			run_show6(pc);
			return 1;
		case 4:
			if (!strcasecmp(argv[3], "eui-64") || !strcasecmp(argv[3], "eui64"))
				eui64 = 1;
		case 3:
			if (!strcasecmp(argv[2], "eui-64") || !strcasecmp(argv[2], "eui64"))
				eui64 = 1;
			else {
				pc->ip6.cidr = atoi(argv[2]);
				if (pc->ip6.cidr == 0)
					pc->ip6.cidr = 64;
				hasMask = 1;
			}
		case 2:
			if (!hasMask)
				pc->ip6.cidr = 64;
			if (vinet_pton6(AF_INET6, argv[1], &ipaddr) == 1) {
				vinet_ntop6(AF_INET6, &ipaddr, buf, INET6_ADDRSTRLEN + 1);
				memcpy(pc->ip6.ip.addr8, ipaddr.s6_addr, 16);
				
				if (eui64) {
					pc->ip6.ip.addr8[15] = pc->ip4.mac[5];
					pc->ip6.ip.addr8[14] = pc->ip4.mac[4];
					pc->ip6.ip.addr8[13] = pc->ip4.mac[3];
					pc->ip6.ip.addr8[12] = 0xfe;
					pc->ip6.ip.addr8[11] = 0xff;
					pc->ip6.ip.addr8[10] = pc->ip4.mac[2];
					pc->ip6.ip.addr8[9]  = pc->ip4.mac[1];
					pc->ip6.ip.addr8[8]  = (pc->ip4.mac[0] &0x20) ? 
						pc->ip4.mac[0] & 0xef : (pc->ip4.mac[0] | 0x20);
					pc->ip6.type = IP6TYPE_EUI64;
				} else
					pc->ip6.type = IP6TYPE_NONE;
					
				memset(buf, 0, INET6_ADDRSTRLEN + 1);
				memcpy(ipaddr.s6_addr, pc->ip6.ip.addr8, 16);
				vinet_ntop6(AF_INET6, &ipaddr, buf,INET6_ADDRSTRLEN + 1);
		
				printf("PC%d : %s/%d %s\n", pcid + 1, buf, pc->ip6.cidr,
				    (pc->ip6.type == IP6TYPE_EUI64) ? "eui-64" : "");
				m = nbr_sol(pc);
				
				if (m == NULL) {
					printf("out of memory\n");
					return 1;
				}
				enq(&pc->oq, m);
				
			} else {
				printf("Invalid ipv6 address.\n");
			}
			break;
		default:
			printf("Invalid.\n");
			break;
	}
	return 1;
}

int run_tracert6(int argc, char **argv)
{
	int i, j;
	struct packet *m;
	pcs *pc = &vpc[pcid];
	u_char *dmac;
	int ok = 0;
	struct in6_addr ipaddr;
	ip6 ip;
	int pktnum = 3;
	int count = 99;
	
	printf("\n");

	if (argc < 2) {
		printf("incompleted command.\n");
		return 0;
	}
	
	i = 2;
	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "-c")) {
			if ((i + 1) < argc && digitstring(argv[i + 1]))
				count = atoi(argv[i + 1]);
			break;
		}
	}
	if (count == 99 && digitstring(argv[argc - 1]))
		count = atoi(argv[argc - 1]);
				
	if (optind < argc && digitstring(argv[optind]))
		count = atoi(argv[optind]);
		
	if (count < 1 || count > 64)
		count = 64;
	
			
	if (vinet_pton6(AF_INET6, argv[1], &ipaddr) != 1) {
		printf("Invalid address: %s\n", argv[1]);
		return 0;
	}
	
	memcpy(pc->mscb.dip6.addr8, ipaddr.s6_addr, 16);
	if (pc->mscb.dip6.addr16[0] != IPV6_ADDR_INT16_ULL)
		memcpy(pc->mscb.sip6.addr8, pc->ip6.ip.addr8, 16);
	else
		memcpy(pc->mscb.sip6.addr8, pc->link6.ip.addr8, 16);
		
	dmac = nbDiscovery(pc, &ip);	
	if (dmac == NULL) {
		printf("host (%s) not reachable\n", argv[1]);
		return 0;
	}
	memcpy(pc->mscb.dmac, dmac, 6);
	printf("trace to %s, %d hops max\n", argv[1], count);
	
	/* send the udp packets */
	i = 1;
	while (i <= count && !ctrl_c) {
		struct packet *p;
		struct timeval tv;
		u_int usec;
		int k;
		
		printf("%2d ", i);
		for (j = 0; j < pktnum && !ctrl_c; j++) {			
			
			pc->mscb.ttl = i;
			m = packet6(pc);

			if (m == NULL) {
				printf("out of memory\n");
				return 0;
			}

			gettimeofday(&(tv), (void*)0);
			enq(&pc->oq, m);
			
			k = 0;
			
			while (!timeout(tv, pc->mscb.waittime) && !ctrl_c) {
				delay_ms(1);
				ok = 0;	

				while ((p = deq(&pc->iq)) != NULL && !ok &&
				    !timeout(tv, pc->mscb.waittime) && !ctrl_c) {
					ok = response6(p, &pc->mscb);
					usec = (p->ts.tv_sec - tv.tv_sec) * 1000000 + 
					    p->ts.tv_usec - tv.tv_usec;
						
					del_pkt(p);
					
					if (pc->mscb.icmptype == ICMP6_TIME_EXCEEDED || 
					    IP6EQ(&(pc->mscb.dip6), &(pc->mscb.rdip6))) {
						if (j == 0) {
							char buf[128];
						
							memcpy(ipaddr.s6_addr, pc->mscb.rdip6.addr8, 16);
							memset(buf, 0, 128);
							vinet_ntop6(AF_INET6, &ipaddr, buf, 
							    INET6_ADDRSTRLEN + 1);
							printf("%s ", buf);
						}
							
						printf("  %.3f ms", usec / 1000.0);fflush(stdout);
						
						tv.tv_sec = 0;

						break;
					} else if (pc->mscb.icmptype == ICMP6_DST_UNREACH || 
					    pc->mscb.icmptype == ICMP6_DST_UNREACH_NOPORT) {
						if (j == 0) {
							char buf[128];
						
							memcpy(ipaddr.s6_addr, pc->mscb.rdip6.addr8, 16);
							memset(buf, 0, 128);
							vinet_ntop6(AF_INET6, &ipaddr, buf, INET6_ADDRSTRLEN + 1);
							printf("*%s   %.3f ms (ICMP type:%d, code:%d, %s)\n", buf,
							    usec / 1000.0, pc->mscb.icmptype, pc->mscb.icmpcode,
							    icmpTypeCode2String(6, pc->mscb.icmptype, pc->mscb.icmpcode));
						}

						tv.tv_sec = 0;

						return 1;
					}
				}
				k++;
			}
			if (!ok && !ctrl_c)
				printf("  *");
		}
		printf("\n");
		i++;
		if (pc->mscb.icmptype  == ICMP6_DST_UNREACH)
			break;
	}

	return 1;
}

int run_show6(pcs *pc)
{
	char buf[INET6_ADDRSTRLEN + 1];
	struct in6_addr ipaddr;
	
	memset(buf, 0, INET6_ADDRSTRLEN + 1);
	memcpy(ipaddr.s6_addr, pc->link6.ip.addr8, 16);
	vinet_ntop6(AF_INET6, &ipaddr, buf,INET6_ADDRSTRLEN + 1);
	printf("       %s/%d\n", buf, pc->link6.cidr); 
		
	if (pc->ip6.ip.addr32[0] != 0 || pc->ip6.ip.addr32[1] != 0 || 
	    pc->ip6.ip.addr32[2] != 0 || pc->ip6.ip.addr32[3] != 0) {	
		memset(buf, 0, INET6_ADDRSTRLEN + 1);
		
		memcpy(ipaddr.s6_addr, pc->ip6.ip.addr8, 16);
		vinet_ntop6(AF_INET6, &ipaddr, buf,INET6_ADDRSTRLEN + 1);

		printf("       %s/%d %s\n", buf, pc->ip6.cidr, 
		    (pc->ip6.type == IP6TYPE_EUI64) ? "eui-64" : "");
	}
	
	return 1;
}

int show_ipv6(int argc, char **argv)
{
	int i, j, k;
	char buf[128];
	char buf6[INET6_ADDRSTRLEN + 1];
	struct in6_addr ipaddr;
	struct in_addr in;
	int off1, off2, off3;
	int max6 = 0;
	int id = -1;
	
	printf("\n");
	if (argc == 3) {
		if (!strncmp(argv[2], "all", strlen(argv[2]))) {
			for (i = 0; i < num_pths; i++) {
				if (vpc[i].ip6.ip.addr32[0] != 0 || vpc[i].ip6.ip.addr32[1] != 0 || 
				    vpc[i].ip6.ip.addr32[2] != 0 || vpc[i].ip6.ip.addr32[3] != 0) {
					memset(buf6, 0, INET6_ADDRSTRLEN + 1);
					
					memcpy(ipaddr.s6_addr, vpc[i].ip6.ip.addr8, 16);
					vinet_ntop6(AF_INET6, &ipaddr, buf6, INET6_ADDRSTRLEN + 1);
		
					j = sprintf(buf, "%s/%d", buf6, vpc[i].ip6.cidr);
					if (j > max6)
						max6 = j;
				}
			}
	
			memset(buf, 0, sizeof(buf));
			memset(buf, ' ', sizeof(buf) - 1);
			off1 = 7;
			off2 = off1 + max6 + 2;
			off3 = off2 + 17 + 2;
			
			j = sprintf(buf, "NAME");
			buf[j] = ' ';
			j = sprintf(buf + off1, "IP/MASK");
			buf[j + off1] = ' ';
			j = sprintf(buf + off2, "ROUTER LINK-LAYER");
			buf[j + off2] = ' ';
			j = sprintf(buf + off3, "MTU");
			printf("%s\n", buf);

			for (i = 0; i < num_pths; i++) {
				memset(buf, 0, sizeof(buf));
				memset(buf, ' ', sizeof(buf) - 1);
				if (strcmp(vpc[i].xname, "VPCS")== 0)
					j = sprintf(buf, "%s%d", vpc[i].xname, i + 1);
				else
					j = sprintf(buf, "%s", vpc[i].xname);
				buf[j] = ' ';
						
				memset(buf6, 0, INET6_ADDRSTRLEN + 1);
				memcpy(ipaddr.s6_addr, vpc[i].link6.ip.addr8, 16);
				vinet_ntop6(AF_INET6, &ipaddr, buf6, INET6_ADDRSTRLEN + 1);
				sprintf(buf + 7, "%s/%d", buf6, vpc[i].link6.cidr); 
				j = printf("%s", buf);
				
				if (vpc[i].ip6.ip.addr32[0] != 0 || vpc[i].ip6.ip.addr32[1] != 0 || 
				    vpc[i].ip6.ip.addr32[2] != 0 || vpc[i].ip6.ip.addr32[3] != 0) {	
					memset(buf6, 0, INET6_ADDRSTRLEN + 1);
					
					memcpy(ipaddr.s6_addr, vpc[i].ip6.ip.addr8, 16);
					vinet_ntop6(AF_INET6, &ipaddr, buf6, INET6_ADDRSTRLEN + 1);
			
					printf("\n");
					for (k = 0; k < off1; k++)
						printf(" ");
					j = printf("%s/%d", buf6, vpc[i].ip6.cidr);
					j += off1;
					
				}
				for (k = j; k < off2; k++)
					printf(" ");
				
				if (etherIsZero(vpc[i].ip6.gmac)) {
					j = sprintf(buf, "                 ");
				} else {
					j = 0;
					for (k = 0; k < 6; k++)
						j += sprintf(buf + k * 3, "%2.2x:", vpc[i].ip6.gmac[k]);
					
				}
				buf[j - 1] = ' ';
				if (vpc[i].mtu)
					j += sprintf(buf + j, " %4.4d", vpc[i].mtu);
				else
					j += sprintf(buf + j, "     ");
				//buf[j] = ' ';
				printf("%s\n", buf);
			}
			return 1;
		}
		if (strlen(argv[2]) == 1 && digitstring(argv[2])){
			id = argv[2][0] - '1';
		}	
	} else if (argc == 2)
		id = pcid;
	
	if (id != -1) {
		printf("NAME              : %s[%d]\n", vpc[id].xname, id + 1);
		
		printf("LINK-LOCAL SCOPE  : ");
		memset(buf6, 0, INET6_ADDRSTRLEN + 1);
		memcpy(ipaddr.s6_addr, vpc[id].link6.ip.addr8, 16);
		vinet_ntop6(AF_INET6, &ipaddr, buf6, INET6_ADDRSTRLEN + 1);
		printf("%s/%d\n", buf6, vpc[id].link6.cidr); 
		
		printf("GLOBAL SCOPE      : ");
		
		if (vpc[id].ip6.ip.addr32[0] != 0 || vpc[id].ip6.ip.addr32[1] != 0 || 
		    vpc[id].ip6.ip.addr32[2] != 0 || vpc[id].ip6.ip.addr32[3] != 0) {	
			memset(buf6, 0, INET6_ADDRSTRLEN + 1);
			memcpy(ipaddr.s6_addr, vpc[id].ip6.ip.addr8, 16);
			vinet_ntop6(AF_INET6, &ipaddr, buf6, INET6_ADDRSTRLEN + 1);
			printf("%s/%d", buf6, vpc[id].ip6.cidr);
		}
		printf("\n");		
		printf("ROUTER LINK-LAYER : ");
		if (!etherIsZero(vpc[id].ip6.gmac)) 
			PRINT_MAC(vpc[id].ip6.gmac);
		printf("\n");
		printf("MAC               : ");
		PRINT_MAC(vpc[id].ip4.mac);
		printf("\n");
		printf("LPORT             : %d\n", vpc[id].lport);
		in.s_addr = vpc[id].rhost;
		printf("RHOST:PORT        : %s:%d\n", inet_ntoa(in), vpc[id].rport);
		printf("MTU:              : ");
		if (vpc[id].mtu)
			printf("%d", vpc[id].mtu);
		printf("\n");
		return 1;
	}

	argv[argc - 1 ] = "?";
	help_show(argc, argv);

	return 1;
}

void show_pc_mtu6(pcs *pc)
{
	int i;
	char buf6[INET6_ADDRSTRLEN + 1];
	struct in6_addr ipaddr;

	int empty = 1;

	for (i = 0; i < POOL_SIZE; i++) {
		if (IP6ZERO(&(pc->ip6mtu[i].ip)))
			continue;
			
		if (time_tick - pc->ip6mtu[i].timeout > POOL_TIMEOUT)
			continue;

		memset(buf6, 0, INET6_ADDRSTRLEN + 1);
		memcpy(ipaddr.s6_addr, pc->ip6mtu[i].ip.addr8, 16);
		vinet_ntop6(AF_INET6, &ipaddr, buf6, INET6_ADDRSTRLEN + 1);
	
		printf("%5d\t%3d\t%s/%d\n", pc->ip6mtu[i].mtu, 
		    POOL_TIMEOUT - (time_tick - pc->ip6mtu[i].timeout), 
		    buf6, pc->link6.cidr); 
			
		empty = 0;
	}
	if (empty)
		printf("IPV6 MTU table is empty\n");
}

int show_mtu6(int argc, char **argv)
{
	pcs *pc;
	int si;

	printf("\n");
	
	if (argc == 3) {
		if (!strncmp(argv[2], "all", strlen(argv[2]))) {
			for (si = 0; si < num_pths; si++) {
				pc = &vpc[si];
				printf("%s[%d]:\n", pc->xname, si + 1);
				show_pc_mtu6(pc);
			}
			return 1;	
		} else if (strlen(argv[2]) == 1 && digitstring(argv[2])) {
			si = atoi(argv[2]) - 1;
			if (si < 0) {
				printf("Invalid ID\n");
				return 1;
			}
		} else {
			printf("Invalid ID\n");
			return 1;
		}
	} else {
		si = pcid;
	}
	if (si != pcid)
		printf("%s[%d]:\n", vpc[si].xname, si + 1);
	
	pc = &vpc[si];
	show_pc_mtu6(pc);
	
	return 1;
}

int run_nb6(int argc, char **argv)
{
	pcs *pc = &vpc[pcid];
	char buf[INET6_ADDRSTRLEN + 1];
	struct in6_addr ipaddr;
	int i, j;
	
	printf("\n");
	for (i = 0; i < POOL_SIZE; i++) {
		if (pc->ipmac6[i].timeout > 0) {
			for (j = 0; j < 6; j++)
				sprintf(buf + j * 3, "%2.2x:", pc->ipmac6[i].mac[j]);
			buf[17] = '\0';
			printf("%s", buf);
					
			memset(buf, 0, INET6_ADDRSTRLEN + 1);
			memcpy(ipaddr.s6_addr, pc->ipmac6[i].ip.addr8, 16);
			vinet_ntop6(AF_INET6, &ipaddr, buf,INET6_ADDRSTRLEN + 1);
			printf("   %s/%d\n", buf, pc->ipmac6[i].cidr); 
		}
	}
	return 1;
}

void locallink6(pcs *pc)
{
	pc->link6.ip.addr8[15] = pc->ip4.mac[5];
	pc->link6.ip.addr8[14] = pc->ip4.mac[4];
	pc->link6.ip.addr8[13] = pc->ip4.mac[3];
	pc->link6.ip.addr8[12] = 0xfe;
	pc->link6.ip.addr8[11] = 0xff;
	pc->link6.ip.addr8[10] = pc->ip4.mac[2];
	pc->link6.ip.addr8[9]  = pc->ip4.mac[1];
	pc->link6.ip.addr8[8]  = (pc->ip4.mac[0] ^ 0x2);

	pc->link6.ip.addr8[1] = 0x80;
	pc->link6.ip.addr8[0] = 0xfe;
	
	pc->link6.cidr = 64;
	pc->link6.type = IP6TYPE_LOCALLINK;

	/* try auto-configure stateless */	
	struct packet *m = nbr_sol(pc);
		
	if (m != NULL)
		enq(&pc->oq, m);
}

void autoconf6(void)
{
	int i;
	struct packet *m = NULL;
	
	for (i = 0; i < num_pths; i++) {
		m = nbr_sol(&vpc[pcid]);	
		if (m != NULL)
			enq(&vpc[pcid].oq, m);
	}
}

const char *ip6Info(const int id)
{
	struct in6_addr ipaddr;
	static char buf[INET6_ADDRSTRLEN + 1];
	char tmp[INET6_ADDRSTRLEN + 1];
	
	if (vpc[id].ip6.ip.addr32[0] != 0 || vpc[id].ip6.ip.addr32[1] != 0 || 
		vpc[id].ip6.ip.addr32[2] != 0 || vpc[id].ip6.ip.addr32[3] != 0) {
		memset(buf, 0, INET6_ADDRSTRLEN + 1);
		memcpy(ipaddr.s6_addr, vpc[id].ip6.ip.addr8, 16);
		vinet_ntop6(AF_INET6, &ipaddr, tmp, INET6_ADDRSTRLEN + 1);
		sprintf(buf, "ip %s/%d", tmp, vpc[id].ip6.cidr); 
	} else 
		return NULL;
		
	return buf;
}
/* end of file */

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
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "command.h"
#include "command6.h"
#include "utils.h"
#include "vpcs.h"
#include "dev.h"
#include "packets.h"
#include "packets6.h"
#include "queue.h"
#include "dhcp.h"
#include "tcp.h"
#include "dns.h"

extern int pcid;
extern int devtype;
extern int ctrl_c;
extern u_int time_tick;
extern int dmpflag;
extern u_long ip_masks[33];
extern int canEcho;
extern void clear_hist(void);

int run_arp(char *dummy)
{
	pcs *pc = &vpc[pcid];
	int i, j;
	struct in_addr in;
	char buf[18];
	u_char zero[ETH_ALEN] = {0};
	int empty = 1;
	
	for (i = 0; i < ARP_SIZE; i++) {
		if (pc->ipmac4[i].ip == 0)
			continue;
		if (memcmp(pc->ipmac4[i].mac, zero, ETH_ALEN) == 0)
			continue;
		if (time_tick - pc->ipmac4[i].timeout < 120) {
			for (j = 0; j < 6; j++)
				sprintf(buf + j * 3, "%2.2x:", pc->ipmac4[i].mac[j]);
			buf[17] = '\0';
			in.s_addr = pc->ipmac4[i].ip;
			printf("%s  %s\n", buf, inet_ntoa(in));
			empty = 0;
		}
	}
	if (empty)
		printf("arp table is empty\n");
	return 1;
}
			
/*
 *          1         2         3         4         5         6
 * 012345678901234567890123456789012345678901234567890123456789012345678
 * name   ip/cidr              gw                LPort   RHost:RPort
 */
int run_show(char *cmdstr)
{
	char *argv[3];
	int argc;
	int i, j, k;
	struct in_addr in;
	char buf[128];
	
	printf ("\n");

	memset(buf, 0, sizeof(buf));
	memset(buf, ' ', sizeof(buf) - 1);

	argc = mkargv(cmdstr, argv, 2);
	if (argc == 2) {
		if (!strncmp("arp", argv[1], strlen(argv[1]))) {
			run_arp(NULL);
			return 1;
		}
		/*       12345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5                 
		 */
		printf( "\033[1mshow [arp]\033[0m\n"
			"    arp     Show arp table\n");
		return 1;
	}
	switch(devtype) {
		case DEV_TAP:
			j = sprintf(buf, "NAME");
			buf[j] = ' ';
			j = sprintf(buf + 7, "IP/CIDR");
			buf[j + 7] = ' ';
			j = sprintf(buf + 28, "GATEWAY");
			buf[j + 28] = ' ';
			j = sprintf(buf + 64, "GATEWAY");
			printf("%s\n", buf);

			for (i = 0; i < NUM_PTHS; i++) {
				memset(buf, 0, sizeof(buf));
				memset(buf, ' ', sizeof(buf) - 1);
				
				if (strcmp(vpc[i].xname, "VPCS")== 0)
					j = sprintf(buf, "%s%d", vpc[i].xname, i + 1);
				else
					j = sprintf(buf, "%s", vpc[i].xname);
				buf[j] = ' ';
				
				in.s_addr = vpc[i].ip4.ip;
				j = sprintf(buf + 7, "%s/%d", inet_ntoa(in), vpc[i].ip4.cidr);
				
				buf[j + 7] = ' ';
				in.s_addr = vpc[i].ip4.gw;
				sprintf(buf + 28, "%s", inet_ntoa(in));
				
				for (k = 0; k < 6; k++)	
					sprintf(buf + 46 + k * 3, "%2.2x:", vpc[i].ip4.mac[k]);

				printf("%s\n", buf);
				run_show6(&vpc[i]);
			}
			break;
		case DEV_UDP:
			j = sprintf(buf, "NAME");
			buf[j] = ' ';
			j = sprintf(buf + 7, "IP/CIDR");
			buf[j + 7] = ' ';
			j = sprintf(buf + 28, "GATEWAY");
			buf[j + 28] = ' ';
			j = sprintf(buf + 46, "MAC");
			buf[j + 46] = ' ';
			j = sprintf(buf + 65, "LPORT");
			buf[j + 65] = ' ';
			j = sprintf(buf + 72, "RHOST:PORT");
			printf("%s\n", buf);
			
			for (i = 0; i < NUM_PTHS; i++) {
				memset(buf, 0, sizeof(buf));
				memset(buf, ' ', sizeof(buf) - 1);
				if (strcmp(vpc[i].xname, "VPCS")== 0)
					j = sprintf(buf, "%s%d", vpc[i].xname, i + 1);
				else
					j = sprintf(buf, "%s", vpc[i].xname);
				buf[j] = ' ';
				
				in.s_addr = vpc[i].ip4.ip;
				j = sprintf(buf + 7, "%s/%d", inet_ntoa(in), vpc[i].ip4.cidr);
				
				buf[j + 7] = ' ';
				in.s_addr = vpc[i].ip4.gw;
				j = sprintf(buf + 28, "%s", inet_ntoa(in));
				buf[j + 28] = ' ';
				
				for (k = 0; k < 6; k++)
					sprintf(buf + 46 + k * 3, "%2.2x:", vpc[i].ip4.mac[k]);
				buf[63] = ' ';
				buf[64] = ' ';
				j = sprintf(buf + 65, "%d", vpc[i].sport);
				buf[j + 65] = ' ';
				in.s_addr = vpc[i].rhost;
				j = sprintf(buf + 72, "%s:%d", inet_ntoa(in), vpc[i].rport);
				printf("%s\n", buf);
				run_show6(&vpc[i]);
			}
			break;
	}
	return 1;
}

/* ping host */
int run_ping(char *cmdstr)
{
	int i, j;
	int gip;
	struct in_addr in;
	char *argv[12];
	int argc;
	struct packet *m;
	pcs *pc = &vpc[pcid];

	char proto_seq[16];
	int count = 5;
	int interval = 1000;
	
	argc = mkargv(cmdstr, (char **)argv, 12);
	
	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5         6         7         8
		 */
		printf( "\n\033[1mping address [options]\033[0m, Ping the network host, Ctrl+C to stop the command\n"		       
			"    -1             ICMP mode, default\n"
			"    -2             UDP mode\n"
			"    -3             TCP mode\n"
			"    -P [protocol]  Same as above, setting ip protocol\n"
			"                    1 - icmp, 17 - udp, 6 - tcp\n"
			"    -c count       packet count \n"
			"    -l size        data size\n"
			"    -T ttl         set TTL, default 64\n"
			"    -s port        source port\n"
			"    -p port        destination port\n"
			"    -f flag        tcp head flag, |C|E|U|A|P|R|S|F|\n"
			"                             bits |7 6 5 4 3 2 1 0|\n"
			"    -t             send packet until interrupt by Ctrl+C\n"
			"    -i ms          wait 'ms' milliseconds between sending each packet\n"
			"    -w ms          wait 'ms' milliseconds to receive the response\n");
		return 0;
	}
	pc->mscb.frag = 0;
	pc->mscb.mtu = pc->ip4.mtu;
	pc->mscb.waittime = 1000;
	pc->mscb.ipid = time(0) & 0xffff;
	pc->mscb.seq = time(0);
	pc->mscb.proto = IPPROTO_ICMP;
	pc->mscb.ttl = TTL;
	pc->mscb.dsize = 64;
	pc->mscb.sport = (random() % (65000 - 1024)) + 1024;
	pc->mscb.dport = 7;
	pc->mscb.sip = pc->ip4.ip;
	memcpy(pc->mscb.smac, pc->ip4.mac, 6);
	strcpy(proto_seq, "icmp_seq");
	
	i = 2;
	while (i < argc) {
		int c;
		
		if (argv[i++][0] != '-')
			continue;
			
		c = argv[i - 1][1];
					
		switch (c) {
			case 'D':
				pc->mscb.frag = 1;
				break;
			case 'u':
				if (i < argc)
					pc->mscb.mtu = atoi(argv[i++]);
				if (pc->mscb.mtu < 576 || pc->mscb.mtu > 65535)
					pc->mscb.mtu = 1500;
			case '1':
				pc->mscb.proto = IPPROTO_ICMP;
				strcpy(proto_seq, "icmp_seq");
				break;
			case '2':
				pc->mscb.proto = IPPROTO_UDP;
				strcpy(proto_seq, "udp_seq");
				break;
			case '3':
				pc->mscb.proto = IPPROTO_TCP;
				strcpy(proto_seq, "tcp_seq");
				break;
			case 'P':
				if (i < argc) {
					int pro = atoi(argv[i++]);
					if (pro == IPPROTO_ICMP) {
						pc->mscb.proto = IPPROTO_ICMP;
						strcpy(proto_seq, "icmp_seq");
					} else if (pro == IPPROTO_UDP) {
						pc->mscb.proto = IPPROTO_UDP;
						strcpy(proto_seq, "udp_seq");
					} else if (pro == IPPROTO_TCP) {
						pc->mscb.proto = IPPROTO_TCP;
						strcpy(proto_seq, "tcp_seq");
					}
				}
				break;
			case 'c':
				if (i < argc)
					count = atoi(argv[i++]);
				break;
			case 'l':
				if (i < argc)
					pc->mscb.dsize = atoi(argv[i++]);
				break;
			case 'T':
				if (i < argc)
					pc->mscb.ttl = atoi(argv[i++]);
				break;
			case 's':
				if (i < argc)
					pc->mscb.sport = atoi(argv[i++]);
				break;
			case 'p':
				if (i < argc)
					pc->mscb.dport = atoi(argv[i++]);
				break;
			case 'a':
				if (i < argc)
					pc->mscb.aproto = atoi(argv[i]);
				break;
			case 'f':
				if (i < argc) {
					for (j = 0; j < strlen(argv[i]); j++) {
						switch (argv[i][j] | 0x20) {
							case 'c':
								pc->mscb.flags |= 0x80;
								break;
							case 'e':
								pc->mscb.flags |= 0x40;
								break;
							case 'u':
								pc->mscb.flags |= 0x20;
								break;
							case 'a':
								pc->mscb.flags |= 0x10;
								break;		
							case 'p':
								pc->mscb.flags |= 0x08;
								break;
							case 'r':
								pc->mscb.flags |= 0x04;
								break;
							case 's':
								pc->mscb.flags |= 0x02;
								break;
							case 'f':
								pc->mscb.flags |= 0x01;
								break;
							default:
								printf("Invalid options\n");
							return 0;
						}
					}	
					i++;
				}
				break;
			case 'i':
				if (i < argc)
					interval = atoi(argv[i++]);
				if (interval < 1)
					interval = 1000;
				break;	
			case 'w':
				if (i < argc)
					pc->mscb.waittime = atoi(argv[i++]);
				if (pc->mscb.waittime < 1)
					pc->mscb.waittime = 1000;
				break;
			case 't':
				count = -1;
				break;
			default:
				printf("Invalid options\n");
				return 0;
				break;	
		}
	}
	
	if (pc->mscb.winsize == 0)
		pc->mscb.winsize = 0xb68; /* 1460 * 4 */

	if (strchr(argv[1], ':') != NULL) {
		pc->mscb.mtu = pc->ip6.mtu;
		return run_ping6(count, interval, cmdstr);
	}	
	pc->mscb.dip = inet_addr(argv[1]);
	
	if (pc->mscb.dip == -1 || pc->mscb.dip == 0) {
		if (hostresolv(pc, argv[1], &(pc->mscb.dip)) == 0) {
			printf("Cannot resolve %s\n", argv[1]);
			return 0;
		} else {
			in.s_addr = pc->mscb.dip;
			printf("%s resolved to %s\n", argv[1], inet_ntoa(in)); 	
		}
	}
	
	/* find ether address of destination host or gateway */
	if (pc->mscb.dip == pc->ip4.ip) {
		i = 1;
		in.s_addr = pc->mscb.dip;
		while ((i <= count || count == -1) && !ctrl_c) {
			printf("%s icmp_seq=%d ttl=%d time=0.001 ms\n",
			    inet_ntoa(in), i++, pc->mscb.ttl);
			delay_ms(1);
		}
		return 1;
	}

redirect:		
	if (sameNet(pc->mscb.dip, pc->ip4.ip, pc->ip4.cidr))
		gip = pc->mscb.dip;
	else {
		if (pc->ip4.gw == 0) {
			printf("No gateway found\n");
			return 0;
		} else
		
		gip = pc->ip4.gw;
	}

	in.s_addr = pc->mscb.dip;
	
	/* try to get the ether address of the destination */
	if (!arpResolve(pc, gip, pc->mscb.dmac)) {
		in.s_addr = gip;
		printf("host (%s) not reachable\n", inet_ntoa(in));
		return 0;
	}

	if (pc->mscb.proto == IPPROTO_TCP && pc->mscb.flags == 0) {	
		i = 0;

		while ((i++ < count || count == -1) && !ctrl_c) {
			struct timeval ts0, ts;
			u_int usec;
			int k;
			int dsize = pc->mscb.dsize;
			int traveltime = 1;

			if (i > 1)
				delay_ms(pc->mscb.waittime);
			
			/* clear the input queue */
			while ((m = deq(&pc->iq)) != NULL);
			/* connect the remote */
			gettimeofday(&(ts), (void*)0);
			k = tcp_open(4);
			
			/* restore data size */
			pc->mscb.dsize = dsize;
			
			gettimeofday(&(ts0), (void*)0);
			usec = (ts0.tv_sec - ts.tv_sec) * 1000000 + ts0.tv_usec - ts.tv_usec;
			if (k == 0) {
				printf("Connect   %d@%s timeout\n", pc->mscb.dport, argv[1]);
				continue;
			} else if (k == 2) {
				struct in_addr din;
				din.s_addr = pc->mscb.rdip;
				printf("*%s %s=%d ttl=%d time=%.3f ms", 
				    inet_ntoa(din), proto_seq, i++, pc->mscb.rttl, usec / 1000.0);
						
				printf(" (ICMP type:%d, code:%d, %s)\n", 
				    pc->mscb.icmptype, pc->mscb.icmpcode, 
				    icmpTypeCode2String(4, pc->mscb.icmptype, pc->mscb.icmpcode));
				continue;
			} else if (k == 3) {
				printf("Connect   %d@%s RST returned\n", pc->mscb.dport, argv[1]);
				continue;	
			}
			printf("Connect   %d@%s seq=%d ttl=%d time=%.3f ms\n", 
			    pc->mscb.dport, argv[1], i, pc->mscb.rttl, usec / 1000.0);
			
			traveltime = 0.6 * usec / 1000;
			/* send data after 1.5 * time2travel */
			delay_ms(traveltime);
			gettimeofday(&(ts), (void*)0);
			k = tcp_send(4);
			if (k == 0) {
				printf("SendData  %d@%s timeout\n", pc->mscb.dport, argv[1]);
				continue;
			}
			
			gettimeofday(&(ts0), (void*)0);
			usec = (ts0.tv_sec - ts.tv_sec) * 1000000 + ts0.tv_usec - ts.tv_usec;
			printf("SendData  %d@%s seq=%d ttl=%d time=%.3f ms\n", 
			    pc->mscb.dport, argv[1], i, pc->mscb.rttl, usec / 1000.0);
			
			/* close after 1.5 * time2travel */
			if (k != 2)
				delay_ms(traveltime);
			gettimeofday(&(ts), (void*)0);	
			k = tcp_close(4);
			if (k == 0) {
				printf("Close     %d@%s timeout\n", pc->mscb.dport, argv[1]);
				continue;
			}
			
			gettimeofday(&(ts0), (void*)0);
			usec = (ts0.tv_sec - ts.tv_sec) * 1000000 + ts0.tv_usec - ts.tv_usec;
			printf("Close     %d@%s seq=%d ttl=%d time=%.3f ms\n", 
			    pc->mscb.dport, argv[1], i, pc->mscb.rttl, usec / 1000.0);
		}
	} else {
		i = 1;
		while ((i <= count || count == -1) && !ctrl_c) {
			struct packet *p = NULL;
			struct timeval tv;
			u_int usec;
			int respok = 0;

			pc->mscb.sn = i;
			pc->mscb.timeout = time_tick;
			
			m = packet(&pc->mscb);
			if (m == NULL) {
				printf("out of memory\n");
				return 0;
			}
        	
			dmp_packet(m, dmpflag);
			
			gettimeofday(&(tv), (void*)0);
			enq(&pc->oq, m);

			while (!timeout(tv, pc->mscb.waittime) && !ctrl_c) {
				delay_ms(1);
				respok = 0;
				
				while ((p = deq(&pc->iq)) != NULL && !respok && !ctrl_c) {

					pc->mscb.icmptype = pc->mscb.icmpcode = 0; 
					respok = response(p, &pc->mscb);
					usec = (p->ts.tv_sec - tv.tv_sec) * 1000000 + 
					    p->ts.tv_usec - tv.tv_usec;
					
					if (respok != 0)
						dmp_packet(p, dmpflag);
					
					del_pkt(p);
					
					if (respok == 0)
						continue;
					
					tv.tv_sec = 0;
					
					if ((pc->mscb.proto == IPPROTO_ICMP && pc->mscb.icmptype == ICMP_ECHOREPLY) ||
					    (pc->mscb.proto == IPPROTO_UDP && respok == IPPROTO_UDP) ||
					    (pc->mscb.proto == IPPROTO_TCP && respok == IPPROTO_TCP)) {
						printf("%s %s=%d ttl=%d time=%.3f ms\n", inet_ntoa(in), 
						    proto_seq, i++, pc->mscb.rttl, usec / 1000.0);
						break;
					}
						
					if (respok == IPPROTO_ICMP) {
						struct in_addr din;
						
						if (pc->mscb.icmptype == ICMP_REDIRECT && 
						    pc->mscb.icmpcode == ICMP_REDIRECT_NET) {
						    	din.s_addr = pc->ip4.gw;	
						    	printf("Redirect Network, gateway %s",  inet_ntoa(din));
						    	din.s_addr = pc->mscb.rdip;
						    	printf(" -> %s\n", inet_ntoa(din));
						    	
						    	pc->ip4.gw = pc->mscb.rdip;
						    	goto redirect;
						}
						din.s_addr = pc->mscb.rdip;
						printf("*%s %s=%d ttl=%d time=%.3f ms", 
						    inet_ntoa(din), proto_seq, i++, pc->mscb.rttl, usec / 1000.0);
							
						printf(" (ICMP type:%d, code:%d, %s)\n", 
						    pc->mscb.icmptype, pc->mscb.icmpcode,
						    icmpTypeCode2String(4, pc->mscb.icmptype, pc->mscb.icmpcode));
						break;
					}
				}
			}
			
			if (!respok && !ctrl_c)
				printf("%s %s=%d timeout\n", argv[1], proto_seq, i++);
				
			delay_ms(interval);
		}
	}

	return 1;
}

int run_dhcp(char *cmdstr)
{
	int i;
	struct packet *m;
	int ok;
	pcs *pc = &vpc[pcid];
	int ts[3] = {1, 3, 9};
	struct packet *p;
	struct in_addr in;
	char *argv[3];
	int argc;
	int opt_dump = 0;
	int opt_renew = 0;
	int opt_release = 0;
	u_char mac[6];
	
	argc = mkargv(cmdstr, (char**)argv, 3);
	
	i = 1;
	while (i < argc) {
		if (argv[i][0] != '-')
			continue;
		switch (argv[i][1]) {
			case 'd':
				opt_dump = 1;
				break;
			case 'r':
				opt_renew = 1;
				break;
			case 'x':
				opt_release = 1;
				break;
			case '?':
				printf( "\n\033[1mdhcp [options]\033[0m\n"		       
					"    -d   Show packet decode\n"
					"    -r   Renew DHCP lease\n"
					"    -x   Release DHCP lease\n");
				return 0;
		}
		i++;
	}
	if (opt_release) {
		m = dhcp4_release(pc);	
		if (m == NULL) {
			printf("out of memory\n");
			return 0;
		}
		if (opt_dump)
			dmp_dhcp(pc, m);
		enq(&pc->oq, m);
		pc->ip4.ip = 0;
		pc->ip4.cidr = 0;
		pc->ip4.gw = 0;
		return 0;
	}
	srand(time(0));
	pc->ip4.dhcp.xid = rand();
	
	/* discover */
	i = 0;
	ok = 0;
	while (i < 3 && !ok) {
		if (!opt_dump) {
			printf("D"); 
			fflush(stdout);
		}
		m = dhcp4_discover(pc, opt_renew);
		if (m == NULL) {
			printf("out of memory\n");
			return 0;
		}
		if (opt_dump)
			dmp_dhcp(pc, m);
		enq(&pc->oq, m);
		sleep(ts[i]);
		
		while ((p = deq(&pc->iq)) != NULL && !ok) {
			if ((ok = isDhcp4_Offer(pc, p))) {
				if (opt_dump)
					dmp_dhcp(pc, p);
				else {
					printf("O"); 
					fflush(stdout);
				}
			}
			free(p);
		}
		
		i++;
	}
	if (i == 3) {
		printf("\nCan't find dhcp server\n");
		return 1;
	}
	
	/* request */
	i = 0;
	ok = 0;
	while (i < 3 && !ok) {
		m = dhcp4_request(pc);
		if (m == NULL) {
			printf("out of memory\n");
			return 0;
		}
		if (opt_dump)
			dmp_dhcp(pc, m);
		else {
			printf("R"); 
			fflush(stdout);
		}
		enq(&pc->oq, m);
		sleep(1);
		
		while ((p = deq(&pc->iq)) != NULL && !ok) {
			if ((ok = isDhcp4_packer(pc, p))) {
				if (opt_dump)
					dmp_dhcp(pc, p);
				else {
					printf("A");
					fflush(stdout);
				}
			}
			free(p);
		}
		
		i++;
	}
	if (i == 3) {
		printf("\nCan't get ip address from dhcp server\n");
		return 1;
	}

	/* check ip address via gratuitous ARP */
	if (arpResolve(pc, pc->ip4.ip, mac) == 1) {
		in.s_addr = pc->ip4.ip;
		PRINT_MAC(mac);
		printf(" use my ip %s\n",  inet_ntoa(in));  	
		
		/* clear ip address */
		pc->ip4.ip = 0;
		pc->ip4.cidr = 0;
		pc->ip4.gw = 0;
		
		return 0;
	}
	 
	in.s_addr = pc->ip4.ip;
	if (!opt_dump)
		printf(", ");
	printf("IP %s/%d",  inet_ntoa(in), pc->ip4.cidr);
	if (pc->ip4.gw != 0) {
		in.s_addr = pc->ip4.gw;
		printf(" GW %s\n", inet_ntoa(in));
	}
	pc->ip4.dynip = 1;
	pc->ip4.mtu = MTU;
	
	return 1;
}

int run_ipset(char *cmdstr)
{
	char buf[MAX_LEN];
	struct in_addr in;
	char *argv[4];
	int argc;
	int icidr = 24;
	u_int rip, gip, tip;
	int i;
	int hasgip = 1;
	pcs *pc = &vpc[pcid];

	argc = mkargv(cmdstr, (char **)argv, 4);
	
	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5         6         7         8
		 */
		printf( "\n\033[1mip [arguments]\033[0m, Configure PC's IP settings\n"
			"    dhcp         Configure host/gateway address using DHCP, only ipv4\n"
			"    auto         Stateless address autoconfiguration, only ipv6\n"
			"                 PC will try to get the ipv6 address from the router at startup\n"
			"    address [gateway] [CIDR] \n"
			"                 set the PC's ip, gateway's ip and network mask\n"
			"                 Default IPv4 CIDR is 24, IPv6 is 64. In the ether mode, \n"
			"                 the ip of the tapx is the maximum host ID of the subnet.\n\n"
			"                 'ip 10.1.1.70 10.1.1.65 26', set the host ip to 10.1.1.70, \n"
			"                 the gateway ip to 10.1.1.65, the netmask to 255.255.255.192, \n"
			"                 the tapx ip to 10.1.1.126 in the ether mode.\n"
			"    mtu value    set MTU, at least 576\n"
			"    dns ip       set dns, delete if ip is '0'\n"
			"    show         Show mtu and dns\n");

		return 0;
	}
	
	if (strchr(argv[1], ':') != NULL)
		return run_ipset6(cmdstr);	
	
	if (!strncmp("dhcp", argv[1], strlen(argv[1])))
		return run_dhcp((void *)0);
	
	if (!strncmp("auto", argv[1], strlen(argv[1]))) {
		struct packet *m = nbr_sol(&vpc[pcid]);	
		if (m != NULL)
			enq(&vpc[pcid].oq, m);
		return 1;
	}
	if (!strncmp("mtu", argv[1], strlen(argv[1]))) {
		i = atoi(argv[2]);
		if (i < 576) {
			printf("Invalid MTU, should bigger than 576\n");
		} else
			pc->ip4.mtu = i;
		return 1;
	}
	
	if (!strncmp("dns", argv[1], strlen(argv[1]))) {
		if (argc == 3) {
			if (!strcmp(argv[2], "0")) {
				pc->ip4.dns[0] = 0;
				return 1;
			}
			rip = inet_addr(argv[2]);
			if (rip == -1 || rip == 0) {
				printf("Invalid address\n");
				return 0;
			}
			pc->ip4.dns[0] = rip;
		}				
		if (argc == 4) {
			if (!strcmp(argv[2], "0")) {
				pc->ip4.dns[0] = 0;
				return 1;
			}
			rip = inet_addr(argv[2]);
			if (rip == -1 || rip == 0) {
				printf("Invalid address: %s\n", argv[2]);
				return 0;
			}
			pc->ip4.dns[0] = rip;

			if (!strcmp(argv[3], "0")) {
				pc->ip4.dns[0] = 0;
				return 1;
			}
			rip = inet_addr(argv[3]);
			if (rip == -1 || rip == 0) {
				printf("Invalid address: %s\n", argv[3]);
				return 0;
			}
			pc->ip4.dns[1] = rip;	
		}
		return 1;
	}
	if (!strncmp("show", argv[1], strlen(argv[1]))) {
		printf("\n");
		printf("MTU = %d\n",  pc->ip4.mtu);
	
		if (pc->ip4.dns[0] != 0) {
			in.s_addr = pc->ip4.dns[0];
			printf("DNS Primary Server: %s\n", inet_ntoa(in));
		}
		if (pc->ip4.dns[1] != 0) {
			in.s_addr = pc->ip4.dns[1];
			printf("DNS Secondary Server: %s\n", inet_ntoa(in));
		}

		return 1;	
	}
	
	switch (argc) {
		case 4:
			rip = inet_addr(argv[1]);
			if (strchr(argv[2], '.') != NULL) {
				gip = inet_addr(argv[2]);
				icidr = atoi(argv[3]);
			} else {
				icidr = atoi(argv[2]);
				gip = inet_addr(argv[3]);
			}
			break;
		case 3:
			rip = inet_addr(argv[1]);
			if (strchr(argv[2], '.') != NULL) {
				gip = inet_addr(argv[2]);
				icidr = 24;
			} else {
				hasgip = gip = 0;
				icidr = atoi(argv[2]);
			}
			break;
		case 2:
			rip = inet_addr(argv[1]);
			hasgip = gip = 0;
			icidr = 24;
			break;
		default:
			printf("incompleted command.\n");
			return 0;
	}
	
	if (icidr < 1 || icidr > 30)
		icidr = 24;
		
	if (rip == -1 || gip == -1 || rip == gip) {
		printf("Invalid address\n");
		return 0;
	}
	
	tip = ntohl(rip) & (~ip_masks[icidr]); 
	if (tip == 0 ||	((tip | ip_masks[icidr])  == 0xffffffff)) {
		printf("Invalid host address\n");
		return 0;
	}
	
	if (hasgip) {
		tip = ntohl(gip) & (~ip_masks[icidr]); 
		if (tip == 0 ||	((tip | ip_masks[icidr])  == 0xffffffff)) {
			printf("Invalid gateway address\n");
			return 0;
		}

		if ((ntohl(rip) & ip_masks[icidr]) != (ntohl(gip) & ip_masks[icidr])) {
			printf("not same subnet\n");
			return 0;
		}
	}
	pc->ip4.dynip = 0;
	pc->ip4.ip = rip;
	pc->ip4.gw = gip;
	pc->ip4.cidr = icidr;
	pc->ip4.mtu = MTU;
	
	/* set tap ip address */
	if (DEV_TAP == devtype) {
		tip = (ntohl(rip) | (~ip_masks[icidr])) - 1;
		in.s_addr = ntohl(tip);
		i = sprintf(buf, "ifconfig tap%d %s ", pcid, inet_ntoa(in));
		in.s_addr = ntohl(ip_masks[icidr]);	
		sprintf(buf + i, " netmask %s up", inet_ntoa(in));
		i = system(buf);
	}
	
	/* display configuration */
	in.s_addr = pc->ip4.ip;
	printf("PC%d : %s", pcid + 1, inet_ntoa(in));
	in.s_addr = ntohl(ip_masks[icidr]);
	printf(" %s", inet_ntoa(in));
	
	if (hasgip) {
		in.s_addr = pc->ip4.gw;
		printf(" gateway %s\n", inet_ntoa(in));
	}
	
	return 1;
}

int run_tracert(char *cmdstr)
{
	int i;
	u_int gip;
	struct in_addr in;
	char *argv[3];
	int argc;
	int count = 64;		/* default 64 hops */
	struct packet *m;
	pcs *pc = &vpc[pcid];
	int ok = 0;
	int pktnum = 3;
	int prn_ip = 1;
		
	pc->mscb.seq = time(0);
	pc->mscb.proto = IPPROTO_UDP;
	pc->mscb.dsize = 64;
	pc->mscb.mtu = pc->ip4.mtu;
	pc->mscb.sport = rand() & 0xfff1;
	pc->mscb.dport = pc->mscb.sport + 1;
	pc->mscb.sip = pc->ip4.ip;
	pc->mscb.waittime = 1000;
	memcpy(pc->mscb.smac, pc->ip4.mac, 6);
	

	argc = mkargv(cmdstr, (char**)argv, 3);
	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5         6         7         8
		 */
		printf( "\n\033[1mtracert address [maxhops]\033[0m, Print the route packets take to network host.\n");
		return 0;
	}
	
	if (argc == 3)
		count = atoi(argv[2]);

	if (count < 1 || count > 64)
		count = 64;
	
	if (strchr(argv[1], ':')) {
		pc->mscb.mtu = pc->ip6.mtu;
		return run_tracert6(count, cmdstr);
	}
		
	pc->mscb.dip = inet_addr(argv[1]);

	if (pc->mscb.dip == -1 || pc->mscb.dip == 0) {
		if (hostresolv(pc, argv[1], &(pc->mscb.dip)) == 0) {
			printf("Cannot resolve %s\n", argv[1]);
			return 0;
		} else {
			in.s_addr = pc->mscb.dip;
			printf("%s resolved to %s\n", argv[1], inet_ntoa(in)); 	
		}
	}
	
	if (pc->mscb.dip == pc->ip4.ip) {
		i = 1;
		in.s_addr = pc->mscb.dip;
		printf("traceroute to %s, %d hops max\n", argv[1], count);
		printf(" 1 %s     0.001 ms\n", inet_ntoa(in));
		return 1;
	}

redirect:
	if (sameNet(pc->mscb.dip, pc->ip4.ip, pc->ip4.cidr))
		gip = pc->mscb.dip;
	else {
		if (pc->ip4.gw == 0) {
			printf("No gateway found\n");
			return 0;
		} else
		
		gip = pc->ip4.gw;
	}
	
	/* try to get the ether address of destination */
	if (!arpResolve(pc, gip, pc->mscb.dmac)) {
		in.s_addr = gip;
		printf("host (%s) not reachable\n", inet_ntoa(in));
		return 0;
	}
	printf("traceroute to %s, %d hops max, press Ctrl+C to stop\n", argv[1], count);
	
	/* send the udp packets */
	
	
	i = 1;
	while (i <= count && !ctrl_c) {
		struct packet *p;
		struct timeval tv;
		u_int usec;
		int j;
		
		/* clean input queue */
		while ((p = deq(&pc->iq)) != NULL)
			del_pkt(p);
			
		prn_ip = 1;
		printf("%2d   ", i);
		for (j = 0; j < pktnum && !ctrl_c; j++) {
			pc->mscb.ttl = i;
			m = packet(&pc->mscb);
			if (m == NULL) {
				printf("out of memory\n");
				return false;
			}
			dmp_packet(m, dmpflag);
			
			gettimeofday(&(tv), (void*)0);
			enq(&pc->oq, m);

			while (!timeout(tv, pc->mscb.waittime) && !ctrl_c) {
				delay_ms(1);
				ok = 0;	
					
				while ((p = deq(&pc->iq)) != NULL && !ok 
					&& !timeout(tv, pc->mscb.waittime) && !ctrl_c) {

					ok = response(p, &pc->mscb);
					usec = (p->ts.tv_sec - tv.tv_sec) * 1000000 + 
					    p->ts.tv_usec - tv.tv_usec;
					
					if (ok)
						dmp_packet(p, dmpflag);

					del_pkt(p);
					
					if (pc->mscb.icmptype == ICMP_REDIRECT && 
					    pc->mscb.icmpcode == ICMP_REDIRECT_NET) {
						in.s_addr = pc->ip4.gw;	
						printf("Redirect Network, gateway %s",  inet_ntoa(in));
						in.s_addr = pc->mscb.rdip;
						printf(" -> %s\n", inet_ntoa(in));
						    	
						pc->ip4.gw = pc->mscb.rdip;
						
						goto redirect;
					}
					
					if (pc->mscb.icmptype == ICMP_TIMXCEED || 
					    (pc->mscb.dip == pc->mscb.rdip)) {
						in.s_addr = pc->mscb.rdip;
						if (prn_ip) {
							printf("%s ", inet_ntoa(in));
							prn_ip = 0;
						}	
						printf("  %.3f ms", usec / 1000.0);
						fflush(stdout);
						tv.tv_sec = 0;

						break;
					} else if (pc->mscb.icmptype == ICMP_UNREACH) {
						in.s_addr = pc->mscb.rdip;
						
						if (prn_ip) {
							printf("*%s   %.3f ms (ICMP type:%d, code:%d, %s)\n", 
							    inet_ntoa(in), usec / 1000.0, pc->mscb.icmptype, 
							    pc->mscb.icmpcode, 
							    icmpTypeCode2String(4, pc->mscb.icmptype, 
							        pc->mscb.icmpcode));
							prn_ip = 0;
						}
						tv.tv_sec = 0;

						return 1;
					} 
				}
			}
			if (!ok && !ctrl_c) {
				printf("  *");
				fflush(stdout);
			}
		}
		printf("\n");

		i++;
		if (pc->mscb.icmptype == ICMP_UNREACH)
			break;
	}
	
	return 1;
}

int run_set(char *cmdstr)
{
	int value;
	char *argv[3];
	int argc;
	int fd;
	int flags;
	pcs *pc = &vpc[pcid];
	u_int ip;

	argc = mkargv(cmdstr, argv, 3);

	if (argc < 3 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5         6         7         8
		 */
		printf( "\n\033[1mset [lport|rport|rhost|pcname|echo]\033[0m\n"
			"    lport port     local port\n"
			"    rport port     remote peer port\n"
			"    rhost address  remote peer host\n"
			"    pcname name    rename the current pc\n"
			"    echo [on|off]  set echoing on or off\n");
		return 0;
	}
	if (!strncmp("lport", argv[1], strlen(argv[1]))) {
		value = atoi(argv[2]);
		if (value < 1024 || value > 65000) {
			printf("Invalid port. 1024 > port < 65000.\n");
		} else {
			fd = open_udp(value);
			if (fd <= 0) {
				fd = 0;
				printf("Device(%d) open error [%s]\n", pcid, strerror(errno));
				return 0;
			}
		
			pc->fd = fd;
			pc->sport = value;
		
			flags = fcntl(pc->fd, F_GETFL, NULL);
			flags |= O_NONBLOCK;
			fcntl(pc->fd, F_SETFL, flags);
		}
	} else if (!strncmp("rport", argv[1], strlen(argv[1]))) {
		value = atoi(argv[2]);
		if (value < 1024 || value > 65000) {
			printf("Invalid port. 1024 > port < 65000.\n");
		} else
			pc->rport = value;
	} else if (!strncmp("rhost", argv[1], strlen(argv[1]))) {
			ip = inet_addr(argv[2]);
			if (ip == -1) {
				printf("Invalid address: %s\n", argv[2]);
				return 0;
			}
			pc->rhost = ip;
	} else if (!strncmp("pcname", argv[1], strlen(argv[1]))) {
		if (strlen(argv[2]) > MAX_NAMES_LEN)
			printf("Hostname is too long. (should be less than %d)\n", MAX_NAMES_LEN);
		else 
			strcpy(vpc[pcid].xname, argv[2]);
	} else  if (!strncmp("echo", argv[1], strlen(argv[1]))) {
		if (!strcasecmp(argv[2], "on")) {
			canEcho = 1;
		} else if (!strcasecmp(argv[2], "off")) {
			canEcho = 0;
		}
	} else 
		printf("Invalid command.\n");
	return 1;
}

int run_zzz(char *cmdstr)
{
	char *argv[2];
	int argc;
	int t;
	
	printf("\n");
	
	argc = mkargv(cmdstr, argv, 2);
	if (argc < 2)
		t = 1;
	t = atoi(argv[1]);
	sleep(t);
	
	return 1;
}

int run_clear(char *cmdstr)
{
	char *argv[2];
	int argc;
	u_char mac[6];
	
	argc = mkargv(cmdstr, (char **)argv, 2);
	
	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5         6         7         8
		 */
		printf( "\n\033[1mclear [ip|ipv6|arp|neighbor|hist]\033[0m\n"
			"    clear ip/ipv6 address, arp/neighbor table, command history\n");

		return 0;
	}
	if (!strcmp("ip", argv[1])) {
		memcpy(mac, vpc[pcid].ip4.mac, 6);
		memset(&vpc[pcid].ip4, 0, sizeof(vpc[pcid].ip4));
		memcpy(&vpc[pcid].ip4.mac, mac, 6);
	} else if (!strcmp("ipv6", argv[1]))
		memset(&vpc[pcid].ip6, 0, sizeof(vpc[pcid].ip6));
	else if (!strcmp("arp", argv[1]))
		memset(&vpc[pcid].ipmac4, 0, sizeof(vpc[pcid].ipmac4));
	else if (!strcmp("neighbor", argv[1]))
		memset(&vpc[pcid].ipmac6, 0, sizeof(vpc[pcid].ipmac6));
	else if (!strcmp("hist", argv[1]))
		clear_hist();
		
	return 1;
}								

int run_echo(char *cmdstr)
{
	char *p = NULL;
	
	p = strchr(cmdstr, ' ');
	
	if (p != NULL)
		printf("%s", p + 1);	
	else {
		p = strchr(cmdstr, '\t');
		if (p != NULL)
			printf("%s", p + 1);
	}
	
	printf("\n");
	return 1;
}	
const char *ip4Info(const int id)
{
	struct in_addr in;
	static char buf[128];
	int pos = 0;
	
	memset(buf, 0, sizeof(buf));
	if (vpc[id].ip4.ip != 0) {
		in.s_addr = vpc[id].ip4.ip;
		pos = sprintf(buf, "ip %s", (char*)inet_ntoa(in));
		in.s_addr = vpc[id].ip4.gw;
		if (vpc[id].ip4.gw != 0) {
			in.s_addr = vpc[id].ip4.gw;
			pos += sprintf(buf + pos, " %s", inet_ntoa(in));
		}
		sprintf(buf + pos, " %d", vpc[id].ip4.cidr);
	} else 
		return NULL;
		
	return buf;
}

/* end of file */

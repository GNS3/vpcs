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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/param.h>
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
#include "remote.h"
#include "readline.h"
#include "help.h"
#include "dump.h"
#include "relay.h"

extern int pcid;
extern int devtype;
extern int ctrl_c;
extern int ctrl_z;
extern u_int time_tick;
extern u_long ip_masks[33];
extern struct echoctl echoctl;
//int canEcho;
extern void clear_hist(void);
extern const char *ver;
extern struct rls *rls;
extern int runLoad;
extern int runStartup;
extern const char *default_startupfile;
extern int num_pths;

static const char *color_name[8] = {
	"black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"};

static int set_dump(int argc, char **argv);
static int show_dump(int argc, char **argv);
static int show_ip(int argc, char **argv);
static int show_echo(int argc, char **argv);
static int show_arp(int argc, char **argv);

static int run_dhcp_new(int renew, int dump);
static int run_dhcp_release(int dump);

static int str2color(const char *cstr);

/*
 *          1         2         3         4         5         6
 * 012345678901234567890123456789012345678901234567890123456789012345678
 * name   ip/cidr              gw                LPort   RHost:RPort
 */
int run_show(int argc, char **argv)
{
	int i, j, k;
	struct in_addr in;
	char buf[128];

	memset(buf, 0, sizeof(buf));
	memset(buf, ' ', sizeof(buf) - 1);

	if (argc > 1) {
		if (help_show(argc, argv))
			return 1;

		if (!strncmp("arp", argv[1], strlen(argv[1])))
			return show_arp(argc, argv);

		if (!strncmp("dump", argv[1], strlen(argv[1])))
			return show_dump(argc, argv);

		if (!strcmp("ip", argv[1]))
			return show_ip(argc, argv);

		if (!strncmp("ipv6", argv[1], strlen(argv[1])))
			return show_ipv6(argc, argv);

		if (!strncmp("echo", argv[1], strlen(argv[1])))
			return show_echo(argc, argv);

		if (!strncmp("version", argv[1], strlen(argv[1])))
			return run_ver(0, NULL);

		if (!strncmp("history", argv[1], strlen(argv[1])))
			return run_hist(0, NULL);

		printf("Invalid arguments\n");
		return 1;
	}

	printf("\n");
	switch(devtype) {
		case DEV_TAP:
			j = sprintf(buf, "NAME");
			buf[j] = ' ';
			j = sprintf(buf + 7, "IP/MASK");
			buf[j + 7] = ' ';
			j = sprintf(buf + 28, "GATEWAY");
			buf[j + 28] = ' ';
			j = sprintf(buf + 64, "GATEWAY");
			printf("%s\n", buf);

			for (i = 0; i < num_pths; i++) {
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
			j = sprintf(buf + 7, "IP/MASK");
			buf[j + 7] = ' ';
			j = sprintf(buf + 28, "GATEWAY");
			buf[j + 28] = ' ';
			j = sprintf(buf + 46, "MAC");
			buf[j + 46] = ' ';
			j = sprintf(buf + 65, "LPORT");
			buf[j + 65] = ' ';
			j = sprintf(buf + 72, "RHOST:PORT");
			printf("%s\n", buf);

			for (i = 0; i < num_pths; i++) {
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
				j = sprintf(buf + 65, "%d", vpc[i].lport);
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
int run_ping(int argc, char **argv)
{
	int i, j;
	int gip;
	u_int gwip;
	struct in_addr in;
	struct packet *m;
	pcs *pc = &vpc[pcid];
	char dname[256];
	u_char flags;

	char proto_seq[16];
	int count = 5;
	int interval = 1000;

	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		return help_ping(argc, argv);
	}

	pc->mscb.frag = IPF_FRAG;
	pc->mscb.mtu = pc->mtu;
	pc->mscb.waittime = 1000;
	pc->mscb.ipid = time(0) & 0xffff;
	pc->mscb.seq = time(0);
	pc->mscb.proto = IPPROTO_ICMP;
	pc->mscb.ttl = TTL;
	pc->mscb.dsize = PAYLOAD56;
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
				pc->mscb.frag = ~IPF_FRAG;
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
		pc->mscb.mtu = pc->mtu;
		return run_ping6(argc, argv);
	}
	pc->mscb.dip = inet_addr(argv[1]);

	if (pc->mscb.dip == -1 || pc->mscb.dip == 0) {
		strcpy(dname, argv[1]);
		if (hostresolv(pc, dname, &(pc->mscb.dip)) == 0) {
			printf("Cannot resolve %s\n", argv[1]);
			return 0;
		} else {
			in.s_addr = pc->mscb.dip;
			printf("%s resolved to %s\n", dname, inet_ntoa(in));
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
	gwip = pc->ip4.gw;
	flags = pc->mscb.flags;
redirect:
	if (sameNet(pc->mscb.dip, pc->ip4.ip, pc->ip4.cidr))
		gip = pc->mscb.dip;
	else {
		if (gwip == 0) {
			printf("No gateway found\n");
			return 0;
		} else

		gip = gwip;
	}

	in.s_addr = pc->mscb.dip;

	/* try to get the ether address of the destination */
	if (!arpResolve(pc, gip, pc->mscb.dmac)) {
		in.s_addr = gip;
		printf("host (%s) not reachable\n", inet_ntoa(in));
		return 0;
	}

	pc->mscb.flags = flags;
	if (pc->mscb.proto == IPPROTO_TCP && pc->mscb.flags == 0) {
		i = 0;

		while ((i++ < count || count == -1) && !ctrl_c) {
			struct timeval ts0, ts;
			u_int usec;
			int k;
			int dsize;
			int traveltime = 1;

			if (i > 1)
				delay_ms(pc->mscb.waittime);

			/* clear the input queue */
			while ((m = deq(&pc->iq)) != NULL)
				del_pkt(m);
			/* connect the remote */
			gettimeofday(&(ts), (void*)0);

			dsize = pc->mscb.dsize;
			pc->mscb.dsize = PAYLOAD56;
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
				if (pc->mscb.icmptype == ICMP_REDIRECT &&
				    pc->mscb.icmpcode == ICMP_REDIRECT_NET) {
					din.s_addr = pc->ip4.gw;
					printf("Redirect Network, gateway %s",  inet_ntoa(din));
					din.s_addr = pc->mscb.rdip;
					printf(" -> %s\n", inet_ntoa(din));

					gwip = pc->mscb.rdip;
					delay_ms(100);
					goto redirect;
				}
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
			dsize = pc->mscb.dsize;
			pc->mscb.dsize = PAYLOAD56;
			k = tcp_close(4);
			pc->mscb.dsize = dsize;
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

			/* clean input queue */
			while ((p = deq(&pc->iq)) != NULL)
				del_pkt(p);

			gettimeofday(&(tv), (void*)0);
			enq(&pc->oq, m);

			while (!timeout(tv, pc->mscb.waittime) && !respok && !ctrl_c) {
				delay_ms(1);
				respok = 0;

				while ((p = deq(&pc->iq)) != NULL && !respok && !ctrl_c) {

					pc->mscb.icmptype = pc->mscb.icmpcode = 0;
					respok = response(p, &pc->mscb);

					usec = (p->ts.tv_sec - tv.tv_sec) * 1000000 +
					    p->ts.tv_usec - tv.tv_usec;

					del_pkt(p);

					if (respok == 0)
						continue;

					//tv.tv_sec = 0;

					if ((pc->mscb.proto == IPPROTO_ICMP && pc->mscb.icmptype == ICMP_ECHOREPLY) ||
					    (pc->mscb.proto == IPPROTO_UDP && respok == IPPROTO_UDP) ||
					    (pc->mscb.proto == IPPROTO_TCP && respok == IPPROTO_TCP)) {
						printf("%d bytes from %s %s=%d ttl=%d time=%.3f ms\n",
						    pc->mscb.rdsize, inet_ntoa(in), proto_seq, i++,
						    pc->mscb.rttl, usec / 1000.0);
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

						gwip = pc->mscb.rdip;
						delay_ms(100);
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

int run_dhcp(int argc, char **argv)
{
	int dump = 0;
	int flag = 0;
	int i;

	i = 0;
	while (++i < argc) {
		if (!strcmp(argv[i], "-d")) {
			dump = 1;
			continue;
		}

		if (!strcmp(argv[i], "-r")) {
			flag = (flag << 4) + 0x5;
			continue;
		}

		if (!strcmp(argv[i], "-x")) {
			flag = (flag << 4) + 0xa;
			continue;
		}
		flag = -1;
		break;
	}
	if (flag == -1)
		return help_ip(argc, argv);

	switch (flag) {
		case 0:
			run_dhcp_new(0, dump);
			break;
		case 0x5:
			run_dhcp_new(1, dump);
			break;
		case 0xa:
			run_dhcp_release(dump);
			break;
		case 0x5a:
			run_dhcp_new(1, dump);
			run_dhcp_release(dump);
			break;
		case 0xa5:
			run_dhcp_release(dump);
			run_dhcp_new(1, dump);
			break;
	}
	return 1;
}

static int run_dhcp_new(int renew, int dump)
{
	int i;
	struct packet *m;
	int ok;
	pcs *pc = &vpc[pcid];
	int ts[3] = {1, 3, 9};
	struct packet *p;
	struct in_addr in;
	u_char mac[6];

	pc->ip4.dynip = 1;

	srand(time(0));
	pc->ip4.dhcp.xid = rand();

	/* discover */
	i = 0;
	ok = 0;
	while (i < 3 && !ok) {
		if (!dump) {
			printf("D");
			fflush(stdout);
		}
		m = dhcp4_discover(pc, renew);
		if (m == NULL) {
			printf("out of memory\n");
			return 0;
		}
		if (dump)
			dmp_dhcp(pc, m);
		enq(&pc->oq, m);
		sleep(ts[i]);

		while ((p = deq(&pc->iq)) != NULL && !ok) {
			if ((ok = isDhcp4_Offer(pc, p))) {
				if (dump)
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
		if (dump)
			dmp_dhcp(pc, m);
		else {
			printf("R");
			fflush(stdout);
		}
		enq(&pc->oq, m);
		sleep(1);

		while ((p = deq(&pc->iq)) != NULL && !ok) {
			if ((ok = isDhcp4_packer(pc, p))) {
				if (dump)
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
		memset(pc->ipmac4, 0, sizeof(pc->ipmac4));
		/* clear ip address */
		pc->ip4.ip = 0;
		pc->ip4.cidr = 0;
		pc->ip4.gw = 0;

		return 0;
	}

	in.s_addr = pc->ip4.ip;

	printf(" IP %s/%d",  inet_ntoa(in), pc->ip4.cidr);
	if (pc->ip4.gw != 0) {
		in.s_addr = pc->ip4.gw;
		printf(" GW %s\n", inet_ntoa(in));
	}

	pc->mtu = MTU;
	if (pc->ip4.dhcp.renew == 0)
		pc->ip4.dhcp.renew = pc->ip4.dhcp.lease / 2;
	if (pc->ip4.dhcp.rebind == 0)
		pc->ip4.dhcp.rebind = pc->ip4.dhcp.lease * 7 / 8;
	pc->ip4.dhcp.timetick = time_tick;

	return 1;
}

static int run_dhcp_release(int dump)
{
	struct packet *m;
	pcs *pc = &vpc[pcid];

	m = dhcp4_release(pc);
	if (m == NULL) {
		printf("out of memory\n");
		return 0;
	}

	if (dump)
		dmp_dhcp(pc, m);
	enq(&pc->oq, m);
	pc->ip4.ip = 0;
	pc->ip4.cidr = 0;
	pc->ip4.gw = 0;

	return 0;
}

int run_ipconfig(int argc, char **argv)
{
	char buf[MAX_LEN];
	struct in_addr in;
	int icidr = 24;
	u_int rip, gip, tip;
	int i, j;
	int hasgip = 1;
	pcs *pc = &vpc[pcid];
	u_char mac[6];

	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		return help_ip(argc, argv);
	}

	if (strchr(argv[1], ':') != NULL)
		return run_ipset6(argc, argv);

	if (!strncmp("dhcp", argv[1], strlen(argv[1]))) {
		int dump = 0;
		int flag = 0;
		i = 1;
		while (++i < argc) {
			if (!strcmp(argv[i], "-d")) {
				dump = 1;
				continue;
			}

			if (!strcmp(argv[i], "-r")) {
				flag = (flag << 4) + 0x5;
				continue;
			}

			if (!strcmp(argv[i], "-x")) {
				flag = (flag << 4) + 0xa;
				continue;
			}
			flag = -1;
			break;
		}
		if (flag == -1)
			return help_ip(argc, argv);

		switch (flag) {
			case 0:
				run_dhcp_new(0, dump);
				break;
			case 0x5:
				run_dhcp_new(1, dump);
				break;
			case 0xa:
				run_dhcp_release(dump);
				break;
			case 0x5a:
				run_dhcp_new(1, dump);
				run_dhcp_release(dump);
				break;
			case 0xa5:
				run_dhcp_release(dump);
				run_dhcp_new(1, dump);
				break;
		}
		return 1;
	}

	if (!strncmp("auto", argv[1], strlen(argv[1])))
		return ipauto6();



	if (!strncmp("domain", argv[1], strlen(argv[1]))) {
		if (argc != 3) {
			printf("Incomplete command.\n");
			return 1;
		}
		if (strlen(argv[2]) > 64 || strstr(argv[2], "..")) {
			printf("Invalid domain name.\n");
			return 1;
		}
		char *p = argv[2];
		while (*p) {
			if (*p == '.')
				p++;
			else {
				strcpy(vpc[pcid].ip4.domain, p);
				p = vpc[pcid].ip4.domain;
				if (p[strlen(p) - 1] == '.')
					p[strlen(p) - 1] = '\0';
				return 1;
			}
		}
		return 1;
	}

	if (!strncmp("dns", argv[1], strlen(argv[1]))) {
		if (!strcmp(argv[argc - 1] , "?"))
			return help_ip(argc, argv);

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

	rip = inet_addr(argv[1]);
	hasgip = gip = 0;
	icidr = 24;

	i = 1;
	while (++i < argc) {
		/* netmask */
		if (digitstring(argv[i]) && strlen(argv[i]) < 3) {
			icidr = atoi(argv[i]);
			continue;
		}

		if ((strlen(argv[i]) > 8) && (!strncmp(argv[i], "255.", 4))) {
		    	gip = inet_addr(argv[i]);
		    	for (j = 0; i < 33; j++) {
		    		if (ip_masks[j] == ntohl(gip)) {
		    			icidr = j;
		    			break;
		    		}
		    	}
			continue;
		}
		j = strlen(argv[i]);
		if (j > 6 && j < 16) {
			hasgip = 1;
			gip = inet_addr(argv[i]);
			continue;
		} else {
			printf("Invalid options\n");
			return 0;
		}
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
	/* check ip address via gratuitous ARP */
	pc->ip4.ip = rip;

   /*
   printf("Checking for duplicate address...\n");
	if (arpResolve(pc, rip, mac) == 1 && !memcmp(mac, pc->ip4.mac, ETH_ALEN)) {
		in.s_addr = rip;
		printf("%s is being used by MAC ",  inet_ntoa(in));
		PRINT_MAC(mac);
		printf("\nAddress not changed\n");
		memset(pc->ipmac4, 0, sizeof(pc->ipmac4));
		// clear ip address
		pc->ip4.ip = 0;
		pc->ip4.cidr = 0;
		pc->ip4.gw = 0;

		return 0;
	}
   */

	pc->ip4.dynip = 0;
	pc->ip4.ip = rip;
	pc->ip4.gw = gip;
	pc->ip4.cidr = icidr;
	pc->mtu = MTU;

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
		printf(" gateway %s", inet_ntoa(in));
	}
	printf("\n");
	return 1;
}

int run_tracert(int argc, char **argv)
{
	int i, j;
	u_int gip, gwip;
	struct in_addr in;
	int count = 128;
	struct packet *m;
	pcs *pc = &vpc[pcid];
	int ok = 0;
	int pktnum = 3;
	int prn_ip = 1;
	char outbuf[1024];
	int buf_off = 0;
	char dname[256];

	pc->mscb.seq = time(0);
	pc->mscb.proto = IPPROTO_UDP;
	pc->mscb.dsize = 64;
	pc->mscb.mtu = pc->mtu;
	pc->mscb.sport = rand() & 0xfff1;
	pc->mscb.dport = pc->mscb.sport + 1;
	pc->mscb.sip = pc->ip4.ip;
	pc->mscb.waittime = 1000;
	pc->mscb.timeout = time_tick;
	memcpy(pc->mscb.smac, pc->ip4.mac, 6);

	if (argc < 2 || (argc == 2 && !strcmp(argv[1], "?"))) {
		return help_trace(argc, argv);
	}

	if (strchr(argv[1], ':')) {
		pc->mscb.mtu = pc->mtu;
		return run_tracert6(argc, argv);
	}

	if (argc > 2) {
		i = 2;
		while (i < argc) {
			if (!strcmp(argv[i], "-P")) {
				if (i + 1 >= argc) {
					printf("Missing protocol\n");
					return 0;
				}
				i++;
				if (!digitstring(argv[i])) {
					printf("Invalid protocol\n");
					return 0;
				}
				j = atoi(argv[i]);
				if (j == IPPROTO_ICMP) {
					pc->mscb.proto = IPPROTO_ICMP;
				} else if (j == IPPROTO_UDP) {
					pc->mscb.proto = IPPROTO_UDP;
				} else if (j == IPPROTO_TCP) {
					pc->mscb.proto = IPPROTO_TCP;
					pc->mscb.flags |= 0x02;
				} else {
					printf("Invalid protocol\n");
					return 0;
				}
				i++;
				continue;
			}
			if (!strcmp(argv[i], "-m")) {
				if (i + 1 >= argc) {
					printf("Missing TTL\n");
					return 0;
				}
				if (!digitstring(argv[i + 1])) {
					printf("Invalid TTL\n");
					return 0;
				}
				i++;
				j = atoi(argv[i]);
				if (j > 0 && j <= 64)
					count = j;
				else {
					printf("Invalid TTL\n");
					return 0;
				}
				i++;
				continue;
			}
			if (digitstring(argv[i])) {
				if (count == 128) {
					j = atoi(argv[i]);
					if (j > 0 && j <= 64)
						count = j;
					else {
						printf("Invalid TTL\n");
						return 0;
					}
					i++;
					continue;
				}
			}
			return help_trace(argc, argv);
		}
	}

	/* no TTL given */
	if (count == 128)
		count = 8;

	pc->mscb.dip = inet_addr(argv[1]);

	if (pc->mscb.dip == -1 || pc->mscb.dip == 0) {
		strcpy(dname, argv[1]);
		if (hostresolv(pc, dname, &(pc->mscb.dip)) == 0) {
			printf("Cannot resolve %s\n", argv[1]);
			return 0;
		} else {
			in.s_addr = pc->mscb.dip;
			printf("%s resolved to %s\n", dname, inet_ntoa(in));
		}
	}

	if (pc->mscb.dip == pc->ip4.ip) {
		i = 1;
		in.s_addr = pc->mscb.dip;
		printf("traceroute to %s, %d hops max\n", argv[1], count);
		printf(" 1 %s     0.001 ms\n", inet_ntoa(in));
		return 1;
	}

	printf("trace to %s, %d hops max", argv[1], count);
	if (pc->mscb.proto == IPPROTO_ICMP)
		printf("%s", " (ICMP)");
	else if (pc->mscb.proto == IPPROTO_TCP)
		printf("%s", " (TCP)");
	printf(", press Ctrl+C to stop\n");

	gwip = pc->ip4.gw;
redirect:
	if (sameNet(pc->mscb.dip, pc->ip4.ip, pc->ip4.cidr))
		gip = pc->mscb.dip;
	else {
		if (gwip == 0) {
			printf("No gateway found\n");
			return 0;
		} else

		gip = gwip;
	}

	/* try to get the ether address of destination */
	if (!arpResolve(pc, gip, pc->mscb.dmac)) {
		in.s_addr = gip;
		printf("host (%s) not reachable\n", inet_ntoa(in));
		return 0;
	}



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
		buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off, "%2d   ", i);
		for (j = 0; j < pktnum && !ctrl_c; j++) {
			pc->mscb.ttl = i;
			pc->mscb.icmptype = 0;
			pc->mscb.rdip = pc->mscb.dip;
			m = packet(&pc->mscb);
			if (m == NULL) {
				printf("out of memory\n");
				return false;
			}

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

					del_pkt(p);

					if (pc->mscb.icmptype == ICMP_REDIRECT &&
					    pc->mscb.icmpcode == ICMP_REDIRECT_NET) {
						in.s_addr = pc->ip4.gw;
						buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off,
						    "Redirect Network, gateway %s",  inet_ntoa(in));
						in.s_addr = pc->mscb.rdip;
						buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off,
						    " -> %s\n", inet_ntoa(in));

						gwip = pc->mscb.rdip;
						delay_ms(100);
						goto redirect;
					}

					if (pc->mscb.icmptype == ICMP_TIMXCEED) {
						in.s_addr = pc->mscb.rdip;
						if (prn_ip) {
							buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off,
							    "%s ", inet_ntoa(in));
							prn_ip = 0;
						}
						buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off,
						    "  %.3f ms", usec / 1000.0);

						tv.tv_sec = 0;

						break;
					} else if (pc->mscb.icmptype == ICMP_UNREACH) {
						in.s_addr = pc->mscb.rdip;
						if (prn_ip) {
							buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off,
							    "*%s   %.3f ms (ICMP type:%d, code:%d, %s)",
							    inet_ntoa(in), usec / 1000.0, pc->mscb.icmptype,
							    pc->mscb.icmpcode,
							    icmpTypeCode2String(4, pc->mscb.icmptype,
							        pc->mscb.icmpcode));
							prn_ip = 0;
						}
						tv.tv_sec = 0;
						ok = 99999;
						break;
					} else if (pc->mscb.dip == pc->mscb.rdip) {
						in.s_addr = pc->mscb.rdip;
						if (prn_ip) {
							buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off,
							    "%s ", inet_ntoa(in));
							prn_ip = 0;
						}
						buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off,
						    "  %.3f ms", usec / 1000.0);

						tv.tv_sec = 0;
						ok = 99999;
						break;
					}
					//printf("IP %4.4x-%4.4x\n", pc->mscb.dip, pc->mscb.rdip);
				}
			}
			if (!ok && !ctrl_c) {
				buf_off += snprintf(outbuf + buf_off, sizeof(outbuf) - buf_off, "  *");
				fflush(stdout);
			}
		}
		printf("%s\n", outbuf);
		buf_off = 0;

		i++;
		if (ok == 99999)
			break;
	}

	return 1;
}

int run_set(int argc, char **argv)
{
	int value;
	int fd;
	pcs *pc = &vpc[pcid];
	u_int ip;

	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		return help_set(argc, argv);
		return 0;
	}

	if (!strncmp("dump", argv[1], strlen(argv[1]))) {
		if (!strcmp(argv[argc - 1], "?"))
			return help_set(argc, argv);
		return set_dump(argc, argv);
	}

	if (!strncmp("mtu", argv[1], strlen(argv[1]))) {
		if (argc == 2 || argc > 3 ||
		    (argc == 3 && !digitstring(argv[2]))) {
		    	argc = 3;
		    	argv[2] = "?";
			return help_set(argc, argv);
		}
		value = atoi(argv[2]);
		if (value < 576) {
			printf("Invalid MTU, should bigger than 576\n");
		} else
			pc->mtu = value;
		return 1;
	}

	if (!strncmp("lport", argv[1], strlen(argv[1]))) {
		if (argc != 3) {
			printf("Incomplete command.\n");
			return 1;
		}
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
			close(pc->fd);
			pc->fd = fd;
			pc->lport = value;
		}
	} else if (!strncmp("rport", argv[1], strlen(argv[1]))) {
		if (argc != 3) {
			printf("Incomplete command.\n");
			return 1;
		}
		value = atoi(argv[2]);
		if (value < 1024 || value > 65000) {
			printf("Invalid port. 1024 > port < 65000.\n");
		} else
			pc->rport = value;
	} else if (!strncmp("rhost", argv[1], strlen(argv[1]))) {
		if (argc != 3) {
			printf("Incomplete command.\n");
			return 1;
		}
		ip = inet_addr(argv[2]);
		if (ip == -1) {
			printf("Invalid address: %s\n", argv[2]);
			return 0;
		}
		pc->rhost = ip;
	} else if (!strncmp("pcname", argv[1], strlen(argv[1]))) {
		if (argc != 3) {
			printf("Incomplete command.\n");
			return 1;
		}
		if (strlen(argv[2]) > MAX_NAMES_LEN)
			printf("Hostname is too long. (Maximum %d characters)\n", MAX_NAMES_LEN);
		else
			strcpy(vpc[pcid].xname, argv[2]);
	} else if (!strncmp("echo", argv[1], strlen(argv[1]))) {
		if (!strcmp(argv[argc - 1], "?"))
			return help_set(argc, argv);

		if (argc < 3) {
			printf("Incomplete command.\n");
			return 1;
		}
		if (!strcasecmp(argv[2], "on")) {
			echoctl.enable = 1;
		} else if (!strcasecmp(argv[2], "off")) {
			echoctl.enable = 0;
		}
		if (argc > 3 && !strcasecmp(argv[2], "color")) {
			if (argc == 4) {
				if (!strcasecmp(argv[3], "clear")) {
					echoctl.fgcolor = 0;
					echoctl.bgcolor = 0;
				} else
					echoctl.fgcolor = str2color(argv[3]);
			}
			if (argc == 5) {
				echoctl.fgcolor = str2color(argv[3]);
				echoctl.bgcolor = str2color(argv[4]) + 10;
			}
		} else if (argc > 4 && !strcasecmp(argv[3], "color")) {
			if (argc == 5) {
				if (!strcasecmp(argv[3], "clear")) {
					echoctl.fgcolor = 0;
					echoctl.bgcolor = 0;
				} else
					echoctl.fgcolor = str2color(argv[4]);
			}
			if (argc == 6) {
				echoctl.fgcolor = str2color(argv[4]);
				echoctl.bgcolor = str2color(argv[5]) + 10;
			}
		}

	} else
		printf("Invalid command.\n");
	return 1;
}

int run_sleep(int argc, char **argv)
{
	int t;
	int ac = argc;
	int i;

	t = 0;
	if (argc == 2) {
		if (digitstring(argv[1])) {
			t = atoi(argv[1]);
			ac = 2;
		} else
			ac = 1;
	} else if (argc > 2) {
		ac = 1;
		if (digitstring(argv[1])) {
			t = atoi(argv[1]);
			ac = 2;
		}
	}

	if (argc != 1) {
		for (i = ac; i < argc; i++)
			printf("%s ", argv[i]);
		printf("\n");
	}

	if (t == 0) {
		if (argc == 1)
			printf("Press any key to continue\n");
		kbhit(0);
	} else
		sleep(t);

	return 1;
}

int run_clear(int argc, char **argv)
{
	u_char mac[6];

	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		return help_clear(argc, argv);
	}
	if (!strcmp("ip", argv[1])) {
		memcpy(mac, vpc[pcid].ip4.mac, 6);
		memset(&vpc[pcid].ip4, 0, sizeof(vpc[pcid].ip4));
		memcpy(&vpc[pcid].ip4.mac, mac, 6);
		printf("IPv4 address/mask, gateway, DNS, and DHCP cleared\n");
	} else if (!strncmp("ipv6", argv[1], strlen(argv[1]))) {
		memset(&vpc[pcid].ip6, 0, sizeof(vpc[pcid].ip6));
		printf("IPv6 address/mask and router link-layer address cleared\n");
	} else if (!strncmp("arp", argv[1], strlen(argv[1])))
		memset(&vpc[pcid].ipmac4, 0, sizeof(vpc[pcid].ipmac4));
	else if (!strncmp("neighbor", argv[1], strlen(argv[1])))
		memset(&vpc[pcid].ipmac6, 0, sizeof(vpc[pcid].ipmac6));
	else if (!strncmp("hist", argv[1], strlen(argv[1])))
		clear_hist();
	else
		printf("Invalid options\n");

	return 1;
}

int run_echo(int argc, char **argv)
{
	int i;

	if (echoctl.fgcolor != 0) {
		if (echoctl.bgcolor != 0)
			printf("\033[%d;%dm", echoctl.fgcolor, echoctl.bgcolor);
		else
			printf("\033[%dm", echoctl.fgcolor);
	}
	for (i = 1; i < argc; i++)
		printf("%s ", argv[i]);

	if (echoctl.fgcolor != 0)
		printf("\033[0m");

//	printf("\n");

	return 1;
}

int run_remote(int argc, char **argv)
{
	if (!strcmp(argv[argc - 1], "?"))
		return help_rlogin(argc, argv);

	if (argc == 2) {
		if (!digitstring(argv[1])) {
			printf("Invalid port\n");
			return help_rlogin(argc, argv);
		}
		return open_remote(0, "127.0.0.1", atoi(argv[1]));
	} else if (argc == 3) {
		if (!digitstring(argv[2])) {
			printf("Invalid port\n");
			return help_rlogin(argc, argv);
		}
		return open_remote(0, argv[1], atoi(argv[2]));
	}

	return help_rlogin(argc, argv);
}

static int set_dump(int argc, char **argv)
{
	int ok = 1;
	int i = 2;
	pcs *pc = &vpc[pcid];

	int dmpflag = 0;

	if (argc == 2)
		ok = 0;

	while (i < argc) {
		if (!strncmp(argv[i], "mac", strlen(argv[i])))
			dmpflag |= DMP_MAC;
		else if (!strncmp(argv[i], "raw", strlen(argv[i])))
			dmpflag |= DMP_RAW;
		else if (!strncmp(argv[i], "detail", strlen(argv[i])))
			dmpflag |= DMP_DETAIL;
		else if (!strncmp(argv[i], "all", strlen(argv[i])))
			dmpflag |= DMP_ALL;
		else if (!strncmp(argv[i], "file", strlen(argv[i]))) {
			if (pc->dmpfile == NULL) {
				char tfname[1024];
				sprintf(tfname, "vpcs%d", pc->id + 1);
				pc->dmpfile = open_dmpfile(tfname);
			}
			dmpflag |= DMP_FILE;
		} else if (!strncmp(argv[i], "off", strlen(argv[i]))) {
			dmpflag = 0;
			/* give pthread reader/writer a little time */
			usleep(1000);
			if (pc->dmpfile) {
				close_dmpfile(pc->dmpfile);
				pc->dmpfile = NULL;
			}
		} else {
			printf("Invalid options\n");
			ok = 0;
			break;
		}
		i++;
	}
	if (ok) {
		if (dmpflag == 0)
			pc->dmpflag = 0;
		else
			pc->dmpflag |= dmpflag;

		printf("\ndump flags:");
		if (pc->dmpflag & DMP_MAC)
			printf(" mac");
		if (pc->dmpflag & DMP_RAW)
			printf(" raw");
		if (pc->dmpflag & DMP_DETAIL)
			printf(" detail");
		if (pc->dmpflag & DMP_ALL)
			printf(" all");
		if (pc->dmpflag & DMP_FILE)
			printf(" file");
		if (pc->dmpflag == 0)
			printf(" (none)");
		printf("\n");
		return 1;
	}

	return 1;
}

int show_arp(int argc, char **argv)
{
	pcs *pc;
	int i, j;
	struct in_addr in;
	char buf[18];
	u_char zero[ETH_ALEN] = {0};
	int empty = 1;
	int si;

	printf("\n");

	if (argc == 3) {
		if (!strncmp(argv[2], "all", strlen(argv[2]))) {
			for (si = 0; si < num_pths; si++) {
				pc = &vpc[si];
				printf("%s[%d]:\n", pc->xname, si + 1);

				for (i = 0; i < ARP_SIZE; i++) {
					if (pc->ipmac4[i].ip == 0)
						continue;
					if (memcmp(pc->ipmac4[i].mac, zero, ETH_ALEN) == 0)
						continue;
					if (time_tick - pc->ipmac4[i].timeout > 120)
						continue;
					for (j = 0; j < 6; j++)
						sprintf(buf + j * 3, "%2.2x:", pc->ipmac4[i].mac[j]);
					buf[17] = '\0';
					in.s_addr = pc->ipmac4[i].ip;
					printf("%s  %s expires in %d seconds \n", buf, inet_ntoa(in),
					    120 - (time_tick - pc->ipmac4[i].timeout));
					empty = 0;

				}
				if (empty)
					printf("arp table is empty\n");
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
	for (i = 0; i < ARP_SIZE; i++) {
		if (pc->ipmac4[i].ip == 0)
			continue;
		if (etherIsZero(pc->ipmac4[i].mac))
			continue;
		if (time_tick - pc->ipmac4[i].timeout < 120) {
			for (j = 0; j < 6; j++)
				sprintf(buf + j * 3, "%2.2x:", pc->ipmac4[i].mac[j]);
			buf[17] = '\0';
			in.s_addr = pc->ipmac4[i].ip;
			printf("%s  %s expires in %d seconds \n", buf, inet_ntoa(in),
			    120 - (time_tick - pc->ipmac4[i].timeout));
			empty = 0;
		}
	}
	if (empty)
		printf("arp table is empty\n");

	return 1;
}
static int show_dump(int argc, char **argv)
{
	int i;
	pcs *pc = &vpc[pcid];

	printf("\n");
	if (argc == 3) {
		if (!strncmp(argv[2], "all", strlen(argv[2]))) {
			for (i = 0; i < num_pths; i++) {
				printf("%s[%d] dumpflag:", vpc[i].xname, i + 1);
				if (vpc[i].dmpflag & DMP_MAC)
					printf(" mac");
				if (vpc[i].dmpflag & DMP_RAW)
					printf(" raw");
				if (vpc[i].dmpflag & DMP_DETAIL)
					printf(" detail");
				if (vpc[i].dmpflag & DMP_ALL)
					printf(" all");
				if (vpc[i].dmpflag & DMP_FILE)
					printf(" file");
				if (vpc[i].dmpflag == 0)
					printf(" (none)");
				printf("\n");
			}
			return 1;
		}
		if (strlen(argv[2]) == 1 && digitstring(argv[2])) {
			i = atoi(argv[2]) - 1;
			pc = &vpc[i];
		} else {
			printf( "\033[1mshow dump [all]\033[0m\n"
				"    all     all vpc's dump flags\n");
		}

		return 1;
	}
	printf("dump flags:");
	if (pc->dmpflag & DMP_MAC)
		printf(" mac");
	if (pc->dmpflag & DMP_RAW)
		printf(" raw");
	if (pc->dmpflag & DMP_DETAIL)
		printf(" detail");
	if (pc->dmpflag & DMP_ALL)
		printf(" all");
	if (pc->dmpflag & DMP_FILE)
		printf(" file");
	if (pc->dmpflag == 0)
		printf(" (none)");
	printf("\n");
	return 1;
}

static int show_ip(int argc, char **argv)
{
	int i, j, k;
	struct in_addr in;
	char buf[128];
	int id = -1;

	if (argc == 3) {
		if (!strncmp(argv[2], "all", strlen(argv[2]))) {
			memset(buf, 0, sizeof(buf));
			memset(buf, ' ', sizeof(buf) - 1);
			j = sprintf(buf, "NAME");
			buf[j] = ' ';
			j = sprintf(buf + 7, "IP/MASK");
			buf[j + 7] = ' ';
			j = sprintf(buf + 28, "GATEWAY");
			buf[j + 28] = ' ';
			j = sprintf(buf + 46, "MAC");
			buf[j + 46] = ' ';
			j = sprintf(buf + 65, "DNS");
			printf("\n%s\n", buf);

			for (i = 0; i < num_pths; i++) {
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
				buf[65] = '\0';
				k = 65;
				if (vpc[i].ip4.dns[0]) {
					in.s_addr = vpc[i].ip4.dns[0];
					j = sprintf(buf + k, "%s", inet_ntoa(in));
				}
				if (vpc[i].ip4.dns[1]) {
					in.s_addr = vpc[i].ip4.dns[1];
					buf[j + 65] = ' ';
					k = j + 66;
					j = sprintf(buf + k, "%s", inet_ntoa(in));
				}
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
		printf("\n");
		printf("NAME        : %s[%d]\n", vpc[id].xname, id + 1);
		in.s_addr = vpc[id].ip4.ip;
		printf("IP/MASK     : %s/%d\n", inet_ntoa(in), vpc[id].ip4.cidr);
		in.s_addr = vpc[id].ip4.gw;
		printf("GATEWAY     : %s\n", inet_ntoa(in));
		printf("DNS         : ");
		if (vpc[id].ip4.dns[0]) {
			in.s_addr = vpc[id].ip4.dns[0];
			printf("%s  ", inet_ntoa(in));
		}
		if (vpc[id].ip4.dns[1]) {
			in.s_addr = vpc[id].ip4.dns[1];
			printf("%s", inet_ntoa(in));
		}
		printf("\n");
		if (vpc[id].ip4.dhcp.svr) {
			in.s_addr = vpc[id].ip4.dhcp.svr;
			printf("DHCP SERVER : %s\n", inet_ntoa(in));
			k = time_tick - vpc[id].ip4.dhcp.timetick;
			k = vpc[id].ip4.dhcp.lease - k;
			printf("DHCP LEASE  : %u, %u/%u/%u\n",
			    k > 0 ? k : 0,
			    vpc[id].ip4.dhcp.lease,
			    vpc[id].ip4.dhcp.renew,
			    vpc[id].ip4.dhcp.rebind);
		}
		if (vpc[id].ip4.domain[0]) {
			printf("DOMAIN NAME : %s\n", vpc[id].ip4.domain);
		} else if (vpc[id].ip4.dhcp.domain[0]) {
			printf("DOMAIN NAME : %s\n", vpc[id].ip4.dhcp.domain);
		}
		printf("MAC         : ");
		PRINT_MAC(vpc[id].ip4.mac);
		printf("\n");
		printf("LPORT       : %d\n", vpc[id].lport);
		in.s_addr = vpc[id].rhost;
		printf("RHOST:PORT  : %s:%d\n", inet_ntoa(in), vpc[id].rport);
		printf("MTU:        : %d\n", vpc[id].mtu);
		return 1;
	}

	argv[argc - 1 ] = "?";
	help_show(argc, argv);

	return 1;
}

static int show_echo(int argc, char **argv)
{
	printf("\n");

	esc_prn("Echo {H%s}\n", (echoctl.enable) ? "On" : "Off");
	printf("Foreground color: %s\n",
	    (echoctl.fgcolor >= 30 && echoctl.fgcolor <= 37) ?
	    color_name[echoctl.fgcolor - 30] :
	    "default");

	printf("Background color: %s\n",
	    (echoctl.bgcolor >= 40 && echoctl.bgcolor <= 47) ?
	    color_name[echoctl.bgcolor - 40] :
	    "default");

	return 1;
}

int run_ver(int argc, char **argv)
{
	printf ("\r\n"
		"Welcome to Virtual PC Simulator, version %s\r\n"
		"Dedicated to Daling.\r\n"
		"Build time: %s %s\r\n"
		"Copyright (c) 2007-2014, Paul Meng (mirnshi@gmail.com)\r\n"
		"All rights reserved.\r\n\r\n"
		"VPCS is free software, distributed under the terms of the \"BSD\" licence.\r\n"
		"Source code and license can be found at vpcs.sf.net.\r\n"
		"For more information, please visit wiki.freecode.com.cn.\r\n",
		ver, __DATE__, __TIME__ );

	return 1;
}

int run_hist(int argc, char **argv)
{
	int i;

	for (i = 0; i < rls->hist_total; i++)
		printf("%s\n", rls->history[i]);

	return 1;
}

int run_load(int argc, char **argv)
{
	FILE *fp;
	char buf[MAX_LEN];
	char fname[PATH_MAX];
	char *filename = "startup.vpc";

	if (argc > 2 || (argc == 2 && !strcmp(argv[1], "?"))) {
		return help_load(argc, argv);
	}
	else if (argc == 2) {
		filename = argv[1];
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		/* try to open .vpc */
		if (!strrchr(filename, '.') &&
		    (strlen(filename) < PATH_MAX - 5)) {
			memset(fname, 0, PATH_MAX);
			strncpy(fname, filename, PATH_MAX - 1);
			strcat(fname, ".vpc");
			fp = fopen(fname, "r");
		}
	}
	if (fp == NULL) {
		printf("Can't open \"%s\"\n", filename);
		return -1;
	}

	if (runStartup)
		printf("\nExecuting the startup file\n");
	else
		printf("\nExecuting the file \"%s\"\n", filename);

	while (!feof(fp) && !ctrl_c) {
		runLoad = 1;
		if (fgets(buf, MAX_LEN, fp) == NULL)
			break;
		ttrim(buf);
		/*
		if (buf[strlen(buf) - 1] == '\n') {
			buf[strlen(buf) - 1] = '\0';
			if (buf[strlen(buf) - 1] == '\r')
				buf[strlen(buf) - 1] = '\0';
		}*/
		if (buf[0] == '#' || buf[0] == ';')
			continue;
		if (strlen(buf) > 0)
			parse_cmd(buf);
	}
	runLoad = 0;
	fclose(fp);
	return 1;
}

int run_save(int argc, char **argv)
{
	FILE *fp;
	int i;
	char *p;
	char buf[64];
	u_int local_ip;
	struct in_addr in;
	char fname[PATH_MAX];

	memset(fname, 0, PATH_MAX);
	if (argc > 2 || (argc == 2 && !strcmp(argv[1], "?"))) {
		return help_save(argc, argv);
	}
	else if (argc == 1) {
		strncpy(fname, default_startupfile, PATH_MAX - 1);
	}
	else {
		if (strlen(argv[1]) > PATH_MAX - 5) {
			printf("%s is too long\n", argv[1]);
			return 1;
		}
		else {
			strncpy(fname, argv[1], PATH_MAX - 1);
		}
	}

	if (!strrchr(fname, '.'))
		strcat(fname, ".vpc");

	fp = fopen(fname, "w");
	if (fp == NULL) {
		printf("failed: %s\n", strerror(errno));
		return 1;
	}

	printf("Saving startup configuration to %s\n", fname);
	local_ip = inet_addr("127.0.0.1");
	for (i = 0; i < num_pths; i++) {
		if (num_pths > 1)
			fprintf(fp, "%d\n", i + 1);
		sprintf(buf, "VPCS[%d]", i + 1);
		if (strncmp(vpc[i].xname, buf, 3))
			fprintf(fp, "set pcname %s\n", vpc[i].xname);

		if (num_pths > 1) {
			if (vpc[i].lport != (20000 + i))
				fprintf(fp, "set lport %d\n", vpc[i].lport);
			if (vpc[i].rport != (30000 + i))
				fprintf(fp, "set rport %d\n", vpc[i].rport);
			if (vpc[i].rhost != local_ip) {
				in.s_addr = vpc[i].rhost;
				fprintf(fp, "set rhost %s\n", inet_ntoa(in));
			}
		}

		if (vpc[i].ip4.dynip == 1)
			fputs("dhcp\n", fp);
		else {
			p = (char *)ip4Info(i);
			if (p != NULL)
				fprintf(fp, "%s\n", p);
			p = (char *)ip6Info(i);
			if (p != NULL)
				fprintf(fp, "%s\n", p);
			if (vpc[i].ip4.domain[0])
				fprintf(fp, "ip domain %s\n", vpc[i].ip4.domain);
			if (vpc[i].ip4.dns[0]) {
				in.s_addr = vpc[i].ip4.dns[0];
				fprintf(fp, "ip dns %s", inet_ntoa(in));
				if (vpc[i].ip4.dns[1]) {
					in.s_addr = vpc[i].ip4.dns[1];
					fprintf(fp, " %s", inet_ntoa(in));
				}
				fprintf(fp, "\n");
			}
		}

		if (vpc[i].ip6auto == 1)
			fputs("ip auto\n", fp);

		if (vpc[i].mtu != 1500)
			fprintf(fp, "set mtu %d\n", vpc[i].mtu);

		printf(".");
	}

	save_relay(fp);

	if (num_pths > 1)
		fprintf(fp, "1\n");

	fclose(fp);
	printf("  done\n");

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

int str2color(const char *cstr)
{
	int i;

	for (i = 0; i < 8; i++)
		if (!strncasecmp(cstr, color_name[i], strlen(color_name[i])))
			break;
	if (i == 8)
		return 0;
	else
		return 30 + i;
}
/* end of file */

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
#include <signal.h>
#include <unistd.h>	 /* usleep */
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "globle.h"
#include "vpcs.h"
#include "readline.h"
#include "packets.h"
#include "utils.h"
#include "dev.h"
#include "command.h"
#include "command6.h"
#include "daemon.h"

#ifndef Darwin
#include "getopt.h"
#endif

const char *ver = "0.4a5";
const char *copy = "Copyright (c) mirnshi, $Revision: 1.13 $";

int pcid = 0;  /* current vpc id */
int devtype = 0;
int sport = 20000;
int rport = 30000;
int rport_flag = 0;
u_int rhost = 0; /* remote host */
//int dmpflag = 0;
int canEcho = 0; /* echoing on if 1, off if 0 */
int runLoad = 0; /* work with canEcho */

int runStartup = 0; /* execute startup if 1 */
char *startupfile = NULL;
const char *default_startupfile = "startup.vpc";
char *histfile = "vpcs.hist";

u_int time_tick = 0; /* time tick (second) */

int ctrl_c = 0; /* ctrl+c was pressed */

struct rls *rls = NULL;

int daemon_port = 0;

void *pth_proc(void *devid);
void *pth_timer_tick(void *);
void parse_cmd(char *cmdstr);
void sig_int(int sig);
void clear_hist(void);

void welcome(void);
void usage();
void startup(void);

int run_quit(char*);
int run_help(char*);
int run_ver(char*);
int run_load(char*);
int run_save(char*);

/* command */
extern int run_show(char *);
extern int run_hist(char *dummy);
extern int run_ping(char *);
extern int run_ipset(char *);
extern int run_tracert(char *);
extern int run_set(char *cmdstr);
extern int run_arp(char *);
extern int run_dhcp(char *);
extern int run_nb6(char *dummy);
extern int run_zzz(char *time);
extern int run_echo(char *);
extern int run_remote(char *);

extern char *get_pc_cfg(int i);
extern char *get_pc_cfg6(int i);
extern void locallink6(pcs *pc);

struct stub
{
	char *name;
	int (*f)(char *);
};
typedef struct stub cmdStub;

cmdStub cmd_entry[] = {
	{"?",		run_help},
	{"quit",	run_quit},
	{"show",	run_show},
	{"arp",		run_arp},
	{"set",		run_set},
	{"hist",	run_hist},
	{"ip",		run_ipset},
	{"ping",	run_ping},
	{"tracert",	run_tracert},
	{"dhcp",	run_dhcp},
	{"neighbor",	run_nb6},
	{"zzz",		run_zzz},
	{"ver",		run_ver},
	{"save",	run_save},
	{"load",	run_load},
	{"clear",	run_clear},
	{"echo",	run_echo},
	{"rlogin",      run_remote},
	{NULL, NULL}
};

int main(int argc, char **argv)
{
	int i;
	char prompt[MAX_LEN];
	int c;
	pthread_t timer_pid;
	char *cmd;
	
	
	if (!isatty(0)) {
		printf("Please run in the tty\n");
		exit(-1);
	}	
	
	rhost = inet_addr("127.0.0.1");
	
	devtype = DEV_UDP;
	while (1) {
		c = getopt(argc, argv, "-h?eus:c:r:t:p:");
		if (-1 == c)
			break;
		switch (c) {
			case 'u':
				devtype = DEV_UDP;
				break;
			case 's':
				sport = arg_to_int(optarg, 1024, 65000, 20000);
				break;
			case 'c':
				rport_flag = 1;
				rport = arg_to_int(optarg, 1024, 65000, 30000);
				break;
			case 'r':
				startupfile = optarg;
				break;				
			case 'e':
				devtype = DEV_TAP;
				break;
			case 't':
				if (inet_addr(optarg) != -1)
					rhost = inet_addr(optarg);
				break;
			case 'p':
				daemon_port = arg_to_int(optarg, 1024, 65000, 10000);
				break;
			case 'h':
			case '?':
			default:
				usage();
				exit(1);
				break;
		}
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGINT, &sig_int);
	
	if (daemon_port && daemonize(daemon_port))
		exit(1);
		
	welcome();
	
	srand(time(0));
	memset(vpc, 0, NUM_PTHS * sizeof(pcs));
	for (i = 0; i < NUM_PTHS; i++) {
		if (pthread_create(&(vpc[i].pid), NULL, pth_proc, (void *)&i) != 0) {
			printf("PC%d error\n", i + 1);
			exit(-1);
		}
		strcpy(vpc[i].xname, "VPCS");
		while (vpc[i].ip4.mac[4] == 0) 
			delay_ms(10);
		delay_ms(50);
	}
	pthread_create(&timer_pid, NULL, pth_timer_tick, (void *)0);
	pcid = 0;
	
	delay_ms(50);
	autoconf6();
	
	delay_ms(50);
	startup();
	
	rls = readline_init(50, MAX_LEN);
	if (rls == NULL) {
		printf("initialize readline error\n");
		return 1;
	}
	if (histfile != NULL)
		loadhistory(histfile, rls);

	while (1) {
		snprintf(prompt, sizeof(prompt), "\n\r%s[%d]> ", vpc[pcid].xname, pcid + 1);
		ctrl_c = 0;
		cmd = readline(prompt, rls);
		if (cmd != NULL)
			parse_cmd(cmd);
	}
	return 1;
}

void parse_cmd(char *cmdstr)
{
	cmdStub *ep = NULL, *cmd = NULL;
	char *argv[5];
	int argc = 0;
	int rc = 0;
	
	argc = mkargv(cmdstr, (char **)argv, 5);
	
	if (argc == 1 && strlen(argv[0]) == 1 &&
	    (argv[0][0] - '0') > 0 && (argv[0][0] - '0') <= 9) {
		if (canEcho && runLoad)
			printf("%s[%d] %s\n", vpc[pcid].xname, pcid + 1, cmdstr);
		pcid = argv[0][0] - '0' - 1;
		return;
	} 
	
	rc = 0;
	printf("\n");
	
	if (!strncmp(argv[0], "echo", strlen(argv[0]))) {
		char *p = NULL;
	
		p = strchr(cmdstr, ' ');
		
		if (p != NULL)
			printf("%s\n", p + 1);	
		else {
			p = strchr(cmdstr, '\t');
			if (p != NULL)
				printf("%s\n", p + 1);
		}
		return;
	}
	for (ep = cmd_entry; ep->name != NULL; ep++) {
		if(!strncmp(argv[0], ep->name, strlen(argv[0]))) {
        		if (cmd != NULL)
        			printf("%s\n", cmd->name);
        		cmd = ep;
        		rc++;
        	}
	}

	if (rc > 1) {
		printf("%s\n", cmd->name);
		return;
	}
	
	if(cmd && cmd->name != NULL) {
		if (canEcho && runLoad)
			printf("%s[%d] %s\n", vpc[pcid].xname, pcid + 1, cmdstr);
		/* the session control block */
		memset(&vpc[pcid].mscb, 0, sizeof(vpc[pcid].mscb));
		vpc[pcid].mscb.sock = 1;
		
		rc = cmd->f(cmdstr);

		memset(&vpc[pcid].mscb, 0, sizeof(vpc[pcid].mscb));

	}  else
   		printf("Bad command: \"%s\". Use ? for help.\n", cmdstr);

    return;
}

void sig_int(int sig)
{
	ctrl_c = 1;
	signal(SIGINT, &sig_int);
}

void *pth_proc(void *devid)
{
	int id;
	pcs *pc = NULL;
	struct packet *m = NULL;
	u_char buf[PKT_MAXSIZE];
	int rc;
	u_int local_ip;

	id = *(int *)devid;
	pc  = &vpc[id];
	pc->id = id;

	local_ip = inet_addr("127.0.0.1");
	
	pc->rhost = rhost;
	pc->sport = sport + id;
	if (rhost != local_ip && !rport_flag)
		pc->rport = sport + id;
	else
		pc->rport = rport + id;
	pc->ip4.mac[0] = 0x00;
	pc->ip4.mac[1] = 0x50;
	pc->ip4.mac[2] = 0x79;
	pc->ip4.mac[3] = 0x66;
	pc->ip4.mac[4] = 0x68;
	pc->ip4.mac[5] = id & 0xff;
	
	if (pc->fd == 0)
		pc->fd = open_dev(id);
		
	if (pc->fd <= 0) {
		if (devtype == DEV_TAP)
			printf("Create Tap%d error [%s]\n", id, strerror(errno));
		else if (devtype == DEV_UDP)
			printf("Open port %d error [%s]\n", vpc[id].sport, strerror(errno));
		return NULL;
	}
		
	pthread_mutex_init(&(pc->locker), NULL);
	init_queue(&pc->iq);
	pc->iq.type = 0 + id * 100;
	init_queue(&pc->oq);
	pc->oq.type = 1 + id * 100;
	
	locallink6(pc);
	
	while (1) {
		while (1) {
			struct packet *pkt = NULL;
			
			pkt = deq(&pc->oq);

			if (pkt == NULL) 
				break;

			dmp_packet(pkt, pc->dmpflag);
			if (VWrite(pc, pkt->data, pkt->len) != pkt->len)
				printf("Send packet error\n");
			del_pkt(pkt);
		}
		
		rc = VRead(pc, buf, PKT_MAXSIZE);
		if (rc > 0) {
			m = new_pkt(PKT_MAXSIZE);
			if (m == NULL) {
				printf("Out of memory.\n");
				exit(-1);
			}
			memcpy(m->data, buf, rc);
			m->len = rc;
			gettimeofday(&(m->ts), (void*)0);

			if (pc->dmpflag & DMP_ALL || !memcmp(m->data, pc->ip4.mac, ETH_ALEN))
				dmp_packet(m, pc->dmpflag);
			rc = upv4(pc, m);
			
			if (rc == PKT_UP) {
				if (pc->mscb.sock != 0) {
					enq(&pc->iq, m);
				} else
					del_pkt(m);
			} else if (rc == PKT_DROP)
				del_pkt(m);
		} else
			delay_ms(0.5);
	}		

	return NULL;
}

void *pth_timer_tick(void *dummy)
{
	while (1) {
		time_tick ++;
		sleep(1);
	}
}

void startup(void)
{
	FILE *fp;
	char cmd[1024];

	if (startupfile == NULL) {
		fp = fopen(default_startupfile, "r");
		if (fp != NULL) {
			fclose(fp);
			snprintf(cmd, sizeof(cmd), "load %s", default_startupfile);
			runStartup = 1;
			run_load(cmd);
			runStartup = 0;
		}
		return;
	} else {
		fp = fopen(startupfile, "r");
		if (fp != NULL) {
			fclose(fp);
			snprintf(cmd, sizeof(cmd), "load %s", startupfile);
			runStartup = 1;
			run_load(cmd);
			runStartup = 0;
		} else
			printf("Can't open %s\n", startupfile);
		return;
	}
}

int run_load(char *cmdstr)
{
	FILE *fp;
	char buf[MAX_LEN];
	char *argv[2];
	int argc;
	
	argc = mkargv(cmdstr, argv, 2);
	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5         6         7         8
		 */
		printf( "\n\033[1mload filename\033[0m, Load the configuration/script from the file 'filename'.\n");
		return 0;
	}
		
	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		printf("Can't open %s\n", argv[1]);
		return -1;
	}

	if (runStartup)
		printf("\nExecuting the startup file\n");
	else
		printf("\nExecuting the file %s\n", argv[1]);

	while (!feof(fp) && !ctrl_c) {
		runLoad = 1;
		if (fgets(buf, MAX_LEN, fp) == NULL)
			break;
		if (buf[strlen(buf) - 1] == '\n') {
			buf[strlen(buf) - 1] = '\0';
			if (buf[strlen(buf) - 1] == '\r')
				buf[strlen(buf) - 1] = '\0';
		}		
		if (buf[0] == '#' ||
			buf[0] == '!' ||
			buf[0] == ';')
			continue;
		if (strlen(buf) > 0)	
			parse_cmd(buf);
	}
	runLoad = 0;
	fclose(fp);
	return 1;
}

int run_save(char *cmdstr)
{
	FILE *fp;
	int i;
	char *p;
	char *argv[2];
	int argc;
	char buf[64];
	u_int local_ip;
	struct in_addr in;
	
	argc = mkargv(cmdstr, argv, 2);
	if (argc < 2 || (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?')) {
		/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5         6         7         8
		 */
		printf( "\n\033[1msave filename\033[0m, Save the configuration to the file 'filename'.\n");
		return 0;
	}	
	fp = fopen(argv[1], "w");
	if (fp != NULL) {
		local_ip = inet_addr("127.0.0.1");
		for (i = 0; i < NUM_PTHS; i++) {
			fprintf(fp, "%d\n", i + 1);
			
			sprintf(buf, "VPCS[%d]", i + 1);
			if (strncmp(vpc[i].xname, buf, 3)) 
				fprintf(fp, "set pcname %s\n", vpc[i].xname);
			
			if (vpc[i].sport != (20000 + i)) 
				fprintf(fp, "set lport %d\n", vpc[i].sport);
				
			if (vpc[i].rport != (30000 + i)) 
				fprintf(fp, "set rport %d\n", vpc[i].rport);
			if (vpc[i].rhost != local_ip) {
				in.s_addr = vpc[i].rhost;
				fprintf(fp, "set rhost %s\n", inet_ntoa(in));
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
			}
			printf(".");
		}
		fprintf(fp, "1\n");
		fclose(fp);
		printf("  done\n");
	} else
		printf("Can not write %s\n", argv[1]);
	return 1;
}

int run_quit(char *dummy)
{
	int i;
	pid_t pid;
	
	if (daemon_port) {
		pid = getppid();
		kill(pid, SIGUSR1);
		return 0;
	}
		
	for (i = 0; i < NUM_PTHS; i++)
		close(vpc[i].fd);

	if (histfile != NULL) 
		savehistory(histfile, rls);

	printf("\n");
	exit(1);
}

int run_hist(char *cmdstr)
{
	char *argv[2];
	int argc;
	int i;
	
	argc = mkargv(cmdstr, (char **)argv, 2);
	
	if (argc == 2 && strlen(argv[1]) == 1 && argv[1][0] == '?') {
		/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890
		 *       1         2         3         4         5         6         7         8
		 */
		printf( "\n\033[1mhist\033[0m, List the history command.\n"
			"    use up/down arrow keys to get recently-executed commands.\n");
		return 0;
	}
	
	printf("\n");
	
	for (i = 0; i < rls->hist_total; i++)
		printf("%s\n", rls->history[i]);
		
	return 1;
}

void clear_hist(void)
{
	rls->hist_total = 0;	
}

void welcome(void)
{
	printf ("\n"
		"Welcome to Virtual PC Simulator for dynamips, v%s\n"
		"Dedicated to Daling.\n"
		"Build time: %s %s\n"
		"All rights reserved.\n\n"
		"Please contact me at mirnshi@gmail.com if you have any questions. \n\n"
		"Press '?' to get help.\n\n",
		ver, __DATE__, __TIME__ );	
	return;			
}

void usage()
{
	printf ("usage: vpcs [options]\n"
		"           -p port   daemon port\n"
		"           -u        udp mode, default\n"
		"           -e        tap mode, using /dev/tapx (only linux)\n"
		"           -s port   local udp port, default from 20000\n"
		"           -c port   remote udp port(dynamips udp ports)\n"
		"                     default from 30000, or 20000 if rhost is set\n"
		"           -t rhost  remote host\n"
		"           -r file   run startup file\n"
		"\n");
}

int run_ver(char *dummy)
{
	printf("\nVersion: %s, build time: %s %s\n", ver, __DATE__, __TIME__ );
	return 1;	
}

int run_help(char *dummy) 
{
	printf ("\n"
		"show [options]             Print the net configuration of PCs\n"
		"d                          Switch to the PC[d], d is digit, range 1 to 9\n"
		"history                    List the command history\n"
		"ip [arguments]             Configure PC's IP settings\n"
		"dhcp [options]             Configure host/gateway address using DHCP\n"
		"arp                        Show arp table\n"
		"ping address [options]     Ping the network host\n"
		"tracert address [maxhops]  Print the route packets take to network host\n"
		"rlogin [ip] port           Telnet remote host, connect 127.0.0.1 if no ip\n"
		"echo [text]                Display text in output\n"
		"clear [arguments]          Clear ip/ipv6, arp/neighbor cache\n"
		"set [arguments]            Set hostname, connection port and echo on or off\n"
		"load filename              Load the configuration/script from the file 'filename'\n"
		"save filename              Save the configuration to the file 'filename'\n"
		"ver                        Show version\n"
		"?                          Print help\n"
		"quit                       Quit program\n");
	return 1;			
}
/* end of file */

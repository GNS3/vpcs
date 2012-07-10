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
#include "help.h"

#ifndef Darwin
#include "getopt.h"
#endif

const char *ver = "0.4a13";
const char *copy = "Copyright (c) mirnshi, $Revision: 1.13 $";

int pcid = 0;  /* current vpc id */
int devtype = 0;
int lport = 20000;
int rport = 30000;
int rport_flag = 0;
u_int rhost = 0; /* remote host */

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

int run_quit(int argc, char **argv);

struct stub
{
	char *name;
	char *grpname;
	int (*f)(int argc, char **argv);
	int (*help)(int argc, char **argv);
	
};
typedef struct stub cmdStub;

cmdStub cmd_entry[] = {
	{"?",		NULL,	run_help,	help_help},
	{"arp",		"show",	run_show,	help_show},
	{"clear",	NULL,	run_clear,	help_clear},
	{"dhcp",	"ip",	run_ipconfig,	help_ip},
	{"echo",	NULL,	run_echo,	NULL},
	{"help",	NULL,	run_help,	help_help},
	{"hist",	NULL,	run_hist,	NULL},
	{"ip",		NULL,	run_ipconfig,	help_ip},
	{"load",	NULL,	run_load,	help_load},
	{"neighbor",	NULL,	run_nb6,	NULL},
	{"ping",	NULL,	run_ping,	help_ping},
	{"quit",	NULL,	run_quit,	NULL},
	{"tracer",	NULL,	run_tracert,	help_trace},
	{"rlogin",      NULL,	run_remote,	help_rlogin},
	{"save",	NULL,	run_save,	help_save},
	{"set",		NULL,	run_set,	help_set},
	{"show",	NULL,	run_show,	help_show},
	{"version",	NULL,	run_ver,	NULL},
	{"sleep",	NULL,	run_sleep,	help_sleep},
	{"zzz",		NULL,	run_sleep,	help_sleep},
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
				lport = arg_to_int(optarg, 1024, 65000, 20000);
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
				daemon_port = arg_to_int(optarg, 1024, 65000, 5000);
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
	char *argv[20];
	int argc = 0;
	int rc = 0;
	
	argc = mkargv(cmdstr, (char **)argv, 20);
	
	if (argc == 0)
		return;

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
			printf("%s", p + 1);	
		else {
			p = strchr(cmdstr, '\t');
			if (p != NULL)
				printf("%s", p + 1);
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
		if (cmd->grpname != NULL) {
			argc = insert_argv(argc, argv, cmd->grpname);	
			for (ep = cmd_entry; ep->name != NULL; ep++) {
				if(!strcmp(argv[0], ep->name)) {
					cmd = ep;
					break;
				}
			}
		}
		
		if (canEcho && runLoad) {
			if (!strcmp(cmd->name, "sleep") && 
			    (argc != 2 || (argc == 2 && !digitstring(argv[1])))) {
			    	;
			} else
				printf("%s[%d] %s\n", vpc[pcid].xname, pcid + 1, cmdstr);
		}
		if (argc > 1 && cmd->help != NULL && 
		    ((!strcmp(argv[argc - 1], "?") || !strcmp(argv[argc - 1], "help")))) {
		    	argv[0] = cmd->name;
			cmd->help(argc, argv);
			return;
		}
						
		/* the session control block */
		memset(&vpc[pcid].mscb, 0, sizeof(vpc[pcid].mscb));
		vpc[pcid].mscb.sock = 1;
		
		rc = cmd->f(argc, argv);

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
	pc->lport = lport + id;
	if (rhost != local_ip && !rport_flag)
		pc->rport = lport + id;
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
			printf("Open port %d error [%s]\n", vpc[id].lport, strerror(errno));
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
	time_t t0, t1;
	t0 = time(0);
	while (1) {
		t1 = time(0);
		if (t1 - t0 > 0) {
			time_tick += t1 - t0;
			t0 = t1;
		}
		usleep(100);
	}
}

void startup(void)
{
	FILE *fp;
	int argc;
	char *argv[3];
	
	if (startupfile == NULL) {
		fp = fopen(default_startupfile, "r");
		if (fp != NULL) {
			fclose(fp);
			argv[0] = "load";
			argv[1] = (char *)default_startupfile;
			argv[2] = NULL;
			argc = 2;
			runStartup = 1;
			run_load(argc, argv);
			runStartup = 0;
		}
		return;
	} else {
		fp = fopen(startupfile, "r");
		if (fp != NULL) {
			fclose(fp);
			runStartup = 1;
			
			argv[0] = "load";
			argv[1] = (char *)startupfile;
			argv[2] = NULL;
			argc = 2;
			run_load(argc, argv);
			
			runStartup = 0;
		} else
			printf("Can't open %s\n", startupfile);
		return;
	}
}

int run_quit(int argc, char **argv)
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

	if (rls != NULL && histfile != NULL) 
		savehistory(histfile, rls);

	printf("\n");
	exit(1);
}

void clear_hist(void)
{
	rls->hist_total = 0;	
}

void welcome(void)
{
	run_ver(0, NULL);
	
	printf("\nPress '?' to get help.\n");
	return;			
}

void usage()
{
	run_ver(0, NULL);
	printf ("\nusage: vpcs [options]\n"
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



/* end of file */

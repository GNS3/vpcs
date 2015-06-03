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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>	 /* usleep */
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#ifdef cygwin
#include <windows.h>
#include <sys/cygwin.h>
#endif

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
#include "dump.h"
#include "relay.h"
#include "dhcp.h"
#include "frag6.h"

const char *ver = "0.8 dev";
/* track the binary */
static const char *ident = "$Id$";

int pcid = 0;  /* current vpc id */
int devtype = 0;
int lport = 20000;
int rport = 30000;
int rport_flag = 0;
u_int rhost = 0; /* remote host */
struct echoctl echoctl;

int runLoad = 0;	/* work with canEcho */
int runRelay = 1;	/* sw of relay function */
int runStartup = 0;	/* execute startup if 1 */

char *startupfile = NULL;
const char *default_startupfile = "startup.vpc";
char *histfile = "vpcs.hist";

u_int time_tick = 0; /* time tick (second) */

int ctrl_c = 0; /* ctrl+c was pressed */

struct rls *rls = NULL;

int daemon_port = 0;

int num_pths = MAX_NUM_PTHS;  /* number of VPCs */

char *tapname = "tap0";  /* TAP device name (only when 1 VPC is created) */

int macaddr = 0; /* the last byte of ether address */


static void *pth_reader(void *devid);
static void *pth_output(void *devid);
static void *pth_writer(void *devid);
static void *pth_timer_tick(void *);
static void *pth_bgjob(void *);
void parse_cmd(char *cmdstr);
static void sig_int(int sig);
static void sig_clean(int sig);
void clear_hist(void);
static int invoke_cmd(const char *);

static void welcome(void);
void usage();
static void startup(void);

static int run_quit(int argc, char **argv);
static int run_disconnect(int argc, char **argv);

struct stub
{
	char *name;
	char *grpname;
	int (*f)(int argc, char **argv);
	int (*help)(int argc, char **argv);
	
};
typedef struct stub cmdStub;

static cmdStub cmd_entry[] = {
	{"?",		NULL,	run_help,	help_help},
	{"arp",		"show",	run_show,	help_show},
	{"clear",	NULL,	run_clear,	help_clear},
	{"dhcp",	"ip",	run_ipconfig,	help_ip},
	{"disconnect",  NULL,   run_disconnect, NULL},
	{"echo",	NULL,	run_echo,	NULL},
	{"help",	NULL,	run_help,	help_help},
	{"history",	NULL,	run_hist,	NULL},
	{"relay",       NULL,   run_relay,      help_relay},
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

#ifdef HV
int vpcs(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	int i;
	char prompt[MAX_LEN];
	int c;
	pthread_t timer_pid, relay_pid, bgjob_pid;
	int daemon_bg = 1;
	char *cmd;

	memset(&echoctl, 0, sizeof(struct echoctl));
	rhost = inet_addr("127.0.0.1");
	
	devtype = DEV_UDP;		
	while ((c = getopt(argc, argv, "?c:ehm:p:r:Rs:t:uvFi:d:")) != -1) {
		switch (c) {
			case 'c':
				rport_flag = 1;
				rport = arg2int(optarg, 1024, 65000, 30000);
				break;
			case 'e':
				devtype = DEV_TAP;
				break;
			case 'm':
				macaddr = arg2int(optarg, 0, 240, 0);
				break;
			case 'p':
				daemon_port = arg2int(optarg, 1024, 65000, 5000);
				break;
			case 'r':
				startupfile = strdup(optarg);
				break;
			case 'R':
				runRelay = 0;
				break;
			case 's':
				lport = arg2int(optarg, 1024, 65000, 20000);
				break;
			case 't':
				if (inet_addr(optarg) != -1)
					rhost = inet_addr(optarg);
				break;
			case 'u':
				devtype = DEV_UDP;
				break;
			case 'v':
				run_ver(argc, argv);
				exit(0);
				break;
			case 'F':
				daemon_bg = 0;
				break;
			case 'i':
				num_pths = arg2int(optarg, 1, 9, 9);
				break;
			case 'd':
				if (num_pths != 1) {
					usage();
					exit(0);
				}
				tapname = strdup(optarg);
				break;

			case 'h':
			case '?':
				usage();
				exit(0);
				break;
		}
	}
	if (optind != argc) {
		if (optind + 1 == argc)
			startupfile = strdup(argv[optind]);
		else {
			usage();
			exit(0);
		}
	}

	if (daemon_port && daemonize(daemon_port, daemon_bg))
		exit(0);

	if (!isatty(0)) {
		printf("Please run in the tty\n");
		exit(-1);
	}	

	signal(SIGINT, &sig_int);
	signal(SIGUSR1, &sig_clean);
	signal(SIGCHLD, SIG_IGN);
		
	welcome();

	srand(time(0));
	
	init_ipfrag();
	init_ip6frag();
	
	memset(vpc, 0, MAX_NUM_PTHS * sizeof(pcs));
	for (i = 0; i < num_pths; i++) {
		if (pthread_create(&(vpc[i].rpid), NULL, pth_reader, (void *)&i) != 0) {
			printf("PC%d error\n", i + 1);
			fflush(stdout);
			exit(-1);
		}
		strcpy(vpc[i].xname, "VPCS");
		while (vpc[i].ip4.mac[4] == 0) 
			delay_ms(10);
		delay_ms(100);
	}
	pthread_create(&timer_pid, NULL, pth_timer_tick, (void *)0);
	delay_ms(100);
	pthread_create(&relay_pid, NULL, pth_relay, (void *)0);
	pthread_create(&bgjob_pid, NULL, pth_bgjob, (void *)0);
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
		if (num_pths > 1)
			snprintf(prompt, sizeof(prompt), "\n\r%s[%d]> ", vpc[pcid].xname, pcid + 1);
		else
			snprintf(prompt, sizeof(prompt), "\n\r%s> ", vpc[pcid].xname);
		ctrl_c = 0;
		cmd = readline(prompt, rls);
		if (cmd != NULL) {
			ttrim(cmd);
			parse_cmd(cmd);
		}
	}
	return 0;
}

void parse_cmd(char *cmdstr)
{
	cmdStub *ep = NULL, *cmd = NULL;
	char *argv[20];
	int argc = 0;
	int rc = 0;
	char *pcmd;
	int at = 0;
	
	if (cmdstr[0] == '#' || cmdstr[0] == ';')
		return;

	argc = mkargv(cmdstr, (char **)argv, 20);
	
	if (argc == 0)
		return;

	if (argc == 1 && strlen(argv[0]) == 1 && num_pths >= 1 &&
	    (argv[0][0] >= '0' && argv[0][0] <= '9')) {
	    	if ((argv[0][0] - '0') <= num_pths) {
			if (echoctl.enable && runLoad)
				printf("%s[%d] %s\n", vpc[pcid].xname, 
				    pcid + 1, cmdstr);
			pcid = argv[0][0] - '0' - 1;
			
		} else 
			printf("\nOnly %d VPCs actived\n", num_pths);
		return;
	} 
	
	rc = 0;
	printf("\n");
	
	if (!strcmp(argv[0], "srcid")) {
		printf("Source code ID: %s\n", ident);
		return;
	}
	
	if (!strncmp(argv[0], "echo", strlen(argv[0]))) {
		char *p = NULL;
	
		p = strchr(cmdstr, ' ');
		
		if (echoctl.fgcolor != 0) {
			if (echoctl.bgcolor != 0)
				printf("\033[%d;%dm", echoctl.fgcolor, 
					echoctl.bgcolor);
			else
				printf("\033[%dm", echoctl.fgcolor);
		}
		if (p != NULL)
			printf("%s", p + 1);	
		else {
			p = strchr(cmdstr, '\t');
			if (p != NULL)
				printf("%s", p + 1);
		}
		if (echoctl.fgcolor != 0)
			printf("\033[0m");
		fflush(stdout);
		return;
	}
	
	if (*cmdstr == '!') {
		char *p = NULL;
		if (strlen(cmdstr) > 1) {
			p = cmdstr + 1;
			while (*p== ' ' || *p == '\t')
				p++;
				
			if (*p && strcmp(p, "?")) {
				invoke_cmd(p);
				return;
			}
		}
		help_shell(0, NULL);
		return;
	}
	pcmd = argv[0];
	if (*pcmd == '@') {
		at = 1;
		pcmd ++;
	}
	for (ep = cmd_entry; ep->name != NULL; ep++) {
		if(!strncmp(pcmd, ep->name, strlen(pcmd))) {
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
				if(!strcmp(pcmd, ep->name)) {
					cmd = ep;
					break;
				}
			}
		}
		
		if (echoctl.enable && runLoad) {
			if (!strcmp(cmd->name, "sleep") && 
			    (argc != 2 || (argc == 2 && !digitstring(argv[1])))) {
			    	;
			} else if (at == 0)
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

void *pth_reader(void *devid)
{
	int id;
	pcs *pc = NULL;
	struct packet *m = NULL;
	u_char buf[PKT_MAXSIZE];
	int rc;

	id = *(int *)devid;
	pc  = &vpc[id];
	pc->id = id;
	
	pc->rhost = rhost;
	pc->lport = lport + id;
	pc->rport = rport + id;
	
	pc->ip4.mac[0] = 0x00;
	pc->ip4.mac[1] = 0x50;
	pc->ip4.mac[2] = 0x79;
	pc->ip4.mac[3] = 0x66;
	pc->ip4.mac[4] = 0x68;
	pc->ip4.mac[5] = (id + macaddr) & 0xff;
	pc->ip4.flags |= IPF_FRAG;
	pc->mtu = 1500;
	
	if (pc->fd == 0)
		pc->fd = open_dev(id);
		
	if (pc->fd <= 0) {
		if (devtype == DEV_TAP)
			if (num_pths > 1)
				printf("Create TAP device tap%d error [%s]\n", id, strerror(errno));
			else
				printf("Create TAP device %s error [%s]\n", tapname, strerror(errno));
		else if (devtype == DEV_UDP)
			printf("Open port %d error [%s]\n", vpc[id].lport, strerror(errno));
		return NULL;
	}
		
	pthread_mutex_init(&(pc->locker), NULL);
	init_queue(&pc->iq);
	pc->iq.type = 0 + id * 100;
	init_queue(&pc->oq);
	pc->oq.type = 1 + id * 100;
	init_queue(&pc->bgiq);
	pc->bgiq.type = 2 + id * 100;
	init_queue(&pc->bgoq);
	pc->bgoq.type = 3 + id * 100;
	
	
	if (pthread_create(&(pc->wpid), NULL, pth_writer, devid) != 0) {
		printf("PC%d error\n", id + 1);
		exit(-1);
	}

	if (pthread_create(&(pc->outid), NULL, pth_output, devid) != 0) {
		printf("PC%d error\n", id + 1);
		exit(-1);
	}
	
	while (1) {
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

			if (!memcmp(m->data, pc->ip4.mac, ETH_ALEN) ||
			    pc->dmpflag & DMP_ALL) {
				if (pc->dmpflag & DMP_FILE)
					dmp_packet2file(m, pc->dmpfile);					
				dmp_packet(m, pc->dmpflag);
			}
	
			rc = upv4(pc, &m);
			if (rc == PKT_UP) {
				if (dhcp_enq(pc, m))
					continue;
				if (pc->mscb.sock != 0) {
					enq(&pc->iq, m);
				} else
					del_pkt(m);
			} else if (rc == PKT_DROP)
				del_pkt(m);
		}
	}

	return NULL;
}

void *pth_output(void *devid)
{
	int id;
	pcs *pc = NULL;
	struct packet *m = NULL;
	
	id = *(int *)devid;
	pc  = &vpc[id];
	
	/* send4 or send6 will block this thread for a while to get 
	   the ether address via arpresolv or neighbor solicitation 
	*/
	while (1) {
		m = waitdeq(&pc->bgoq);
		
		while (m) {
			send4(pc, m);
			m = deq(&pc->bgoq);
		}
	}
	return NULL;
}

void *pth_writer(void *devid)
{
	int id;
	pcs *pc = NULL;
	
	id = *(int *)devid;
	pc  = &vpc[id];
	
	locallink6(pc);
	
	while (1) {
		struct packet *m = NULL;

		m = waitdeq(&pc->oq);

		while (m) {
			if (pc->dmpflag & DMP_FILE)
				dmp_packet2file(m, pc->dmpfile);

			dmp_packet(m, pc->dmpflag);
			if (VWrite(pc, m->data, m->len) != m->len)
				printf("Send packet error\n");
			del_pkt(m);
			
			m = deq(&pc->oq);
		}
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
			//time_tick += t1 - t0;
			time_tick = t1;
			t0 = t1;
		}
		usleep(100);
	}
	return NULL;
}

void *pth_bgjob(void *dummy)
{
	int i;
	int t, s;

	i = 0;
	do {
		if (vpc[i].ip4.dhcp.svr && vpc[i].ip4.dhcp.timetick) {
			t = time_tick - vpc[i].ip4.dhcp.timetick;
			s = t - vpc[i].ip4.dhcp.renew;
			if (t > vpc[i].ip4.dhcp.renew && s < 4) {
			    	vpc[i].bgjobflag = 1;
			    	if (dhcp_renew(&vpc[i]))
			    		vpc[i].ip4.dhcp.timetick = time_tick;
			    	vpc[i].bgjobflag = 0;
			    	continue;
			}
			s = t - vpc[i].ip4.dhcp.rebind;
			if (t > vpc[i].ip4.dhcp.rebind && s < 4) {
			    	vpc[i].bgjobflag = 1;
			    	if (dhcp_rebind(&vpc[i]))
			    		vpc[i].ip4.dhcp.timetick = time_tick;
			    	vpc[i].bgjobflag = 0;
			    	continue;
			}
		}
		usleep(10000);
		i = (i + 1) % num_pths;
	} while (1);
	
	return NULL;
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


void 
sig_clean(int sig)
{
	int i;
	
	for (i = 0; i < num_pths; i++)
		close(vpc[i].fd);

	if (rls != NULL && histfile != NULL) 
		savehistory(histfile, rls);	
}

int run_quit(int argc, char **argv)
{
	pid_t pid;
	
	if (daemon_port) {
		pid = getppid();
		kill(pid, SIGUSR1);
	}
		
	sig_clean(0);

	printf("\n");
	exit(0);
}

int run_disconnect(int argc, char **argv)
{
	pid_t pid;
	
	if (daemon_port) {
		pid = getppid();
		kill(pid, SIGQUIT);
	} else
		printf("NOT daemon mode\n");
	
	return 0;
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

static int 
invoke_cmd(const char *cmd)
{
	int rc = 0;
	
#ifdef cygwin
	char str[1024];
	snprintf(str, sizeof(str), "%s /c %s", getenv("COMSPEC"), cmd);
	rc = WinExec(str, SW_SHOW);
#else	
	rc = system(cmd);
#endif	
	return rc;
}

void usage()
{
	run_ver(0, NULL);
	esc_prn("\r\nusage: vpcs [{UOPTIONS}] [{UFILENAME}]\r\n"
		"{HOPTIONS}:\r\n"
		"  {H-h}             print this help then exit\r\n"
		"  {H-v}             print version information then exit\r\n"
		"\r\n"
		"  {H-R}             disable relay function\r\n"
		"  {H-i} {Unum}         number of vpc instances to start (default is 9)\r\n"
		"  {H-p} {Uport}        run as a daemon listening on the tcp {Uport}\r\n"
		"  {H-m} {Unum}         start byte of ether address, default from 0\r\n"
		"  [{H-r}] {UFILENAME}  load and execute script file {HFILENAME}\r\n"
		"\r\n"
		"  {H-e}             tap mode, using /dev/tapx by default (linux only)\r\n"
		"  [{H-u}]           udp mode, default\r\n"
		"\r\nudp mode options:\r\n"
		"  {H-s} {Uport}        local udp base {Uport}, default from 20000\r\n"
		"  {H-c} {Uport}        remote udp base {Uport} (dynamips udp port), default from 30000\r\n"
		"  {H-t} {Uip}          remote host {UIP}, default 127.0.0.1\r\n"
		"\r\ntap mode options:\r\n"
		"  {H-d} {Udevice}      {Udevice} name, works only when -i is set to 1\r\n"
		"\r\nhypervisor mode option:\r\n"
		"  {H-H} {Uport}        run as the hypervisor listening on the tcp {Uport}\r\n"
		"\r\n"
		"  If no {HFILENAME} specified, vpcs will read and execute the file named\r\n"
		"  startup.vpc if it exists in the current directory.\r\n"
		"\r\n");
}
/* end of file */

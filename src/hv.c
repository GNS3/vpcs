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

#include <sys/types.h>
#include <sys/param.h>
 
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <libgen.h>
#include <getopt.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "hv.h"
#include "utils.h"

const char *ver = "0.5a1";

static int parse_cmd(char *buf);
static int readpid(int port, pid_t *pid);
static void welcome(void);
static void usage(void);
static int exist(const char *name);

static int run_vpcs(int ac, char **av);
static int run_list(int ac, char **av);
static int run_quit(int ac, char **av);
static int run_killme(int ac, char **av);
static int run_stop(int ac, char **av);
static int run_help(int ac, char **av);

static int cmd_quit = 0;
static int cmd_kill = 0;

static struct list vpcs_list[MAX_DAEMONS];
static char vpcspath[PATH_MAX];
static char cmdbuffer[1024];

static int hvport = 0;

static FILE *hvout, *hvin; /* input, output */

cmdStub cmd_entry[] = {
	{"vpcs",   run_vpcs},
	{"quit",   run_quit},
	{"list",   run_list},
	{"killme", run_killme},
	{"stop",   run_stop},
	{"help",   run_help},
	{"?",      run_help},
	{NULL,     NULL}};
	
int 
main(int argc, char **argv)
{
	pid_t pid;
	int sock, sock_cli;
	struct sockaddr_in serv, cli;	
	int slen;
	int prompt = 1;
	int c;
	char buf[PATH_MAX];
	
	memset(vpcspath, 0, sizeof(vpcspath));
	while ((c = getopt(argc, argv, "?hp:f:")) != -1) {
		switch (c) {
			case 'p':
				hvport = atoi(optarg);
				break;
			case 'f':
				if (!realpath(optarg, vpcspath)) {
					printf("Can not resolve the path\n");
					return 1;
				}
				break;
			case 'h':
			case '?':
				usage();
				return 0;
		}
	}
	
	if (hvport < 1024 || hvport > 65534)
		hvport = DEFAULT_PORT;
	
	if (vpcspath[0] == 0) {
		if (realpath(argv[0], buf)) {
			snprintf(vpcspath, sizeof(vpcspath), "%s/vpcs", 
		    	    dirname(buf));
		} else {
			printf("Can not resolve the path: %s\n", argv[0]);
			return 1;
		}
	}
	
	if (!exist(vpcspath)) {
		printf("VPCS can not be found: %s\n", vpcspath);	
		return 1;
	}
	
	printf("VPCS Hypervisor is listening on port %d\n", hvport);
	pid = fork();
	if (pid < 0) {
		perror("Daemon fork");
		return 1;
	}
	if (pid > 0)
		exit(0);

	setsid();

	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	
	memset(vpcs_list, 0, MAX_DAEMONS * sizeof(struct list));
	
	/* daemon socket */
   	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("Create socket");
		return 1;
	}

	c = 1;
	(void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
	    (char *)&c, sizeof(c));

	bzero((char *) &serv, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(hvport);
	
	if (bind(sock, (struct sockaddr *) &serv, sizeof(serv)) < 0) {
		perror("bind socket");
		close(sock);
		return 1;
	}
	if (listen(sock, 5) < 0) {
		perror("listen socket");
		close(sock);
		return 1;
	}

	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC); 
	slen = sizeof(cli);
	while (!cmd_kill) {
		cmd_quit = 0;
		
		if ((sock_cli = accept(sock, (struct sockaddr *) &cli, 
		    (socklen_t *)&slen)) < 0)
			continue;

		fcntl(sock_cli, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC); 
		
		hvin = fdopen(sock_cli, "r");
		hvout = fdopen(sock_cli, "w");
		if (!hvin || !hvout) {
			snprintf(buf, sizeof(buf), "Internal error: %d", errno);
			write(sock_cli, buf, strlen(buf));
			close(sock_cli);
			continue;
		}
		while (!cmd_quit) {	
			if (prompt) {
				welcome();
				prompt = 0;
			}
			
			fprintf(hvout, ">> ");
			fflush(hvout);
			
			memset(cmdbuffer, 0, sizeof(cmdbuffer));
			if (!fgets(cmdbuffer, sizeof(cmdbuffer), hvin))
				break;

			ttrim(cmdbuffer);
			parse_cmd(cmdbuffer);
		}
		
		fclose(hvin);
		fclose(hvout);
	}
	
	return 0;
}

static int 
parse_cmd(char *cmdstr)
{
	char *av[20];
	int ac = 0;
	cmdStub *ep = NULL;
	
	ac = mkargv(cmdstr, (char **)av, 20);
	
	if (ac == 0)
		return 0;

	for (ep = cmd_entry; ep->name != NULL; ep++) {
		if(!strncmp(av[0], ep->name, strlen(av[0]))) {
        		return ep->f(ac, av);
        	}
	}
	
	ERR(hvout, "Invalid or incomplete command\r\n");
	
	return 0;
}

static int
run_vpcs(int ac, char **av)
{
	int i, j, c;
	struct list *pv;
	pid_t pid;
	char *agv[20];
	int agc = 0;
	char buf[1024];
	
	/* find free slot */
	for (i = 0; i < MAX_DAEMONS && vpcs_list[i].pid != 0; i++);
	
	if (i == MAX_DAEMONS)
		return 0;

	pv = &vpcs_list[i];
	memset(pv, 0, sizeof(struct list));
	
	/* reinitialized, call getopt twice */
	optind = 1;
#if (defined(FreeBSD) || defined(Darwin))
	optreset = 1;
#endif	
	while ((c = getopt(ac, av, "p:m:s:c:")) != -1) {
		switch (c) {
			case 'p':
				pv->vport = atoi(optarg);
				if (pv->vport == 0) {
					ERR(hvout, "Invalid daemon port\r\n");
					return 1;
				}
				break;
			case 'm':
				pv->vmac = atoi(optarg);
				if (pv->vmac == 0) {
					ERR(hvout, "Invalid ether address\r\n");
					return 1;
				}
				break;
			case 's':
				pv->vsport = atoi(optarg);
				if (pv->vsport == 0) {
					ERR(hvout, "Invalid local port\r\n");
					return 1;
				}
				break;
			case 'c':
				pv->vcport = atoi(optarg);
				if (pv->vcport == 0) {
					ERR(hvout, "Invalid remote port\r\n");
					return 1;
				}
				break;				
		}
	}
	
	/* set the new daemon port */
	if (pv->vport == 0) {
		j = 0;
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			if (vpcs_list[i].vport > j)
				j = vpcs_list[i].vport;
		}
		if (j == 0)
			pv->vport = hvport + 1;
		else
			pv->vport = j + 1;
		
	} else {
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			if (pv->vport != vpcs_list[i].vport)
				continue;
			ERR(hvout, "Port %d already in use\r\n", pv->vport);
			return 1;
		}
	}
	
	/* set the new mac */
	if (pv->vmac == 0) {
		j = 0;
		c = 0;
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			if (vpcs_list[i].vmac > j)
				j = vpcs_list[i].vmac;
			c = 1;
		}
		if (j == 0) {
			/* there's vpcs which ether address start from 0 */
			if (c == 1)
				pv->vmac = STEP;
			else
				pv->vmac = 0;
		} else
			pv->vmac = j + STEP;
		
	} else {
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			if (((pv->vmac >= vpcs_list[i].vmac) && 
			    ((pv->vmac - vpcs_list[i].vmac) < STEP)) ||
			    ((pv->vmac < vpcs_list[i].vmac) && 
			    ((vpcs_list[i].vmac - pv->vmac) < STEP))) {
				ERR(hvout, "Ether address overlapped\r\n");
				return 1;		
			}
		}
	}
	
	/* set the new local port */
	if (pv->vsport == 0) {
		j = 0;
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			if (vpcs_list[i].vsport > j)
				j = vpcs_list[i].vsport;
		}
		if (j == 0)
			pv->vsport = DEFAULT_SPORT;
		else
			pv->vsport = j + STEP;
	} else {
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			if (((pv->vsport >= vpcs_list[i].vsport) && 
			    ((pv->vsport - vpcs_list[i].vsport) < STEP)) ||
			    ((pv->vsport < vpcs_list[i].vsport) && 
			    ((vpcs_list[i].vsport - pv->vsport) < STEP))) {
				ERR(hvout, "Local udp port overlapped\r\n");
				return 1;		
			}
		}
	}
	
	/* set the new remote port */
	if (pv->vcport == 0) {
		j = 0;
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			if (vpcs_list[i].vcport > j)
				j = vpcs_list[i].vcport;
		}
		if (j == 0)
			pv->vcport = DEFAULT_CPORT;
		else
			pv->vcport = j + STEP;
	} else {
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			if (((pv->vcport >= vpcs_list[i].vcport) && 
			    ((pv->vcport - vpcs_list[i].vcport) < STEP)) ||
			    ((pv->vcport < vpcs_list[i].vcport) && 
			    ((vpcs_list[i].vcport - pv->vcport) < STEP))) {
				ERR(hvout,"Remote udp port overlapped\r\n");
				return 1;		
			}
		}
	}
	
	pv->cmdline = strdup(cmdbuffer);
	
	i = 0;
	if (pv->vport) 
		i += snprintf(buf + i, sizeof(buf) - i, "-p %d ", 
		    pv->vport);
	if (pv->vsport)
		i += snprintf(buf + i, sizeof(buf) - i, "-s %d ", 
		    pv->vsport);
	if (pv->vcport) 
		i += snprintf(buf + i, sizeof(buf) - i, "-c %d ", 
		    pv->vcport);
	if (pv->vmac) 
		i += snprintf(buf + i, sizeof(buf) - i, "-m %d ", 
		    pv->vmac);
	j = 1;
	while (j < ac) {
		if (!strcmp(av[j], "-p") || !strcmp(av[j], "-s") ||
		    !strcmp(av[j], "-c") || !strcmp(av[j], "-m")) {
			j += 2;
			continue;
		}
		i += snprintf(buf + i, sizeof(buf) - i, "%s ", 
		    av[j]);
		j++;
	}

	pv->cmdline = strdup(buf);
	agc = mkargv(buf, (char **)(agv + 1), 20);
	
	agv[0] = vpcspath;
	agc++;

	pid = fork();
	if (pid < 0)
		return 0;
		
	if (pid == 0) {
		if (execvp(agv[0], agv) == -1) {
			syslog(LOG_ERR, "Fork VPCS failed: %s", 
			    strerror(errno));
		}
	}
	
	waitpid(pid, NULL, 0);
	delay_ms(200);
	readpid(pv->vport, &pid);
	if (pid == 0)
		return 0;

	/* existed pid */
	for (j = 0; j < MAX_DAEMONS; j++) {
		if (vpcs_list[j].pid == pid)
			return 0;
	}
	
	/* check the process */
	if (kill(pid, 0)) {
		pid = 0;
		ERR(hvout, "Fork VPCS failed.\r\n");
		return 0;
	}
	pv->pid = pid;
	
	SUCC(hvout, "VPCS started with %s\r\n", pv->cmdline);
	
	return 0;
}

static int 
run_list(int ac, char **av)
{
	int i, k;

	fprintf(hvout, "ID\tPID\tParameters\r\n");
	 
	for (i = 0, k = 1; i < MAX_DAEMONS; i++) {
		if (vpcs_list[i].pid == 0)
			continue;
		fprintf(hvout, "%-2d\t%-5d\t%s\r\n", 
		    k, vpcs_list[i].pid, vpcs_list[i].cmdline);
		k++;
	}
	SUCC(hvout, "OK\r\n");
	return 0;
}

static int 
run_quit(int ac, char **av)
{
	cmd_quit = 1;
	
	return 0;
}

static int 
run_killme(int ac, char **av)
{
	int i;
	
	for (i = 0; i < MAX_DAEMONS; i++) {
		if (vpcs_list[i].pid == 0)
			continue;
		kill(vpcs_list[i].pid, SIGUSR2);
		vpcs_list[i].pid = 0;
		if (vpcs_list[i].cmdline)
			free(vpcs_list[i].cmdline);
	}
	
	cmd_quit = 1;
	cmd_kill = 1;
	
	return 0;
}

static int 
run_stop(int ac, char **av)
{
	int i, j, k;

	if (ac != 2)
		return 1;
		
	j = atoi(av[1]);
	i = 0;
	k = 0;
	for (i = 0; i < MAX_DAEMONS; i++) {
		if (vpcs_list[i].pid == 0)
			continue;
		k++;
		if (k != j)
			continue;

		SUCC(hvout, "VPCS ID %d is terminated\r\n", vpcs_list[i].pid);

		kill(vpcs_list[i].pid, SIGUSR2);
		vpcs_list[i].pid = 0;
		if (vpcs_list[i].cmdline)
			free(vpcs_list[i].cmdline);
			
		break;
	}
	
	return 0;
}

static int 
run_help(int ac, char **av)
{
	fprintf(hvout,  
		"vpcs [parameters]     start vpcs with parameters of vpcs\r\n"
		"stop id               stop vpcs process\r\n"
		"list                  list vpcs process\r\n"
		"quit                  disconnect\r\n"
		"killme                stop vpcs process and hypervisor\r\n"
		"help | ?              print help\r\n");
	
	return 0;
}

static int 
exist(const char *name)
{
	struct stat sb;
	
	if (name == NULL)
		return 0;
		
	if (stat(name, &sb) == 0 && S_ISREG(sb.st_mode))
		return 1;
	
	return 0;
}

static int 
readpid(int port, pid_t *pid)
{
	FILE *fp;
	char path[1024];
	
	snprintf(path, sizeof(path), "/tmp/vpcs.%d", port);

	fp = fopen(path, "r");
	if (fp) {
		if (fscanf(fp, "%d", pid) != 1)
			*pid = 0;
		fclose(fp);
	}

	return 0;
}

static void 
usage(void)
{
	printf(	"Welcome to Hypervisor of VPCS, version %s\n"
		"Build time: %s %s\n"
		"Copyright (c) 2013, Paul Meng (mirnshi@gmail.com)\n"
		"All rights reserved.\n\n"
		"VPCS is free software, distributed under the terms of "
		"the \"BSD\" licence.\n"
		"Source code and license can be found at vpcs.sf.net.\n"
		"For more information, please visit wiki.freecode.com.cn.\n", 
		ver, __DATE__, __TIME__ );
		
	printf( "\nusage: hv [options]\n"
		"    -h|?             print this help then exit\n"
		"    -p <port>        listen port\n"
		"    -f <vpcs_path>   VPCS filename\n");
}


static void 
welcome(void)
{
	fprintf(hvout,  
		"Welcome to Hypervisor of VPCS, version %s\r\n"
		"Build time: %s %s\r\n"
		"Copyright (c) 2013, Paul Meng (mirnshi@gmail.com)\r\n"
		"All rights reserved.\r\n\r\n"
		"VPCS is free software, distributed under the terms of "
		"the \"BSD\" licence.\r\n"
		"Source code and license can be found at vpcs.sf.net.\r\n"
		"For more information, please visit wiki.freecode.com.cn.\r\n", 
		ver, __DATE__, __TIME__ );
		
	fprintf(hvout, "\r\nPress '?' to get help.\r\n");
}
/* end of file */

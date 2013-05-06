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

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "utils.h"

static int gcc_happy_int;
static void *gcc_happy_ptr;

const char *ver = "0.5a0";

#define delay_ms(x) usleep((x) * 1000)
#define print(s, str) do { gcc_happy_int = write((s), (str), strlen(str)); } while (0);

static int parse_cmd(char *buf, int s);
static void help(int sock);
static int readpid(char *port, pid_t *pid);
static void welcome(int s);

static int cmd_quit = 0;
static int cmd_kill = 0;
static char prgpath[PATH_MAX];

#define MAX_DAEMONS (10)
struct list {
	pid_t pid;
	char *cmdline;
};

static struct list vpcs_list[MAX_DAEMONS];

#define DEFAULT_PORT (21000)

int main(int argc, char **argv)
{
	pid_t pid;
	int sock, sock_cli;
	struct sockaddr_in serv, cli;
	int slen;
	fd_set set;
	char buf[1024];
	int i;
	int port = 0;
	int prompt = 1;
	
	if (argc == 2)
		port = atoi(argv[1]);
	
	if (port < 1024 || port > 65534)
		port = DEFAULT_PORT;
	
	pid = fork();
	if (pid < 0) {
		perror("Daemon fork");
		return 1;
	}
	if (pid > 0)
		exit(0);

	setsid();
	
	signal (SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal (SIGHUP, SIG_IGN);
	
	memset(vpcs_list, 0, MAX_DAEMONS * sizeof(struct list));
	gcc_happy_ptr = realpath(argv[0], prgpath);
	
	/* daemon socket */
   	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("Create socket");
		return 1;
	}

	i = 1;
	(void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
	    (char *)&i, sizeof(i));

	bzero((char *) &serv, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(port);
	
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
		sock_cli = accept(sock, (struct sockaddr *) &cli, 
		    (socklen_t *)&slen);
		
		if (sock_cli < 0) 
			continue;
		fcntl(sock_cli, F_SETFD, fcntl(sock_cli, F_GETFD) | FD_CLOEXEC); 
		while (!cmd_quit) {
			FD_ZERO(&set);
			FD_SET(sock_cli, &set);
			if (select(sock_cli + 1, &set, &set, NULL, NULL) < 0)
				break;
				
			if (!FD_ISSET(sock_cli, &set)) 
				continue;
			if (prompt) {
				welcome(sock_cli);
				prompt = 0;
			}
			
			print(sock_cli, ">> ");	
		
			memset(buf, 0, sizeof(buf));
			i = read(sock_cli, buf, sizeof(buf));
			if (i <= 0)
				break;
			ttrim(buf);
			parse_cmd(buf, sock_cli);
		}
		close(sock_cli);
	}
	return 0;
}

int parse_cmd(char *cmdstr, int sock)
{
	char *av[20];
	int ac = 0;
	int i, j, k;
	pid_t pid;
	char *p;
	char ag0[1024];
	char *ag1 = "-p";
	char *ag2 = "2000";

	ac = mkargv(cmdstr, (char **)av, 3);
	
	if (ac == 0)
		return 0;
	
	if (!strncmp(av[0], "start", strlen(av[0]))) {
		p = strstr(cmdstr, "-p");
		if (p == NULL) {
			av[ac++] = ag1;
			av[ac++] = ag2;
			av[ac] = NULL;
			p = ag2;
		} else {
			p = NULL;
			/* get the '-p [port]' */
			for (i = 0; i < ac; i++) {
				if (!strcmp(av[i], "-p") && (i + 1) < ac) {
					p = av[i + 1];
					break;
				}
			}
		}
		
		/* find free slot */
		for (i = 0; i < MAX_DAEMONS && vpcs_list[i].pid != 0; i++);
		
		if (i == MAX_DAEMONS || p == NULL)
			return 0;
		
		pid = fork();
		if (pid < 0)
			return 0;
			
		if (pid == 0) {
			snprintf(ag0, sizeof(ag0), "%s/vpcs", dirname(prgpath));  
			av[0] = ag0;
			if (execvp(av[0], av) == -1) {
				syslog(LOG_ERR, "Fork vpcs failed: %s", 
				    strerror(errno));
			}
		}
		
		waitpid(pid, NULL, 0);
		delay_ms(10);
		readpid(p, &pid);
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
			unlink(p);
			printf("Fork vpcs failed.\n");
			return 0;
		}
		vpcs_list[i].pid = pid;
		p = ttrim(cmdstr + strlen(av[0]));
		if (p) {
			vpcs_list[i].cmdline = strdup(p);
			syslog(LOG_INFO, "Start vpcs(%d) with %s\n", 
			    vpcs_list[i].pid, p);
		} else {
			vpcs_list[i].cmdline = NULL;
			syslog(LOG_INFO, "Start vpcs(%d)\n", vpcs_list[i].pid);
		}
		
		return 0;
	}
	
	if (ac == 2 && !strncmp(av[0], "stop", strlen(av[0]))) {
		j = atoi(av[1]);
		i = 0;
		k = 0;
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			k++;
			if (k == j) {
				kill(vpcs_list[i].pid, SIGUSR2);
				vpcs_list[i].pid = 0;
				if (vpcs_list[i].cmdline)
					free(vpcs_list[i].cmdline);
				break;
			}
		}
		return 0;
	}
	
	if (!strncmp(av[0], "list", strlen(av[0]))) {
		for (i = 0, k = 1; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid == 0)
				continue;
			snprintf(ag0, sizeof(ag0), "%-2d\t%-5d\t%s\n", 
			    k, vpcs_list[i].pid, vpcs_list[i].cmdline);
			print(sock, ag0);
			k++;
		}
		return 0;
	}

	if (!strncmp(av[0], "quit", strlen(av[0]))) {
		cmd_quit = 1;
		return 0;
	}

	if (!strncmp(av[0], "killme", strlen(av[0]))) {
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

	if (!strncmp(av[0], "help", strlen(av[0])) || !strcmp(av[0], "?")) {
		help(sock);
		return 0;
	}
	
	print(sock, "Invalid or incomplete command\n");
	return 0;
}

int readpid(char *port, pid_t *pid)
{
	FILE *fp;
	char path[1024];
	
	snprintf(path, sizeof(path), "/tmp/vpcs.%s", port);

	fp = fopen(path, "r");
	if (fp) {
		if (fscanf(fp, "%d", pid) != 1)
			*pid = 0;
		fclose(fp);
	}

	return 0;
}

void help(int sock)
{
	char buf[1024];
	
	snprintf(buf, sizeof(buf), 
		"start [parameters]    start vpcs with parameters of vpcs\n"
		"stop id               stop vpcs process\n"
		"list                  list vpcs process\n"
		"quit                  disconnect\n"
		"killme                stop vpcs process and hypervisor\n"
		"help | ?              print help\n");

	print(sock, buf);
}

void welcome(int sock)
{
	char buf[1024];
	
	snprintf(buf, sizeof(buf), 
		"Welcome to Hypervisor of VPCS, version %s\n"
		"Build time: %s %s\n"
		"Copyright (c) 2013, Paul Meng (mirnshi@gmail.com)\n"
		"All rights reserved.\n\n"
		"VPCS is free software, distributed under the terms of the \"BSD\" licence.\n"
		"Source code and license can be found at vpcs.sf.net.\n"
		"For more information, please visit wiki.freecode.com.cn.\n", 
		ver, __DATE__, __TIME__ );
	
	print(sock, buf);	
	print(sock, "\nPress '?' to get help.\n");
}
/* end of file */


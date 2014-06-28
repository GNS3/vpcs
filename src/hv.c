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
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libgen.h>
#include <getopt.h>
#include <pthread.h>
#include <termios.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <sys/ioctl.h>
#include <termios.h>

#ifdef Darwin
#include <util.h>
#elif Linux || GNUkFreeBSD
#include <pty.h>
#elif FreeBSD
#include <libutil.h>
#endif

#ifdef cygwin
#include <windows.h>
#endif

#include <syslog.h>

#include "hv.h"
#include "utils.h"
#include "readline.h"
#include "remote.h"

static void set_telnet_mode(int s);
static void loop(void);
static void* pty_master(void *arg);
static void* pty_slave(void *arg);
static void clean(void);
static int hypervisor(int port);
static char *getpath(const char *name);
extern int vpcs(int argc, char **argv);
extern int help_rlogin(int argc, char **argv);

static int run_vpcs(int ac, char **av);
static int run_list(int ac, char **av);
static int run_quit(int ac, char **av);
static int run_disconnect(int ac, char **av);
static int run_stop(int ac, char **av);
static int run_help(int ac, char **av);
static int run_rlogin(int ac, char **av);
extern void usage(void);

static struct list vpcs_list[MAX_DAEMONS];

static int ptyfdm, ptyfds;
static FILE *fptys;
static int sock = -1;
static int sock_cli = -1;
static int cmd_quit = 0;
static volatile int cmd_wait = 0;
static pthread_t pid_master, pid_salve;
static int hvport = 2000;
static struct rls *rls = NULL;
static char prgname[PATH_MAX];

static cmdStub cmd_entry[] = {
	{"?",          run_help},
	{"disconnect", run_disconnect},
	{"help",       run_help},
	{"list",       run_list},
	{"quit",       run_quit},
	{"rlogin",     run_rlogin},
	{"telnet",     run_rlogin},
	{"stop",       run_stop},
	{"vpcs",       run_vpcs},
	{NULL,         NULL}};

int 
main(int argc, char **argv, char** envp)
{	
	
	if (argc == 3 && !strcmp(argv[1], "-H")) {
		hvport = atoi(argv[2]);
		if (hvport < 1024 || hvport > 65000) {
			printf("Invalid port\n");
			exit(1);
		}
		/* keep program name for vpcs */
#ifdef cygwin
		/* using windows native API to get 'real' path */
		if (GetModuleFileName(NULL, prgname, PATH_MAX) == 0) {
#else			
		if (!getpath(argv[0])) {
#endif
		    	printf("Can not get file path\n");
		    	return 1;
		}
		return hypervisor(hvport);
	}

	/* go to vpcs */
 	return vpcs(argc, argv);
}
	
int 
hypervisor(int port)
{
	struct sockaddr_in serv;
	int on = 1;
	
	setsid();
#if 1
	if (daemon(1, 1)) {
		perror("Daemonize fail");
		goto ret;
	}
#endif	

	memset(vpcs_list, 0, MAX_DAEMONS * sizeof(struct list));
	
	if (openpty(&ptyfdm, &ptyfds, NULL, NULL, NULL)) {
		perror("Create pseudo-terminal");
		goto ret;
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	fptys = fdopen(ptyfds, "w");
	
	rls = readline_init(50, 128);
	rls->fdin = ptyfds;
	rls->fdout = ptyfds;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) >= 0) {
		(void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		    (char *)&on, sizeof(on));
		
		//fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);
		
		bzero((char *) &serv, sizeof(serv));
		serv.sin_family = AF_INET;
		serv.sin_addr.s_addr = htonl(INADDR_ANY);
		serv.sin_port = htons(port);
		
		if (bind(sock, (struct sockaddr *) &serv, sizeof(serv)) < 0) {
			perror("Daemon bind port");
			goto ret;
		}
		if (listen(sock, 5) < 0) {
			perror("Daemon listen");
			goto ret;
		}
	
		loop();
		close(sock);
	}
ret:	
	if (rls)
		readline_free(rls);
	return 1;		
	
}

static void* 
pty_master(void *arg)
{
	int i;
	u_char buf[128];
	
	while (!cmd_quit) {
		memset(buf, 0, sizeof(buf));
		i = read(ptyfdm, buf, sizeof(buf));
		if (i > 0 && write(sock_cli, buf, i))
			;
	}
	return NULL;
}


static void* 
pty_slave(void *arg)
{
	char *cmd;
	char *av[20];
	int ac = 0;
	cmdStub *ep = NULL;
	int matched = 0;
	
	while (!cmd_quit) {
		cmd = readline("HV > " , rls);
		
		fprintf(fptys, "\r\n");
		fflush(fptys);
		usleep(1);
		
		if (!cmd) 
			continue;

		ttrim(cmd);
		ac = mkargv(cmd, (char **)av, 20);
		if (ac == 0) 
			continue;

		for (ep = cmd_entry, matched = 0; ep->name != NULL; ep++) {
			if(!strncmp(av[0], ep->name, strlen(av[0]))) {
				matched = 1;
				break;
	        	}	
		}

		if (matched) {
			ep->f(ac, av);
		} else
			ERR(fptys, "Invalid or incomplete command\r\n");
	}

	return NULL;
}

static void 
loop(void)
{
	struct sockaddr_in cli;
	int slen;
	u_char buf[256], *p;
	int i;
	fd_set set;
	struct timeval tv;
		
	slen = sizeof(cli);
	
	
			
	while (cmd_quit != 2) {
		cmd_quit = 0;
		sock_cli = accept(sock, (struct sockaddr *) &cli, 
		    (socklen_t *)&slen);
		if (sock_cli < 0) 
			continue;
		
		set_telnet_mode(sock_cli);

		pthread_create(&pid_master, NULL, pty_master, NULL);
		pthread_create(&pid_salve, NULL, pty_slave, NULL);

		fcntl(0, F_SETFL, fcntl(sock_cli, F_GETFL) | O_NONBLOCK);

		while (!cmd_quit) {
			FD_ZERO(&set);
			FD_SET(sock_cli, &set);
			
			/* wait 1s */
			tv.tv_sec = 1;
			tv.tv_usec = 0; 
			i = select(sock_cli + 1, &set, NULL, NULL, &tv);
			
			/* error */
			if (i < 0)
				break;
			/* time out */
			if (i == 0)
				continue;
			
			if (FD_ISSET(sock_cli, &set)) {	    
				memset(buf, 0, sizeof(buf));
				i = read(sock_cli, buf, sizeof(buf));
				if (i < 0)
					break;
				if (i == 0)
					continue;
				p = buf;
	
				/* skip telnet IAC... */
				if (*p == 0xff)
					while (*p && !isprint(*p))
						p++;
	
				if (*p == '\0')
					continue;
	
				i = i - (p - buf);
	
				while (i > 0 && *(p + i - 1) == '\0')
					i--;
		
				if (i <= 0)
					continue;
				
				if (*p == CTRLD) {
					p = buf;
					strcpy((char *)buf, "disconnect\n");
					i = strlen((char *)buf);
					i = write(ptyfdm, p, i);
					usleep(100);
					strcpy((char *)buf, "\n");
					i = strlen((char *)buf);					
				}
				
				/* ignore pty error */
				if (write(ptyfdm, p, i))
					;
			}
		}
		
		pthread_cancel(pid_master);
		pthread_cancel(pid_salve);
		
		close(sock_cli);
	}
}

static void 
clean(void)
{
	close(ptyfdm);
	close(ptyfds);
	close(sock_cli);
	close(sock);	
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
	int fd1;
	
	if (ac == 2 && !strcmp(av[1], "?")) {
		/* redirect STDOUT to socket */
		fd1 = dup(STDOUT_FILENO);
		dup2(sock_cli, STDOUT_FILENO);
		usage();
		fflush(stdout);
		dup2(fd1, STDOUT_FILENO);
		return 0;
	}
	
	/* find free slot */
	for (i = 0; i < MAX_DAEMONS && vpcs_list[i].pid != 0; i++);
	
	if (i == MAX_DAEMONS)
		return 0;

	pv = &vpcs_list[i];
	memset(pv, 0, sizeof(struct list));
	
	/* reinitialized, maybe call getopt twice */
	optind = 1;
#if ((!defined(GNUkFreeBSD) && defined(FreeBSD)) || defined(Darwin))
	optreset = 1;
#endif	
	while ((c = getopt(ac, av, "p:m:s:c:")) != -1) {
		switch (c) {
			case 'p':
				pv->vport = atoi(optarg);
				if (pv->vport == 0) {
					ERR(fptys, "Invalid daemon port\r\n");
					return 1;
				}
				break;
			case 'm':
				pv->vmac = atoi(optarg);
				if (pv->vmac == 0) {
					ERR(fptys, "Invalid ether address\r\n");
					return 1;
				}
				break;
			case 's':
				pv->vsport = atoi(optarg);
				if (pv->vsport == 0) {
					ERR(fptys, "Invalid local port\r\n");
					return 1;
				}
				break;
			case 'c':
				pv->vcport = atoi(optarg);
				if (pv->vcport == 0) {
					ERR(fptys, "Invalid remote port\r\n");
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
			ERR(fptys, "Port %d already in use\r\n", pv->vport);
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
				ERR(fptys, "Ether address overlapped\r\n");
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
				ERR(fptys, "Local udp port overlapped\r\n");
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
				ERR(fptys,"Remote udp port overlapped\r\n");
				return 1;		
			}
		}
	}
	
	/* the arguments for vpcs */
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
	agv[0] = "vpcs";
	agv[1] = "-F";
	agc = mkargv(buf, (char **)(agv + 2), 20);
	agc++;
	agc++;
	agv[agc] = NULL;

	pid = fork();
	switch (pid) {
		case -1:
			return 0;
		case 0:
			/* 'real' vpcs */	
			clean();
			if (execvp(prgname, agv) == -1) {
				syslog(LOG_ERR, "Execute vpcs failed: %s\n", 
				    strerror(errno)); 
			}
			/* never here */
			exit(0);
			break;
		default:
			pv->pid = pid;
			SUCC(fptys, "VPCS started with %s\r\n", pv->cmdline);
			break;
	}
	
	return 0;
}

static int 
run_list(int ac, char **av)
{
	int i, k;

	fprintf(fptys, "ID\tPID\tParameters\r\n");
	 
	for (i = 0, k = 1; i < MAX_DAEMONS; i++) {
		if (vpcs_list[i].pid == 0)
			continue;
		/* remove the invalid instance */
		if (kill(vpcs_list[i].pid, 0)) {
			vpcs_list[i].pid = 0;
			continue;
		}
		fprintf(fptys, "%-2d\t%-5d\t%s\r\n", 
		    k, vpcs_list[i].pid, vpcs_list[i].cmdline);
		k++;
	}
	SUCC(fptys, "OK\r\n");
	
	return 0;
}

static int 
run_disconnect(int ac, char **av)
{
	cmd_quit = 1;
	
	return 0;
}

static int 
run_quit(int ac, char **av)
{
	int i;
	char ans[8];
	char *warning_quit = 
		"Warning: there are active VPCS sessions.\r\n"
		"Are you sure you want to quit and terminate these sessions(y/N)? ";

	if (ac == 1) {
		for (i = 0; i < MAX_DAEMONS; i++) {
			if (vpcs_list[i].pid != 0)
				break;
		}
		/* There are active VPCS sessions */
		if (i < MAX_DAEMONS) {
			i = write(sock_cli, warning_quit, strlen(warning_quit));
			memset(ans, 0, sizeof(ans));
			i = read(sock_cli, ans, sizeof(ans));
			if (i <= 0)
				return 0;
			i = write(sock_cli, ans, strlen(ans));
			i = write(sock_cli, "\r\n", 2);
			if (strcmp(ans, "y") && strcmp(ans, "Y"))
				return 0;
		}
	} else if (ac == 2 && strcmp(av[1], "-f"))
		return 1;
	else if (ac > 2) {
		ERR(fptys, "Invalid command\r\n");
		return 1;
	}	
	
	for (i = 0; i < MAX_DAEMONS; i++) {
		if (vpcs_list[i].pid == 0)
			continue;
		kill(vpcs_list[i].pid, SIGUSR2);
		vpcs_list[i].pid = 0;
		if (vpcs_list[i].cmdline)
			free(vpcs_list[i].cmdline);
	}
	
	cmd_quit = 2;

	return 0;
}

static int 
run_rlogin(int argc, char **argv)
{
	if (!strcmp(argv[argc - 1], "?"))
		return help_rlogin(argc, argv);

	if (argc == 2) {
		if (!digitstring(argv[1])) {
			printf("Invalid port\n");
			return help_rlogin(argc, argv);
		}
		return open_remote(ptyfds, "127.0.0.1", atoi(argv[1]));
	} else if (argc == 3) {
		if (!digitstring(argv[2])) {
			printf("Invalid port\n");
			return help_rlogin(argc, argv);
		}
		return open_remote(ptyfds, argv[1], atoi(argv[2]));
	}
	
	return help_rlogin(argc, argv);
}

static int 
run_stop(int ac, char **av)
{
	int i, j, k, found = 0;
	
	if (ac == 1) {
		ERR(fptys, "Invalid or incomplete command\r\n");
		return 1;
	}
	
	j = atoi(av[1]);
	i = 0;
	k = 0;
	for (i = 0; i < MAX_DAEMONS; i++) {
		if (vpcs_list[i].pid == 0)
			continue;
		k++;
		if (k != j)
			continue;

		SUCC(fptys, "VPCS PID %d is terminated\r\n", vpcs_list[i].pid);

		kill(vpcs_list[i].pid, SIGUSR2);
		vpcs_list[i].pid = 0;
		if (vpcs_list[i].cmdline)
			free(vpcs_list[i].cmdline);
		found = 1;	
		break;
	}
	
	if (!found)
		ERR(fptys, "VPCS id %s does not exist\r\n", av[1]);
		
	return 0;
}

static int
is_there(char *candidate)
{
	struct stat fin;

	/* XXX work around access(2) false positives for superuser */
	if (access(candidate, X_OK) == 0 &&
	    stat(candidate, &fin) == 0 &&
	    S_ISREG(fin.st_mode) &&
	    (getuid() != 0 ||
	    (fin.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0)) {
		return (1);
	}
	return (0);
}

static char *
getpath(const char *name)
{
	char *pathenv = NULL, *env;
	const char *d;
	int found;
	char rpath[PATH_MAX];
	
	if (strchr(name, '/') != NULL) {
		strcpy(rpath, name);
		if (is_there(rpath)) {
			found = 1;
			goto ret;
		} else
			return NULL;
	}

	if (getenv("PATH") == NULL)
		return NULL;
	
	pathenv = strdup(getenv("PATH"));
	if (pathenv == NULL)
		return NULL;

	found = 0;
	env = pathenv;
	while ((d = strsep(&env, ":")) != NULL) {
		if (*d == '\0')
			d = ".";
		if (snprintf(rpath, sizeof(rpath), "%s/%s", d, name) >= 
		    (int)sizeof(rpath))
			continue;
		if (is_there(rpath)) {
			found = 1;
			break;
		}
	}

	free(pathenv);
ret:	
	if (found) {
		return realpath(rpath, prgname);
	} else
		return NULL;
}

static int 
run_help(int ac, char **av)
{
	fprintf(fptys,
		"help | ?              Print help\r\n"
		"vpcs [parameters]     Start vpcs with parameters of vpcs\r\n"
		"stop id               Stop vpcs process\r\n"
		"list                  List vpcs process\r\n"
		"disconnect            Exit the telnet session\r\n"
		"quit [-f]             Stop vpcs processes and hypervisor\r\n"
		"                        -f force quit without prompting\r\n"
		"telnet [<ip>] <port>  Telnet to <port> at <ip> (def 127.0.0.1)\r\n"
		"rlogin [<ip>] <port>  Same as telnet\r\n"
		);
	
	return 0;
}

void set_telnet_mode(int s)
{
	/* DO echo */
	char *neg =
	    "\xFF\xFD\x01"
	    "\xFF\xFB\x01"
	    "\xFF\xFD\x03"
	    "\xFF\xFB\x03";
	
	if (write(s, neg, strlen(neg)))
		;
}

/* end of file */

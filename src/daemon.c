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
#define _XOPEN_SOURCE
#define _GNU_SOURCE

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

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

extern int ctrl_c;
static int cmd_quit = 0;
static pid_t fdtty_pid;
static int daemon_port;

#ifdef cygwin
BOOL WINAPI handler_routine(DWORD e);
#endif

static void daemon_proc(int sock, int fdtty);
static void sig_usr1(int sig);
static void sig_usr2(int sig);
static void sig_quit(int sig);
static void sig_term(int sig);
static void sig_int(int sig);
static int set_telnet_mode(int s);
static void set_nonblock(int fd);
static int pipe_rw(int fds, int fdd);

int 
daemonize(int port, int bg)
{
	int sock = 0;
	struct sockaddr_in serv;
	int on = 1;
	int fdtty;	
	pid_t pid;
		
	if (bg) {
		pid = fork();
		if (pid < 0) {
			perror("Daemon fork");
			return (-1);
		}
		if (pid > 0)
			exit(0);
	}

	daemon_port = port;
	
	setsid();
	
#ifdef cygwin
	SetConsoleCtrlHandler(handler_routine, TRUE);
#endif

	signal(SIGTERM, &sig_term);
	signal(SIGQUIT, &sig_quit);
	signal(SIGINT, &sig_int);
	signal(SIGHUP, SIG_IGN);
	signal(SIGUSR1, &sig_usr1);
   	signal(SIGUSR2, &sig_usr2);
   	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	
   	/* open an tty as standard I/O for vpcs */
   	fdtty_pid = forkpty(&fdtty, NULL, NULL, NULL);
   	
   	if (fdtty_pid < 0) {
   		perror("Daemon fork tty\n");
   		return (-1);
	}
	
   	/* child process, the 'real' vpcs */
   	if (fdtty_pid == 0) 
   		return 0;
   	
   	set_nonblock(fdtty);
   	
   	/* daemon socket */
   	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("Daemon socket");
		goto err;
	}
	(void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
	    (char *)&on, sizeof(on));

	bzero((char *) &serv, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(port);
	
	if (bind(sock, (struct sockaddr *) &serv, sizeof(serv)) < 0) {
		perror("Daemon bind port");
		goto err;
	}
	if (listen(sock, 5) < 0) {
		perror("Daemon listen");
		goto err;
	}

	daemon_proc(sock, fdtty);
err:
	printf("error\n");
	if (sock >= 0)
		close(sock);

	close(fdtty);
	kill(fdtty_pid, 9);
	exit(-1);
}

static int 
pipe_rw(int fds, int fdd)
{
	fd_set set;
	struct timeval tv;
	int rc, len;
	int n;
	u_char buf[512];
	
	tv.tv_sec = 0;
	tv.tv_usec = 10 * 1000; 
	
	n = 0;
	
	while (1) {
		FD_ZERO(&set);
		FD_SET(fds, &set);
		rc = select(fds + 1, &set, NULL, NULL, &tv);
		
		if (rc < 0)
			return rc;
		if (rc == 0) {
			n++;
			if (n < 10)
				continue;
			else
				return 0;
		}
		n = 0;
		if (FD_ISSET(fds, &set)) {
			memset(buf, 0, sizeof(buf));	
			len = read(fds, buf, sizeof(buf));
			if (len <= 0)
				return len;
			write(fdd, buf, len);
		}
	}
}

static void 
daemon_proc(int sock, int fdtty)
{
	char *goodbye = "\r\nGood-bye\r\n";
	int sock_cli;
	struct sockaddr_in cli;
	int slen;
	int rc;

	slen = sizeof(cli);
	while (1) {
		cmd_quit = 0;
		sock_cli = accept(sock, (struct sockaddr *) &cli, (socklen_t *)&slen);
		if (sock_cli < 0) 
			continue;
		
		set_telnet_mode(sock_cli);
		set_nonblock(fdtty);
		
		while (!cmd_quit) {
			if ((rc = pipe_rw(fdtty, sock_cli)) < 0)
				break;
			rc = pipe_rw(sock_cli, fdtty);
			/* error */
			if (rc < 0)
				break;
			/* time out */
			if (rc == 0)
				continue;
		}	
		pipe_rw(fdtty, sock_cli);
		rc = write(sock_cli, goodbye, strlen(goodbye));
		close(sock_cli);
	}
}

static void 
set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
	
#ifdef cygwin
/* to stop VPCS from another process on Windows
 */
BOOL WINAPI
handler_routine(DWORD e)
{
	if (e == CTRL_BREAK_EVENT) {
		sig_term(21);
		return TRUE;
	}
	return FALSE;
}
#endif

/* to stop VPCS from another process
 */
static void
sig_term(int sig)
{
	usleep(100000);
	kill(fdtty_pid, SIGKILL);

	exit(0);
}

/* should be sent from 'real vpcs' command: disconnect
 */
static void 
sig_quit(int sig)
{
	cmd_quit = 1;
	signal(SIGQUIT, &sig_quit);
}


/* should be sent from 'real vpcs' command: quit
 * vpcs has exited. 
 */
static void 
sig_usr1(int sig)
{
	usleep(100000);
	kill(fdtty_pid, SIGKILL);
		
	exit(0);
}

/* should be sent from hypervisor command: stop or quit 
 */
static void 
sig_usr2(int sig)
{
	/* release the resource and save workspace */
	kill(fdtty_pid, SIGUSR1);
	
	usleep(100000);
	kill(fdtty_pid, SIGKILL);
	
	usleep(100000);
	exit(0);
}

/* Ctrl+C was pressed */
static void 
sig_int(int sig)
{
	ctrl_c = 1;
	signal(SIGINT, &sig_int);
}

static int 
set_telnet_mode(int s)
{
	/* DO echo */
	char *neg =
	    "\xFF\xFD\x01"
	    "\xFF\xFB\x01"
	    "\xFF\xFD\x03"
	    "\xFF\xFB\x03";
	u_char buf[512];
	int n;
	
	n = write(s, neg, strlen(neg));
	n = read(s, buf, sizeof(buf));
	
	return n;
}

/* end of file */

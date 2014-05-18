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
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "globle.h"
#include "vpcs.h"
#include "dev.h"
#include "relay.h"

struct node {
	u_int32_t ip;
	u_short port;
};

struct peerlist {
	struct node nodea;
	struct node nodeb;
	struct peerlist *next;
};

static struct peerlist *peerlist = NULL;
static int relay_fd = 0;
static int relay_port = 0;

int run_relay(int argc, char **argv)
{
	int port;
	struct peerlist peer, *tpeer, *peerhost;
	struct in_addr in;
	char tmp[32];
	char *p;
	int i, j;
	
	if (argc == 3 && !strcmp(argv[1], "port")) {
		port = atoi(argv[2]);
		if (port > 1024 && port < 65534)
			relay_port = port;
			if (relay_fd) {
				close(relay_fd);
			
			relay_fd = open_udp(relay_port);
			if (relay_fd <= 0) {
				printf("Open relay port %d error [%s]\n", 
				    relay_port, strerror(errno));
			}
		} else
			printf("The port is out of range\n");
		return 0;	
	}
	
	if (argc == 2 && !strcmp(argv[1], "show")) {
		printf("Relay port: %d\n", relay_port);
	
		peerhost = peerlist;
		printf("Relay list");
		if (!peerhost || peerhost->nodea.port == 0) {
			printf(": none\n");
			return 0;
		}
		printf(":\n");
		i = 0;
		while (peerhost) {
			in.s_addr = peerhost->nodea.ip;
			printf("  %2d %s:%d", ++i, inet_ntoa(in), ntohs(peerhost->nodea.port)); 
			in.s_addr = peerhost->nodeb.ip;
			printf(" <-> %s:%d\n", inet_ntoa(in), ntohs(peerhost->nodeb.port));
			peerhost = peerhost->next;
		}
		return 0;	
	}

	if (argc == 4 && !strcmp(argv[1], "add")) {
		p = strchr(argv[2], ':');
		if (p) {
			bzero(tmp, sizeof(tmp));
			strncpy(tmp, argv[2], p - argv[2]);
			peer.nodea.ip = inet_addr(tmp);
			i = atoi(p + 1);
			if (i < 1024 || i > 65534) {
				printf("port %d is out of range\n", i);
				return 0;
			}
			peer.nodea.port = htons(i);
		} else {
			peer.nodea.ip = htonl(INADDR_ANY);
			i = atoi(argv[2]);
			if (i < 1024 || i > 65534) {
				printf("port %d is out of range\n", i);
				return 0;
			}
			peer.nodea.port = htons(i);	
		}
		
		p = strchr(argv[3], ':');
		if (p) {
			bzero(tmp, sizeof(tmp));
			strncpy(tmp, argv[3], p - argv[3]);
			peer.nodeb.ip = inet_addr(tmp);
			i = atoi(p + 1);
			if (i < 1024 || i > 65534) {
				printf("port %d is out of range\n", i);
				return 0;
			}
			peer.nodeb.port = htons(i);
		} else {
			peer.nodeb.ip = htonl(INADDR_ANY);
			i = atoi(argv[3]);
			if (i < 1024 || i > 65534) {
				printf("port %d is out of range\n", i);
				return 0;
			}
			peer.nodeb.port = htons(i);	
		}
		
		/* existed ? */
		peerhost = peerlist;
		for (j = 0;peerhost;) {
			if (((peerhost->nodea.ip == peer.nodea.ip) && 
			    (peerhost->nodea.port == peer.nodea.port)) ||
			    ((peerhost->nodeb.ip == peer.nodea.ip) && 
			    (peerhost->nodeb.port == peer.nodea.port))) {
			  	in.s_addr = peer.nodea.ip;
			  	port = peer.nodea.port;
			    	j = 1;
			    	break;
			}
			if (((peerhost->nodea.ip == peer.nodeb.ip) && 
			    (peerhost->nodea.port == peer.nodeb.port)) ||
			    ((peerhost->nodeb.ip == peer.nodeb.ip) && 
			    (peerhost->nodeb.port == peer.nodeb.port))) {
			  	in.s_addr = peer.nodeb.ip;
			  	port = peer.nodeb.port;
			    	j = 1;
			    	break;
			}
			peerhost = peerhost->next;
		}
		if (j == 1) {
			printf("%s:%d is existed\n", inet_ntoa(in), ntohs(port));
			return 0;
		}
		
		/* append the rule */	
		tpeer = (struct peerlist *)malloc(sizeof(struct peerlist));
		if (tpeer) {
			memcpy(tpeer, &peer, sizeof(peer));
			tpeer->next = NULL;
		} else
			printf("Out of memory\n");

		if (peerlist == NULL)
			peerlist = tpeer;
		else {
			peerhost = peerlist;
			while (peerhost->next)
				peerhost = peerhost->next;
			peerhost->next = tpeer;
		}
		return 0;
	}

	/* relay del <id> */
	if (argc == 3 && !strcmp(argv[1], "del")) {
		j = atoi(argv[2]);
		tpeer = peerlist;
		
		/* drop the head */
		if (j == 1) {
			if (peerlist) {
				peerlist = peerlist->next;
				free(tpeer);
			} 
			return 0;
		}
		
		peerhost = tpeer->next;
		i = 2;
		while (peerhost) {
			if (i == j) {
				tpeer->next = peerhost->next;
				free(peerhost);
				break;
			}
			tpeer = peerhost;
			peerhost = peerhost->next;
			i++;
		}
		return 0;
	}
	
	/* relay del port port */
	if (argc == 4 && !strcmp(argv[1], "del")) {
		p = strchr(argv[2], ':');
		if (p) {
			bzero(tmp, sizeof(tmp));
			strncpy(tmp, argv[2], p - argv[2]);
			peer.nodea.ip = inet_addr(tmp);
			peer.nodea.port = htons(atoi(p + 1));
		} else {
			peer.nodea.ip = htonl(INADDR_ANY);
			peer.nodea.port = htons(atoi(argv[2]));	
		}
		
		p = strchr(argv[3], ':');
		if (p) {
			bzero(tmp, sizeof(tmp));
			strncpy(tmp, argv[3], p - argv[3]);
			peer.nodeb.ip = inet_addr(tmp);
			peer.nodeb.port = htons(atoi(p + 1));
		} else {
			peer.nodeb.ip = htonl(INADDR_ANY);
			peer.nodea.port = htons(atoi(argv[3]));	
		}

		tpeer = peerlist;
		peerhost = peerlist;
		for (;peerhost;) {
			if ((peerhost->nodea.ip == peer.nodea.ip) && 
			    (peerhost->nodea.port == peer.nodea.port) &&
			    (peerhost->nodeb.ip == peer.nodeb.ip) && 
			    (peerhost->nodea.port == peer.nodea.port)) {
			    	if (tpeer == peerlist)
			    		peerlist = peerhost->next;
			    	else	
					tpeer->next = peerhost->next;
				free(peerhost);
				break;
			}
			tpeer = peerhost;
			peerhost = peerhost->next;
		}

		return 0;
	}		
	return 0;
}

void *pth_relay(void *dummy)
{
	char buf[1500];
	int len;
	int n = 0;
	struct sockaddr_in peeraddr;
	struct sockaddr_in addr;
	socklen_t size;
	struct peerlist *peerhost;
		
	relay_port = vpc[0].lport + MAX_NUM_PTHS;
	relay_fd = open_udp(relay_port);
	if (relay_fd <= 0)
		relay_fd = 0;

	/* waiting hub enable */
	while (!peerlist)
		sleep(1);
	while (1) {
		len = sizeof(buf);
		size = sizeof(struct sockaddr_in);
		n = recvfrom(relay_fd, buf, len, 0, 
		    (struct sockaddr *)&peeraddr, &size);
		    
		bzero(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		peerhost = peerlist;
		for (;peerhost;) {
			if (peerhost->nodea.port == peeraddr.sin_port) {
				if (peerhost->nodea.ip == htonl(INADDR_ANY) ||
				    peerhost->nodea.ip == peeraddr.sin_addr.s_addr) {	
					addr.sin_addr.s_addr = peerhost->nodeb.ip;
					addr.sin_port = peerhost->nodeb.port;
					break;
				}
			}
			if (peerhost->nodeb.port == peeraddr.sin_port) {
				if (peerhost->nodeb.ip == htonl(INADDR_ANY) ||
				    peerhost->nodeb.ip == peeraddr.sin_addr.s_addr) {
			    		addr.sin_addr.s_addr = peerhost->nodea.ip;
			    		addr.sin_port = peerhost->nodea.port;
					break;
				}
			}
			peerhost = peerhost->next;
		}
		if (addr.sin_port) {
			sendto(relay_fd, buf, n, 0, 
			    (struct sockaddr *)&addr, sizeof(addr));
		}
		
	}
	return NULL;
}

/* end of file */

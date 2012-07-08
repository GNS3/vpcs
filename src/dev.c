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
#include <fcntl.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/if.h>

#ifdef Linux
#ifdef TAP
#include <linux/if_tun.h>
#endif
#endif

#include "globle.h"
#include "dev.h"

extern int devtype;

int VRead(pcs *pc, void *buf, int len)
{
	struct sockaddr addr;
	socklen_t size;
	int n = 0;
	
	switch (devtype) {
		case DEV_TAP:
			n = read(pc->fd, buf, len);
			break;
		case DEV_UDP:
			size = sizeof(addr);
			n = recvfrom(pc->fd, buf, len, 0, (struct sockaddr *)&addr, &size);
			break;
	}
	return n;
}

int VWrite(pcs *pc, void *buf, int len)
{
	struct sockaddr_in addr;
	int n = 0;

	switch (devtype) {
		case DEV_TAP:
			n = write(pc->fd, buf, len);
			break;
		case DEV_UDP:
			bzero(&addr, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(pc->rport);
			addr.sin_addr.s_addr = pc->rhost;
		
			n = sendto(pc->fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));

			break;
	}
	return n;
}


int open_dev(int id)
{
	int fd = 0;
	int flags;	
	

	switch(devtype) {
#ifdef TAP
		case DEV_TAP:
			fd = open_tap(id);
			if (fd <= 0) {
				fd = 0;
				return 0;
			}
			break;
#endif			
		case DEV_UDP:
			fd = open_udp(vpc[id].lport);
			if (fd <= 0) {
				fd = 0;
				return 0;
			}
			break;
	}
		
	flags = fcntl(fd, F_GETFL, NULL);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
    
	return fd;
}

int open_udp(int port)
{
	int s;
	struct sockaddr_in addr_in;
	
	s = socket(AF_INET, SOCK_DGRAM, 0);
	
	if (s == -1) 
		return 0;
	
	bzero(&addr_in, sizeof(addr_in));
	addr_in.sin_family = AF_INET;
	addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
	addr_in.sin_port = htons(port);
	
	if(bind(s, (struct sockaddr *)&addr_in, sizeof(addr_in)) == -1) {
		close(s);
		return 0;
	}
	return s;
}

#ifdef TAP
int open_tap(int id)
{
	struct ifreq ifr;
	int fd;

	char dev[IFNAMESIZ];
	
	sprintf(dev, "tap%d", id);
		
	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		return(-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	
	/*
	 * IFF_TAP   - TAP device  
	 * IFF_NO_PI - Do not provide packet information 
	 *             TUNSLMODE | TUNSIFHEAD on the freebsd.
	 */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, IFNAMESIZ);

	if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
		close(fd);
		return(-1);
	}
	return(fd);
}
#endif

/* end of file */


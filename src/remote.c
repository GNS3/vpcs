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

#include "globle.h"
#include "remote.h"
#include "readline.h"
#include "utils.h"

int open_remote(int fdio, const char *destip, const u_short destport)
{
	int s;
	struct sockaddr_in addr_in;
	struct termios termios;
	char kb[512];
	u_char outbuf[512];
	int rc;
	int i;
	struct timeval tv;
	fd_set fset;
	static FILE *fpio;
	
	i = inet_addr(destip);
	if (i == -1) {
		printf("Invalid IP address\n");
		return 0;
	}
	
	s = socket(AF_INET, SOCK_STREAM, 0);	
	
	if (s == -1) 
		return 0;
		
	bzero(&addr_in, sizeof(addr_in));
	addr_in.sin_family = AF_INET;
	addr_in.sin_addr.s_addr = inet_addr(destip);
	addr_in.sin_port = htons(destport);
	
	fpio = fdopen(fdio, "w");
	
	rc = connect(s, (struct sockaddr*)&addr_in, sizeof(struct sockaddr));
	if (rc < 0) {
		if (errno == EINPROGRESS) {
			FD_ZERO(&fset);
			FD_SET(s, &fset);
			tv.tv_sec = 5;
			tv.tv_usec = 0;
			rc = select(s + 1, &fset, NULL, NULL, &tv);
			
			if (rc > 0 && FD_ISSET(s, &fset)) {
				i = sizeof(rc);
				getsockopt(s, SOL_SOCKET, SO_ERROR, 
				    &rc, (socklen_t *)&i);
				if (rc == 0)
					goto next;
				if (errno == EINPROGRESS)
					fprintf(fpio, "Connect timeout\n");
				else
					fprintf(fpio, "Connect failed: %s\n", 
					    strerror(errno));
			} else if (rc == 0) 
				fprintf(fpio, "Connect timeout\n");
			else
				fprintf(fpio, "Connect error: %s\n", 
				    strerror(errno));
			
			fflush(fpio);	
			close(s);
			return 1;
		}
	}
	
next:
	set_terminal(fdio, &termios);
	
	fprintf(fpio, "\r\nConnect %s:%d, press Ctrl+X to quit\r\n", 
	    destip, destport);
	fprintf(fpio,
	    "NOTES: you will be back to the starting point, NOT THE LAST, \r\n"
	    "       if using Ctrl+X to quit.\r\n");
	fflush(fpio);
				
	while (1) {
		/* check socket */
		kb[0] = 0xff;
		if (write(s, kb, 1) < 0)
			break;
					
		FD_ZERO(&fset);
		FD_SET(s, &fset);
		FD_SET(fdio, &fset);
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		rc = select((fdio > s) ? (fdio + 1) : (s + 1), &fset, NULL, NULL, &tv);
		if (rc < 0)
			break;
		if (rc == 0)
			continue;

		if (FD_ISSET(s, &fset)) {
			rc = read(s, outbuf, sizeof(outbuf));
			if (rc < 0) 
				break;
			if (rc > 0) {
				i = 0;
				/* discard IAC */
				while (outbuf[i] == 0xff && i < rc) 
					i += 3;
				if (i < rc) {
					rc = write(fdio, outbuf + i, rc - i);
					if (rc < 0) 
						break;
				 }
			}
		}

		if (FD_ISSET(fdio, &fset)) {
			rc = read(fdio, kb, sizeof(kb));
			if (rc < 0) 
				break;

			if (kb[0] == CTRLX)
				break;
			
			/* my buddy likes '\r' */
			if (kb[0] == LF) {
				rc = write(s, "\r", 1);
				if (rc < 0) 
					break;
				continue;
			}
	
			if (rc > 0) {
				rc = write(s, kb, rc);
				if (rc < 0) 
					break;
			}
		}	
	}
	close(s);
	
	fprintf(fpio, "\r\nDisconnected from %s:%d\r\n", 
	    destip, destport);
	fflush(fpio);
	
	
	
	reset_terminal(fdio, &termios);

	return 0;
}

/* end of file */


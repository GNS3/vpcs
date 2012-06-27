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

#include "globle.h"
#include "remote.h"
#include "readline.h"

int open_remote(const char *destip, const u_short destport)
{
	int s;
	struct sockaddr_in addr_in;
	struct termios termios;
	char kb[16];
	u_char outbuf[512];
	int rc;
	/* char *neg = "\xFF\xFB\x18\xFF\xFD\x01\xFF\xFD\x03"; */
	int i;
	int flags;
	
	s = socket(AF_INET, SOCK_STREAM, 0);	
	
	if (s == -1) 
		return 0;
		
	bzero(&addr_in, sizeof(addr_in));
	addr_in.sin_family = AF_INET;
	addr_in.sin_addr.s_addr = inet_addr(destip);
	addr_in.sin_port = htons(destport);
	
	if (connect(s, (struct sockaddr *)&addr_in, sizeof(addr_in)) == -1) {
		printf("Connect %s:%d error: %s\n", destip, destport, strerror(errno));	
		close(s);
		return errno;
	}
	
	printf("Connect %s:%d, press Ctrl+X to quit\n", destip, destport);
	
	flags = fcntl(0, F_GETFL);
	fcntl(0, F_SETFL, O_NONBLOCK);
	fcntl(s, F_SETFL, O_NONBLOCK);
	
	set_terminal(&termios);
	
	usleep(10);
	
   	while (1) {
   		rc = read(s, outbuf, sizeof(outbuf));
   		if (rc > 0) {
   			i = 0;
   			/* discard IAC */
   			while (outbuf[i] == 0xff && i < rc) 
   				i += 3;
   			if (i < rc)
   				rc = write(0, outbuf + i, rc - i);
   			
   		}

   		rc = read(0, kb, sizeof(kb));
		if (rc <= 0) {
			usleep(1);
			continue;
		}

		if (kb[0] == CTRLX)
			break;
		
		/* my buddy likes '\r' */
		if (kb[0] == LF) {
			rc = write(s, "\r", 1);
			continue;
		}
		rc = write(s, kb, rc);
	}
	close(s);
	
	reset_terminal(&termios);
	
	fcntl(0, F_SETFL, flags);
	
	return 1;
}

/* end of file */


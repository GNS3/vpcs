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

#ifndef _HV_H_
#define _HV_H_

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#define delay_ms(x) usleep((x) * 1000)

#define ERR(out, ...) do { \
	fprintf(out, "200-"); \
	fprintf(out, __VA_ARGS__); \
	fflush(out); \
} while (0);

#define SUCC(out, ...) do { \
	fprintf(out, "100-"); \
	fprintf(out, __VA_ARGS__); \
	fflush(out); \
} while (0);

#define DEFAULT_PORT (21000)
#define DEFAULT_SPORT (20000)
#define DEFAULT_CPORT (30000)
#define STEP (10)


#define MAX_DAEMONS (10)
struct list {
	pid_t pid;
	int vport;
	int vmac;
	int vsport;
	int vcport;
	char *cmdline;
};

typedef struct stub {
	char *name;
	int (*f)(int argc, char **argv);
} cmdStub;

#endif

/* end of file */

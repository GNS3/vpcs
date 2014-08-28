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

#ifndef _DUMP_H_
#define _DUMP_H_

#include <sys/types.h>


#include "queue.h"

typedef struct pcap_hdr_s {
        u_int magic_number;     /* magic number */
        u_short version_major;  /* major version number */
        u_short version_minor;  /* minor version number */
        u_int  thiszone;        /* GMT to local correction */
        u_int sigfigs;          /* accuracy of timestamps */
        u_int snaplen;          /* max length of captured packets, in octets */
        u_int network;          /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        u_int ts_sec;         /* timestamp seconds */
        u_int ts_usec;        /* timestamp microseconds */
        u_int incl_len;       /* number of octets of packet saved in file */
        u_int orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

int dmp_packet(const struct packet *m, const int flag);

FILE *open_dmpfile(const char *fname);
void close_dmpfile(FILE *fp);
int dmp_packet2file(const struct packet *m, FILE *fp);
int dmp_buffer2file(const char *m, int len, FILE *fp);

#endif

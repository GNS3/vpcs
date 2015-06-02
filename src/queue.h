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

#ifndef _PKTQ_H_
#define _PKTQ_H_

#include <sys/types.h>
#include <pthread.h>		
#include <sys/time.h>

#define PKTQ_SIZE	(101)

#define PKT_DROP	0	/* drop it */
#define PKT_ENQ		1	/* enqueued */
#define PKT_UP		2	/* application */

struct packet {
	struct packet *next;
	int len;
	struct timeval ts;
	char data[0];
};

struct pq {
	int type;				/* for debug */
	int ip;					/* pointer of the queue */
	int size;				/* size of queue */
	pthread_mutex_t locker;
	pthread_cond_t cond;
	struct packet *q;
};

#define copy_pkt(dst, src) { \
	dst->len = src->len; \
	memcpy(dst->data, src->data, src->len); \
	dst->ts = src->ts; \
}

void init_queue(struct pq*);
struct packet *enq(struct pq*, struct packet *pkt);
struct packet *deq(struct pq*);
struct packet *waitdeq(struct pq *pq);
void lock_q(struct pq*);
void ulock_q(struct pq*);
struct packet *new_pkt(int len);
void del_pkt(struct packet *m);
void free_pkts(struct packet *m);

#endif

/* end of file */

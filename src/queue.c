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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "queue.h"

void del_pkt(struct packet *m)
{
	free(m);
}

struct packet *new_pkt(int len)
{
	struct packet *m = NULL;
	
	m = (struct packet *)malloc(len + sizeof(struct packet) - 1);
	if (m != NULL) {
		memset(m, 0, len + sizeof(struct packet) - 1);
		m->len = len;
		return m;
	} else
		return NULL;
}

struct packet *deq_impl(struct pq *pq, int cond)
{
	struct packet *m = NULL;
	
	lock_q(pq);
	
	if (cond && (pq->q == NULL))
		pthread_cond_wait(&(pq->cond), &(pq->locker));

	if (pq->q != NULL) {
		m = pq->q;
		pq->q = pq->q->next;
		pq->size --;
		m->next = NULL;
	}	
	
	ulock_q(pq);

	return m;
}

struct packet *deq(struct pq *pq)
{
	return deq_impl(pq, 0);
}

struct packet *waitdeq(struct pq *pq)
{
	return deq_impl(pq, 1);
}

struct packet *enq(struct pq *pq, struct packet *m)
{
	struct packet *q = NULL;
	
	if (pq->size == PKTQ_SIZE) {
		printf("queue is full \n");
		return NULL;
	}

	lock_q(pq);

	gettimeofday(&(m->ts), (void*)0);
	
	if (pq->q == NULL)
		pq->q = m;
	else {
		q = pq->q;
		while (q->next != NULL) q = q->next;
		q->next = m;	
	}

	while (m) {
		pq->size ++;
		m = m->next;
	}
	pthread_cond_signal(&(pq->cond));

	ulock_q(pq);
	
	return q;
}

void init_queue(struct pq *pq)
{
	pthread_mutex_init(&(pq->locker), NULL);
	pthread_cond_init(&(pq->cond), NULL);
	pq->ip = 0;
	pq->size = 0;
}

void lock_q(struct pq *pq)
{
	pthread_mutex_lock(&(pq->locker));
}

void ulock_q(struct pq *pq)
{
	pthread_mutex_unlock(&(pq->locker));
}

/* end of file */


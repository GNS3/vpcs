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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "frag.h"

extern u_int time_tick;

static struct fraglink *fraglink_head = NULL;
static pthread_mutex_t fraglink_locker;

#define LIST_LOCK_INIT pthread_mutex_init(&fraglink_locker, NULL)
#define LIST_LOCK pthread_mutex_lock(&fraglink_locker)
#define LIST_UNLOCK pthread_mutex_unlock(&fraglink_locker)
#define LIST_FOREACH(nq) \
	for ((nq) = fraglink_head; (nq) != NULL; (nq) = (nq)->next)

#define FREE_NODE(n) do { 				\
	if (n) {					\
		if ((n) == fraglink_head) 		\
			fraglink_head = (n)->next;	\
		else 					\
			(n)->prev->next = (n)->next;	\
		free(n);				\
	} 						\
} while (0);

#define ADD_NODE(n) do {		\
	(n)->next = fraglink_head;	\
	fraglink_head = (n);		\
} while (0);


static struct packet *defrag(struct packet **m0);

struct packet *ipfrag(struct packet *m0, int mtu)
{
	struct packet *m = NULL, *mh = NULL;
	iphdr *ip = NULL, *ip0 = NULL;
	int hlen, len, off, elen, flen, last;
	int nfrags;
	
	elen = sizeof(ethdr) + sizeof(iphdr);
	
	ip0 = (iphdr *)(m0->data + sizeof(ethdr));
	if (ntohs(ip0->len) <= mtu)
		return m0;
		
	hlen = ip0->ihl << 2;
	len = (mtu - hlen) & ~7; /* payload in fragment */
	ip0->len = ntohs(ip0->len);

	/* too small, let it alone */
	if (len < 8)
		return m0;
	
	flen = len;
	off = hlen + len;
	
	mh = m0;
	last = 0;
	for (nfrags = 1; off < ip0->len; off += len, nfrags++) {
		if (off + len >= ip0->len) {
			last = 1;
			m = new_pkt(elen + ip0->len - off);
			len = ip0->len - off;
		} else
			m = new_pkt(elen + len);

		if (m == NULL) 
			goto ipfrag_err;

		/* ether and ip head */
		memcpy(m->data, m0->data, elen);
		memcpy(m->data + elen, m0->data + sizeof(ethdr) + off, len);
		ip = (iphdr *)(m->data + sizeof(ethdr));
		ip->frag = ((off -hlen) >> 3);
	
		if (!last) {
			ip->frag |= IP_MF;
			ip->len = htons(len + sizeof(iphdr));
		} else
			ip->len = htons(sizeof(iphdr) + ip0->len - off);		
		ip->frag = htons(ip->frag);
		ip->cksum = 0;
		ip->cksum = cksum((u_short *)ip, sizeof(iphdr));
		m->next = NULL;
		mh->next = m;
		mh = m;
	}
	m0->len = elen + flen;
	ip0->len = htons(flen + sizeof(iphdr));
	ip0->frag = htons(IP_MF);
	ip0->cksum = 0;
	ip0->cksum = cksum((u_short *)ip0, sizeof(iphdr));

	return m0;
	
ipfrag_err:
	for (m = mh->next; m; m = mh) {
		mh = m->next;
		del_pkt(m);
	}
	
	return m0;
}

/* 
 * return NULL, the packet is a piece, expired, or invalid.
 * return packet, all of pieces have been arrived and reassembled.
 */
struct packet *
ipreass(struct packet *m)
{
	ethdr *eh = (ethdr *)(m->data);
	iphdr *ip = (iphdr *)(eh + 1);
	iphdr *ip0;
	struct fraglink *nq = NULL;
	struct packet *m0 = NULL, *m2 = NULL;
	u_short off, off0;
	int next;

	ip->frag = ntohs(ip->frag);
	
	LIST_LOCK;
	LIST_FOREACH(nq) {
		if (time_tick - nq->expired > 30) {
			free_pkts(nq->m);
			FREE_NODE(nq);
			continue;
		}
		
		if (ip->id != nq->id || ip->proto != nq->proto ||
		    ip->sip != nq->sip || ip->dip != nq->dip)
			continue;
		
		/* a fragment is existed */
		if ((ip->frag & IP_MF) == IP_MF)
			nq->flags |= FF_HEAD;
		else if ((ip->frag & (~IP_OFFMASK)) == 0)
			nq->flags |= FF_TAIL;

		off = ip->frag << 3;
		if (off == 0 && (ip->frag & IP_MF)) {
			if (!ip->len || (ip->len & 0x7) != 0) {
				del_pkt(m);
				free_pkts(nq->m);
				FREE_NODE(nq);
				goto ret_null;
			}
			m->next = nq->m;
			nq->m = m;
		} else {
			/* Find a segment, insertion sort on singly linked list
			 */
			m2 = NULL;
			for (m0 = nq->m; m0; m2 = m0, m0 = m0->next) {
				ip0 = (iphdr *)(m0->data + sizeof(ethdr));
				off0 = ip0->frag << 3;
				if (off0 > off)
					break;	
			}
			if (m2) {
				m->next = m2->next;
				m2->next = m;
			} else {
				m->next = nq->m;
				nq->m = m;
			}
		}	
		nq->nfrags++;
		/* too many fragments */
		if (nq->nfrags > 16) {
			free_pkts(nq->m);
			FREE_NODE(nq);
			goto ret_null;
		}
		/* the head and tail are arrived, scan the chain 
		 * Note: overlap is invalid here.
		 */
		if (nq->flags == (FF_TAIL | FF_HEAD)) {		
			for (next = 0, m0 = nq->m; m0; m0 = m0->next) {
				ip0 = (iphdr *)(m0->data + sizeof(ethdr));
				off0 = ip0->frag << 3;			
				if (next < off0)
					goto ret_null;			
				/* the last fragment */
				if ((ip0->len & 0x7) != 0) {					
					m = nq->m;
					FREE_NODE(nq);
					/* copy to single packet buffer
					 * free the old buffer
					 */	
					m = defrag(&m);
					goto ret;
				}
				next += ip0->len;
			}
		}
		goto ret_null;
	}
	/* new fragment */
	nq = (struct fraglink *)malloc(sizeof(struct fraglink));
	if (!nq)
		goto ret;

	memset(nq, 0, sizeof(struct fraglink));
	
	nq->expired = time_tick;
	nq->nfrags = 1;
	nq->proto = ip->proto;
	nq->id = ip->id;
	nq->sip = ip->sip;
	nq->dip = ip->dip;
	nq->m = m;
	m->next = NULL;
	if ((ip->frag & IP_MF) == IP_MF)
		nq->flags = FF_HEAD;
	else if ((ip->frag & (~IP_OFFMASK)) == 0)
		nq->flags = FF_TAIL;
		
	ADD_NODE(nq);
	
	
ret_null:
	LIST_UNLOCK;
	return NULL;

ret:
	LIST_UNLOCK;
	return m;	
}

static struct packet *defrag(struct packet **m0)
{
	struct packet *m, *mh, *m2;
	iphdr *ip;
	int len;
	int elen;
	int off;
	
	mh = *m0;	
	len = 0;
	while (mh) {
		ip = (iphdr *)(mh->data + sizeof(ethdr));
				
		len += ntohs(ip->len) - sizeof(iphdr);
		mh = mh->next;
	}		
	m = new_pkt(len + sizeof(iphdr) + sizeof(ethdr));
	if (m == NULL)
		return *m0;

	mh = *m0;
	memcpy(m->data, mh->data, mh->len);
	ip = (iphdr *)(m->data + sizeof(ethdr));
	ip->len = ntohs(len + sizeof(iphdr));
	off = mh->len;
	elen = sizeof(ethdr) + sizeof(iphdr);
	m2 = mh;
	mh = mh->next;
	del_pkt(m2);
	while (mh) {
		len = mh->len - elen;
		memcpy(m->data + off, mh->data + elen, len);
		off += len;
		m2 = mh;
		mh = mh->next;
		del_pkt(m2);
	}
	ip->frag = 0;
	ip->cksum = 0;
	ip->cksum = cksum((u_short *)ip, sizeof(iphdr));
	
	return m;
}

void init_ipfrag(void)
{
	LIST_LOCK_INIT;
}

/* */
#undef LIST_LOCK_INIT
#undef LIST_LOCK
#undef LIST_UNLOCK
#undef LIST_FOREACH
#undef FREE_NODE_SAFE
#undef ADD_NODE
/* end of file */

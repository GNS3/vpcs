/*
 * Copyright (c) 2015, Paul Meng (mirnshi@gmail.com)
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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "queue.h"
#include "ip.h"
#include "packets6.h"
#include "frag6.h"

extern u_int time_tick;

static struct frag6link *frag6link_head = NULL;
static pthread_mutex_t frag6link_locker;

#define LIST_LOCK_INIT pthread_mutex_init(&frag6link_locker, NULL)
#define LIST_LOCK pthread_mutex_lock(&frag6link_locker)
#define LIST_UNLOCK pthread_mutex_unlock(&frag6link_locker)
#define LIST_FOREACH(nq) \
	for ((nq) = frag6link_head; (nq) != NULL; (nq) = (nq)->next)

#define FREE_NODE(n) do { 					\
	if ((n) == frag6link_head) frag6link_head = (n)->next;	\
	else (n)->prev->next = (n)->next;			\
	free(n);						\
} while (0);

#define ADD_NODE(n) do {		\
	(n)->next = frag6link_head;	\
	frag6link_head = (n);		\
} while (0);
	

static struct packet *defrag6(struct packet **m0);

void
init_ip6frag(void)
{
	LIST_LOCK_INIT;
}

struct packet *
ipfrag6(struct packet *m0, int mtu)
{
	struct packet *m = NULL, *mh = NULL;
	ip6hdr *ip = NULL, *ip0 = NULL;
	struct ip6frag *ip6frag = NULL;
	int hlen, off, last, plen, ehlen, eilen, dlen, clen;
	int nfrags;
	u_int32_t frgid;
	u_int8_t nxt;
	
	ip0 = (ip6hdr *)(m0->data + sizeof(ethdr));
	
	/*         |<-- plen ..................................-->|
	 * | ethdr | ip6hdr | data ...............................|
	 *                  | frag1 | frag2 | ..... ......| fragn | 
	 * | ethdr | ip6hdr | ip6frag | frag1(dlen) |
	 * |<-- eilen ...-->|
	 * |<-- ehlen .............-->|
	 *         |<-- hlen ......-->|
	 *         |<-- mtu .....................-->|
	 * | ethdr | ip6hdr | ip6frag | frag2(dlen) |
	 * ...
	 * | ethdr | ip6hdr | ip6frag | fragn |
	 *
	*/
	plen = ntohs(ip0->ip6_plen) + sizeof(ip6hdr);
	if (plen <= mtu)
		return m0;
	
	eilen = sizeof(ethdr) + sizeof(ip6hdr);
	hlen = sizeof(ip6hdr) + sizeof(ip6frag);
	ehlen = sizeof(ethdr) + hlen;
	dlen = (mtu - hlen) & ~7;

	off = eilen + dlen;
	frgid = rand();
	
	nxt = ip0->ip6_nxt;
	mh = m0;
	last = 0;
	for (nfrags = 1, last = 0; off < plen; off += dlen, nfrags++) {
		if (off + dlen >= plen) {
			last = 1;
			clen = plen - dlen * nfrags - sizeof(ip6hdr);
		} else
			clen = dlen;
	
		m = new_pkt(ehlen + clen);
		if (m == NULL) 
			goto ipfrag6_err;

		/* ether, ip head, frag exthead, payload */
		memcpy(m->data, m0->data, sizeof(ethdr) + sizeof(ip6hdr));
		memcpy(m->data + ehlen, m0->data + off, dlen);
		ip = (ip6hdr *)(m->data + sizeof(ethdr));
		
		ip->ip6_nxt = IPPROTO_FRAGMENT;
		ip->ip6_plen = htons(clen + sizeof(ip6frag));
		ip6frag = (struct ip6frag *)(ip + 1);
		ip6frag->nxt = nxt;
		ip6frag->reserved = 0;
		ip6frag->offlg = htons((u_short)((off - eilen) & ~7));
		ip6frag->ident = frgid;
		
		if (!last)
			ip6frag->offlg |= IP6F_MORE_FRAG;

		m->next = NULL;
		mh->next = m;
		mh = m;
	}
	
	m = new_pkt(ehlen + dlen);
	if (!m)
		goto ipfrag6_err;
	memcpy(m->data, m0->data + sizeof(ethdr) + sizeof(ip6hdr), dlen);

	dlen = (mtu - hlen) & ~7;
	ip0->ip6_nxt = 44;
	ip0->ip6_plen = htons(dlen + sizeof(ip6frag));

	ip6frag = (struct ip6frag *)(ip0 + 1);
	ip6frag->nxt = nxt;
	ip6frag->reserved = 0;
	ip6frag->offlg = 0;
	ip6frag->offlg |= IP6F_MORE_FRAG;
	ip6frag->ident = frgid;
	memcpy(m0->data + ehlen, m->data, dlen);
	m0->len = ehlen + dlen;
	
	return m0;
	
ipfrag6_err:
	for (m = mh->next; m; m = mh) {
		mh = m->next;
		del_pkt(m);
	}

	return m0;
}

struct packet *
ipreass6(struct packet *m)
{
	ethdr *eh = (ethdr *)(m->data);
	ip6hdr *ip = (ip6hdr *)(eh + 1);
	ip6hdr *ip0;
	struct frag6link *nq;
	struct ip6frag *fg = NULL, *fg0 = NULL;
	struct packet *m0 = NULL, *m2 = NULL;
	u_short off, off0;
	int hoff;
	
	if (ip->ip6_plen == 0)
		return m;
	
	hoff = ip6ehdr(ip, m->len - sizeof(ethdr), IPPROTO_FRAGMENT);
	if (hoff == 0)
		return m;
	
	fg = (struct ip6frag *)((char *)ip + hoff);
	off = ntohs((fg->offlg & IP6F_OFF_MASK));
	
	LIST_LOCK;
	LIST_FOREACH(nq) {
		if (time_tick - nq->expired > 30) {
			free_pkts(nq->m);
			FREE_NODE(nq);
			continue;
		}
		if (fg->ident != nq->id || 
		    fg->nxt != nq->proto ||
		    !IP6EQ(&ip->src, &nq->sip) || 
		    !IP6EQ(&ip->dst, &nq->dip)) {
			continue;
		}

		if ((fg->offlg & IP6F_MORE_FRAG) && 
		    (fg->offlg & IP6F_OFF_MASK) == 0) {
			nq->flags |= FF_HEAD;
		}else if ((fg->offlg & IP6F_MORE_FRAG) == 0)
			nq->flags |= FF_TAIL;
		
		/* find a position and insert */
		m2 = NULL;
		for (m0 = nq->m; m0; m2 = m0, m0 = m0->next) {
			ip0 = (ip6hdr *)(m0->data + sizeof(ethdr));
			hoff = ip6ehdr(ip0, m->len - sizeof(ethdr), 
			    IPPROTO_FRAGMENT);
			
			if (hoff == 0)
				return m;
	
			fg0 = (struct ip6frag *)((char *)ip0 + hoff);
			
			off0 = ntohs((fg0->offlg & IP6F_OFF_MASK));
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
			m = nq->m;
			FREE_NODE(nq);
			m = defrag6(&m);
			goto ret;
		} else
			goto ret_null;
	}
	
	/* new fragment */
	nq = (struct frag6link *)malloc(sizeof(struct frag6link));
	if (!nq)
		goto ret;

	memset(nq, 0, sizeof(struct frag6link));
	
	nq->expired = time_tick;
	nq->nfrags = 1;
	nq->proto = fg->nxt;
	nq->id = fg->ident;
	memcpy(nq->sip.addr8, ip->src.addr8, sizeof(ip->src.addr8));
	memcpy(nq->dip.addr8, ip->dst.addr8, sizeof(ip->dst.addr8));
	nq->m = m;
	m->next = NULL;

	if ((fg->offlg & IP6F_MORE_FRAG) && (fg->offlg & IP6F_OFF_MASK) == 0)
		nq->flags = FF_HEAD;
	else if ((fg->offlg & IP6F_MORE_FRAG) == 0)
		nq->flags = FF_TAIL;
	
	ADD_NODE(nq);

ret_null:
	LIST_UNLOCK;
	return NULL;

ret:
	LIST_UNLOCK;
	return m;
}

struct packet *defrag6(struct packet **m0)
{
	struct packet *m, *mh, *m2;
	struct ip6frag *fg = NULL;
	ip6hdr *ip;
	int len;
	int hoff, doff, off;
	u_int8_t nxt;

	/* calculate the payload size */
	mh = *m0;
	ip = (ip6hdr *)(mh->data + sizeof(ethdr));
	hoff = ip6ehdr(ip, mh->len - sizeof(ethdr), IPPROTO_FRAGMENT);
	doff = hoff + sizeof(struct ip6frag);
	fg = (struct ip6frag *)((char *)ip + hoff);
	nxt = fg->nxt;
	
	len = 0;
	while (mh) {
		ip = (ip6hdr *)(mh->data + sizeof(ethdr));
		len = len + ntohs(ip->ip6_plen) + sizeof(ip6hdr) - doff;
		
		mh = mh->next;
	}

	m = new_pkt(len + hoff + sizeof(ethdr));
	if (m == NULL)
		return *m0;

	/* copy the first header */
	mh = *m0;
	memcpy(m->data, mh->data, hoff + sizeof(ethdr));
	ip = (ip6hdr *)(m->data + sizeof(ethdr));
	ip->ip6_nxt = nxt;
	ip->ip6_plen = htons(len + hoff - sizeof(ip6hdr));
	off = hoff + sizeof(ethdr);
	
	/* copy the payload */
	while (mh) {
		ip = (ip6hdr *)(mh->data + sizeof(ethdr));
		len = ntohs(ip->ip6_plen) + sizeof(ip6hdr) - doff;
		memcpy(m->data + off, mh->data + sizeof(ethdr) + doff, len);
		off += len;
		m2 = mh;
		mh = mh->next;
		del_pkt(m2);
	}
	return m;
}

/* */
#undef LIST_LOCK_INIT
#undef LIST_LOCK
#undef LIST_UNLOCK
#undef LIST_FOREACH
#undef FREE_NODE
#undef ADD_NODE
/* end of file */

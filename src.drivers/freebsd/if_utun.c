/*-
 * Copyright (c) 2013 Paul Meng (mirnshi@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/* $Id$
 *
 * utun, pseudo interface driver
 *       encapsulates the traffic into UDP packets. 
 *
 *  outgoing path
 *    --> utun -- UDP(*)  --> 127.0.0.1 --> ip_input()
 *                     \  
 *                      \--> 'real' NIC
 *
 * incoming path
 *   --> ip_input()  --> strip UDP header --> utun 
 *      (PFIL hook)
 *
 * Makefile:
 *          .PATH: ${.CURDIR}/../../net
 *          KMOD=   if_utun
 *          SRCS=   if_utun.c
 *          .include <bsd.kmod.mk>
 *
 * usage: kldload if_utun.ko
 *        ifconfig utun create a.b.c.d netmask A.B.C.D
 *        sysctl net.link.utun.0.sport=40001
 *        sysctl net.link.utun.0.dport=40002
 *        sysctl net.link.utun.0.destaddr="127.0.0.1"
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_clone.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/pfil.h>
#include <net/route.h>
#include <net/bpf.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <machine/in_cksum.h>

#define	UTUNNAME	"utun"
#define UTUNMTU 1400
#define MTAG_UTUN 20130824

LIST_HEAD(utun_softc_head, utun_softc);

struct utun_softc {
	struct	ifnet *ifp;
	char		destip[16];	/* destination address, sysctl */
	struct in_addr	src_addr;	/* local address */
	struct in_addr	dst_addr;	/* destination address */
	int		src_port;
	int		dst_port;
	
	struct sysctl_ctx_list ctx;	/* sysctl list */
	
	LIST_ENTRY(utun_softc) sc_list;
	
	int (*ether_output_p)(struct ifnet *ifp, struct mbuf *m,
				struct sockaddr *dst, struct route *ro);
};

#define UTUN_BPF_MTAP(_ifp, _m) do {			\
	if (bpf_peers_present((_ifp)->if_bpf)) {	\
		bpf_mtap((_ifp)->if_bpf, (_m));		\
	}						\
} while (0)

static void utun_init(void *foo);
static int  utun_ioctl(struct ifnet *, u_long, caddr_t);
static void utun_start(struct ifnet *ifp);

static int utun_clone_match(struct if_clone *, const char *);
static int utun_clone_create(struct if_clone *, char *, size_t, caddr_t);
static int utun_clone_destroy(struct if_clone *, struct ifnet *);

static void utun_sysctl(struct utun_softc *sc);
static void utun_setaddr(struct ifnet *ifp);
static u_char *utun_etheraddr(int idx);

static int  utun_output(struct ifnet *ifp, struct mbuf *m,
		struct sockaddr *dst, struct route *ro);
static int utun_input(void *arg, struct mbuf **mp, struct ifnet *ifp, 
		int dir, struct inpcb *inp);
static struct sockaddr_in *utun_route(struct route *ro, struct in_addr dest, 
				struct mbuf *m);
static int utun_encap(struct ifnet *ifp, struct mbuf **m,
			struct sockaddr *dst);

static MALLOC_DEFINE(M_UTUN, UTUNNAME, "Virtual Interface");

static struct rwlock utun_mtx;
static struct utun_softc_head utun_softc_list;

static struct if_clone utun_cloner = IFC_CLONE_INITIALIZER(UTUNNAME, NULL,
    IF_MAXUNIT, NULL, utun_clone_match, utun_clone_create, utun_clone_destroy);
    
SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, OID_AUTO, utun, CTLFLAG_RW, 0, "Virtual Interface");

#if 0
#include <machine/stdarg.h>

static char *fmtstr(char *fmt, ...);

#define BUFSIZE (2048)
static char fmtbuf[4][BUFSIZE];

static char *
fmtstr(char *fmt, ...)
{
	static int idx = 0;
	va_list ap;
	int off = 0, max;
	char *pbuf;
	union {
		u_int32_t ui;
		u_int16_t us[2];
		u_int8_t uc[4];
	} u32;
	
	va_start(ap, fmt);
	
	pbuf = fmtbuf[idx];
	while (*fmt) {
		if (*fmt != '%') {
			off += snprintf(pbuf + off, BUFSIZE - off, "%c", *fmt);
			fmt ++;
			continue;
		}
		fmt ++;
		switch (*fmt) {
		case 'd':
			off += snprintf(pbuf + off, BUFSIZE - off, 
			    "%d", va_arg(ap, int));
			break;
		case 'I':
			u32.ui = va_arg(ap, int);
			off += snprintf(pbuf + off, BUFSIZE - off, 
			    "%d.%d.%d.%d", 
			    u32.uc[0], u32.uc[1], u32.uc[2], u32.uc[3]);
			break;
		}
		fmt++;
	}	
	idx++;
	idx %= 4;
	
	return pbuf;
}
#endif

static int
utun_clone_match(struct if_clone *ifc, const char *name)
{
	const char *cp;
 
	if (strncmp(UTUNNAME, name, sizeof(UTUNNAME) - 1) != 0)
		return 0;

	for (cp = name + sizeof(UTUNNAME) - 1; *cp != '\0'; cp++) {
		if (*cp < '0' || *cp > '9')
			return 0;
	}

	return 1;
}

static int
utun_clone_destroy(struct if_clone *ifc, struct ifnet *ifp)
{
	struct utun_softc *sc = ifp->if_softc;
	int unit = ifp->if_dunit;

	rw_wlock(&utun_mtx);
	LIST_REMOVE(sc, sc_list);
	rw_wunlock(&utun_mtx);
	
	sysctl_ctx_free(&sc->ctx);
	
	ether_ifdetach(ifp);
	if_free_type(ifp, IFT_ETHER);
	
	free(sc, M_UTUN);
	ifc_free_unit(ifc, unit);
	
	return 0;
}

static int
utun_clone_create(struct if_clone *ifc, char *name, size_t len, caddr_t params)
{
	char *dp;
	int wildcard;
	int unit;
	int error;
	struct utun_softc *sc;
	struct ifnet *ifp;

	if (params) {
		sc = (struct utun_softc *)params;
		ifp = sc->ifp;

		ether_ifattach(ifp, utun_etheraddr(ifp->if_index));

		strlcpy(name, sc->ifp->if_xname, len);
		
		goto fin;
	}

	error = ifc_name2unit(name, &unit);
	if (error != 0)
		return error;
	wildcard = (unit < 0);

	error = ifc_alloc_unit(ifc, &unit);
	if (error != 0)
		return error;

	/* In the wildcard case, we need to update the name. */
	if (wildcard) {
		for (dp = name; *dp != '\0'; dp++);
		if (snprintf(dp, len - (dp-name), "%d", unit) >
		    len - (dp-name) - 1) {
			panic("%s: interface name too long", __func__);
		}
	}

	sc = malloc(sizeof(struct utun_softc), M_UTUN, M_WAITOK | M_ZERO);
	ifp = sc->ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		ifc_free_unit(ifc, unit);
		free(sc, M_UTUN);
		return ENOSPC;
	}

	sc->src_port = sc->dst_port = 0;	
	ifp->if_softc = sc;

	strlcpy(ifp->if_xname, name, IFNAMSIZ);
	ifp->if_dname = ifc->ifc_name;
	ifp->if_dunit = unit;
	ifp->if_type = IFT_ETHER;
	ifp->if_start = utun_start;
	ifp->if_init = utun_init;
	ifp->if_ioctl = utun_ioctl;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	
	ether_ifattach(ifp, utun_etheraddr(ifp->if_index));

	/* change mtu */
	ifp->if_mtu = UTUNMTU;
	
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	
	/* save ether_output, in /sys/net/if_ethersubr.c */
	sc->ether_output_p = ifp->if_output;
	ifp->if_output = utun_output;

fin:	
	/* create sysctl node */
	utun_sysctl(sc);
	
	rw_wlock(&utun_mtx);
	LIST_INSERT_HEAD(&utun_softc_list, sc, sc_list);
	rw_wunlock(&utun_mtx);
	
	return 0;
}

static void 
utun_sysctl(struct utun_softc *sc)
{
	struct sysctl_oid *oid;
	char num[8];
	
	sysctl_ctx_init(&sc->ctx);
	
	snprintf(num, sizeof(num), "%d", sc->ifp->if_dunit);
	oid = SYSCTL_ADD_NODE(&sc->ctx, &SYSCTL_NODE_CHILDREN(_net_link, utun),
		OID_AUTO, num, CTLFLAG_RD, NULL, "");

	SYSCTL_ADD_INT(&sc->ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"sport", CTLTYPE_INT|CTLFLAG_RW, &sc->src_port, sc->src_port,
		"Source port");
	SYSCTL_ADD_INT(&sc->ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"dport", CTLTYPE_INT|CTLFLAG_RW, &sc->dst_port, sc->dst_port,
		"Destination port");
	SYSCTL_ADD_STRING(&sc->ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"destaddr", CTLTYPE_INT|CTLFLAG_RW, sc->destip, 16,
		"Destination ip address");	
                
}

/* PFIL hook function */
static int
utun_input(void *arg, struct mbuf **mp, struct ifnet *ifp, 
	int dir, struct inpcb *inp)
{
	struct ip *ip = NULL;
	struct udphdr *uh;
	struct mbuf *m = *mp;
	struct m_tag *mtag;
	struct utun_softc *sc;

	/* check mtag */
	mtag = m_tag_locate(m, MTAG_UTUN, 0, NULL);
	if (mtag && (*(int *)(mtag + 1)) == MTAG_UTUN) {
		m_tag_delete(m, mtag);
		ifp->if_ipackets++;
		return 0;
	}
	
	ip = mtod(m, struct ip *);
	
	if (ip->ip_p == IPPROTO_UDP) {
		uh = (struct udphdr *)(ip + 1);
		
		rw_rlock(&utun_mtx);
		LIST_FOREACH(sc, &utun_softc_list, sc_list) {
			if (sc->src_port != ntohs(uh->uh_dport))
				continue;
			if (sc->dst_port != ntohs(uh->uh_sport))
				continue;
			
			if (sc->dst_addr.s_addr == 0)
				utun_setaddr(sc->ifp);
			
			if (ip->ip_src.s_addr != sc->dst_addr.s_addr)
				continue;
			if (ip->ip_dst.s_addr != sc->src_addr.s_addr)
				continue;
			break;
		}
		rw_runlock(&utun_mtx);
		
		if (sc) {
			/* create tag */
			mtag = m_tag_alloc(MTAG_UTUN, 0, sizeof(int), M_NOWAIT);
			if (mtag) {
				*(int *)(mtag + 1) = MTAG_UTUN;
				m_tag_prepend(m, mtag);
				
				/* skip udp header */
				m_adj(m, sizeof(struct udpiphdr));
				
				m->m_pkthdr.rcvif = sc->ifp;
				(*sc->ifp->if_input)(sc->ifp, m);
				
				*mp = NULL;
			}
		}
	}

	return 0;
}

static int
utun_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst0, 
	struct route *ro0)
{
	struct utun_softc *sc;
	struct route ro;
	struct sockaddr_in *dst = NULL;
	struct in_addr dest;
	int error;
	int olen;
	
	sc = ifp->if_softc;
	
	/* set destination address and port */
	if (!sc->dst_addr.s_addr || !sc->src_addr.s_addr)
		utun_setaddr(ifp);
	
	if (!sc->dst_addr.s_addr || !sc->src_addr.s_addr) {
		ifp->if_oerrors++;
		error = EINVAL;
		goto bad;

	}
	
	olen = m_length(m, 0);
        if (utun_encap(ifp, &m, dst0)) {
        	ifp->if_oerrors++;
        	if (m) {
        		m_free(m);
        		error = EINVAL;
        	} else
        		error = ENOBUFS;
        	goto bad;
        }
	
	/* encapsulate and
	 * send to upper layer if the destination is local host 
	 */
	if (ntohl(sc->dst_addr.s_addr) == 0x7f000001) {	
		m->m_pkthdr.rcvif = V_loif;
		m->m_pkthdr.csum_flags |= CSUM_IP_CHECKED | CSUM_IP_VALID;
		ifp->if_opackets++;
		ifp->if_obytes += olen;

		return netisr_queue(NETISR_IP, m);
	}
	
	dest.s_addr = sc->dst_addr.s_addr;
	if ((dst = utun_route(&ro, dest, m)) == NULL) {
		ifp->if_oerrors++;
		m_free(m);
		return ENETUNREACH;
	}
		
	/* send out */
	ifp->if_opackets++;	
	ifp->if_obytes += olen;
	ifp = ro.ro_rt->rt_ifp;
	error = (*ifp->if_output)(ifp, m, (struct sockaddr *)dst, &ro);
	
	RTFREE(ro.ro_rt);
	
bad:
	return error;
}

static int
utun_encap(struct ifnet *ifp, struct mbuf **mp, struct sockaddr *dst)
{
	struct utun_softc *sc;
	struct llentry *lle = NULL;
	u_char edst[ETHER_ADDR_LEN];
	struct mbuf *m;
	struct ether_header *eh;
	struct arphdr *ah;
	struct ip *ip;
	struct udpiphdr *ui;
	u_short type;
	int error;
	int hlen, olen;
	char b[9];
	
	sc = ifp->if_softc;
	m = *mp;
	
	type = 0;
	switch (dst->sa_family) {
	case AF_ARP:
		ah = mtod(m, struct arphdr *);
                ah->ar_hrd = htons(ARPHRD_ETHER);
                
                switch(ntohs(ah->ar_op)) {
                case ARPOP_REQUEST:
                case ARPOP_REPLY:
                default:
                        type = htons(ETHERTYPE_ARP);
                        break;
                }

                if (m->m_flags & M_BCAST)
                        bcopy(ifp->if_broadcastaddr, edst, ETHER_ADDR_LEN);
                else
                        bcopy(ar_tha(ah), edst, ETHER_ADDR_LEN);
		break;
	case AF_INET:
		error = arpresolve(ifp, NULL, m, dst, edst, &lle);
		if (error)
                	goto ret;
		type = htons(ETHERTYPE_IP);
		break;
	} 

	if (!type)
		return 1;

	olen = m_length(m, 0);
	hlen = sizeof(struct udpiphdr) + 2 * ETHER_HDR_LEN;
	M_PREPEND(m, hlen, M_DONTWAIT);
	if (m == NULL) {
		*mp = NULL;
		error = ENOBUFS;
		goto ret;
	}
	*mp = m;

	error = 0;
	m_adj(m, ETHER_HDR_LEN);
	
	ip = mtod(m, struct ip *);
	ui = (struct udpiphdr *)(ip);
	eh = (struct ether_header *)(ui + 1);
	
	(void)memcpy(&eh->ether_type, &type,
		sizeof(eh->ether_type));
	(void)memcpy(eh->ether_dhost, edst, sizeof (edst));
	(void)memcpy(eh->ether_shost, IF_LLADDR(ifp),
		sizeof(eh->ether_shost));

	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_len = htons(m->m_pkthdr.len);
	ip->ip_id = ip_newid();
	ip->ip_tos = 0;
	ip->ip_ttl = IPDEFTTL;
	ip->ip_off = htons(IP_DF);
	ip->ip_p = IPPROTO_UDP;
	
	if (ntohl(sc->dst_addr.s_addr) == 0x7f000001)
		ip->ip_src.s_addr = sc->dst_addr.s_addr;
	else
		ip->ip_src.s_addr = sc->src_addr.s_addr;
	
	ip->ip_dst.s_addr = sc->dst_addr.s_addr;

	ui->ui_sport = htons(sc->src_port);
	ui->ui_dport = htons(sc->dst_port);
	ui->ui_ulen = htons(sizeof(struct udphdr) + olen + ETHER_HDR_LEN);
	ui->ui_len = ui->ui_ulen;
	ui->ui_sum = 0;
#if 1	
	bcopy(((struct ipovly *)ip)->ih_x1, b, 9);
	bzero(((struct ipovly *)ip)->ih_x1, 9);
		
	ui->ui_len = ui->ui_ulen;
	ui->ui_sum = in_cksum(m, ntohs(ui->ui_ulen) + sizeof (struct ip));	
	
	bcopy(b, ((struct ipovly *)ip)->ih_x1, 9);
#endif	
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum_hdr(ip);

ret:	
	return error;
}

static void
utun_init(void *foo __unused)
{
}

static void
utun_start(struct ifnet *ifp)
{
}

static int
utun_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	return ether_ioctl(ifp, cmd, data);
#if 0
	int error = 0;
	struct utun_softc *sc;
	struct ifreq *ifr;
	
	sc = ifp->if_softc;
	ifr = (struct ifreq *)data;
	
	switch (cmd) {
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;	
	}
	
	return error;
#endif
}

static int 
utun_hook(void)
{
	struct pfil_head *ph_inet;
	
	ph_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
	if (ph_inet == NULL)
		return ENODEV;
	
	pfil_add_hook((void *)utun_input, NULL,
	    PFIL_IN|PFIL_WAITOK, ph_inet);
	
	return 0;
}

static int 
utun_unhook(void)
{
	struct pfil_head *ph_inet;
	
	ph_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
	if (ph_inet != NULL) {
		pfil_remove_hook((void *)utun_input, NULL,
		    PFIL_IN|PFIL_WAITOK, ph_inet);  
	}
	
	return 0;
}

static int
utun_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
		rw_init(&utun_mtx, "utun_mtx");
		LIST_INIT(&utun_softc_list);
		if_clone_attach(&utun_cloner);
		utun_hook();
		break;
	case MOD_UNLOAD:
		utun_unhook();
		if_clone_detach(&utun_cloner);
		rw_destroy(&utun_mtx);
		break;
	default:
		return EOPNOTSUPP;
	}
	return 0;
}

static moduledata_t utun_mod = {
	"utun",
	utun_modevent,
	0
};

DECLARE_MODULE(utun, utun_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);

/* try to get the ether address of the first 'real' interface
 * and convert it to LAA, to be as my address
 */
static u_char *
utun_etheraddr(int idx)
{
	static u_char sea[ETHER_ADDR_LEN] = {0};
	struct ifnet *ifp;
	u_char *ea;
	int found = 0;
	
	if (sea[0] & 0x2) {
		sea[5] = idx & 0xff;
		return sea;
	}
	
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		if ((ifp->if_type & IFT_ETHER) == 0)
			continue;
		ea = IF_LLADDR(ifp);
		if (*ea & 0x2)
			continue;
		found = 1;
		memcpy(sea, ea, sizeof(sea));
		sea[0] |= 0x2;
		break;
	}
	IFNET_RUNLOCK_NOSLEEP();

	if (!found) {
		sea[0] = 0x02;
		sea[1] = 0x50;
		sea[2] = 0x79;
		sea[3] = 0x68;
		sea[4] = 0x66;
		sea[5] = idx & 0xff;
	}
	
	return sea;
}

static void 
utun_setaddr(struct ifnet *ifp)
{
	struct utun_softc *sc;
	struct ifaddr *ifa;
	struct in_addr in;
	struct sockaddr_in *si, sin;
	
	sc = ifp->if_softc;

	if (sc->dst_addr.s_addr == 0 && sc->destip[0] != '\0' && 
	    inet_aton(sc->destip, &in)) {
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(si);
		sin.sin_addr.s_addr = in.s_addr;
				
		ifa = ifa_ifwithnet(sintosa(&sin), 0);
		if (ifa) {
			si = (struct sockaddr_in *)ifa->ifa_addr;
			sc->src_addr.s_addr = si->sin_addr.s_addr;
			sc->dst_addr.s_addr = in.s_addr;
		}
	}
}

static struct sockaddr_in *
utun_route(struct route *ro, struct in_addr dest, struct mbuf *m)
{
	struct sockaddr_in *dst;
	struct rtentry *rt;

	bzero(ro, sizeof(*ro));
	dst = (struct sockaddr_in *)&ro->ro_dst;
	dst->sin_family = AF_INET;
	dst->sin_len = sizeof(*dst);
	dst->sin_addr.s_addr = dest.s_addr;
	in_rtalloc_ign(ro, 0, M_GETFIB(m));

	rt = ro->ro_rt;
	if (rt && (rt->rt_flags & RTF_UP) &&
	    (rt->rt_ifp->if_flags & IFF_UP) &&
	    (rt->rt_ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		if (rt->rt_flags & RTF_GATEWAY)
			dst = (struct sockaddr_in *)rt->rt_gateway;
	} else {
		if (rt)
			RTFREE(rt);
		return NULL;
	}
	
	return dst;
}

/* end of file */

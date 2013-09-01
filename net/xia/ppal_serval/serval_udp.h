/*
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef __SERVAL_UDP_H__
#define __SERVAL_UDP_H__

#include <linux/ip.h>
#include <net/udp.h>
#include <linux/export.h>

/* The AF_SERVAL socket */
struct serval_udp_sock {
	/* NOTE: serval_sock has to be the first member */
	struct serval_sock ssk;
};

static inline struct serval_udp_sock *serval_udp_sk(const struct sock *sk)
{
	return (struct serval_udp_sock *)sk;
}

/*
 *	Generic checksumming routines for UDP(-Lite) v4 and v6
 */
static inline __sum16 __serval_udp_checksum_complete(struct sk_buff *skb)
{
	return __skb_checksum_complete(skb);
}

static inline int serval_udp_checksum_complete(struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
		__serval_udp_checksum_complete(skb);
}

static inline int serval_udp_csum_init(struct sk_buff *skb,
				       struct udphdr *uh,
				       int proto)
{
	/* These addresses don't make sense in XIA. */
	const __be32 saddr = 0;
	const __be32 daddr = 0;

	if (uh->check == 0) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!csum_tcpudp_magic(saddr, daddr, skb->len,
			proto, skb->csum))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (!skb_csum_unnecessary(skb))
		skb->csum = csum_tcpudp_nofold(saddr, daddr, skb->len,
			proto, 0);
	return 0;
}

#endif /* __SERVAL_UDP_H__ */

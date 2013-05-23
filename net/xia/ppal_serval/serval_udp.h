/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef __SERVAL_UDP_H__
#define __SERVAL_UDP_H__

#include <platform.h>
#include <skbuff.h>
#include <serval_udp_sock.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/ip.h>
#include <net/udp.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
#include <linux/export.h>
#endif
#endif

#if defined(OS_USER)
#include <netinet/ip.h>
#if defined(OS_BSD)
#include <serval/platform_tcpip.h>
#else
#include <netinet/udp.h>
#endif
#endif /* OS_USER */

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
        const struct iphdr *iph = ip_hdr(skb);

	if (uh->check == 0) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len,
                                       proto, skb->csum))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (!skb_csum_unnecessary(skb))
		skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
					       skb->len, proto, 0);
	return 0;
}

#endif /* __SERVAL_UDP_H__ */

#ifndef _NET_XIA_DST_TABLE_H
#define _NET_XIA_DST_TABLE_H

/* Please DO NOT include this file, prefer <net/xia_route.h>.
 * The only purpose of this file is to avoid cyclic includes
 * in <net/netns/xia.h>. */

/* XXX This data structure is definitely not perfect because
 * it does not reflect the load/capacity of a given namespace (struct net),
 * however, it's not clear how it should be shaped since XIA is too
 * young to have any usage data.
 */

/* It must be a power of 2. */
#define XIP_DST_TABLE_SIZE 256

struct xip_dst_table {
	struct dst_entry	*buckets[XIP_DST_TABLE_SIZE];
};

#endif	/* _NET_XIA_DST_TABLE_H */

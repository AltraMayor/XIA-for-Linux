#ifndef __NETNS_XIA_H__
#define __NETNS_XIA_H__

/*
 * XIA's net namespace
 */

#include <net/dst_ops.h>

/* Hash of principals.
 * It has to be power of 2.
 * Until one has a significant number of principals, or a way to instantiate
 * them in userland, a fixed arrary is enough.
 */
#define NUM_PRINCIPAL_HINT	128

/* XIP Principal Context
 *
 * Principals that need to link data to struct net, should do so using
 * the struct defined below. It avoids messing the struct netns_xia, and
 * simplifies loading and unloading of principals.
 */
struct fib_xip_ppal_ctx {
	struct hlist_head	ppal[NUM_PRINCIPAL_HINT];
};

/* It must be a power of 2. */
#define XIP_DST_TABLE_SIZE 256

/* XXX This data structure is definitely not perfect because
 * it does not reflect the load/capacity of a given namespace (struct net),
 * however, it's not clear how it should be shaped since XIA is too
 * young to have any usage data.
 */
struct xip_dst_table {
	struct dst_entry	*buckets[XIP_DST_TABLE_SIZE];
	u32			last_bucket; /* Used for garbage collection. */
};

struct netns_xia {
	/* Principals should only hang data at @fib_ctx. */
	struct fib_xip_ppal_ctx	fib_ctx;

	/* Route cache. */
	struct dst_ops		xip_dst_ops;
	struct xip_dst_table	xip_dst_table;
};

#endif /* __NETNS_XIA_H__ */

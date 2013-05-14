#ifndef __NETNS_XIA_H__
#define __NETNS_XIA_H__

/*
 * XIA's net namespace
 */

#include <net/dst_ops.h>

/* Maximum number of XID types recognized at the same time. */
#define XIP_MAX_XID_TYPES	8

/* It must be a power of 2. */
#define XIP_DST_TABLE_SIZE	256

/* XXX This data structure is definitely not perfect because
 * it does not reflect the load/capacity of a given namespace (struct net),
 * however, it's not clear how it should be shaped since XIA is too
 * young to have any usage data.
 */
struct xip_dst_table {
	struct dst_entry	*buckets[XIP_DST_TABLE_SIZE];
	atomic_t		last_bucket; /* Used for garbage collection. */
};

struct netns_xia {
	/* Hash of principal contexts.
	 * Principals that need to link data to struct net, should do so using
	 * struct xip_ppal_ctx. It avoids messing the struct netns_xia, and
	 * simplifies loading and unloading of principals.
	 */
	struct xip_ppal_ctx	*fib_ctx[XIP_MAX_XID_TYPES];

	/* Route cache. */
	struct dst_ops		xip_dst_ops;
	struct xip_dst_table	xip_dst_table;
};

#endif /* __NETNS_XIA_H__ */

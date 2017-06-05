#ifndef _NET_XIA_ETHER_H
#define _NET_XIA_ETHER_H
/* prevents double declarations */
#ifdef __KERNEL__
/* only for kernel use */

#include <linux/netdevice.h>
#include <net/xia_list_fib.h>

/* Ethernet Principal */
#define XIDTYPE_ETHER (__cpu_to_be32(0x12))


/* Local ETHERs */

struct fib_xid_ether_local {
	struct xip_dst_anchor	xhl_anchor;

	/* WARNING: @xhl_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xhl_common;
};

static inline struct fib_xid_ether_local *fxid_lether(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ether_local, xhl_common)
		: NULL;
}

/* Main ETHERs */

struct fib_xid_ether_main {

	/* WARNING: @xhl_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xhl_common;
};

static inline struct fib_xid_ether_main *fxid_mether(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ether_main, xhm_common)
		: NULL;
}

/* ETHER context */
struct xip_ether_ctx
{
	struct xip_ppal_ctx ctx;
};

#endif /* __KERNEL__ */
#endif		/* _NET_XIA_ETHER_H */
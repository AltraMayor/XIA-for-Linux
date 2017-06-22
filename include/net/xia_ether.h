#ifndef _NET_XIA_ETHER_H
#define _NET_XIA_ETHER_H
/* prevents double declarations */

#include <linux/netdevice.h>
#include <net/xia_list_fib.h>
#include <linux/netlink.h>

/* Ethernet Principal */
#define XIDTYPE_ETHER (__cpu_to_be32(0x12))

#ifdef __KERNEL__
/* only for kernel use */

/* ETHER's virtal XID type. */
int ether_vxt __read_mostly = -1;

/* Local ETHERs */

struct fib_xid_ether_local {
	struct xip_dst_anchor	xel_anchor;

	/* WARNING: @xel_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xel_common;
};

static inline struct fib_xid_ether_local *fxid_lether(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ether_local, xel_common)
		: NULL;
}

/* Main ETHERs */
struct interface_addr{
	struct fib_xid_ether_main 	mfxid;
	struct list_head 			interface_common_addr;
	struct ether_interface 		*outgress_interface;
	struct rcu_head				rcu_head;

	//TODO:check size
	u8 		ha[MAX_ADDR_LEN];
};

struct fib_xid_ether_main {

	/* WARNING: @xhl_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xem_common;
};

static inline struct fib_xid_ether_main *fxid_mether(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ether_main, xem_common)
		: NULL;
}

/* ETHER context */
struct xip_ether_ctx
{
	struct xip_ppal_ctx ctx;
};

static inline struct xip_ether_ctx *ctx_ether(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_ether_ctx, ctx)
		: NULL;
}

extern int ether_vxt;	//TODO:might not be necessary later

#endif /* __KERNEL__ */
#endif		/* _NET_XIA_ETHER_H */
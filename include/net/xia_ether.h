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
struct ether_interface{
	struct net_device			*dev;
	atomic_t					refcnt;
	int 						dead;
	struct rcu_head				rcu_head;

	atomic_t					neigh_cnt;
	spinlock_t					interface_lock;
	struct list_head			list_interface_common_addr;
};
struct interface_addr{
	struct fib_xid_ether_main 	*mfxid;
	struct list_head 			interface_common_addr;
	struct net_device	 		*outgress_interface;
	struct rcu_head				rcu_head;

	//TODO:check size and alignment
	u8 		ha[MAX_ADDR_LEN];
};

struct fib_xid_ether_main {
	struct xip_dst_anchor	xem_anchor;
	struct interface_addr 	*neigh_addr;
	struct net_device	 	*host_interface;
	int 					xem_dead;

	/* WARNING: @xhm_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xem_common;
};

static inline struct ether_interface *ether_interface_get(const struct net_device *dev)
{
	struct ether_interface *interface;

	rcu_read_lock();
	interface = rcu_dereference(dev->eth_ptr);
	if(interface)
		atomic_inc(interface->refcnt);
	rcu_read_unlock();

	return interface;
}

static struct interface_addr *allocate_interface_addr(struct net_device *interface, 
						const u8 *lladdr, gfp_t flags)
{
	struct interface_addr *ia = kzalloc(sizeof(*ia), flags);
	if (!ia)
		return NULL;

	INIT_LIST_HEAD(&ia->interface_common_addr);

	ia->outgress_interface = interface;
	dev_hold(interface);
	
	memmove(ia->ha, lladdr, interface->dev->addr_len);
	return ha;
}

static void del_interface_addr(struct interface_addr *to_del)
{
	struct ether_interface *einterface;
	struct fib_xid_ether_main *mfib_xid;

	mfib_xid = to_del->mfxid;
	mfib_xid->neigh_addr = NULL;

	einterface = ether_interface_get(to_del->outgress_interface);

	spin_lock(&einterface->interface_lock);
	list_del_rcu(&to_del->interface_common_addr);
	spin_unlock(&einterface->interface_lock);
	atomic_dec(&einterface->neigh_cnt);

	ether_interface_put(einterface);
}

static inline struct fib_xid_ether_main *fxid_mether(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ether_main, xem_common)
		: NULL;
}

/* ETHER context */
struct xip_ether_ctx
{
	struct net		*net;
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
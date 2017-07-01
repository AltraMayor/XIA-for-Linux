#ifndef _NET_XIA_ETHER_H
#define _NET_XIA_ETHER_H
/* prevents double declarations */

#include <linux/netdevice.h>
#include <net/xia_list_fib.h>
#include <linux/netlink.h>

/* Ethernet Principal */
#define XIDTYPE_ETHER (__cpu_to_be32(0x12))

struct rtnl_xia_ether_addrs {
	__u16		attr_len;
	__u8		interface_addr_len;
	__u8		interface_addr[MAX_ADDR_LEN];
	int		interface_index;
};

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

static inline void einterface_hold(struct ether_interface *eint)
{
	atomic_inc(&eint->refcnt);
}

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

static inline int cmp_addr(struct interface_addr *addr, const u8 *str_ha, struct net_device *dev)
{
	int c1 = memcmp(addr->ha, str_ha, dev->addr_len);
	int c2 = addr->dev == dev;

	if (likely(!c1 && c2)) {
		return 1;
	}

	return 0;
}

static void interface_finish_destroy(struct ether_interface *interface)
{
	struct net_device *dev = interface->dev;
#ifdef NET_REFCNT_DEBUG
	pr_debug("%s: %p=%s\n", __func__, interface, dev->name);
#endif
	if (!interface->dead) {
		pr_err("%s: freeing alive ether_interface %p=%s\n",__func__, interface, dev->name);
		dump_stack();
	}
	dev_put(dev);
	kfree(interface);
}

static void mether_finish_destroy(struct fib_xid_ether_main *ether_main)
{
	BUG_ON(!ether_main->xem_dead);
	kfree(ether_main);
}

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

static inline void ether_interface_put(struct ether_interface *interface)
{
	if(atomic_dec_and_test(&interface->refcnt))
		interface_finish_destroy(interface);
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

static inline void free_ia_norcu(struct interface_addr *addr)
{
	dev_put(addr->outgress_interface);
	if(addr->mfxid->dead)
		mether_finish_destroy(addr->fxid);
	kfree(addr);
}

static int attach_neigh_addr_to_fib_entry(struct fib_xid_ether_main *mether,struct interface_addr *addr)
{
	addr->mfxid = mether;
	mether->dead = false;
	mether->neigh_addr = addr;

	struct ether_interface *einterface;
	einterface = ether_interface_get(addr->dev);

	spin_lock(&einterface->interface_lock);
	list_add_tail_rcu(&einterface->list_interface_common_addr,&addr->interface_common_addr);
	spin_unlock(&einterface->interface_lock);
	atomic_inc(&einterface->neigh_cnt);

	ether_interface_put(einterface);
}

static void __free_ia(struct rcu_head *head)
{
	free_ia_norcu(container_of(head, struct interface_addr, rcu_head));
}

static inline void free_interface_addr(struct interface_addr *addr)
{
	call_rcu(&addr->rcu_head, __free_ia);
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

static inline struct ether_interface *__ether_get_rtnl(const struct net_device *dev)
{
	return rtnl_dereference(dev->ether_ptr);
}

extern int ether_vxt;	//TODO:might not be necessary later

#endif /* __KERNEL__ */
#endif		/* _NET_XIA_ETHER_H */
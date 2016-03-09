#ifndef _NET_XIA_HID_H
#define _NET_XIA_HID_H

#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/xia_list_fib.h>

/* Host Principal */
#define XIDTYPE_HID (__cpu_to_be32(0x11))

struct rtnl_xia_hid_hdw_addrs {
	__u16		hha_len;
	__u8		hha_addr_len;
	__u8		hha_ha[MAX_ADDR_LEN];
	int		hha_ifindex;
};

static inline int RTHA_OK(struct rtnl_xia_hid_hdw_addrs *rtha, int len)
{
	return len >= 0 && (unsigned)len >= sizeof(*rtha) &&
		rtha->hha_len <= (unsigned)len;
}

static inline struct rtnl_xia_hid_hdw_addrs *RTHA_NEXT(
	struct rtnl_xia_hid_hdw_addrs *rtha)
{
	return	(struct rtnl_xia_hid_hdw_addrs *)
		(((char *)rtha) + NLMSG_ALIGN(rtha->hha_len));
}

#ifdef __KERNEL__

#include <linux/timer.h>
#include <linux/rtnetlink.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>

/*
 *	HID context
 */

struct xip_hid_ctx {
	struct xip_ppal_ctx	ctx;

	/* Simplify scanning network devices. */
	struct net		*net;

	/* NWP's state per struct net. */
	atomic_t	to_announce;
	atomic_t	announced;
	atomic_t	me; /* Number of local HIDs in ctx.xpc_xtbl. */
	struct timer_list announce_timer;
};

static inline struct xip_hid_ctx *ctx_hid(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_hid_ctx, ctx)
		: NULL;
}

extern int hid_vxt;
extern const struct xia_ppal_rt_iops *hid_rt_iops;

/*
 *	Neighborhood Watch Protocol (NWP)
 *
 *	Exported by nwp.c
 */

/*
 *	Neighbor Table
 */

/* Hardware Address. */
struct hrdw_addr {
	struct fib_xid_hid_main	*mhid;
	struct list_head	ha_list;
	struct list_head	hdev_list;
	struct net_device	*dev;
	struct xip_dst_anchor	anchor;
	struct rcu_head		rcu_head;

	/* Since @ha is at the end of struct hrdw_addr, one doesn't need to
	 * enforce alignment, otherwise use the following line:
	 * u8 ha[ALIGN(MAX_ADDR_LEN, sizeof(long))];
	 */
	u8			ha[MAX_ADDR_LEN];
};

struct fib_xid_hid_main {
	struct list_head	xhm_haddrs;
	atomic_t		xhm_refcnt;
	bool			xhm_dead;

	/* WARNING: @xhm_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xhm_common;
};

static inline struct fib_xid_hid_main *fxid_mhid(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_hid_main, xhm_common)
		: NULL;
}

static inline void mhid_hold(struct fib_xid_hid_main *mhid)
{
	atomic_inc(&mhid->xhm_refcnt);
}

/* Don't call this function directly, call mhid_put() instead. */
void mhid_finish_destroy(struct fib_xid_hid_main *mhid);

static inline void mhid_put(struct fib_xid_hid_main *mhid)
{
	if (atomic_dec_and_test(&mhid->xhm_refcnt))
		mhid_finish_destroy(mhid);
}

int insert_neigh(struct xip_hid_ctx *hid_ctx, const char *id,
	struct net_device *dev, const u8 *lladdr, u32 rtnl_flags);

int remove_neigh(struct fib_xid_table *xtbl, const char *id,
	struct net_device *dev, const u8 *lladdr);

void main_free_hid(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/*
 *	HID Device
 */

struct hid_dev {
	/* These fields are inspired by struct in_device. */
	struct net_device	*dev;
	atomic_t		refcnt;
	int			dead;
	struct rcu_head		rcu_head;

	atomic_t		neigh_cnt;
	spinlock_t		neigh_lock; /* Lock for the neighs list. */
	struct list_head	neighs;
};

static inline struct hid_dev *__hid_dev_get_rcu(const struct net_device *dev)
{
	return rcu_dereference(dev->hid_ptr);
}

static inline struct hid_dev *hid_dev_get(const struct net_device *dev)
{
	struct hid_dev *hdev;

	rcu_read_lock();
	hdev = __hid_dev_get_rcu(dev);
	if (hdev)
		atomic_inc(&hdev->refcnt);
	rcu_read_unlock();
	return hdev;
}

static inline struct hid_dev *__hid_dev_get_rtnl(const struct net_device *dev)
{
	return rtnl_dereference(dev->hid_ptr);
}

void hid_dev_finish_destroy(struct hid_dev *hdev);

static inline void hid_dev_put(struct hid_dev *hdev)
{
	if (atomic_dec_and_test(&hdev->refcnt))
		hid_dev_finish_destroy(hdev);
}

static inline void hid_dev_hold(struct hid_dev *hdev)
{
	atomic_inc(&hdev->refcnt);
}

/*
 *	Loading/unloading
 */

int hid_nwp_init(void);
void hid_nwp_exit(void);

int hid_init_hid_state(struct xip_hid_ctx *hid_ctx);
void hid_release_hid_state(struct xip_hid_ctx *hid_ctx);

#endif /* __KERNEL__ */

#endif /* _NET_XIA_HID_H */

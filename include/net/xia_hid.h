#ifndef _NET_XIA_HID_H
#define _NET_XIA_HID_H

#include <linux/netdevice.h>
#include <linux/netlink.h>

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
	return	(struct rtnl_xia_hid_hdw_addrs*)
		(((char*)rtha) + NLMSG_ALIGN(rtha->hha_len));
}

#ifdef __KERNEL__

#include <linux/timer.h>
#include <linux/rtnetlink.h>
#include <net/xia_fib.h>

/*
 *	Neighborhood Watch Protocol (NWP)
 *
 * 	Exported by nwp.c
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
	/* Since @ha is at the end of struct hrdw_addr, one doesn't need to
	 * enforce alignment, otherwise use the following line:
	 * u8 ha[ALIGN(MAX_ADDR_LEN, sizeof(long))];
	 */
	u8			ha[MAX_ADDR_LEN];
};

struct fib_xid_hid_main {
	struct fib_xid		xhm_common; /* It must be first field! */
	struct list_head	xhm_haddrs;
};

int insert_neigh(struct fib_xid_table *xtbl, const char *xid,
	struct net_device *dev, const u8 *lladdr);

int remove_neigh(struct fib_xid_table *xtbl, const char *xid,
	struct net_device *dev, const u8 *lladdr);

void free_mhid(struct fib_xid_hid_main *mhid);

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
 *	NWP state per struct net
 */

/* XXX This struct should have pointers to local and main HID tables to
 * simplify the code that often looks up those table.
 */
/* struct xia_hid_state keeps the state of NWP per struct net. */
struct xia_hid_state {
	atomic_t	to_announce;
	atomic_t	announced;
	struct timer_list announce_timer;
};

int hid_nwp_init(void);
void hid_nwp_exit(void);

int hid_new_hid_state(struct net *net);
void hid_free_hid_state(struct net *net);

#endif /* __KERNEL__ */

#endif /* _NET_XIA_HID_H */

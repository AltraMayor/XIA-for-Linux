#ifndef _NET_XIA_HID_H
#define _NET_XIA_HID_H

#include <linux/netdevice.h>
#include <linux/netlink.h>

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

/*
 *	Neighborhood Watch Protocol (NWP)
 *
 * 	Exported by nwp.c
 */

/* struct xia_hid_state keeps the state of HID principal per struct net. */
struct xia_hid_state {
	/* TODO Use attomic here! */
	u8	new_hids_to_announce;

	/* 3 bytes free. */

	struct timer_list announce_timer;
};

int hid_nwp_init(void);
void hid_nwp_exit(void);

int hid_new_hid_state(struct net *net);
void hid_free_hid_state(struct net *net);

void announce_myself(struct net *net);
void stop_announcements(struct net *net);

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

static inline void __hid_dev_put(struct hid_dev *hdev)
{
	atomic_dec(&hdev->refcnt);
}

static inline void hid_dev_hold(struct hid_dev *hdev)
{
	atomic_inc(&hdev->refcnt);
}

#endif /* __KERNEL__ */

#endif /* _NET_XIA_HID_H */

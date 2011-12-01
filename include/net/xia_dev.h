#ifndef _XIA_DEV_H
#define _XIA_DEV_H

#include <linux/rtnetlink.h>

struct xip_dev {
	/* These fields are inspired by struct in_device. */
	struct net_device	*dev;
	atomic_t		refcnt;
	int			dead;
	struct rcu_head		rcu_head;

#if defined(CONFIG_XIA_PPAL_HID) || defined(CONFIG_XIA_PPAL_HID_MODULE)
	/* TODO */
#endif
};

static inline struct xip_dev *__xip_dev_get_rcu(const struct net_device *dev)
{
	return rcu_dereference(dev->xip_ptr);
}

static inline struct xip_dev *xip_dev_get(const struct net_device *dev)
{
	struct xip_dev *xdev;

	rcu_read_lock();
	xdev = __xip_dev_get_rcu(dev);
	if (xdev)
		atomic_inc(&xdev->refcnt);
	rcu_read_unlock();
	return xdev;
}

static inline struct xip_dev *__xip_dev_get_rtnl(const struct net_device *dev)
{
	return rtnl_dereference(dev->xip_ptr);
}

void xip_dev_finish_destroy(struct xip_dev *xdev);

static inline void xip_dev_put(struct xip_dev *xdev)
{
	if (atomic_dec_and_test(&xdev->refcnt))
		xip_dev_finish_destroy(xdev);
}

static inline void __xip_dev_put(struct xip_dev *xdev)
{
	atomic_dec(&xdev->refcnt);
}

static inline void xip_dev_hold(struct xip_dev *xdev)
{
	atomic_inc(&xdev->refcnt);
}

int xipdev_init(void);
void xipdev_exit(void);

#endif /* _XIA_DEV_H */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <asm/cache.h>
#include <net/xia_dev.h>

void xip_dev_finish_destroy(struct xip_dev *xdev)
{
	struct net_device *dev = xdev->dev;
	char *dev_name = dev ? dev->name : "NIL";

#ifdef NET_REFCNT_DEBUG
	printk(KERN_DEBUG "%s: %p=%s\n", __FUNCTION__, xdev, dev_name);
#endif
	dev_put(dev);
	if (!xdev->dead)
		pr_err("Freeing alive xip_dev %p=%s\n", xdev, dev_name);
	else
		kfree(xdev);
}
EXPORT_SYMBOL(xip_dev_finish_destroy);

static struct xip_dev *xdev_init(struct net_device *dev)
{
	struct xip_dev *xdev;

	ASSERT_RTNL();

	xdev = kzalloc(sizeof(*xdev), GFP_KERNEL);
	if (!xdev)
		goto out;

	xdev->dev = dev;
	dev_hold(dev);

	xip_dev_hold(xdev);
	RCU_INIT_POINTER(dev->xip_ptr, xdev);
	goto out;

/*
xdev:
	kfree(xdev);
	xdev = NULL;
*/
out:
	return xdev;
}

static void xip_dev_rcu_put(struct rcu_head *head)
{
	struct xip_dev *xdev = container_of(head, struct xip_dev, rcu_head);
	xip_dev_put(xdev);
}

static void xdev_destroy(struct xip_dev *xdev)
{
	struct net_device *dev;

	ASSERT_RTNL();
	dev = xdev->dev;

	xdev->dead = 1;
	RCU_INIT_POINTER(dev->xip_ptr, NULL);
	call_rcu(&xdev->rcu_head, xip_dev_rcu_put);
}

static int xip_netdev_event(struct notifier_block *nb,
	unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct xip_dev *xdev = __xip_dev_get_rtnl(dev);

	ASSERT_RTNL();

	switch (event) {
	case NETDEV_REGISTER:
		BUG_ON(xdev);
		xdev = xdev_init(dev);
		if (!xdev)
			return notifier_from_errno(-ENOMEM);
		break;
	case NETDEV_UNREGISTER:
		xdev_destroy(xdev);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block xip_netdev_notifier __read_mostly = {
	.notifier_call = xip_netdev_event,
};

/*
 *	Initialize XIP Device
 */

int xipdev_init(void)
{
	return register_netdevice_notifier(&xip_netdev_notifier);
}

void xipdev_exit(void)
{
	unregister_netdevice_notifier(&xip_netdev_notifier);
}

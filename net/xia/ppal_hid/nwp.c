#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <asm/cache.h>
#include <net/xia_hid.h>

/*
 *	Announce myself
 */

/* The reason it doesn't process the announcement right away is that
 * it's common to have other announces to do soon, so we wait a little
 * bit to make a single announcement.
 */
void announce_myself(struct net *net)
{
	/* TODO Use attomic here! */
	net->xia.hid_state->new_hids_to_announce++;

	/* XXX Put this as a parameter in /proc. */
	mod_timer(&net->xia.hid_state->announce_timer, jiffies + 1*HZ);
}

void stop_announcements(struct net *net)
{
	del_timer_sync(&net->xia.hid_state->announce_timer);
}

static void announce_event(unsigned long data)
{
	struct net *net = (struct net *)data;

	if (net->xia.hid_state->new_hids_to_announce) {
		/* TODO Announce myself! */

		/* TODO Use attomic here! */
		net->xia.hid_state->new_hids_to_announce--;
	} else {
		/* TODO Decide if I'll announce myself based on the number of
		 * neighbors.
		 */
		/* TODO Announce myself if it's the case. */
	}


	/* XXX Put this as a parameter in /proc. */
	mod_timer(&net->xia.hid_state->announce_timer, jiffies + 60*HZ);
}

/*
 *	State associated to net
 */

int hid_new_hid_state(struct net *net)
{
	int rc = -ENOMEM;
	struct xia_hid_state *state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		goto state;

	init_timer(&state->announce_timer);
	state->announce_timer.function = announce_event;
	/* TODO This reference to net needs to be released when it goes away! */
	state->announce_timer.data = (unsigned long)net;

	net->xia.hid_state = state;
	rc = 0;
	goto out;

/*
free_state:
	kfree(state);
*/
state:
	net->xia.hid_state = NULL;
out:
	return rc;
}

void hid_free_hid_state(struct net *net)
{
	struct xia_hid_state *state = net->xia.hid_state;
	del_timer_sync(&state->announce_timer);
	kfree(state);
	net->xia.hid_state = NULL;
}

/*
 *	Receive NWP packets from the device layer
 */

/* This function is based on net/ipv4/arp.c:arp_rcv */
static int nwp_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	/* TODO */
	return 0;
}

static struct packet_type nwp_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_NWP),
	.func = nwp_rcv,
};

/*
 *	Network Devices
 */

void hid_dev_finish_destroy(struct hid_dev *hdev)
{
	struct net_device *dev = hdev->dev;

#ifdef NET_REFCNT_DEBUG
	printk(KERN_DEBUG "%s: %p=%s\n", __FUNCTION__, hdev, dev->name);
#endif
	if (!hdev->dead)
		pr_err("%s: freeing alive hid_dev %p=%s\n",
			__FUNCTION__, hdev, dev->name);

	dev_put(dev);
	kfree(hdev);
}

static struct hid_dev *hdev_init(struct net_device *dev)
{
	struct hid_dev *hdev;

	ASSERT_RTNL();

	hdev = kzalloc(sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return NULL;

	hdev->dev = dev;
	dev_hold(dev);

	spin_lock_init(&hdev->neigh_lock);
	INIT_LIST_HEAD(&hdev->neighs);

	hid_dev_hold(hdev);
	RCU_INIT_POINTER(dev->hid_ptr, hdev);
	return hdev;
}

static void hid_dev_rcu_put(struct rcu_head *head)
{
	struct hid_dev *hdev = container_of(head, struct hid_dev, rcu_head);
	hid_dev_put(hdev);
}

static void hdev_destroy(struct hid_dev *hdev)
{
	ASSERT_RTNL();
	hdev->dead = 1;
	RCU_INIT_POINTER(hdev->dev->hid_ptr, NULL);

	/* TODO Remove neighbors from neighs list. Is it the right place? */

	call_rcu(&hdev->rcu_head, hid_dev_rcu_put);
}

static int hid_netdev_event(struct notifier_block *nb,
	unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct hid_dev *hdev;

	ASSERT_RTNL();
	hdev = __hid_dev_get_rtnl(dev);

	switch (event) {
	case NETDEV_REGISTER:
		BUG_ON(hdev);
		hdev = hdev_init(dev);
		if (!hdev)
			return notifier_from_errno(-ENOMEM);
		break;
	case NETDEV_UNREGISTER:
		hdev_destroy(hdev);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block hid_netdev_notifier __read_mostly = {
	.notifier_call = hid_netdev_event,
};

/*
 *	Initialize NWP
 */

int hid_nwp_init(void)
{
	int rc;

	rc = register_netdevice_notifier(&hid_netdev_notifier);
	if (rc)
		goto out;

	dev_add_pack(&nwp_packet_type);

out:
	return rc;
}

void hid_nwp_exit(void)
{
	struct net *net;
	struct net_device *dev;

	dev_remove_pack(&nwp_packet_type);
	unregister_netdevice_notifier(&hid_netdev_notifier);

	/* Remove hid_dev from all devices. */
	rtnl_lock();
	for_each_net(net)
		for_each_netdev(net, dev)
			hdev_destroy(__hid_dev_get_rtnl(dev));
	rtnl_unlock();
}

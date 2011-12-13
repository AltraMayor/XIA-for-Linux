#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <asm/cache.h>
#include <net/xia_hid.h>

/*
 *	Neighbor Table
 */

static struct hrdw_addr *new_ha(struct net_device *dev, const u8 *lladdr)
{
	struct hrdw_addr *ha = kzalloc(sizeof(*ha), GFP_KERNEL);
	if (!ha)
		return NULL;
	INIT_LIST_HEAD(&ha->ha_list);
	ha->dev = dev;
	dev_hold(dev);
	memmove(ha->ha, lladdr, dev->addr_len);
	return ha;
}

/* ATTENTION! @ha should not be inserted in a list! If so, remove with
 * a del_ha* function.
 */
static inline void free_ha(struct hrdw_addr *ha)
{
	dev_put(ha->dev);
	ha->dev = NULL;
	kfree(ha);
}

static int add_ha(struct fib_xid_hid_main *mhid, struct hrdw_addr *ha)
{
	struct hrdw_addr *pos_ha, *insert_here, *same_dev;
	struct hid_dev *hdev;
	struct list_head *neighs_insert_here;

	/* Inserting on mhid->xhm_haddrs. */
	insert_here = same_dev = NULL;
	list_for_each_entry(pos_ha, &mhid->xhm_haddrs, ha_list) {
		int c1 = memcmp(pos_ha->ha, ha->ha, ha->dev->addr_len);
		int c2 = pos_ha->dev == ha->dev;
		if (unlikely(!c1 && c2))
			return -ESRCH;	/* It's a duplicate. */

		/* Keep listed sorted, but look at all ha's that have
		 * the same ha->ha.
		 */
		if (!insert_here && c1 > 0)
			insert_here = pos_ha;

		if (c2) {
			/* Keep updating @same_dev to add @ha after
			 * all others ha's in hdev->neighs.
			 */
			same_dev = pos_ha;
		}

		if (insert_here && same_dev)
			break;
	}
	ha->mhid = mhid;
	if (!insert_here)
		insert_here = pos_ha;
	list_add_tail_rcu(&ha->ha_list, &insert_here->ha_list);

	/* Inserting on hdev->neighs. */
	hdev = hid_dev_get(ha->dev);
	spin_lock(&hdev->neigh_lock);
	/* Inserting @ha in hdev_list following other ha's of @mhid
	 * that have the same dev is important to list all ha's of
	 * @mhid together from @hdev.
	 */
	neighs_insert_here = same_dev ? &same_dev->hdev_list : &hdev->neighs;
	list_add_tail_rcu(&ha->hdev_list, neighs_insert_here);
	spin_unlock(&hdev->neigh_lock);
	/* There's no point in moving the following line before the unlock
	 * because @hdev->neighs is mainly browsed with RCU, that is,
	 * @neigh_cnt won't always be in sync with @hdev->neighs.
	 * Thus, moving it before the unlock will just spend more time on
	 * the lock.
	 * @neigh_cnt should be seem as a good hint of
	 * the length of @hdev->neighs.
	 */
	atomic_inc(&hdev->neigh_cnt);
	hid_dev_put(hdev);

	return 0;
}

static void del_ha(struct hrdw_addr *ha)
{
	struct hid_dev *hdev;
	list_del_rcu(&ha->ha_list);

	hdev = hid_dev_get(ha->dev);

	spin_lock(&hdev->neigh_lock);
	list_del_rcu(&ha->hdev_list);
	spin_unlock(&hdev->neigh_lock);
	atomic_dec(&hdev->neigh_cnt);

	hid_dev_put(hdev);

	synchronize_rcu();
	ha->mhid = NULL;
}

static int del_ha_from_mhid(struct fib_xid_hid_main *mhid, const u8 *str_ha,
	struct net_device *dev)
{
	struct hrdw_addr *pos_ha, *nxt;

	/* Notice that one could use list_for_each_entry here, but
	 * it could break if someone changes the code later and doesn't pay
	 * attention to this detail; playing safe!
	 */
	list_for_each_entry_safe(pos_ha, nxt, &mhid->xhm_haddrs, ha_list) {
		int c1 = memcmp(pos_ha->ha, str_ha, dev->addr_len);
		int c2 = pos_ha->dev == dev;
		if (unlikely(!c1 && c2)) {
			del_ha(pos_ha);
			free_ha(pos_ha);
			return 0;
		}
		/* List is sorted, but look at all ha's that have
		 * the same ha->ha.
		 */
		if (c1 > 0)
			break;
	}
	return -ESRCH;
}

static void del_has_by_dev(struct list_head *head, struct net_device *dev)
{
	struct hrdw_addr *pos_ha, *nxt;
	list_for_each_entry_safe(pos_ha, nxt, head, ha_list)
		if (pos_ha->dev == dev) {
			del_ha(pos_ha);
			free_ha(pos_ha);
		}
}

/* Caller must hold RTNL lock, and makes sure that nobody adds entries
 * in hdev->neighs while it's running.
 */
static void free_neighs_by_dev(struct hid_dev *hdev)
{
	struct net_device *dev = hdev->dev;
	struct net *net = dev_net(dev);
	struct fib_xid_table *xtbl;

	ASSERT_RTNL();

	rcu_read_lock();
	xtbl = xia_find_xtbl_rcu(net->xia.main_rtbl, XIDTYPE_HID);
	BUG_ON(!xtbl);
	xtbl_hold(xtbl);
	rcu_read_unlock();

	while (1) {
		struct hrdw_addr *ha;
		u8 xid[XIA_XID_MAX];
		struct fib_xid_hid_main *mhid;

		/* Obtain xid of the first entry in @hdev->neighs.
		 *
		 * We use rcu_read_lock() here just to allow one to remove
		 * entries in parallel.
		 */
		rcu_read_lock();
		if (list_empty(&hdev->neighs)) {
			rcu_read_unlock();
			break;
		}
		ha = list_first_entry_rcu(&hdev->neighs, struct hrdw_addr,
			hdev_list);
		memmove(xid, ha->mhid->xhm_common.fx_xid, XIA_XID_MAX);
		rcu_read_unlock();

		/* We don't lock hdev->neigh_lock to avoid deadlock. */
		mhid = (struct fib_xid_hid_main *)xia_find_xid_lock(xtbl, xid);
		if (mhid) {
			/* We must test mhid != NULL because
			 * we didn't hold a lock before the find.
			 */
			del_has_by_dev(&mhid->xhm_haddrs, dev);
			if (list_empty(&mhid->xhm_haddrs)) {
				fib_rm_fxid_locked(xtbl, &mhid->xhm_common);
				free_fxid(xtbl, &mhid->xhm_common);
			}
		}
		fib_unlock_xid(xtbl, xid);
	}

	xtbl_put(xtbl);
}

int insert_neigh(struct fib_xid_table *xtbl, const char *xid,
	struct net_device *dev, const u8 *lladdr)
{
	struct fib_xid_hid_main *mhid;
	struct hrdw_addr *ha;
	int rc;

	rc = -EINVAL;
	if (!(dev->flags & IFF_UP))
		goto out;

	rc = -ENOMEM;
	ha = new_ha(dev, lladdr);
	if (!ha)
		goto out;

	mhid = (struct fib_xid_hid_main *)xia_find_xid_lock(xtbl, xid);
	if (mhid) {
		rc = add_ha(mhid, ha);
		fib_unlock_xid(xtbl, xid);
		if (rc)
			goto ha;
		goto out;
	}
	fib_unlock_xid(xtbl, xid);

	/* Add new @mhid. */
	rc = -ENOMEM;
	mhid = kzalloc(sizeof(*mhid), GFP_KERNEL);
	if (!mhid)
		goto ha;
	init_fxid(&mhid->xhm_common, xid);
	INIT_LIST_HEAD(&mhid->xhm_haddrs);
	rc = add_ha(mhid, ha);
	BUG_ON(rc);
	rc = fib_add_fxid(xtbl, &mhid->xhm_common);
	if (rc)
		free_fxid(xtbl, &mhid->xhm_common);
	goto out;

ha:
	free_ha(ha);
out:
	return rc;
}

int remove_neigh(struct fib_xid_table *xtbl, const char *xid,
	struct net_device *dev, const u8 *lladdr)
{
	struct fib_xid_hid_main *mhid;
	int rc;

	mhid = (struct fib_xid_hid_main *)xia_find_xid_lock(xtbl, xid);
	if (!mhid) {
		fib_unlock_xid(xtbl, xid);
		return -ESRCH;
	}

	rc = del_ha_from_mhid(mhid, lladdr, dev);
	if (rc) {
		fib_unlock_xid(xtbl, xid);
		return rc;
	}

	if (list_empty(&mhid->xhm_haddrs)) {
		fib_rm_fxid_locked(xtbl, &mhid->xhm_common);
		free_fxid(xtbl, &mhid->xhm_common);
	}

	fib_unlock_xid(xtbl, xid);
	return 0;
}

static void free_haddrs(struct list_head *head)
{
	struct hrdw_addr *pos_ha, *nxt;
	list_for_each_entry_safe(pos_ha, nxt, head, ha_list) {
		del_ha(pos_ha);
		free_ha(pos_ha);
	}
}

/* Don't call this function! Use free_fxid instead. */
void free_mhid(struct fib_xid_hid_main *mhid)
{
	free_haddrs(&mhid->xhm_haddrs);
}

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

	free_neighs_by_dev(hdev);

	RCU_INIT_POINTER(hdev->dev->hid_ptr, NULL);
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
	case NETDEV_DOWN:
		free_neighs_by_dev(hdev);
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

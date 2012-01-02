#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <asm/cache.h>
#include <net/ip_vs.h>
#include <net/xia_dag.h>
#include <net/xia_hid.h>

/* XXX Consider implementing slabs for struct hrdw_addr and
 * struct fib_xid_hid_main to release the memory preasure when priority
 * is GFP_ATOMIC.
 */

/*
 *	Neighbor Table
 */

static struct hrdw_addr *new_ha(struct net_device *dev, const u8 *lladdr,
	gfp_t flags)
{
	struct hrdw_addr *ha = kzalloc(sizeof(*ha), flags);
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

	xtbl = xia_find_xtbl_hold(net->xia.main_rtbl, XIDTYPE_HID);
	BUG_ON(!xtbl);

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
	struct net_device *dev, const u8 *lladdr, gfp_t flags)
{
	struct net *net;
	struct fib_xid_table *local_xtbl;
	struct fib_xid_hid_main *mhid;
	struct hrdw_addr *ha;
	int rc, is_me;

	rc = -EINVAL;
	if (!(dev->flags & IFF_UP) || (dev->flags & IFF_LOOPBACK))
		goto out;

	/* XXX The test below isn't race free, one can add the entry to local
	 * xtbl after it's tested, and before the neighbor table is updated.
	 */
	/* Test if @xid is already inserted in the local xtbl. */
	rc = -EINVAL;
	net = xtbl_net(xtbl);
	local_xtbl = xia_find_xtbl_hold(net->xia.local_rtbl, XIDTYPE_HID);
	BUG_ON(xtbl == local_xtbl);
	BUG_ON(net != xtbl_net(local_xtbl));
	rcu_read_lock();
	is_me = xia_find_xid_rcu(local_xtbl, xid) != NULL;
	rcu_read_unlock();
	xtbl_put(local_xtbl);
	if (is_me)
		goto out;

	rc = -ENOMEM;
	ha = new_ha(dev, lladdr, flags);
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

	/* XXX Avoid call fib_unlock_xid above and implement
	 * fib_add_fxid_locked, thus one can't add it before us.
	 */
	/* Add new @mhid. */
	rc = -ENOMEM;
	mhid = kzalloc(sizeof(*mhid), flags);
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

struct announcement_state {
	struct hid_dev	*hdev;
	struct sk_buff	*skb;
	unsigned int	data_len;
	unsigned int	mtu;
};

#define NWP_VERSION		0x01

#define NWP_TYPE_ANNOUCEMENT	0x01
#define NWP_TYPE_NEIGH_LIST	0x02
#define NWP_TYPE_MAX		0x03

struct general_hdr {
	u8	version;
	u8	type;
	u8	hid_count;
	u8	haddr_len;
} __attribute__ ((packed));

struct announcement_hdr {
	u8	version;
	u8	type;
	u8	hid_count;
	u8	haddr_len;

	u8	haddr_begin[0];
	u8	haddr[MAX_ADDR_LEN];
} __attribute__ ((packed));

struct neighs_hdr {
	u8	version;
	u8	type;
	u8	hid_count;
	u8	haddr_len;

	u8	neighs_begin[0];
/*	XID_1 NUM_1 HA_11 HA_12 ... HA_1NUM_1
 *	XID_2 NUM_2 HA_21 HA_22 ... HA_2NUM_2
 *	...
 *	XID_count NUM_count HA_count1 HA_count2 ... HA_countNUM_count
 *
 *	count == hid_count.
 */
} __attribute__ ((packed));

static inline int announcement_hdr_len(struct net_device *dev)
{
	return offsetof(struct announcement_hdr, haddr_begin) + dev->addr_len;
}

static int __announce_on_dev(struct fib_xid_table *xtbl,
	struct fib_xid *fxid, void *arg)
{
	struct announcement_state *state = arg;
	struct net_device *dev = state->hdev->dev;
	struct sk_buff *skb = state->skb;
	struct announcement_hdr *nwp;

	if (skb->len + XIA_XID_MAX > state->data_len) {
		/* XXX Enhance NWP to support multiple-frame announcements. */
		printk(KERN_WARNING "XIA HID NWP: Can't announce all "
			"local HIDs on dev %s because its largest frame "
			"(MTU=%u) doesn't fit them\n", dev->name, state->mtu);
		return 1;
	}

	nwp = (struct announcement_hdr *)skb_network_header(skb);
	if (nwp->hid_count == 0xff) {
		/* XXX Enhance NWP to support multiple-frame announcements. */
		printk(KERN_WARNING "XIA HID NWP: Can't announce all "
			"local HIDs on dev %s because there are more than "
			"255 local HIDs\n", dev->name);
		return 1;
	}

	nwp->hid_count++;
	memcpy(skb_put(skb, XIA_XID_MAX), fxid->fx_xid, XIA_XID_MAX);
	return 0;
}

static void send_nwp_frame(struct sk_buff *skb, const void *saddr,
	const void *daddr)
{
	/* Fill the device header. */
	if (dev_hard_header(skb, skb->dev, ETH_P_NWP, daddr, saddr,
		skb->len) < 0) {
		kfree_skb(skb);
		return;
	}

	/* Ignore transmission errors. */
	dev_queue_xmit(skb);
}

static void announce_on_dev(struct fib_xid_table *local_xtbl,
	struct hid_dev *hdev)
{
	struct net_device *dev = hdev->dev;
	unsigned int mtu = dev->mtu;
	int hdr_len = announcement_hdr_len(dev);
	int ll_hlen = LL_RESERVED_SPACE(dev);
	int ll_tlen = dev->needed_tailroom;
	int ll_space = ll_hlen + ll_tlen;
	int min_annoucement = ll_space + hdr_len + XIA_XID_MAX;
	struct sk_buff *skb;
	struct announcement_hdr *nwp;
	struct announcement_state state;

	if (mtu < min_annoucement) {
		printk(KERN_ERR "XIA HID NWP: Can't send an announcement "
			"because dev %s has MTU (%u) smaller than "
			"the smallest annoucement frame (%i)\n",
			dev->name, mtu, min_annoucement);
		return;
	}

	skb = alloc_skb(mtu, GFP_ATOMIC);
	if (!skb)
		return; /* Can't announce this time. */
	skb_reserve(skb, ll_hlen);
	skb_reset_network_header(skb);
	nwp = (struct announcement_hdr *)skb_put(skb, hdr_len);
	skb->dev = dev;
	skb->protocol = htons(ETH_P_NWP);

	/* Fill out the NWP header. */
	nwp->version	= NWP_VERSION;
	nwp->type	= NWP_TYPE_ANNOUCEMENT;
	nwp->hid_count	= 0;
	nwp->haddr_len	= dev->addr_len;
	memcpy(nwp->haddr, dev->dev_addr, dev->addr_len);

	/* Fill out the body. */
	state.hdev	= hdev;
	state.skb	= skb;
	state.data_len	= mtu - ll_space;
	state.mtu	= mtu;
	/* XXX Implement a read only version of xia_iterate_xids.
	 * One has to figure it out if here one has to use rcu_read_lock_bh(),
	 * or rcu_read_lock() is enough.
	 */
	xia_iterate_xids(local_xtbl, __announce_on_dev, &state);
	if (likely(nwp->hid_count))
		send_nwp_frame(skb, dev->dev_addr, dev->broadcast);
}

static int my_turn(int me, struct hid_dev *hdev)
{
	int others;
	u32 threshold, rand;

	if (me <= 0)
		return 0;

	others = atomic_read(&hdev->neigh_cnt);
	if (others <= 0)
		return 1;
		
	threshold = (0xffffffffU / (u32)(others + me)) * (u32)me;
	get_random_bytes(&rand, sizeof(rand));
	return rand <= threshold;
}

static void announce_event(unsigned long data)
{
	struct net *net = (struct net *)data;
	struct xia_hid_state *state = net->xia.hid_state;
	struct fib_xid_table *local_xtbl =
		xia_find_xtbl_hold(net->xia.local_rtbl, XIDTYPE_HID);
	struct net_device *dev;
	int me, last_announced, next_to_announce, force;
	BUG_ON(!local_xtbl);

	next_to_announce = atomic_read(&state->to_announce);
	me = xia_get_fxid_count(local_xtbl);
	if (me <= 0)
		goto out;

	last_announced = atomic_read(&state->announced);
	force = next_to_announce != last_announced;
	
	for_each_netdev(net, dev) {
		struct hid_dev *hdev;
		/* No NWP on this interface. */
		if (dev->flags & (IFF_LOOPBACK | IFF_NOARP))
			continue;

		hdev = hid_dev_get(dev);
		if (force || my_turn(me, hdev))
			announce_on_dev(local_xtbl, hdev);
		hid_dev_put(hdev);
	}

out:
	atomic_set(&state->announced, next_to_announce);
	xtbl_put(local_xtbl);
	mod_timer(&net->xia.hid_state->announce_timer, jiffies + 5*HZ);
}

/*
 *	State associated to net
 */

int hid_new_hid_state(struct net *net)
{
	struct xia_hid_state *state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	init_timer(&state->announce_timer);
	state->announce_timer.function = announce_event;
	state->announce_timer.data = (unsigned long)net;
	hold_net(net);
	net->xia.hid_state = state;
	/* XXX Having a random delay should help to avoid synchronization. */
	/* XXX Not starting timer if there's nothing to announce. */
	mod_timer(&state->announce_timer, jiffies + 5*HZ);
	
	return 0;
}

void hid_free_hid_state(struct net *net)
{
	struct xia_hid_state *state = net->xia.hid_state;
	struct net *netx = (struct net *)state->announce_timer.data;
	BUG_ON(net != netx);
	del_timer_sync(&state->announce_timer);
	net->xia.hid_state = NULL;
	release_net(net);
	kfree(state);
}

/*
 *	Receive NWP packets from the device layer
 */

static struct sk_buff *alloc_neigh_list_skb(struct net_device *dev,
	unsigned int mtu, u8 **pphid_counter)
{
	int ll_hlen = LL_RESERVED_SPACE(dev);
	int ll_tlen = dev->needed_tailroom;
	int ll_space = ll_hlen + ll_tlen;
	int hdr_len = offsetof(struct neighs_hdr, neighs_begin);
	int min_list = ll_space + hdr_len + XIA_XID_MAX + 1 + dev->addr_len;
	struct sk_buff *skb;
	struct neighs_hdr *nwp;

	if (mtu < min_list) {
		printk(KERN_ERR "XIA HID NWP: Can't send a neighbor list "
			"because dev %s has MTU (%u) smaller than "
			"the smallest neighbor list frame (%i)\n",
			dev->name, mtu, min_list);
		return NULL;
	}

	skb = alloc_skb(mtu, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, ll_hlen);
	skb_reset_network_header(skb);
	nwp = (struct neighs_hdr *)skb_put(skb, hdr_len);
	skb->dev = dev;
	skb->protocol = htons(ETH_P_NWP);

	/* Fill out the NWP header. */
	nwp->version	= NWP_VERSION;
	nwp->type	= NWP_TYPE_NEIGH_LIST;
	nwp->hid_count	= 0;
	nwp->haddr_len	= dev->addr_len;

	*pphid_counter = &nwp->hid_count;
	return skb;
}

/* Define @dest_str as char str[XIA_MAX_STRXID_SIZE]; */
static void str_of_xid(char *dest_str, u8 *id)
{
	struct xia_xid xid;
	xid.xid_type = XIDTYPE_HID;
	memcpy(xid.xid_id, id, XIA_XID_MAX);
	xia_xidtop(&xid, dest_str, XIA_MAX_STRXID_SIZE);
}

static void list_neighs_to(struct hid_dev *hdev, u8 *dest_haddr)
{
	struct net_device *dev = hdev->dev;
	unsigned int mtu = dev->mtu;
	struct sk_buff *skb;
	struct fib_xid_hid_main *prv_mhid;
	u8 *phid_counter, *pcounter, dummy;
	int min_entry, data_len;
	struct hrdw_addr *ha;
	int addr_len = dev->addr_len;

	skb = alloc_neigh_list_skb(dev, mtu, &phid_counter);
	if (!skb)
		return;

	/* XXX Add local HIDs in the list. This should be implemented after
	 * having local HIDs associated to interfaces in order to avoid
	 * writing this functionality twice.
	 */

	prv_mhid = NULL;
	dummy = 0;
	pcounter = &dummy;
	min_entry = XIA_XID_MAX + 1 + addr_len;
	data_len = mtu - LL_RESERVED_SPACE(dev) - dev->needed_tailroom;
	rcu_read_lock();
	list_for_each_entry_rcu(ha, &hdev->neighs, hdev_list) {
		int is_new_hid, need_new_skb;
		struct fib_xid_hid_main *mhid = ha->mhid;
		BUG_ON(ha->dev != dev);

		is_new_hid = prv_mhid != mhid;
		need_new_skb = (*phid_counter == 0xff) ||
			(*pcounter == 0xff) ||
			(is_new_hid &&
				/* Space for another HID? */
				(skb->len + min_entry > data_len)) ||
			(!is_new_hid &&
				/* Space for another link layer address? */
				(skb->len + addr_len > data_len));

		if (unlikely(need_new_skb)) {
			send_nwp_frame(skb, dev->dev_addr, dest_haddr);
			skb = alloc_neigh_list_skb(dev, mtu, &phid_counter);
			if (!skb)
				break;
		}

		if (is_new_hid || need_new_skb) {
			/* Add new HID and counter. */
			u8 *buf = skb_put(skb, XIA_XID_MAX + 1);
			memcpy(buf, mhid->xhm_common.fx_xid, XIA_XID_MAX);
			/* Update counters. */
			(*phid_counter)++;
			pcounter = buf + XIA_XID_MAX;
			*pcounter = 0;
		}

		/* Add new hardware address. */
		memcpy(skb_put(skb, addr_len), ha->ha, addr_len);
		(*pcounter)++;

		prv_mhid = mhid;
	}
	rcu_read_unlock();
	BUG_ON(dummy);

	if (skb) {
		if (prv_mhid)
			send_nwp_frame(skb, dev->dev_addr, dest_haddr);
		else
			consume_skb(skb);
	}
}

/* Insert all new entries in neighbor table. */
static void read_announcement(struct sk_buff *skb)
{
	struct net *net = skb_net(skb);
	struct announcement_hdr *nwp;
	struct fib_xid_table *main_xtbl;
	int count;
	u8 *xid;

	nwp = (struct announcement_hdr *)skb_network_header(skb);
	main_xtbl = xia_find_xtbl_hold(net->xia.main_rtbl, XIDTYPE_HID);
	count = nwp->hid_count;
	xid = skb->data;
	while (count > 0) {
		u8 *next_xid = skb_pull(skb, XIA_XID_MAX);
		if (!next_xid) {
			printk(KERN_WARNING "XIA HID NWP: An announcement "
				"was received truncated. It should contain "
				"%i HID(s), but %i HID(s) are missing\n",
				nwp->hid_count, count);
			break;
		}
		/* Ignore errors. */
		insert_neigh(main_xtbl, xid, skb->dev, nwp->haddr, GFP_ATOMIC);
		xid = next_xid;
		count--;
	}
	xtbl_put(main_xtbl);
}

static int process_announcement(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
	int hdr_len = announcement_hdr_len(dev);
	int min_annoucement = hdr_len + XIA_XID_MAX;
	struct announcement_hdr *nwp;
	struct fib_xid_table *local_xtbl;
	struct hid_dev *hdev;
	int me;

	if (!pskb_may_pull(skb, min_annoucement))
		goto out;
	skb_reset_network_header(skb);
	nwp = (struct announcement_hdr *)skb_network_header(skb);
	skb_pull(skb, hdr_len);
	read_announcement(skb);

	/* Reply my list of neighbors. Notice that it'll include the sender
	 * that triggered this event.
	 */

	/* Obtain @me. */
	rcu_read_lock();
	local_xtbl = xia_find_xtbl_rcu(net->xia.local_rtbl, XIDTYPE_HID);
	me = xia_get_fxid_count(local_xtbl);
	rcu_read_unlock();

	hdev = hid_dev_get(dev);
	if (my_turn(me, hdev))
		list_neighs_to(hdev, nwp->haddr);
	hid_dev_put(hdev);

out:
	consume_skb(skb);
	return 0;
}

static int process_neigh_list(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
	int hdr_len = offsetof(struct neighs_hdr, neighs_begin);
	int min_list = hdr_len + XIA_XID_MAX + 1 + dev->addr_len;
	struct neighs_hdr *nwp;
	u8 *xid;
	struct fib_xid_table *main_xtbl;
	int hid_count;

	if (!pskb_may_pull(skb, min_list))
		goto out;
	skb_reset_network_header(skb);
	nwp = (struct neighs_hdr *)skb_network_header(skb);
	xid = skb_pull(skb, hdr_len);

	main_xtbl = xia_find_xtbl_hold(net->xia.main_rtbl, XIDTYPE_HID);
	hid_count = nwp->hid_count;
	while (hid_count > 0) {
		u8 *haddr_or_xid = skb_pull(skb, XIA_XID_MAX + 1);
		int original_ha_count, ha_count;
		if (!haddr_or_xid) {
			printk(KERN_WARNING "XIA HID NWP: A neighbor list "
				"was received truncated. It should contain "
				"%i HID(s), but %i HID(s) are missing\n",
				nwp->hid_count, hid_count);
			break;
		}
		original_ha_count = xid[XIA_XID_MAX];
		ha_count = original_ha_count;
		while (ha_count > 0) {
			u8 *next_haddr_or_xid = skb_pull(skb, dev->addr_len);
			if (!next_haddr_or_xid) {
				char str[XIA_MAX_STRXID_SIZE];
				str_of_xid(str, xid);
				printk(KERN_WARNING "XIA HID NWP: "
					"A neighbor list was received "
					"truncated. It should contain %i "
					"link layer addresses for %s, "
					"but %i are missing\n",
					original_ha_count, str, ha_count);
				goto out_loop;
			}

			insert_neigh(main_xtbl, xid, dev, haddr_or_xid,
				GFP_ATOMIC);

			haddr_or_xid = next_haddr_or_xid;
			ha_count--;
		}
		xid = haddr_or_xid;
		hid_count--;
	}
out_loop:
	xtbl_put(main_xtbl);
out:
	consume_skb(skb);
	return 0;
}

/* This function is based on net/ipv4/arp.c:arp_rcv */
static int nwp_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct general_hdr *ghdr;

	if (!pskb_may_pull(skb, sizeof(*ghdr)))
		goto freeskb;

	ghdr = (struct general_hdr *)skb_network_header(skb);
	if (ghdr->version != NWP_VERSION		||
		ghdr->type >= NWP_TYPE_MAX		||
		ghdr->hid_count == 0			||
		ghdr->haddr_len != dev->addr_len	||
		dev->flags & (IFF_NOARP | IFF_LOOPBACK)	||
		skb->pkt_type == PACKET_OTHERHOST	||
		skb->pkt_type == PACKET_LOOPBACK	)
		goto freeskb;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto out_of_mem;

	switch (ghdr->type) {
	case NWP_TYPE_ANNOUCEMENT:
		return process_announcement(skb);
	case NWP_TYPE_NEIGH_LIST:
		return process_neigh_list(skb);
	}
	BUG();

freeskb:
	kfree_skb(skb);
out_of_mem:
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

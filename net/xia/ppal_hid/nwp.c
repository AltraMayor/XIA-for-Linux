#include <linux/export.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <linux/cache.h>
#include <net/xia_dag.h>
#include <net/xia_hid.h>
#include <net/xia_list_fib.h>

/* Neighbor Table */

static struct hrdw_addr *new_ha(struct net_device *dev, const u8 *lladdr,
				gfp_t flags)
{
	struct hrdw_addr *ha = kzalloc(sizeof(*ha), flags);

	if (!ha)
		return NULL;
	INIT_LIST_HEAD(&ha->ha_list);
	INIT_LIST_HEAD(&ha->hdev_list);
	ha->dev = dev;
	dev_hold(dev);
	xdst_init_anchor(&ha->anchor);
	memmove(ha->ha, lladdr, dev->addr_len);
	return ha;
}

/* ATTENTION!
 *	@ha must not be inserted in a list! If so, remove it with
 *	a del_ha* function, and use free_ha instead.
 *
 *	This function expects that no RCU readers can reach @ha.
 */
static inline void free_ha_norcu(struct hrdw_addr *ha)
{
	xdst_free_anchor(&ha->anchor);
	dev_put(ha->dev);
	if (ha->mhid)
		mhid_put(ha->mhid);
	kfree(ha);
}

/* Don't call this function, use free_ha instead. */
static void __free_ha(struct rcu_head *head)
{
	free_ha_norcu(container_of(head, struct hrdw_addr, rcu_head));
}

/* ATTENTION!
 *	@ha should not be inserted in a list! If so, remove it with
 *	a del_ha* function before calling this function.
 */
static inline void free_ha(struct hrdw_addr *ha)
{
	call_rcu(&ha->rcu_head, __free_ha);
}

static int ha_exists(struct fib_xid_hid_main *mhid, struct net_device *dev,
		     const u8 *lladdr)
{
	struct hrdw_addr *pos_ha;

	list_for_each_entry(pos_ha, &mhid->xhm_haddrs, ha_list) {
		if (unlikely(pos_ha->dev == dev &&
			     !memcmp(pos_ha->ha, lladdr, dev->addr_len)))
			return 1;	/* Yes! */
	}
	return 0;
}

static int add_ha(struct fib_xid_hid_main *mhid, struct hrdw_addr *ha)
{
	struct hrdw_addr *pos_ha, *insert_here, *same_dev;
	struct hid_dev *hdev;
	struct list_head *neighs_insert_here;

	/* Inserting on mhid->xhm_haddrs. */
	same_dev = NULL;
	insert_here = NULL;
	list_for_each_entry(pos_ha, &mhid->xhm_haddrs, ha_list) {
		int c1 = memcmp(pos_ha->ha, ha->ha, ha->dev->addr_len);
		int c2 = pos_ha->dev == ha->dev;

		if (unlikely(!c1 && c2))
			return -EEXIST;	/* It's a duplicate. */

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
	mhid_hold(mhid);
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
	return -ENOENT;
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
	struct net_device *dev;
	struct net *net;
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *xtbl;

	ASSERT_RTNL();

	dev = hdev->dev;
	net = dev_net(dev);
	ctx = xip_find_my_ppal_ctx_vxt(net, hid_vxt);
	xtbl = ctx->xpc_xtbl;

	while (1) {
		struct hrdw_addr *ha;
		u8 xid[XIA_XID_MAX];
		struct fib_xid *fxid;
		u32 bucket;

		/* Obtain xid of the first entry in @hdev->neighs.
		 *
		 * We use rcu_read_lock() here to allow one to remove
		 * entries in parallel.
		 */
		rcu_read_lock();
		ha = list_first_or_null_rcu(&hdev->neighs, struct hrdw_addr,
					    hdev_list);
		if (!ha) {
			rcu_read_unlock();
			break;
		}
		memmove(xid, ha->mhid->xhm_common.fx_xid, XIA_XID_MAX);
		rcu_read_unlock();

		/* We don't lock hdev->neigh_lock to avoid deadlock. */
		fxid = hid_rt_iops->fxid_find_lock(&bucket, xtbl, xid);
		if (fxid && fxid->fx_table_id == XRTABLE_MAIN_INDEX) {
			struct fib_xid_hid_main *mhid = fxid_mhid(fxid);
			/* We must test mhid != NULL because
			 * we didn't hold a lock before the find.
			 */
			del_has_by_dev(&mhid->xhm_haddrs, dev);
			if (list_empty(&mhid->xhm_haddrs)) {
				hid_rt_iops->fxid_rm_locked(&bucket, xtbl,
							    fxid);
				fxid_free(xtbl, fxid);
			}
		}
		hid_rt_iops->fib_unlock(xtbl, &bucket);
	}
}

int insert_neigh(struct xip_hid_ctx *hid_ctx, const char *id,
		 struct net_device *dev, const u8 *lladdr, u32 nl_flags)
{
	struct hrdw_addr *ha;
	struct fib_xid_table *xtbl;
	struct fib_xid *cur_fxid;
	struct xip_deferred_negdep_flush *dnf;
	struct fib_xid_hid_main *new_mhid;
	u32 bucket;
	int rc;

	if (!(dev->flags & IFF_UP) || (dev->flags & IFF_LOOPBACK))
		return -EINVAL;

	/* GFP_ATOMIC is important because this function may be called from
	 * an atomic context.
	 */
	ha = new_ha(dev, lladdr, GFP_ATOMIC);
	if (!ha)
		return -ENOMEM;

	/* Acquire lock. */
	xtbl = hid_ctx->ctx.xpc_xtbl;
	cur_fxid = hid_rt_iops->fxid_find_lock(&bucket, xtbl, id);

	if (cur_fxid) {
		/* We don't issue a warning about trying to insert a neighbor
		 * that shares one of our own local HIDs because if this host
		 * has two interfaces connected to the same medium, it would
		 * lead to a false problem.
		 */
		if (cur_fxid->fx_table_id != XRTABLE_MAIN_INDEX) {
			rc = -EINVAL;
			goto unlock_bucket;
		}
		new_mhid = fxid_mhid(cur_fxid);

		if (ha_exists(new_mhid, dev, lladdr)) {
			if ((nl_flags & NLM_F_EXCL) ||
			    !(nl_flags & NLM_F_REPLACE)) {
				rc = -EEXIST;
				goto unlock_bucket;
			}

			/* Replace entry; nothing to do. */
			rc = 0;
			goto unlock_bucket;
		}
		if (!(nl_flags & NLM_F_CREATE)) {
			rc = -ENOENT;
			goto unlock_bucket;
		}

		/* Add new hardware address. */
		rc = add_ha(new_mhid, ha);
		hid_rt_iops->fib_unlock(xtbl, &bucket);
		if (rc)
			goto ha;
		return 0;
	}

	if (!(nl_flags & NLM_F_CREATE)) {
		rc = -ENOENT;
		goto unlock_bucket;
	}

	/* Add new entry. */

	/* GFP_ATOMIC is important because this function may be called from
	 * an atomic context AND a spin lock is held at this point.
	 */

	dnf = fib_alloc_dnf(GFP_ATOMIC);
	if (!dnf) {
		rc = -ENOMEM;
		goto unlock_bucket;
	}

	new_mhid = hid_rt_iops->fxid_ppal_alloc(sizeof(*new_mhid), GFP_ATOMIC);
	if (!new_mhid) {
		rc = -ENOMEM;
		goto def_upd;
	}
	fxid_init(xtbl, &new_mhid->xhm_common, id, XRTABLE_MAIN_INDEX, 0);
	INIT_LIST_HEAD(&new_mhid->xhm_haddrs);
	atomic_set(&new_mhid->xhm_refcnt, 1);
	new_mhid->xhm_dead = false;
	rc = add_ha(new_mhid, ha);
	BUG_ON(rc);

	BUG_ON(hid_rt_iops->fxid_add_locked(&bucket, xtbl,
					    &new_mhid->xhm_common));
	hid_rt_iops->fib_unlock(xtbl, &bucket);

	/* Before invalidating old anchors to force dependencies to
	 * migrate to @new_mhid, wait an RCU synchronization to make sure that
	 * every thread see @new_mhid.
	 */
	fib_defer_dnf(dnf, hid_ctx->net, XIDTYPE_HID);
	return 0;

def_upd:
	fib_free_dnf(dnf);
unlock_bucket:
	hid_rt_iops->fib_unlock(xtbl, &bucket);
ha:
	free_ha_norcu(ha);
	return rc;
}

int remove_neigh(struct fib_xid_table *xtbl, const char *id,
		 struct net_device *dev, const u8 *lladdr)
{
	u32 bucket;
	struct fib_xid *fxid;
	struct fib_xid_hid_main *mhid;
	int rc;

	fxid = hid_rt_iops->fxid_find_lock(&bucket, xtbl, id);
	if (!fxid) {
		rc = -ENOENT;
		goto unlock_bucket;
	}
	if (fxid->fx_table_id != XRTABLE_MAIN_INDEX) {
		rc = -EINVAL;
		goto unlock_bucket;
	}
	mhid = fxid_mhid(fxid);

	rc = del_ha_from_mhid(mhid, lladdr, dev);
	if (rc)
		goto unlock_bucket;
	if (list_empty(&mhid->xhm_haddrs)) {
		hid_rt_iops->fxid_rm_locked(&bucket, xtbl, fxid);
		fxid_free(xtbl, fxid);
	}

unlock_bucket:
	hid_rt_iops->fib_unlock(xtbl, &bucket);
	return rc;
}

void mhid_finish_destroy(struct fib_xid_hid_main *mhid)
{
	BUG_ON(!mhid->xhm_dead);
	kfree(mhid);
}
EXPORT_SYMBOL_GPL(mhid_finish_destroy);

/* Don't call this function! Use free_fxid instead. */
void main_free_hid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_hid_main *mhid = fxid_mhid(fxid);
	struct hrdw_addr *pos_ha, *nxt;

	/* Free hardware addresses. */
	list_for_each_entry_safe(pos_ha, nxt, &mhid->xhm_haddrs, ha_list) {
		del_ha(pos_ha);
		free_ha(pos_ha);
	}

	mhid->xhm_dead = true;
	mhid_put(mhid);
}

/* Announce myself */

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
} __packed;

struct announcement_hdr {
	u8	version;
	u8	type;
	u8	hid_count;
	u8	haddr_len;

	u8	haddr_begin[0];
	u8	haddr[MAX_ADDR_LEN];
} __packed;

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
} __packed;

static inline int announcement_hdr_len(struct net_device *dev)
{
	return offsetof(struct announcement_hdr, haddr_begin) + dev->addr_len;
}

static int __announce_on_dev(struct fib_xid_table *xtbl,
			     struct fib_xid *fxid, const void *arg)
{
	const struct announcement_state *state;
	struct sk_buff *skb;
	struct net_device *dev;
	struct announcement_hdr *nwp;

	if (fxid->fx_table_id != XRTABLE_LOCAL_INDEX)
		return 0;

	state = arg;
	skb = state->skb;
	dev = state->hdev->dev;
	if (skb->len + XIA_XID_MAX > state->data_len) {
		/* XXX Enhance NWP to support multiple-frame announcements. */
		net_warn_ratelimited("XIA HID NWP: Can't announce all local HIDs on dev %s because its largest frame (MTU=%u) doesn't fit them\n",
				     dev->name, state->mtu);
		return 1;
	}

	nwp = (struct announcement_hdr *)skb_network_header(skb);
	if (nwp->hid_count == 0xff) {
		/* XXX Enhance NWP to support multiple-frame announcements. */
		net_warn_ratelimited("XIA HID NWP: Can't announce all local HIDs on dev %s because there are more than 255 local HIDs\n",
				     dev->name);
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

static void announce_on_dev(struct fib_xid_table *xtbl, struct hid_dev *hdev)
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
		pr_err("XIA HID NWP: Can't send an announcement because dev %s has MTU (%u) smaller than the smallest annoucement frame (%i)\n",
		       dev->name, mtu, min_annoucement);
		dump_stack();
		return;
	}

	skb = alloc_skb(mtu, GFP_ATOMIC);
	if (!skb)
		return; /* Can't announce this time. */
	skb_reserve(skb, ll_hlen);
	skb_reset_network_header(skb);
	nwp = (struct announcement_hdr *)skb_put(skb, hdr_len);
	skb->dev = dev;
	skb->protocol = __cpu_to_be16(ETH_P_NWP);

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
	/* XXX Implement a read only version of xia_iterate_xids. */
	hid_rt_iops->iterate_xids(xtbl, __announce_on_dev, &state);
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
	struct xip_hid_ctx *hid_ctx = (struct xip_hid_ctx *)data;
	struct fib_xid_table *xtbl;
	struct net_device *dev;
	int me, last_announced, next_to_announce, force;

	next_to_announce = atomic_read(&hid_ctx->to_announce);
	me = atomic_read(&hid_ctx->me);
	if (me <= 0)
		goto out;

	last_announced = atomic_read(&hid_ctx->announced);
	force = next_to_announce != last_announced;

	xtbl = hid_ctx->ctx.xpc_xtbl;
	for_each_netdev(hid_ctx->net, dev) {
		struct hid_dev *hdev;
		/* No NWP on this interface. */
		if (dev->flags & (IFF_LOOPBACK | IFF_NOARP))
			continue;

		hdev = hid_dev_get(dev);
		if (force || my_turn(me, hdev))
			announce_on_dev(xtbl, hdev);
		hid_dev_put(hdev);
	}

out:
	atomic_set(&hid_ctx->announced, next_to_announce);
	mod_timer(&hid_ctx->announce_timer, jiffies + 5*HZ);
}

/* State associated to net */

int hid_init_hid_state(struct xip_hid_ctx *hid_ctx)
{
	atomic_set(&hid_ctx->to_announce, 0);
	atomic_set(&hid_ctx->announced, 0);
	atomic_set(&hid_ctx->me, 0);

	init_timer(&hid_ctx->announce_timer);
	hid_ctx->announce_timer.function = announce_event;
	hid_ctx->announce_timer.data = (unsigned long)hid_ctx;
	/* XXX Having a random delay should help to avoid synchronization. */
	/* XXX Not starting timer if there's nothing to announce. */
	mod_timer(&hid_ctx->announce_timer, jiffies + 5*HZ);

	return 0;
}

void hid_release_hid_state(struct xip_hid_ctx *hid_ctx)
{
	del_timer_sync(&hid_ctx->announce_timer);
}

/* Receive NWP packets from the device layer */

static struct sk_buff *alloc_neigh_list_skb(struct net_device *dev,
					    unsigned int mtu,
					    u8 **pphid_counter)
{
	int ll_hlen = LL_RESERVED_SPACE(dev);
	int ll_tlen = dev->needed_tailroom;
	int ll_space = ll_hlen + ll_tlen;
	int hdr_len = offsetof(struct neighs_hdr, neighs_begin);
	int min_list = ll_space + hdr_len + XIA_XID_MAX + 1 + dev->addr_len;
	struct sk_buff *skb;
	struct neighs_hdr *nwp;

	if (mtu < min_list) {
		pr_err("XIA HID NWP: Can't send a neighbor list because dev %s has MTU (%u) smaller than the smallest neighbor list frame (%i)\n",
		       dev->name, mtu, min_list);
		dump_stack();
		return NULL;
	}

	skb = alloc_skb(mtu, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, ll_hlen);
	skb_reset_network_header(skb);
	nwp = (struct neighs_hdr *)skb_put(skb, hdr_len);
	skb->dev = dev;
	skb->protocol = __cpu_to_be16(ETH_P_NWP);

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
	struct net *net = dev_net(skb->dev);
	struct announcement_hdr *nwp;
	struct xip_hid_ctx *hid_ctx;
	int count;
	u8 *xid;

	nwp = (struct announcement_hdr *)skb_network_header(skb);
	hid_ctx = ctx_hid(xip_find_my_ppal_ctx_vxt(net, hid_vxt));
	count = nwp->hid_count;
	xid = skb->data;
	while (count > 0) {
		u8 *next_xid = skb_pull(skb, XIA_XID_MAX);

		if (!next_xid) {
			net_warn_ratelimited("XIA HID NWP: An announcement was received truncated. It should contain %i HID(s), but %i HID(s) are missing\n",
					     nwp->hid_count, count);
			break;
		}
		/* Ignore errors. */
		insert_neigh(hid_ctx, xid, skb->dev, nwp->haddr, NLM_F_CREATE);
		xid = next_xid;
		count--;
	}
}

static int process_announcement(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
	int hdr_len = announcement_hdr_len(dev);
	int min_annoucement = hdr_len + XIA_XID_MAX;
	struct announcement_hdr *nwp;
	struct xip_hid_ctx *hid_ctx;
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
	hid_ctx = ctx_hid(xip_find_my_ppal_ctx_vxt(net, hid_vxt));
	me = atomic_read(&hid_ctx->me);

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
	struct xip_hid_ctx *hid_ctx;
	int hid_count;

	if (!pskb_may_pull(skb, min_list))
		goto out;
	skb_reset_network_header(skb);
	nwp = (struct neighs_hdr *)skb_network_header(skb);
	xid = skb_pull(skb, hdr_len);

	hid_ctx = ctx_hid(xip_find_my_ppal_ctx_vxt(net, hid_vxt));
	hid_count = nwp->hid_count;
	while (hid_count > 0) {
		u8 *haddr_or_xid = skb_pull(skb, XIA_XID_MAX + 1);
		int original_ha_count, ha_count;

		if (!haddr_or_xid) {
			net_warn_ratelimited("XIA HID NWP: A neighbor list was received truncated. It should contain %i HID(s), but %i HID(s) are missing\n",
					     nwp->hid_count, hid_count);
			break;
		}
		original_ha_count = xid[XIA_XID_MAX];
		ha_count = original_ha_count;
		while (ha_count > 0) {
			u8 *next_haddr_or_xid = skb_pull(skb, dev->addr_len);

			if (!next_haddr_or_xid) {
				if (net_ratelimit()) {
					char str[XIA_MAX_STRXID_SIZE];

					str_of_xid(str, xid);
					pr_warn("XIA HID NWP: A neighbor list was received truncated. It should contain %i link layer addresses for %s, but %i are missing\n",
						original_ha_count, str,
						ha_count);
				}
				goto out_loop;
			}

			/* Ignore errors. */
			insert_neigh(hid_ctx, xid, dev, haddr_or_xid,
				     NLM_F_CREATE);

			haddr_or_xid = next_haddr_or_xid;
			ha_count--;
		}
		xid = haddr_or_xid;
		hid_count--;
	}
out_loop:
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
	    ghdr->type >= NWP_TYPE_MAX			||
	    ghdr->hid_count == 0			||
	    ghdr->haddr_len != dev->addr_len		||
	    dev->flags & (IFF_NOARP | IFF_LOOPBACK)	||
	    skb->pkt_type == PACKET_OTHERHOST		||
	    skb->pkt_type == PACKET_LOOPBACK)
		goto freeskb;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto out_of_mem;

	switch (ghdr->type) {
	case NWP_TYPE_ANNOUCEMENT:
		return process_announcement(skb);
	case NWP_TYPE_NEIGH_LIST:
		return process_neigh_list(skb);
	default:
		goto freeskb;
	}

freeskb:
	kfree_skb(skb);
out_of_mem:
	return 0;
}

static struct packet_type nwp_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_NWP),
	.func = nwp_rcv,
};

/* Network Devices */

void hid_dev_finish_destroy(struct hid_dev *hdev)
{
	struct net_device *dev = hdev->dev;

#ifdef NET_REFCNT_DEBUG
	pr_debug("%s: %p=%s\n", __func__, hdev, dev->name);
#endif
	if (!hdev->dead) {
		pr_err("%s: freeing alive hid_dev %p=%s\n",
		       __func__, hdev, dev->name);
		dump_stack();
	}

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
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
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

/* Initialize NWP */

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
	dev_remove_pack(&nwp_packet_type);
	unregister_netdevice_notifier(&hid_netdev_notifier);
}

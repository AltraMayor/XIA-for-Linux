#include <linux/export.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <linux/cache.h>
#include <net/ip_vs.h>
#include <net/xia_dag.h>
#include <net/xia_hid.h>

/*
 *	Neighbor Status
 */

#define ALIVE			0x80000000
#define FAILED			0x00000000

#define STATUS_MASK		0x80000000
#define CLOCK_MASK		0x7FFFFFFF

#define LOCAL_CLOCK_MAX		0xFFFFFFFF
#define REMOTE_CLOCK_MAX	0x7FFFFFFF

#define STAT_LEN		(sizeof(((struct hrdw_addr *)0)->remote_sc))

/* Returns:
 * -1 if @c1 < @c2
 *  0 if @c1 = @c2
 *  1 if @c1 > @c2
 */
static int clockcmp32(u32 c1, u32 c2)
{
	if (c1 == c2)
		return 0;

	/* Check for clock overflow. */
	return ((s32)(c2) - (s32)(c1) > 0) ? -1 : 1;
}

static inline int clockcmp31(u32 c1, u32 c2)
{
	/* The overflow check at the bottom of @clockcmp32 depends on the most
	 * significant (31st) bit representing signedness. Since NWP remote
	 * clocks only use bits 0-30, we need to shift all bits to the left.
	 */
	return clockcmp32(c1 << 1, c2 << 1);
}

static void find_update_neigh_sc(struct net_device *dev, const u8 *lladdr,
	u32 status_clock)
{
	struct hid_dev *hdev;
	struct hrdw_addr *ha;
	struct timeval t;

	hdev = hid_dev_get(dev);
	spin_lock(&hdev->neigh_lock);
	list_for_each_entry(ha, &hdev->neighs, hdev_list) {

		if (memcmp(ha->ha, lladdr, dev->addr_len) != 0)
			continue;

		if (clockcmp31(CLOCK_MASK & status_clock,
				CLOCK_MASK & ha->remote_sc) < 0)
			break;

		do_gettimeofday(&t);
		if ((STATUS_MASK & status_clock) == FAILED) {
			/* If a neigh has failed, we can not know the remote
			 * time of the failed neighbor, and thus @status_clock
			 * does not hold a valid clock. In the false case of
			 * the ternary operator, overflow has occurred. If this
			 * happens, we need to add one. Consider the case where
			 * @new_c = 0 and @ha->local_c = LOCAL_CLOCK_MAX. Then,
			 * it is clear we need to account for the step between
			 * LOCAL_CLOCK_MAX and 0.
			 */
			u32 loc_c = (u32)t.tv_sec;
			ha->remote_sc += loc_c >= ha->local_c
				? loc_c - ha->local_c
				: loc_c + (LOCAL_CLOCK_MAX - ha->local_c) + 1;
			ha->remote_sc = FAILED | (CLOCK_MASK & ha->remote_sc);
			ha->local_c = loc_c;
		} else {
			ha->remote_sc = status_clock;
			ha->local_c = (u32)t.tv_sec;
		}
		break;
	}
	spin_unlock(&hdev->neigh_lock);
	hid_dev_put(hdev);
}

/*
 *	Neighbor Table
 */

static struct hrdw_addr *new_ha(struct net_device *dev, const u8 *lladdr,
	u32 status_clock, bool perm, gfp_t flags)
{
	struct hrdw_addr *ha = kzalloc(sizeof(*ha), flags);
	struct timeval t;
	if (!ha)
		return NULL;
	INIT_LIST_HEAD(&ha->ha_list);
	INIT_LIST_HEAD(&ha->hdev_list);
	ha->dev = dev;
	dev_hold(dev);
	xdst_init_anchor(&ha->anchor);
	memmove(ha->ha, lladdr, dev->addr_len);

	do_gettimeofday(&t);
	ha->local_c = (u32)t.tv_sec;
	ha->remote_sc = status_clock;
	ha->permanent = perm;
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

/* @h1 is a duplicate neighbor; @h2 is already in the neighbor list. */
static void update_ha_sc(struct hrdw_addr *h1, struct hrdw_addr *h2)
{
	u32 h1_clock = CLOCK_MASK & h1->remote_sc;
	u32 h2_clock = CLOCK_MASK & h2->remote_sc;

	switch (clockcmp31(h2_clock, h1_clock)) {
	case (1):
		break;
	case (0):
		/* If clocks are the same but statuses are different, assume
		 * status that has neigh as alive is correct.
		 */
		if ((STATUS_MASK & h1->remote_sc) !=
			(STATUS_MASK & h2->remote_sc))
			h2->remote_sc = ALIVE | h2_clock;
		break;
	case (-1):
		/* Here we are estimating the local time at which this update
		 * took place. The relative time difference between @local_c
		 * and @remote_sc should remain the same.
		 *
		 * At this point we know that @h1_clock is logically greater
		 * than @h2_clock, but it will not be numerically greater if
		 * overflow has occurred. Therefore, the else case handles
		 * overflow of @h1_clock. We need to add 1 to account for
		 * overflow; consider the case where @h2_clock =
		 * REMOTE_CLOCK_MAX and @h1_clock = 0. There is still a step
		 * between REMOTE_CLOCK_MAX and 0, so we need to account for
		 * that step.
		 */
		h2->local_c += (h1_clock >= h2_clock)
				? h1_clock - h2_clock
				: h1_clock + (REMOTE_CLOCK_MAX - h2_clock) + 1;
		h2->remote_sc = h1->remote_sc;
		break;
	default:
		BUG();
	}
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
		if (!c1 && c2) {
			update_ha_sc(ha, pos_ha);
			return -EEXIST; /* It's a duplicate. */
		}

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
	struct net_device *dev = hdev->dev;
	struct net *net = dev_net(dev);
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *main_xtbl;

	ASSERT_RTNL();

	ctx = xip_find_my_ppal_ctx(&net->xia.fib_ctx, XIDTYPE_HID);
	main_xtbl = ctx->xpc_xid_tables[XRTABLE_MAIN_INDEX];

	while (1) {
		struct hrdw_addr *ha;
		u8 xid[XIA_XID_MAX];
		struct fib_xid_hid_main *mhid;
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
		mhid = fxid_mhid(xia_find_xid_lock(&bucket, main_xtbl, xid));
		if (mhid) {
			/* We must test mhid != NULL because
			 * we didn't hold a lock before the find.
			 */
			del_has_by_dev(&mhid->xhm_haddrs, dev);
			if (list_empty(&mhid->xhm_haddrs)) {
				fib_rm_fxid_locked(bucket, main_xtbl,
					&mhid->xhm_common);
				free_fxid(main_xtbl, &mhid->xhm_common);
			}
		}
		fib_unlock_bucket(main_xtbl, bucket);
	}
}

void hid_deferred_negdep(struct net *net, struct xia_xid *xid)
{
	struct xip_hid_ctx *hid_ctx;

	rcu_read_lock();
	hid_ctx = ctx_hid(
		xip_find_ppal_ctx_rcu(&net->xia.fib_ctx, xid->xid_type));
	if (likely(hid_ctx)) {
		/* Flush all @negdep due to XID redirects. */
		xdst_free_anchor(&hid_ctx->negdep);
	}
	rcu_read_unlock();
}

int insert_neigh(struct xip_hid_ctx *hid_ctx, const char *id,
	struct net_device *dev, const u8 *lladdr, u32 status_clock, bool perm)
{
	struct fib_xid_table *local_xtbl, *main_xtbl;
	struct fib_xid_hid_main *mhid;
	struct hrdw_addr *ha;
	u32 local_bucket, main_bucket;
	struct deferred_xip_update *def_upd;
	int rc;

	if (!(dev->flags & IFF_UP) || (dev->flags & IFF_LOOPBACK))
		return -EINVAL;

	/*
	 * The sequence of locks in this function must be careful to avoid
	 * deadlock with main.c:local_newroute.
	 */

	/* Test if @id is already inserted in the local xtbl. */
	local_xtbl = hid_ctx->ctx.xpc_xid_tables[XRTABLE_LOCAL_INDEX];
	/* Notice that having xia_find_xid_lock on @local_xtbl requires
	 * @local_xtbl to support multiple writers.
	 */
	if (xia_find_xid_lock(&local_bucket, local_xtbl, id)) {
		/* We don't issue a warning about trying inserting an entry
		 * already in @local_xtbl into @main_xtbl because if this host
		 * has two interfaces connected to the same medium, it would
		 * lead to a false problem.
		 */
		rc = -EINVAL;
		goto local_xtbl;
	}

	ha = new_ha(dev, lladdr, status_clock, perm, GFP_ATOMIC);
	if (!ha) {
		rc = -ENOMEM;
		goto local_xtbl;
	}

	main_xtbl = hid_ctx->ctx.xpc_xid_tables[XRTABLE_MAIN_INDEX];
	mhid = fxid_mhid(xia_find_xid_lock(&main_bucket, main_xtbl, id));
	if (mhid) {
		rc = add_ha(mhid, ha);
		fib_unlock_bucket(main_xtbl, main_bucket);
		if (rc)
			goto ha;
		goto local_xtbl;
	}

	def_upd = fib_alloc_xip_upd(GFP_ATOMIC);
	if (!def_upd) {
		rc = -ENOMEM;
		goto main_xtbl;
	}

	/* Add new @mhid. */
	mhid = kzalloc(sizeof(*mhid), GFP_ATOMIC);
	if (!mhid) {
		rc = -ENOMEM;
		goto def_upd;
	}
	init_fxid(&mhid->xhm_common, id);
	INIT_LIST_HEAD(&mhid->xhm_haddrs);
	atomic_set(&mhid->xhm_refcnt, 1);
	rc = add_ha(mhid, ha);
	BUG_ON(rc);

	rc = fib_add_fxid_locked(main_bucket, main_xtbl, &mhid->xhm_common);
	if (rc) {
		free_fxid(main_xtbl, &mhid->xhm_common);
		fib_free_xip_upd(def_upd);
		fib_unlock_bucket(main_xtbl, main_bucket);
		goto local_xtbl;
	}
	fib_unlock_bucket(main_xtbl, main_bucket);
	fib_unlock_bucket(local_xtbl, local_bucket);

	/* Before invalidating old anchors to force dependencies to
	 * migrate to @mhid, wait an RCU synchronization to make sure that
	 * every thread see @mhid.
	 */
	fib_defer_xip_upd(def_upd, hid_deferred_negdep, hid_ctx->net,
		XIDTYPE_HID, id);
	return 0;

def_upd:
	fib_free_xip_upd(def_upd);
main_xtbl:
	fib_unlock_bucket(main_xtbl, main_bucket);
ha:
	free_ha_norcu(ha);
local_xtbl:
	fib_unlock_bucket(local_xtbl, local_bucket);
	return rc;
}

int remove_neigh(struct fib_xid_table *xtbl, const char *id,
	struct net_device *dev, const u8 *lladdr)
{
	u32 bucket;
	struct fib_xid_hid_main *mhid;
	int rc;

	mhid = fxid_mhid(xia_find_xid_lock(&bucket, xtbl, id));
	if (!mhid) {
		fib_unlock_bucket(xtbl, bucket);
		return -ENOENT;
	}

	rc = del_ha_from_mhid(mhid, lladdr, dev);
	if (rc) {
		fib_unlock_bucket(xtbl, bucket);
		return rc;
	}

	if (list_empty(&mhid->xhm_haddrs)) {
		fib_rm_fxid_locked(bucket, xtbl, &mhid->xhm_common);
		free_fxid(xtbl, &mhid->xhm_common);
	}

	fib_unlock_bucket(xtbl, bucket);
	return 0;
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

#define NWP_TYPE_ANNOUNCEMENT	0x01
#define NWP_TYPE_NEIGH_LIST	0x02
#define NWP_TYPE_PING		0x03
#define NWP_TYPE_ACK		0x04
#define NWP_TYPE_REQ_PING	0x05
#define NWP_TYPE_REQ_ACK	0x06
#define NWP_TYPE_INV_PING	0x07
#define NWP_TYPE_MAX		0x08

/* If a failed node has been failed for more than NWP_LIST_TIME_MAX,
 * it should not be put in neighbor lists to prevent neighboring nodes from
 * cyclically adding and deleting failed nodes.
 */
#define NWP_LIST_TIME_MAX	(10*HZ)

struct general_hdr {
	u8	version;
	u8	type;
} __packed;

struct announcement_hdr {
	u8	version;
	u8	type;
	u8	hid_count;
	u8	haddr_len;

	__be32	clock; /* Lower 32 bits of announcer's wall time (seconds). */

	u8	haddr_begin[0];
	u8	haddr[MAX_ADDR_LEN];
} __packed;

struct neighs_hdr {
	u8	version;
	u8	type;
	u8	hid_count;
	u8	haddr_len;

	u8	neighs_begin[0];
/*	XID_1 NUM_1 (HA_11 S_11) (HA_12 S_12) ... (HA_1NUM_1 S_1NUM_1)
 *	XID_2 NUM_2 (HA_21 S_21) (HA_22 S_22) ... (HA_2NUM_2 S_2NUM_2)
 *	...
 *	XID_C NUM_C (HA_C1 S_C1) (HA_C2 S_C2) ... (HA_CNUM_C S_CNUM_C)
 *
 *	C == hid_count.
 *	S == bits 0-31: wall time (seconds); bit 31: 0 for failed, 1 for alive.
 */
} __packed;

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
		if (net_ratelimit())
			pr_warn("XIA HID NWP: Can't announce all local HIDs on dev %s because its largest frame (MTU=%u) doesn't fit them\n",
				dev->name, state->mtu);
		return 1;
	}

	nwp = (struct announcement_hdr *)skb_network_header(skb);
	if (nwp->hid_count == 0xff) {
		/* XXX Enhance NWP to support multiple-frame announcements. */
		if (net_ratelimit())
			pr_warn("XIA HID NWP: Can't announce all local HIDs on dev %s because there are more than 255 local HIDs\n",
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

static void announce_on_dev(struct fib_xid_table *local_xtbl,
	struct hid_dev *hdev)
{
	struct net_device *dev = hdev->dev;
	unsigned int mtu = dev->mtu;
	int hdr_len = announcement_hdr_len(dev);
	int ll_hlen = LL_RESERVED_SPACE(dev);
	int ll_tlen = dev->needed_tailroom;
	int ll_space = ll_hlen + ll_tlen;
	int min_announcement = ll_space + hdr_len + XIA_XID_MAX;
	struct sk_buff *skb;
	struct announcement_hdr *nwp;
	struct announcement_state state;
	struct timeval t;

	if (mtu < min_announcement) {
		pr_err("XIA HID NWP: Can't send an announcement because dev %s has MTU (%u) smaller than the smallest announcement frame (%i)\n",
			dev->name, mtu, min_announcement);
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
	nwp->type	= NWP_TYPE_ANNOUNCEMENT;
	nwp->hid_count	= 0;
	nwp->haddr_len	= dev->addr_len;
	do_gettimeofday(&t);
	nwp->clock	= __cpu_to_be32((u32)t.tv_sec);
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
	struct xip_hid_ctx *hid_ctx = (struct xip_hid_ctx *)data;
	struct fib_xid_table *local_xtbl =
		hid_ctx->ctx.xpc_xid_tables[XRTABLE_LOCAL_INDEX];
	struct net_device *dev;
	int me, last_announced, next_to_announce, force;

	next_to_announce = atomic_read(&hid_ctx->to_announce);
	me = xia_get_fxid_count(local_xtbl);
	if (me <= 0)
		goto out;

	last_announced = atomic_read(&hid_ctx->announced);
	force = next_to_announce != last_announced;

	for_each_netdev(hid_ctx->net, dev) {
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
	atomic_set(&hid_ctx->announced, next_to_announce);
	mod_timer(&hid_ctx->announce_timer, jiffies + 5*HZ);
}

/*
 *	NWP Monitoring
 */

/* Maximum number of investigators asked to try to reach a failed node. */
#define NWP_NUM_INVESTIGATORS	3

#define NWP_INTERVAL	(8*HZ) /* Period of one monitoring interval. */
#define NWP_PING_TIME	(4*HZ) /* Worst case RTT for a monitoring ping. */
#define NWP_INV_TIME	(NWP_INTERVAL - NWP_PING_TIME) /* Investigating time. */

#define NWP_FAILED_TTL	(10*HZ) /* Minimum lifetime of neigh after failure. */
#define NWP_CLEAN_TIME	(20*HZ) /* Period between cleaning of neigh list. */

static void end_interval_failure(unsigned long);

struct monitoring_hdr {
	u8	version;
	u8	type;
	u8	reserved;
	u8	haddr_len;

	u32	clock;
	u8	haddrs_begin[0];
} __packed;

static inline int monitoring_hdr_len(struct net_device *dev, u8 type)
{
	return offsetof(struct monitoring_hdr, haddrs_begin) +
		(type == NWP_TYPE_PING || type == NWP_TYPE_ACK)
			? 2 * dev->addr_len
			: 3 * dev->addr_len;
}

static void send_monitoring(struct net_device *dev, const u8 *src,
	const u8 *dst, const u8 *inv, u8 type)
{
	unsigned int mtu = dev->mtu;
	int hdr_len = offsetof(struct monitoring_hdr, haddrs_begin);
	int ll_hlen = LL_RESERVED_SPACE(dev);
	int ll_tlen = dev->needed_tailroom;
	int ll_space = ll_hlen + ll_tlen;
	int min_monitoring = ll_space + hdr_len + 2 * dev->addr_len;
	struct sk_buff *skb;
	struct monitoring_hdr *nwp;
	struct timeval t;

	if (unlikely(mtu < min_monitoring)) {
		pr_err("XIA HID NWP: Can't send a monitoring packet because dev %s has MTU (%u) smaller than the smallest monitoring frame (%i)\n",
			dev->name, mtu, min_monitoring);
		dump_stack();
		return;
	}

	skb = alloc_skb(mtu, GFP_ATOMIC);
	if (unlikely(!skb))
		return;
	skb_reserve(skb, ll_hlen);
	skb_reset_network_header(skb);
	nwp = (struct monitoring_hdr *)skb_put(skb, hdr_len);
	skb->dev = dev;
	skb->protocol = __cpu_to_be16(ETH_P_NWP);

	nwp->version	= NWP_VERSION;
	nwp->type	= type;
	nwp->reserved	= 0;
	nwp->haddr_len	= dev->addr_len;
	do_gettimeofday(&t);
	nwp->clock	= __cpu_to_be32((u32)t.tv_sec);
	memcpy(skb_put(skb, dev->addr_len), src, dev->addr_len);
	memcpy(skb_put(skb, dev->addr_len), dst, dev->addr_len);
	if (inv) {
		BUG_ON(type == NWP_TYPE_PING || type == NWP_TYPE_ACK);
		memcpy(skb_put(skb, dev->addr_len), inv, dev->addr_len);
	}

	switch (type) {
	case NWP_TYPE_PING:
		send_nwp_frame(skb, src, dst);
		break;
	case NWP_TYPE_ACK:
		send_nwp_frame(skb, dst, src);
		break;
	case NWP_TYPE_REQ_PING:
		send_nwp_frame(skb, src, inv);
		break;
	case NWP_TYPE_REQ_ACK:
		send_nwp_frame(skb, inv, src);
		break;
	case NWP_TYPE_INV_PING:
		send_nwp_frame(skb, inv, dst);
		break;
	}
}

static void end_ping_failure(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	struct hid_dev *hdev = hid_dev_get(dev);
	struct hrdw_addr *ha;
	u8 *lladdr = dev->dev_addr;
	u32 start, end, i, num_neighs, num_invs;
	bool need_to_loop;

	num_neighs = atomic_read(&hdev->neigh_cnt);
	if (num_neighs == 1) {
		/* Not enough neighbors to investigate; ping target again with
		 * remaining time in this monitoring interval.
		 */
		hdev->remonitored = true;
		send_monitoring(dev, lladdr, hdev->target, NULL, NWP_TYPE_PING);
		goto out;
	}

	num_invs = NWP_NUM_INVESTIGATORS > num_neighs - 1
			? num_neighs - 1
			: NWP_NUM_INVESTIGATORS;

	/* Here we need a random subset of neighbors. However,
	 * the selection of these neighbors need not be mutually
	 * independent; instead, we can simulate randomness by
	 * choosing a random position to start from in the neighbor
	 * list, and send investigative pings to those @num_invs
	 * neighbors. One of the chosen investigators may be the
	 * target in question.
	 */
	get_random_bytes(&start, sizeof(start));
	start %= num_neighs;
	end = start + num_invs;

	/* If we randomly choose a position near the end of the neighbor list,
	 * we may have to loop around to the beginning of the list to select
	 * @num_invs investigators. This code should re-loop at most once.
	 */
	do {
		need_to_loop = end > num_neighs;
		i = 0;

		rcu_read_lock();
		list_for_each_entry_rcu(ha, &hdev->neighs, hdev_list) {
			if (i >= start)
				send_monitoring(dev, lladdr, hdev->target,
						ha->ha, NWP_TYPE_REQ_PING);
			if (++i >= end)
				break;
		}
		rcu_read_unlock();

		if (need_to_loop) {
			BUG_ON(start == 0);
			start = 0;
			end %= num_neighs;
		}
	} while (need_to_loop);

out:
	hdev->monitor_timer.function = end_interval_failure;
	hdev->investigating = true;
	mod_timer(&hdev->monitor_timer, jiffies + NWP_INV_TIME);
	hid_dev_put(hdev);
}

static bool pick_random_neigh(struct hid_dev *hdev)
{
	struct net_device *dev = hdev->dev;
	struct hrdw_addr *ha;
	u32 target_num, num_neighs, i = 0;
	bool some_neigh_alive = false;

	get_random_bytes(&target_num, sizeof(target_num));
	num_neighs = atomic_read(&hdev->neigh_cnt);
	if (!num_neighs) {
		hdev->monitoring = false;
		return false;
	}
	target_num %= num_neighs;

	rcu_read_lock();
	list_for_each_entry_rcu(ha, &hdev->neighs, hdev_list) {
		if ((STATUS_MASK & ha->remote_sc) == ALIVE)
			some_neigh_alive = true;
		if (i++ == target_num && !ha->permanent &&
			((STATUS_MASK & ha->remote_sc) == ALIVE)) {
			memcpy(hdev->target, ha->ha, dev->addr_len);
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();

	if (!some_neigh_alive)
		hdev->monitoring = false;
	return false;
}

static void monitor(struct net_device *dev, bool need_new_target)
{
	struct hid_dev *hdev = hid_dev_get(dev);
	if (need_new_target)
		do {
			if (pick_random_neigh(hdev))
				break;
			if (!hdev->monitoring)
				goto out;
		} while (hdev->monitoring);

	hdev->monitor_timer.function = end_ping_failure;
	send_monitoring(dev, dev->dev_addr, hdev->target, NULL, NWP_TYPE_PING);
	mod_timer(&hdev->monitor_timer, jiffies + NWP_PING_TIME);

out:
	hid_dev_put(hdev);
}

static void end_interval_failure(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	struct hid_dev *hdev = hid_dev_get(dev);
	bool need_new_target = true;

	/* No investigative neighbors replied; possible network partition. */
	if (!hdev->any_neighs_replied && !hdev->remonitored) {
		hdev->remonitored = true;
		need_new_target = false;
		goto out;
	}

	/* @find_update_neigh_sc will estimate correct remote clock. */
	find_update_neigh_sc(dev, hdev->target, FAILED);
	hdev->any_neighs_replied = false;
	hdev->remonitored = false;

out:
	hdev->investigating = false;
	hid_dev_put(hdev);
	monitor(dev, need_new_target);
}

static void end_interval_success(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	struct hid_dev *hdev = hid_dev_get(dev);
	hdev->any_neighs_replied = false;
	hdev->remonitored = false;
	hid_dev_put(hdev);
	monitor(dev, true);
}

static int process_monitoring(struct sk_buff *skb, u8 type)
{
	struct net_device *dev = skb->dev;
	struct hid_dev *hdev = hid_dev_get(dev);
	struct monitoring_hdr *nwp;
	u8 *src, *dst, *inv, *sender;
	int hdr_len = monitoring_hdr_len(dev, type);

	if (!hdev->monitoring)
		goto out;
	if (!pskb_may_pull(skb, hdr_len))
		goto out;
	skb_reset_network_header(skb);
	nwp = (struct monitoring_hdr *)skb_network_header(skb);
	if (nwp->haddr_len != dev->addr_len)
		goto out;

	nwp->clock = __be32_to_cpu(nwp->clock);
	src = skb_pull(skb, offsetof(struct monitoring_hdr, haddrs_begin));
	dst = skb_pull(skb, nwp->haddr_len);

	switch (type) {
	case NWP_TYPE_PING:
	case NWP_TYPE_INV_PING:
		send_monitoring(dev, src, dst, NULL, NWP_TYPE_ACK);
		sender = NWP_TYPE_PING ? src : skb_pull(skb, nwp->haddr_len);
		break;
	case NWP_TYPE_ACK:
		if (memcmp(dst, hdev->target, nwp->haddr_len) == 0)
			hdev->monitor_timer.function = end_interval_success;
		sender = dst;
		break;
	case NWP_TYPE_REQ_PING:
		inv = skb_pull(skb, nwp->haddr_len);
		send_monitoring(dev, src, dst, inv, NWP_TYPE_REQ_ACK);
		send_monitoring(dev, src, dst, inv, NWP_TYPE_INV_PING);
		sender = src;
		break;
	case NWP_TYPE_REQ_ACK:
		if (hdev->investigating)
			hdev->any_neighs_replied = true;
		sender = skb_pull(skb, nwp->haddr_len);
		break;
	default:
		goto out;
	}

	find_update_neigh_sc(dev, sender, ALIVE | (CLOCK_MASK & nwp->clock));

out:
	hid_dev_put(hdev);
	consume_skb(skb);
	return 0;
}

static void clean_neigh_list(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	struct net *net = dev_net(dev);
	struct hrdw_addr *ha;
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *main_xtbl;
	struct hid_dev *hdev = hid_dev_get(dev);
	struct timeval t;
	int curr_time;

	ctx = xip_find_my_ppal_ctx(&net->xia.fib_ctx, XIDTYPE_HID);
	main_xtbl = ctx->xpc_xid_tables[XRTABLE_MAIN_INDEX];
	do_gettimeofday(&t);
	curr_time = (u32)t.tv_sec;

	/* Remove failed and expired neighs if they are not permanent. */
	list_for_each_entry_rcu(ha, &hdev->neighs, hdev_list)
		if (((STATUS_MASK & ha->remote_sc) == FAILED) &&
			clockcmp32(curr_time, ha->local_c + NWP_FAILED_TTL) &&
			!ha->permanent) {
			char *xid = ha->mhid->xhm_common.fx_xid;
			remove_neigh(main_xtbl, xid, dev, ha->ha);
		}

	mod_timer(&hdev->clean_timer, jiffies + NWP_CLEAN_TIME);
	hid_dev_put(hdev);
}

/*
 *	State associated to net
 */

int hid_init_hid_state(struct xip_hid_ctx *hid_ctx)
{
	atomic_set(&hid_ctx->to_announce, 0);
	atomic_set(&hid_ctx->announced, 0);

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
	int entry_len = XIA_XID_MAX + 1 + dev->addr_len + STAT_LEN;
	int min_list = ll_space + hdr_len + entry_len;
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
	struct timeval t;
	do_gettimeofday(&t);

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
	min_entry = XIA_XID_MAX + 1 + addr_len + STAT_LEN;
	data_len = mtu - LL_RESERVED_SPACE(dev) - dev->needed_tailroom;

	rcu_read_lock();
	list_for_each_entry_rcu(ha, &hdev->neighs, hdev_list) {
		int is_new_hid, need_new_skb;
		struct fib_xid_hid_main *mhid = ha->mhid;
		__be32 be_status_clock = __cpu_to_be32(ha->remote_sc);
		BUG_ON(ha->dev != dev);

		/* If neighbor has failed and expired or if neighbor was
		 * manually-entered (@ha->permanent is true), then do not list.
		 */
		if (ha->permanent || ((clockcmp32((u32)t.tv_sec,
			ha->local_c + NWP_LIST_TIME_MAX) > 0) && 
			((STATUS_MASK & ha->remote_sc) == FAILED)))
			continue;

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
		/* Add status of hardware address. */
		memcpy(skb_put(skb, STAT_LEN), &be_status_clock, STAT_LEN);
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
	struct xip_hid_ctx *hid_ctx;
	int count;
	u8 *xid;

	nwp = (struct announcement_hdr *)skb_network_header(skb);
	hid_ctx = ctx_hid(xip_find_my_ppal_ctx(&net->xia.fib_ctx, XIDTYPE_HID));
	count = nwp->hid_count;
	xid = skb->data;
	while (count > 0) {
		u8 *next_xid = skb_pull(skb, XIA_XID_MAX);
		if (!next_xid) {
			if (net_ratelimit())
				pr_warn("XIA HID NWP: An announcement was received truncated. It should contain %i HID(s), but %i HID(s) are missing\n",
					nwp->hid_count, count);
			break;
		}
		/* Ignore errors. */
		insert_neigh(hid_ctx, xid, skb->dev, nwp->haddr,
			ALIVE | (CLOCK_MASK & __be32_to_cpu(nwp->clock)),
			false);
		xid = next_xid;
		count--;
	}
}

static int process_announcement(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
	int hdr_len = announcement_hdr_len(dev);
	int min_announcement = hdr_len + XIA_XID_MAX;
	struct announcement_hdr *nwp;
	struct xip_ppal_ctx *ctx;
	struct hid_dev *hdev;
	int me;

	if (!pskb_may_pull(skb, min_announcement))
		goto out;
	skb_reset_network_header(skb);
	nwp = (struct announcement_hdr *)skb_network_header(skb);
	if (nwp->hid_count == 0 || nwp->haddr_len != dev->addr_len)
		goto out;
	skb_pull(skb, hdr_len);
	read_announcement(skb);

	/* Reply my list of neighbors. Notice that it'll include the sender
	 * that triggered this event.
	 */

	/* Obtain @me. */
	ctx = xip_find_my_ppal_ctx(&net->xia.fib_ctx, XIDTYPE_HID);
	me = xia_get_fxid_count(ctx->xpc_xid_tables[XRTABLE_LOCAL_INDEX]);

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
	struct hid_dev *hdev = hid_dev_get(dev);
	struct net *net = dev_net(dev);
	int hdr_len = offsetof(struct neighs_hdr, neighs_begin);
	int min_list = hdr_len + XIA_XID_MAX + 1 + dev->addr_len + STAT_LEN;
	struct neighs_hdr *nwp;
	u8 *xid;
	struct xip_hid_ctx *hid_ctx;
	int hid_count;

	if (!pskb_may_pull(skb, min_list))
		goto out;
	skb_reset_network_header(skb);
	nwp = (struct neighs_hdr *)skb_network_header(skb);
	if (nwp->hid_count == 0 || nwp->haddr_len != dev->addr_len)
		goto out;
	xid = skb_pull(skb, hdr_len);

	hid_ctx = ctx_hid(xip_find_my_ppal_ctx(&net->xia.fib_ctx, XIDTYPE_HID));
	hid_count = nwp->hid_count;
	while (hid_count > 0) {
		u8 *haddr_or_xid = skb_pull(skb, XIA_XID_MAX + 1);
		int original_ha_count, ha_count;
		if (!haddr_or_xid) {
			if (net_ratelimit())
				pr_warn("XIA HID NWP: A neighbor list was received truncated. It should contain %i HID(s), but %i HID(s) are missing\n",
					nwp->hid_count, hid_count);
			break;
		}
		original_ha_count = xid[XIA_XID_MAX];
		ha_count = original_ha_count;
		while (ha_count > 0) {
			u32 status_clock =
				__be32_to_cpu(*((__be32 *)skb_pull(skb,
					dev->addr_len)));
			u8 *next_haddr_or_xid = skb_pull(skb, STAT_LEN);

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

			insert_neigh(hid_ctx, xid, dev, haddr_or_xid,
				status_clock, false);

			haddr_or_xid = next_haddr_or_xid;
			ha_count--;
		}
		xid = haddr_or_xid;
		hid_count--;
	}

	if (!hdev->monitoring) {
		if (!timer_pending(&hdev->clean_timer))
			mod_timer(&hdev->clean_timer, jiffies + NWP_CLEAN_TIME);
		hdev->monitoring = true;
		monitor(dev, true);
	}

out_loop:
out:
	hid_dev_put(hdev);
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
		dev->flags & (IFF_NOARP | IFF_LOOPBACK)	||
		skb->pkt_type == PACKET_OTHERHOST	||
		skb->pkt_type == PACKET_LOOPBACK)
		goto freeskb;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto out_of_mem;

	switch (ghdr->type) {
	case NWP_TYPE_ANNOUNCEMENT:
		return process_announcement(skb);
	case NWP_TYPE_NEIGH_LIST:
		return process_neigh_list(skb);
	case NWP_TYPE_PING:
	case NWP_TYPE_ACK:
	case NWP_TYPE_REQ_PING:
	case NWP_TYPE_REQ_ACK:
	case NWP_TYPE_INV_PING:
		return process_monitoring(skb, ghdr->type);
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

/*
 *	Network Devices
 */

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

	del_timer_sync(&hdev->clean_timer);
	del_timer_sync(&hdev->monitor_timer);

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

	init_timer(&hdev->monitor_timer);
	hdev->monitor_timer.data = (unsigned long)dev;

	init_timer(&hdev->clean_timer);
	hdev->clean_timer.data = (unsigned long)dev;
	hdev->clean_timer.function = clean_neigh_list;

	hdev->monitoring = false;
	hdev->any_neighs_replied = false;
	hdev->remonitored = false;
	hdev->investigating = false;

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
	dev_remove_pack(&nwp_packet_type);
	unregister_netdevice_notifier(&hid_netdev_notifier);
}

#include <linux/export.h>
#include <net/ip_vs.h> /* Needed for skb_net. */
#include <net/xia_fib.h>
#include <net/xia_dag.h>
#include <net/xia_output.h> /* Needed for __xip_local_out. */
#include <net/xia_route.h>

/*
 *	Route cache (DST)
 */

static int xip_dst_gc(struct dst_ops *ops);

static struct dst_entry *xip_dst_check(struct dst_entry *dst, u32 cookie)
{
	return NULL;
}

static unsigned int xip_default_advmss(const struct dst_entry *dst)
{
	unsigned int mss = dst_mtu(dst) - MAX_XIP_HEADER;

	BUILD_BUG_ON(XIA_MIN_MSS > XIA_MAX_MSS);
	if (mss < XIA_MIN_MSS)
		return XIA_MIN_MSS;
	if (mss > XIA_MAX_MSS)
		return XIA_MAX_MSS;

	return mss;
}

static unsigned int xip_mtu(const struct dst_entry *dst)
{
	unsigned int mtu = dst_metric_raw(dst, RTAX_MTU);
	if (mtu)
		return mtu;
	return XIP_MIN_MTU;
}

static void xip_dst_destroy(struct dst_entry *dst)
{
	dst_destroy_metrics_generic(dst);
}

static struct dst_entry *xip_negative_advice(struct dst_entry *dst);

/* XXX An ICMP-like error should be genererated here. */
static void xip_link_failure(struct sk_buff *skb)
{
	if (net_ratelimit())
		pr_warn("%s: unreachable destination\n", __func__);
}

static void xip_update_pmtu(struct dst_entry *dst, struct sock *sk,
	struct sk_buff *skb, u32 mtu)
{
	if (mtu < dst_mtu(dst)) {
		mtu = mtu < XIP_MIN_MTU ? XIP_MIN_MTU : mtu;
		dst_metric_set(dst, RTAX_MTU, mtu);
	}
}

static struct neighbour *xip_neigh_lookup(const struct dst_entry *dst,
	struct sk_buff *skb, const void *daddr)
{
	return ERR_PTR(-EINVAL);
}

struct dst_ops xip_dst_ops_template __read_mostly = {
	.family =		AF_XIA,
	.protocol =		cpu_to_be16(ETH_P_XIP),
	/* XXX This value should be reconsidered once struct xip_dst_table
	 * is redesigned. Using the same value of
	 * net/ipv6/route.c:ip6_dst_ops_template.gc_thresh for now.
	 */
	.gc_thresh =		1024,
	.gc =			xip_dst_gc,
	.check =		xip_dst_check,
	.default_advmss =	xip_default_advmss,
	.mtu =			xip_mtu,
	.cow_metrics =		dst_cow_metrics_generic,
	.destroy =		xip_dst_destroy,
	.negative_advice =	xip_negative_advice,
	.link_failure =		xip_link_failure,
	.update_pmtu =		xip_update_pmtu,
	.local_out =		__xip_local_out,
	.neigh_lookup =		xip_neigh_lookup,
};
EXPORT_SYMBOL_GPL(xip_dst_ops_template);

static struct xip_dst *xip_dst_alloc(struct net *net, int flags)
{
	struct xip_dst *xdst = dst_alloc(&net->xia.xip_dst_ops,
		NULL, 1, 0, flags | DST_NOCACHE);
	if (xdst)
		memset(xdst->after_dst, 0, sizeof(*xdst) - sizeof(xdst->dst));
	return xdst;
}

static inline u32 start_edge_hash(int input)
{
	return !!input;
}

static inline void update_edge_hash(u32 *pkey_hash, const struct xia_xid *xid)
{
	const u32 n = sizeof(*xid) / sizeof(u32);
	BUILD_BUG_ON(sizeof(*xid) % sizeof(u32));
	*pkey_hash = jhash2((const u32 *)xid, n, *pkey_hash);
}

static u32 hash_edges(struct xia_row *addr, struct xia_row *row, int input)
{
	int i;
	u32 key_hash = start_edge_hash(input);
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		u8 e = row->s_edge.a[i];
		if (!is_empty_edge(e))
			update_edge_hash(&key_hash, &addr[e].s_xid);
		else
			break;
	}
	return key_hash;
}

static void set_xdst_key(struct xip_dst *xdst, struct xia_row *addr,
	struct xia_row *row, int input, u32 key_hash)
{
	int i;
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		struct xia_xid *xid = &xdst->xids[i];
		u8 e = row->s_edge.a[i];
		if (!is_empty_edge(e)) {
			memmove(xid, &addr[e].s_xid, sizeof(*xid));
		} else {
			BUILD_BUG_ON(XIDTYPE_NAT != 0);
			memset(xid, 0, sizeof(*xid) * (XIA_OUTDEGREE_MAX - i));
			break;
		}
	}
	xdst->key_hash = key_hash;
	xdst->input = !!input;
}

static inline u32 _get_bucket(u32 key_hash)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(XIP_DST_TABLE_SIZE);
	return key_hash & (XIP_DST_TABLE_SIZE - 1);
}

static inline u32 get_bucket(struct xip_dst *xdst)
{
	return _get_bucket(xdst->key_hash);
}

static inline u32 hash_bucket(struct net *net, u32 bucket)
{
	return net_hash_mix(net) + bucket;
}

/* Don't make this function inline, it's bigger than it looks like! */
static void xdst_lock_bucket(struct net *net, u32 bucket) __acquires(bucket)
{
	xia_lock_table_lock(&xia_main_lock_table, hash_bucket(net, bucket));
}

/* Don't make this function inline, it's bigger than it looks like! */
static void xdst_unlock_bucket(struct net *net, u32 bucket) __releases(bucket)
{
	xia_lock_table_unlock(&xia_main_lock_table, hash_bucket(net, bucket));
}

static inline void xdst_hold(struct xip_dst *xdst)
{
	dst_hold(&xdst->dst);
}

static inline void xdst_put(struct xip_dst *xdst)
{
	dst_release(&xdst->dst);
}

static void detach_anchors(struct xip_dst *xdst);

/* DO NOT call this function! Call xdst_free or xdst_rcu_free instead. */
static void xdst_free_common(struct xip_dst *xdst)
{
	detach_anchors(xdst);

	/* Clear references to a principal that may be unloading. */
	xdst->dst.input = dst_discard;
	xdst->dst.output = dst_discard;
}

/* DO NOT wait for RCU synchonization.
 * BE CAREFUL with this funtion!
 */
static inline void xdst_free(struct xip_dst *xdst)
{
	xdst_free_common(xdst);
	xdst_put(xdst);
}

static void _xdst_rcu_free(struct rcu_head *head)
{
	struct xip_dst *xdst = container_of(head, struct xip_dst, dst.rcu_head);
	xdst_put(xdst);
}

/* Wait for RCU synchonization. */
static inline void xdst_rcu_free(struct xip_dst *xdst)
{
	xdst_free_common(xdst);
	call_rcu(&xdst->dst.rcu_head, _xdst_rcu_free);
}

static inline struct dst_entry **dsthead(struct net *net, u32 key_hash)
{
	return &net->xia.xip_dst_table.buckets[_get_bucket(key_hash)];
}

/* Return true if @xdst has the same key of (@addr, @row, @input). */
static int xdst_matches_addr(struct xip_dst *xdst, struct xia_row *addr,
	struct xia_row *row, int input)
{
	int i;

	/* Test @input. */
	input = !!input; /* Normalize @input. */
	/* @xdst->input is always normalized. */
	if (xdst->input != input)
		return 0;

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		struct xia_xid *xid = &xdst->xids[i];
		u8 e = row->s_edge.a[i];
		if (!is_empty_edge(e)) {
			if (!are_sxids_equal(xid, &addr[e].s_xid))
				return 0;
		} else {
			return xia_is_nat(xid->xid_type);
		}
	}
	return 1;
}

static struct xip_dst *find_xdst_rcu(struct net *net, u32 key_hash,
	struct xia_row *addr, struct xia_row *row, int input)
{
	/* The trailing `h' stands for hash because it's pointing to
	 * an entry in a bucket list.
	 */
	struct dst_entry *dsth;

	for (dsth = rcu_dereference(*dsthead(net, key_hash)); dsth;
		dsth = rcu_dereference(dsth->next)) {
		struct xip_dst *xdsth = dst_xdst(dsth);
		if (xdsth->key_hash == key_hash &&
			xdst_matches_addr(xdsth, addr, row, input))
			return xdsth;
	}
	return NULL;
}

static int xdst_matches_xdst(struct xip_dst *xdst1, struct xip_dst *xdst2)
{
	int i;

	if (xdst1->key_hash != xdst2->key_hash || xdst1->input != xdst2->input)
		return 0;

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		struct xia_xid *xid1 = &xdst1->xids[i];
		struct xia_xid *xid2 = &xdst2->xids[i];
		if (xia_is_nat(xid1->xid_type))
			return xia_is_nat(xid2->xid_type);
		if (!are_sxids_equal(xid1, xid2))
			return 0;
	}
	return 1;
}

static struct xip_dst *find_xdst_locked(struct dst_entry **phead,
	struct xip_dst *xdst)
{
	struct dst_entry *dsth;
	for (dsth = *phead; dsth; dsth = dsth->next) {
		struct xip_dst *xdsth = dst_xdst(dsth);
		if (xdst_matches_xdst(xdsth, xdst))
			return xdsth;
	}
	return NULL;
}

/* XXX An ICMP-like error should be genererated here. */
static inline int xip_dst_unreachable(char *direction, struct sk_buff *skb)
{
	if (net_ratelimit())
		pr_warn("XIP: unreachable destination on direction %s\n",
			direction);
	return dst_discard(skb);
}

static int xip_dst_unreachable_in(struct sk_buff *skb)
{
	return xip_dst_unreachable("in", skb);
}

static int xip_dst_unreachable_out(struct sk_buff *skb)
{
	return xip_dst_unreachable("out", skb);
}

/* add_xdst_rcu - Add @xdst to a DST table If it is unique in the table,
 *	otherwise call xdst_free (NOT xdst_rcu_free!) on @xtbl, and
 *	return the entry that is already in the table.
 *
 * NOTE
 *	@xdst must not be already in a list!
 *
 *	Caller must hold a refcount on xdst, which will be the same used
 *	to leave @xdst in its DST table. Thus, caller must call xdst_hold
 *	before leaving an RCU read lock session if @xdst is to be used outside
 *	that session.
 *
 *	One must hold a RCU read lock to call this function in order to
 *	avoid anchors being released before @xdst is in a DST table.
 *	See function xdst_free_anchor_f for more information.
 */
static struct xip_dst *add_xdst_rcu(struct net *net,
	struct xip_dst *xdst, s8 chosen_edge)
{
	struct dst_entry **phead = dsthead(net, xdst->key_hash);
	struct xip_dst *prv_xdst;
	u32 bucket;

	/* @xdst must not be already in a list, nor
	 * potentially holding RCU readers.
	 * Notice that this test isn't complete because @xdst could be at
	 * the end of a list.
	 */
	BUG_ON(xdst->dst.next);

	bucket = get_bucket(xdst);
	xdst_lock_bucket(net, bucket);
	prv_xdst = find_xdst_locked(phead, xdst);
	if (prv_xdst) {
		/* @xdst is NOT unique, @prv_xdst is an equivalent entry. */

		/* Use @prv_xdst. */
		xdst_unlock_bucket(net, bucket);

		/* It may be tempting to include the following verification,
		 * but it may fail even when there is no bugs because
		 * one doesn't not know the version of the records used to
		 * build @prv_xdst and @xdst since we only use RCU read locks.
		 *
		 * BUG_ON(prv_xdst->chosen_edge != chosen_edge);
		 *
		 * Nevertheless, if @prv_xdst is outdated, soon an anchor
		 * will release it.
		 */

		xdst_free(xdst);

		return prv_xdst;
	}

	/* @xdst is unique. */

	/* Add @xdst to the table. */
	xdst->chosen_edge = chosen_edge;
	xdst->dst.next = *phead;
	rcu_assign_pointer(*phead, &xdst->dst);

	/* Use @xdst. */
	xdst_unlock_bucket(net, bucket);
	return xdst;
}

static void clear_xdst_table(struct net *net)
{
	struct xip_dst_table *xdst_tbl = &net->xia.xip_dst_table;
	int i;

	for (i = 0; i < XIP_DST_TABLE_SIZE; i++) {
		struct dst_entry *dsth;

		xdst_lock_bucket(net, i);
		dsth = xdst_tbl->buckets[i];
		RCU_INIT_POINTER(xdst_tbl->buckets[i], NULL);
		xdst_unlock_bucket(net, i);

		while (dsth) {
			struct dst_entry *next = dsth->next;
			RCU_INIT_POINTER(dsth->next, NULL);
			xdst_rcu_free(dst_xdst(dsth));
			dsth = next;
		}
	}
}

/* XXX This is a barebone implementation, more must be done.
 * See net/ipv4/route.c:rt_garbage_collect and net/ipv6/route.c:ip6_dst_gc
 * for ideas.
 *
 * We're also missing a periodic GC similar to
 * net/ipv4/route.c:rt_check_expire.
 */
static int xip_dst_gc(struct dst_ops *ops)
{
	struct net *net;
	int entries;
	u32 bucket;
	struct dst_entry **pdsth;

	entries = dst_entries_get_fast(ops);
	if (entries < ops->gc_thresh)
		return 0;

	net = dstops_net(ops);
	bucket = net->xia.xip_dst_table.last_bucket;
	BUILD_BUG_ON_NOT_POWER_OF_2(XIP_DST_TABLE_SIZE);
	net->xia.xip_dst_table.last_bucket = (bucket + 1) &
		(XIP_DST_TABLE_SIZE - 1);

	xdst_lock_bucket(net, bucket);
	pdsth = &net->xia.xip_dst_table.buckets[bucket];
	while (*pdsth) {
		struct dst_entry **pnext = &(*pdsth)->next;
		if (atomic_read(&(*pdsth)->__refcnt) == 1) {
			rcu_assign_pointer(*pdsth, *pnext);
			xdst_rcu_free(dst_xdst(*pdsth));
		}
		pdsth = pnext;
	}
	xdst_unlock_bucket(net, bucket);

	return dst_entries_get_slow(ops) > 2 * ops->gc_thresh;
}

/*
 *	DST Anchors
 */

static struct xia_lock_table anchor_locktbl __read_mostly;

static inline u32 hash_anchor(struct xip_dst_anchor *anchor)
{
	return (u32)(((unsigned long)anchor) >> L1_CACHE_SHIFT);
}

/* Don't make this function inline, it's bigger than it looks like! */
static void lock_anchor(struct xip_dst_anchor *anchor) __acquires(anchor)
{
	xia_lock_table_lock(&anchor_locktbl, hash_anchor(anchor));
}

/* Don't make this function inline, it's bigger than it looks like! */
static void unlock_anchor(struct xip_dst_anchor *anchor) __releases(anchor)
{
	xia_lock_table_unlock(&anchor_locktbl, hash_anchor(anchor));
}

void xdst_attach_to_anchor(struct xip_dst *xdst, int index,
	struct xip_dst_anchor *anchor)
{
	lock_anchor(anchor);
	if (cmpxchg(&xdst->anchors[index].anchor, NULL, anchor) != NULL)
		BUG();
	hlist_add_head(&xdst->anchors[index].list_node, &anchor->heads[index]);
	unlock_anchor(anchor);
}
EXPORT_SYMBOL_GPL(xdst_attach_to_anchor);

/* NOTE
 *	IMPORTANT! Don't call this function holding a lock on a bucket!
 *	This may lead to a deadlock with function xdst_free_anchor_f.
 *
 *	IMPORTANT! Don't call this function holding a lock on an anchor!
 *	This may lead to a deadlock.
 *
 *	It's okay to call this function on an @xdst that has no anchors.
 */
static void detach_anchors(struct xip_dst *xdst)
{
	int i;
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		struct xip_dst_anchor *anchor, *reread;
		anchor = xdst->anchors[i].anchor;
		if (!anchor)
			continue;

		lock_anchor(anchor);
		reread = xdst->anchors[i].anchor;
		if (reread) {
			/* @xdst is still attached. */
			BUG_ON(anchor != reread);
			hlist_del(&xdst->anchors[i].list_node);
			if (cmpxchg(&xdst->anchors[i].anchor, anchor, NULL) !=
				anchor)
				BUG();
		}
		unlock_anchor(anchor);
	}
}

/* Remove @xdst from the DST table of @xdst->net, and hold a refcount
 *	to it.
 *
 * RETURN
 *	Zero if @xdst was NOT in the DST table.
 *	IMPORTANT! In this case, there's no refcount to @xdst.
 *	This can happen either because @xdst wasn't in the DST table derived
 *	from its @xdst->net (bug), or it wasn't in any DST table at all.
 *	Notice that just checking @next isn't enough because it may have
 *	a non-NULL value just to avoid disrupting RCU readers.
 *
 *	One otherwise. A refcount is held in this case.
 *
 * NOTE
 *	IMPORTANT! Caller must wait an RCU synch before adding
 *	@xdst again to a DST table, or releasing its memory.
 */
static int del_xdst_and_hold(struct xip_dst *xdst)
{
	struct net *net = xdst_net(xdst);
	struct dst_entry **phead = dsthead(net, xdst->key_hash);
	u32 bucket;
	struct dst_entry **pdsth;
	int rc = 0;

	bucket = get_bucket(xdst);
	xdst_lock_bucket(net, bucket);

	for (pdsth = phead; *pdsth; pdsth = &(*pdsth)->next)
		if (*pdsth == &xdst->dst) {
			rcu_assign_pointer(*pdsth, (*pdsth)->next);
			rc = 1;
			/* One doesn't need a hold here because @xdst was just
			 * removed from a DST table.
			 */
			goto out;
		}

out:
	xdst_unlock_bucket(net, bucket);
	return rc;
}

static struct dst_entry *xip_negative_advice(struct dst_entry *dst)
{
	struct xip_dst *xdst = dst_xdst(dst);
	if (del_xdst_and_hold(xdst))
		xdst_rcu_free(xdst);
	xdst_put(xdst);
	return NULL;
}

static void xdst_free_anchor_f(struct xip_dst_anchor *anchor,
	int (*filter)(struct xip_dst *xdst, int anchor_index, void *arg),
	void *arg)
{
	/* Assumptions:
	 *	1. All @xdst's to be found here are in a DST table, or
	 *		is being removed by somebody else, that is,
	 *		they have already being in a DST table once.
	 *	2. Caller waited for a RCU synchronization. This is required
	 *		to implement assumption 1; see function choose_an_edge.
	 *	3. @anchor is not reachable from somewhere else but from
	 *		the @xdst's that point to it.
	 */

	int i;
	struct xip_dst *xdst;
	struct hlist_node *pos, *n;
	struct hlist_head roots[XIA_OUTDEGREE_MAX];

	memset(roots, 0, sizeof(roots));

	lock_anchor(anchor);
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		hlist_for_each_entry_safe(xdst, pos, n, &anchor->heads[i],
			anchors[i].list_node) {
			if (!filter(xdst, i, arg))
				continue;

			hlist_del(&xdst->anchors[i].list_node);
			if (del_xdst_and_hold(xdst)) {
				/* We are responsable for freeing @xdst. */
				hlist_add_head(&xdst->anchors[i].list_node,
					&roots[i]);
			} else {
				/* We don't have a refcount to @xdst, and
				 * assumption 1 guarantees that somebody
				 * else is going to release @xdst.
				 */
			}

			/* Releasing @anchor. */
			if (cmpxchg(&xdst->anchors[i].anchor, anchor, NULL) !=
				anchor)
				BUG();
		}
	}
	unlock_anchor(anchor);

	/* Assumption 3 guarantees that, at this point, nobody will add
	 * an @xdst to @anchor now that the lock was released.
	 */

	/* Free @xdst's that we hold refcount. */
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++)
		hlist_for_each_entry_safe(xdst, pos, n, &roots[i],
			anchors[i].list_node) {
			hlist_del(&xdst->anchors[i].list_node);
			xdst_rcu_free(xdst);
		}
}

static int filter_none(struct xip_dst *xdst, int anchor_index, void *arg)
{
	return 1;
}

void xdst_free_anchor(struct xip_dst_anchor *anchor)
{
	xdst_free_anchor_f(anchor, filter_none, NULL);
}
EXPORT_SYMBOL_GPL(xdst_free_anchor);

static int main_deliver_rcu(struct net *net, const struct xia_xid *xid,
	int anchor_index, struct xip_dst *xdst);

/* An RCU read lock is need to call this function in order to avoid
 * anchors to release @xdst before it's freed, and
 * to avoid releasing @anchor's host struct before returning it.
 */
static struct xip_dst_anchor *find_anchor_of_rcu(struct net *net,
	const struct xia_xid *to)
{
	struct xip_dst *xdst;
	struct xip_dst_anchor *anchor;

	xdst = xip_dst_alloc(net, DST_NOCOUNT);
	if (!xdst)
		return ERR_PTR(-ENOMEM);

	/* Obtain hash for a single edge. */
	xdst->key_hash = start_edge_hash(0); /* @input doesn't matter here. */
	update_edge_hash(&xdst->key_hash, to);

	memmove(&xdst->xids[0], to, sizeof(xdst->xids[0]));
	/* One doesn't need to zero the other @xdst->xids[]'s because
	 * @xdst was just allocated.
	 */

	switch (main_deliver_rcu(net, to, 0, xdst)) {
	case XRP_ACT_NEXT_EDGE:
		/* The anchor never existed, or it's already gone. */
		return NULL;
	case XRP_ACT_FORWARD:
		break;
	default:
		BUG();
	}

	anchor = xdst->anchors[0].anchor;
	BUG_ON(!anchor);
	xdst_free(xdst);
	return anchor;
}

struct filter_from_arg {
	xid_type_t	type;
	const u8	*id;
};

static int filter_from(struct xip_dst *xdst, int anchor_index, void *arg)
{
	struct xia_xid *xid = &xdst->xids[anchor_index];
	struct filter_from_arg *from = (struct filter_from_arg *)arg;
	return xid->xid_type == from->type &&
		are_xids_equal(xid->xid_id, from->id);
}

void xdst_invalidate_redirect(struct net *net, xid_type_t from_type,
	const u8 *from_xid, const struct xia_xid *to)
{
	struct xip_dst_anchor *anchor;
	struct filter_from_arg arg;

	rcu_read_lock();
	anchor = find_anchor_of_rcu(net, to);
	if (IS_ERR_OR_NULL(anchor)) {
		rcu_read_unlock();

		if (!anchor)
			return;

		BUG_ON(anchor != ERR_PTR(-ENOMEM));
		pr_err("%s: XIP positive dependency could not invalidate XIP DST entries because system memory is too low. Clearing XIP DST cache as a last resource...\n",
			__func__);
		clear_xdst_table(net);
		return;
	}

	arg.type = from_type;
	arg.id = from_xid;
	xdst_free_anchor_f(anchor, filter_from, &arg);

	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(xdst_invalidate_redirect);

/*
 *	Principal routing
 */

static DEFINE_SPINLOCK(ppal_lock);
static struct hlist_head principals[NUM_PRINCIPAL_HINT];

static inline struct hlist_head *ppalhead(xid_type_t ty)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(NUM_PRINCIPAL_HINT);
	return &principals[__be32_to_cpu(ty) & (NUM_PRINCIPAL_HINT - 1)];
}

static struct xip_route_proc *find_rproc_locked(xid_type_t ty,
	struct hlist_head *head)
{
	struct xip_route_proc *rproc;
	struct hlist_node *p;
	hlist_for_each_entry(rproc, p, head, xrp_list)
		if (rproc->xrp_ppal_type == ty)
			return rproc;
	return NULL;
}

static struct xip_route_proc *find_rproc_rcu(xid_type_t ty,
	struct hlist_head *head)
{
	struct xip_route_proc *rproc;
	struct hlist_node *p;
	hlist_for_each_entry_rcu(rproc, p, head, xrp_list)
		if (rproc->xrp_ppal_type == ty)
			return rproc;
	return NULL;
}

int xip_add_router(struct xip_route_proc *rproc)
{
	xid_type_t ty = rproc->xrp_ppal_type;
	struct hlist_head *head = ppalhead(ty);
	int rc;

	spin_lock(&ppal_lock);

	rc = -EEXIST;
	if (find_rproc_locked(ty, head))
		goto out;
	hlist_add_head_rcu(&rproc->xrp_list, head);
	rc = 0;

out:
	spin_unlock(&ppal_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(xip_add_router);

void xip_del_router(struct xip_route_proc *rproc)
{
	spin_lock(&ppal_lock);
	hlist_del_rcu(&rproc->xrp_list);
	spin_unlock(&ppal_lock);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(xip_del_router);

static int local_deliver_rcu(struct net *net, const struct xia_xid *xid,
	int anchor_index, struct xip_dst *xdst)
{
	xid_type_t ty = xid->xid_type;
	struct hlist_head *head = ppalhead(ty);
	struct xip_route_proc *rproc;

	rproc = find_rproc_rcu(ty, head);
	if (rproc)
		return rproc->local_deliver(rproc, net, xid->xid_id,
			anchor_index, xdst);

	/* We don't know how to route this principal. */
	return -ENOENT;
}

static int main_deliver_rcu(struct net *net, const struct xia_xid *xid,
	int anchor_index, struct xip_dst *xdst)
{
	const struct xia_xid *left_xid;
	struct xia_xid tmp_xids[2], *right_xid;
	int done = 2; /* Bound the number of redirects. */
	char from[XIA_MAX_STRXID_SIZE];

	left_xid = xid;
	right_xid = &tmp_xids[0];
	do {
		xid_type_t ty = left_xid->xid_type;
		struct hlist_head *head;
		struct xip_route_proc *rproc;
		int rc;

		/* Consult principal. */
		head = ppalhead(ty);
		rproc = find_rproc_rcu(ty, head);
		if (!rproc) {
			/* We don't know how to route this principal. */
			return XRP_ACT_NEXT_EDGE;
		}
		rc = rproc->main_deliver(rproc, net, left_xid->xid_id,
			right_xid, anchor_index, xdst);

		switch (rc) {
		case XRP_ACT_NEXT_EDGE:
		case XRP_ACT_FORWARD:
			return rc;

		case XRP_ACT_REDIRECT:
			if (right_xid->xid_type == ty) {
				char to[XIA_MAX_STRXID_SIZE];
				BUG_ON(xia_xidtop(left_xid, from,
					XIA_MAX_STRXID_SIZE) < 0);
				BUG_ON(xia_xidtop(right_xid, to,
					XIA_MAX_STRXID_SIZE) < 0);
				pr_err("BUG: Principal %u is redirecting to itself, %s -> %s, ignoring this route\n",
					__be32_to_cpu(ty), from, to);
				return XRP_ACT_NEXT_EDGE;
			}
			left_xid = right_xid;
			right_xid = left_xid == &tmp_xids[0] ? &tmp_xids[1] :
				&tmp_xids[0];

			/* Redirecting to a local XID is wrong because
			 * it breaks intrinsic security.
			 * That's why one keeps looking @left_xid up with
			 * only function mail_deliver.
			 */

			break;

		default:
			BUG();
		}
		done--;
	} while (done > 0);
	BUG_ON(xia_xidtop(xid, from, XIA_MAX_STRXID_SIZE) < 0);
	pr_err("BUG: Principal %u is looping too deep, this search started with %s, ignoring this route\n",
		__be32_to_cpu(xid->xid_type), from);
	return XRP_ACT_NEXT_EDGE;
}

static inline void select_edge(u8 *plast_node, struct xia_row *last_row,
	int index)
{
	u8 *pe = &last_row->s_edge.a[index];
	xia_mark_edge(pe);
	*plast_node = *pe;
}

/* XXX An ICMP-like error should be genererated here. */
static inline int xip_dst_not_supported(char *direction, struct sk_buff *skb)
{
	if (net_ratelimit())
		pr_warn("XIP: not supported address for principal on direction %s\n",
		direction);
	return dst_discard(skb);
}

static int xip_dst_not_supported_in(struct sk_buff *skb)
{
	return xip_dst_not_supported("in", skb);
}

static int xip_dst_not_supported_out(struct sk_buff *skb)
{
	return xip_dst_not_supported("out", skb);
}

static struct xip_dst xdst_error = {
	.dst = {
		.__refcnt       = ATOMIC_INIT(1),
		.input		= xip_dst_not_supported_in,
		.output		= xip_dst_not_supported_out,
	},
	.passthrough_action	= XDA_METHOD,
	.sink_action		= XDA_METHOD,
};

/* DO NOT call this function!
 * It is only meant to improve function choose_an_edge's readability.
 */
static inline struct xip_dst *use_dst_table_rcu(
	struct xip_dst *xdst_hint, u32 *pkey_hash, int *pdrop,
	struct net *net, struct xia_row *addr, u8 num_dst, u8 *plast_node,
	struct xia_row **plast_row, int input)
{
	struct xip_dst *xdst;
	struct xia_row *next_row;
	s8 chosen_edge;
	u8 e;
	int action, sink;

	*pdrop = 0;

tail_call:
	if (!xdst_hint) {
		u32 visited = 0;
		if (unlikely(xia_are_edges_valid(*plast_row, *plast_node,
			num_dst, &visited))) {
			*pdrop = 1;
			return NULL;
		}

		/* This function isn't supposed to be called on sinks! */
		BUG_ON(is_it_a_sink(*plast_row, *plast_node, num_dst));

		*pkey_hash = hash_edges(addr, *plast_row, input);

		xdst = find_xdst_rcu(net, *pkey_hash, addr, *plast_row, input);
		if (!xdst)
			/* The DST table doesn't know how to handle this row. */
			return NULL;
	} else {
		xdst = xdst_hint;
	}

	/* Cache hit, interpret @xdst. */

	chosen_edge = xdst->chosen_edge;
	if (chosen_edge < 0) {
		/* Can't pick an edge. */
		BUG_ON(xdst->passthrough_action != XDA_METHOD);
		BUG_ON(xdst->sink_action != XDA_METHOD);
		return xdst;
	}
	BUG_ON(chosen_edge >= XIA_OUTDEGREE_MAX);

	e = (*plast_row)->s_edge.a[chosen_edge];
	next_row = &addr[e];
	sink = is_it_a_sink(next_row, e, num_dst);
	action = sink ? xdst->sink_action : xdst->passthrough_action;

	switch (action) {
	case XDA_DIG:
		BUG_ON(sink);

		/* Record that we're going for a recursion. */
		select_edge(plast_node, *plast_row, chosen_edge);

		*plast_row = next_row;
		xdst_hint = NULL;
		goto tail_call;

	case XDA_ERROR:
		/* Help debugging. */
		select_edge(plast_node, *plast_row, chosen_edge);

		return &xdst_error;

	case XDA_DROP:
		*pdrop = 1;
		return NULL;

	case XDA_METHOD_AND_SELECT_EDGE:
		select_edge(plast_node, *plast_row, chosen_edge);
		/* Fall through. */

	case XDA_METHOD:
		return xdst;

	default:
		BUG();
	}
}

/* The returned reference to a struct xip_dst already has been held. */
static struct xip_dst *choose_an_edge(struct net *net, struct xia_row *addr,
	u8 num_dst, u8 *plast_node, struct xia_row *last_row, int input)
{
	struct xip_dst *xdst;
	int drop, i;
	u32 key_hash;

	xdst = NULL;

	/* Not only is this RCU read lock required by some functions used
	 * in its body, but it also avoids anchors to release a new @xdst
	 * before it's in a table! In order to understand this need,
	 * see function xdst_free_anchor_f.
	 * Not to mention that it avoids reference counting on @xdst entries.
	 */
	rcu_read_lock();

tail_call:
	xdst = use_dst_table_rcu(xdst, &key_hash, &drop,
		net, addr, num_dst, plast_node, &last_row, input);
	if (drop) {
		BUG_ON(xdst);
		goto out;
	}
	if (likely(xdst))
		goto ret_xdst;

	/* Handle DST cache miss. */

	/* Create @xdst. */
	xdst = xip_dst_alloc(net, 0);
	if (!xdst)
		goto out;
	set_xdst_key(xdst, addr, last_row, input, key_hash);

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		u8 e = last_row->s_edge.a[i];
		const struct xia_xid *next_xid;

		if (is_empty_edge(e)) {
			/* An empty edge is supposed to be the last edge.
			 * The destination is unreachable.
			 */
			break;
		}
		next_xid = &addr[e].s_xid;

		/* Is it local? */
		if (!local_deliver_rcu(net, next_xid, i, xdst)) {
			xdst = add_xdst_rcu(net, xdst, i);
			goto tail_call;
		}

		/* Is it forwardable? */
		switch (main_deliver_rcu(net, next_xid, i, xdst)) {
		case XRP_ACT_NEXT_EDGE:
			break;
		case XRP_ACT_FORWARD:
			/* We found an edge that we can use to forward. */
			xdst = add_xdst_rcu(net, xdst, i);
			goto tail_call;
		default:
			BUG();
		}
	}

	/* Destination is unreachable. */
	xdst->dst.input = xip_dst_unreachable_in;
	xdst->dst.output = xip_dst_unreachable_out;
	xdst->passthrough_action = XDA_METHOD;
	xdst->sink_action = XDA_METHOD;
	xdst = add_xdst_rcu(net, xdst, -1);
	goto tail_call;

ret_xdst:
	xdst_hold(xdst);
out:
	rcu_read_unlock();
	return xdst;
}

struct xip_dst *xip_mark_addr_and_get_dst(struct net *net,
	struct xia_row *addr, int num_dst, u8 *plast_node, int input)
{
	int last_node = *plast_node;
	struct xia_row *last_row;
	struct xip_dst *xdst;

	last_row = last_node == XIA_ENTRY_NODE_INDEX ?
		&addr[num_dst - 1] : &addr[last_node];

	/* Basis. */
	if (unlikely(is_it_a_sink(last_row, last_node, num_dst))) {
		/* This case is undefined in XIA,
		 * so we assume that @addr is broken.
		 */
		return ERR_PTR(-EINVAL);
	}

	/* Inductive step. */
	xdst = choose_an_edge(net, addr, num_dst, plast_node, last_row, input);
	if (unlikely(!xdst))
		return ERR_PTR(-ENETUNREACH);

	return xdst;
}
EXPORT_SYMBOL_GPL(xip_mark_addr_and_get_dst);

static inline int xip_route(struct sk_buff *skb, struct xia_row *addr,
		int num_dst, u8 *plast_node, int input)
{
	struct xip_dst *xdst = xip_mark_addr_and_get_dst(skb_net(skb),
		addr, num_dst, plast_node, input);
	if (IS_ERR(xdst))
		return PTR_ERR(xdst);
	skb_dst_set(skb, &xdst->dst);
	return 0;
}

/*
 *	Handling XIP incoming packets
 */

/* Main XIP receive routine. */
static int xip_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct xiphdr *xiph;
	int hdr_len, tot_len;

	/* Don't waste time processing other hosts' packets.
	 * This is needed when the interface is in promiscuous mode.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto out; /* Out of memory. */

	if (!pskb_may_pull(skb, sizeof(struct xiphdr)))
		goto drop;

	xiph = xip_hdr(skb);

	if (xiph->version != 1 || /* It's gotten to be version 1! */
		xiph->num_dst < 1 || /* No destination? */
		xiph->num_dst > XIA_NODES_MAX || /* Too big dest. address. */
		xiph->num_src > XIA_NODES_MAX || /* Too big source address. */
		/* Broken header. */
		!is_row_valid(xiph->last_node, xiph->num_dst))
		goto drop;

	/* Do we have addresses? */
	hdr_len = xip_hdr_len(xiph);
	if (!pskb_may_pull(skb, hdr_len))
		goto drop;

	tot_len = hdr_len + be16_to_cpu(xiph->payload_len);
	if (skb->len < tot_len)
		goto drop;

	/* Our transport medium may have padded the buffer out.
	 * Now that we know it is XIP, we can trim to the true length of
	 * the packet.
	 */
	if (pskb_trim(skb, tot_len))
		goto drop;

	/* Initialise the virtual path cache for the packet.
	 * It describes how the packet travels inside Linux networking.
	 */
	if (!skb_dst(skb) && xip_route(skb, xiph->dst_addr, xiph->num_dst,
		&xiph->last_node, 1))
		goto drop;

	return dst_input(skb);

drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}

static struct packet_type xip_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_XIP),
	.func = xip_rcv,
	/* XXX Implement GSO & GRO methods to improve performance. */
};

/*
 *	Initialization
 */

static int __net_init xip_route_net_init(struct net *net)
{
	struct dst_ops *ops = &net->xia.xip_dst_ops;
	int rc;

	/* Initialize @xip_dst_ops. */
	memmove(ops, &xip_dst_ops_template, sizeof(*ops));
	rc = dst_entries_init(ops);
	if (rc)
		goto out;

	memset(&net->xia.xip_dst_table, 0, sizeof(net->xia.xip_dst_table));

out:
	return rc;
}

static void __net_exit xip_route_net_exit(struct net *net)
{
	clear_xdst_table(net);
	dst_entries_destroy(&net->xia.xip_dst_ops);
}

static struct pernet_operations xip_route_net_ops __read_mostly = {
	.init = xip_route_net_init,
	.exit = xip_route_net_exit,
};

int __init xip_route_init(void)
{
	int rc;

	rc = xia_lock_table_init(&anchor_locktbl, XIA_LTBL_SPREAD_LARGE);
	if (rc < 0)
		goto out;

	rc = -ENOMEM;
	xip_dst_ops_template.kmem_cachep =
		KMEM_CACHE(xip_dst, SLAB_HWCACHE_ALIGN);
	if (!xip_dst_ops_template.kmem_cachep)
		goto anchor;

	rc = register_pernet_subsys(&xip_route_net_ops);
	if (rc)
		goto out_kmem_cache;

	dev_add_pack(&xip_packet_type);
	return 0;

out_kmem_cache:
	kmem_cache_destroy(xip_dst_ops_template.kmem_cachep);
anchor:
	xia_lock_table_finish(&anchor_locktbl);
out:
	return rc;
}

void xip_route_exit(void)
{
	dev_remove_pack(&xip_packet_type);
	unregister_pernet_subsys(&xip_route_net_ops);
	kmem_cache_destroy(xip_dst_ops_template.kmem_cachep);
	xia_lock_table_finish(&anchor_locktbl);
}

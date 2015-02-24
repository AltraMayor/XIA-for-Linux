#include <linux/export.h>
#include <linux/jhash.h>
#include <net/netns/hash.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>
#include <net/xia_output.h>	/* Needed for __xip_local_out(). */
#include <net/xia_socket.h>	/* Needed for copy_n_and_shade_xia_addr(). */
#include <net/xia_vxidty.h>
#include <net/xia_route.h>

/* Route cache (DST) */

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
	struct net_device *dev;

	if (mtu)
		return mtu;

	dev = dst->dev;
	if (dev)
		return dev->mtu;

	return XIP_MIN_MTU;
}

static void xip_dst_destroy(struct dst_entry *dst)
{
	struct xip_dst *xdst = dst_xdst(dst);

	if (xdst->ppal_destroy)
		xdst->ppal_destroy(xdst);
	dst_destroy_metrics_generic(dst);
}

static struct dst_entry *xip_negative_advice(struct dst_entry *dst);

/* XXX An ICMP-like error should be genererated here. */
static void xip_link_failure(struct sk_buff *skb)
{
	net_warn_ratelimited("%s: unreachable destination\n", __func__);
}

static void xip_update_pmtu(struct dst_entry *dst, struct sock *sk,
			    struct sk_buff *skb, u32 mtu)
{
	if (mtu < dst_mtu(dst)) {
		mtu = max_t(typeof(mtu), mtu, XIP_MIN_MTU);
		dst_metric_set(dst, RTAX_MTU, mtu);
	}
}

static struct neighbour *xip_neigh_lookup(const struct dst_entry *dst,
					  struct sk_buff *skb,
					  const void *daddr)
{
	return ERR_PTR(-EINVAL);
}

static int xip_dst_gc(struct dst_ops *ops);

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
		NULL, 1, DST_OBSOLETE_NONE, flags | DST_NOCACHE);
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

static u32 hash_edges(const struct xia_row *addr, const struct xia_row *row,
		      int input)
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

static void set_xdst_key(struct xip_dst *xdst, const struct xia_row *addr,
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

static void detach_anchors(struct xip_dst *xdst);

/* DO NOT call this function! Call xdst_free() or xdst_rcu_free() instead. */
static inline void xdst_free_begin(struct xip_dst *xdst)
{
	detach_anchors(xdst);

	xdst->dst.obsolete = DST_OBSOLETE_KILL;

	/* XXX The following cleanup isn't really safe, but DST's interface
	 * does not provide a safe alternative.
	 */

	/* Clear references to a principal that may be unloading. */
	xdst->dst.input = dst_discard;
	xdst->dst.output = dst_discard_sk;
}

/* DO NOT call this function! Call xdst_free() or xdst_rcu_free() instead. */
static inline void xdst_free_end(struct xip_dst *xdst)
{
	xdst_put(xdst);
}

/* @xdst must not be in any DST table!
 *
 * IMPORTANT: this function does NOT wait for RCU synchronization,
 * so BE CAREFUL with it! If RCU synchronization is needed,
 * call xdst_rcu_free() instead.
 *
 * IMPORTANT: given that this function will call xdst_free_begin(),
 * which, in turn, calls detach_anchors(), one would be better off checking
 * detach_anchors()'s calling constraints.
 */
static void xdst_free(struct xip_dst *xdst)
{
	xdst_free_begin(xdst);
	xdst_free_end(xdst);
}

/* DO NOT call this function! Call xdst_rcu_free() instead. */
static void _xdst_rcu_free(struct rcu_head *head)
{
	struct xip_dst *xdst = container_of(head, struct xip_dst, dst.rcu_head);
	xdst_free_end(xdst);
}

void xdst_rcu_free(struct xip_dst *xdst)
{
	xdst_free_begin(xdst);
	call_rcu(&xdst->dst.rcu_head, _xdst_rcu_free);
}
EXPORT_SYMBOL_GPL(xdst_rcu_free);

void def_ppal_destroy(struct xip_dst *xdst)
{
	kfree(xdst->info);
	xdst->info = NULL;
}
EXPORT_SYMBOL_GPL(def_ppal_destroy);

static inline struct dst_entry **dsthead(struct net *net, u32 key_hash)
{
	return &net->xia.xip_dst_table.buckets[_get_bucket(key_hash)];
}

/* Return true if @xdst has the same key of (@addr, @row, @input). */
static int xdst_matches_addr(struct xip_dst *xdst, const struct xia_row *addr,
			     const struct xia_row *row, int input)
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
				     const struct xia_row *addr,
				     const struct xia_row *row, int input)
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
	/* XXX There should be a variation of xia_ntop() that receives
	 * a struct xia_row instead of a struct xia_addr.
	 * Once copy_n_and_shade_xia_addr() is removed, remove include to
	 * <net/xia_socket.h>.
	 */
	if (net_ratelimit()) {
		const struct xiphdr *xiph = xip_hdr(skb);
		struct xia_addr addr;
		char str_addr[XIA_MAX_STRADDR_SIZE];

		copy_n_and_shade_xia_addr(&addr, xiph->dst_addr, xiph->num_dst);
		BUG_ON(xia_ntop(&addr, str_addr, XIA_MAX_STRADDR_SIZE, 0) < 0);
		pr_warn("XIP: unreachable destination on direction %s, last_node=%i, destination_address=`%s'\n",
			direction, xiph->last_node, str_addr);
	}
	return dst_discard(skb);
}

static int xip_dst_unreachable_in(struct sk_buff *skb)
{
	return xip_dst_unreachable("in", skb);
}

static int xip_dst_unreachable_out(struct sock *sk, struct sk_buff *skb)
{
	return xip_dst_unreachable("out", skb);
}

static void make_xdst_unreachable(struct net *net, struct xip_dst *xdst)
{
	struct net_device *dev;

	xdst->dst.input = xip_dst_unreachable_in;
	xdst->dst.output = xip_dst_unreachable_out;
	xdst->passthrough_action = XDA_METHOD;
	xdst->sink_action = XDA_METHOD;

	/* One must assign some device to  dst.dev so packets can still be
	 * created.
	 */
	BUG_ON(xdst->dst.dev);
	dev = net->loopback_dev;
	xdst->dst.dev = dev;
	dev_hold(dev);
	if (dev->mtu > XIP_MIN_MTU) {
		/* Shrink MTU to minimize waste. */
		dst_metric_set(&xdst->dst, RTAX_MTU, XIP_MIN_MTU);
	}
}

/* add_xdst_rcu - Add @xdst to a DST table if it is unique in the table,
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

void clear_xdst_table(struct net *net)
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
EXPORT_SYMBOL_GPL(clear_xdst_table);

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
	u32 bucket;
	struct dst_entry **pdsth, **p_chosen_dsth;

	/* Get @bucket. */
	net = dstops_net(ops);
	BUILD_BUG_ON_NOT_POWER_OF_2(XIP_DST_TABLE_SIZE);
	bucket = atomic_inc_return(&net->xia.xip_dst_table.last_bucket) &
		(XIP_DST_TABLE_SIZE - 1);

	/* Choose an entry in @bucket to release. */
	p_chosen_dsth = NULL;
	xdst_lock_bucket(net, bucket);
	pdsth = &net->xia.xip_dst_table.buckets[bucket];
	while (*pdsth) {
		if (atomic_read(&(*pdsth)->__refcnt) == 1) {
			if (unlikely(!p_chosen_dsth))
				p_chosen_dsth = pdsth;
			else if (time_after((*p_chosen_dsth)->lastuse,
					    (*pdsth)->lastuse) &&
				(*p_chosen_dsth)->__use > (*pdsth)->__use)
				p_chosen_dsth =  pdsth;
		}
		pdsth = &(*pdsth)->next;
	}
	if (p_chosen_dsth) {
		struct dst_entry *freeable_dst = *p_chosen_dsth;

		rcu_assign_pointer(*p_chosen_dsth, (*p_chosen_dsth)->next);
		xdst_unlock_bucket(net, bucket);
		xdst_rcu_free(dst_xdst(freeable_dst));
		return 0;
	}
	xdst_unlock_bucket(net, bucket);

	return dst_entries_get_slow(ops) > 2 * ops->gc_thresh;
}

/* DST Anchors */

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
	BUG_ON(cmpxchg(&xdst->anchors[index].anchor, NULL, anchor) != NULL);
	hlist_add_head(&xdst->anchors[index].list_node, &anchor->heads[index]);
	unlock_anchor(anchor);
}
EXPORT_SYMBOL_GPL(xdst_attach_to_anchor);

/* NOTE
 *	IMPORTANT! Don't call this function holding a lock on a bucket of
 *	the DST table! This may lead to a deadlock with
 *	function xdst_free_anchor_f.
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
			BUG_ON(cmpxchg(&xdst->anchors[i].anchor, anchor, NULL)
				!= anchor);
		}
		unlock_anchor(anchor);
	}
}

int del_xdst_and_hold(struct xip_dst *xdst)
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
EXPORT_SYMBOL_GPL(del_xdst_and_hold);

static struct dst_entry *xip_negative_advice(struct dst_entry *dst)
{
	struct xip_dst *xdst = dst_xdst(dst);

	if (del_xdst_and_hold(xdst))
		xdst_rcu_free(xdst);
	xdst_put(xdst);
	return NULL;
}

void xdst_init_anchor(struct xip_dst_anchor *anchor)
{
	int i;

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++)
		INIT_HLIST_HEAD(&anchor->heads[i]);
}
EXPORT_SYMBOL_GPL(xdst_init_anchor);

static void xdst_free_anchor_f(struct xip_dst_anchor *anchor,
	int (*filter)(struct xip_dst *xdst, int anchor_index, void *arg),
	void *arg)
{
	/* Assumptions:
	 *	1. All @xdst's to be found here are in a DST table, or
	 *		is being removed by somebody else, that is,
	 *		they have already being in a DST table once.
	 *	2. Caller waited for an RCU synchronization. This is required
	 *		to implement assumption 1; see function choose_an_edge.
	 */

	int i;
	struct xip_dst *xdst;
	struct hlist_node *n;
	struct hlist_head roots[XIA_OUTDEGREE_MAX];

	memset(roots, 0, sizeof(roots));

	lock_anchor(anchor);
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		hlist_for_each_entry_safe(xdst, n, &anchor->heads[i],
					  anchors[i].list_node) {
			int held;

			if (!filter(xdst, i, arg))
				continue;

			/* Remove @xdst from a DST table if it's there. */
			held = del_xdst_and_hold(xdst);

			/* Release @anchor in @xdst. */
			hlist_del(&xdst->anchors[i].list_node);
			BUG_ON(cmpxchg(&xdst->anchors[i].anchor, anchor, NULL)
				!= anchor);

			if (held) {
				/* We are responsable for freeing @xdst. */
				hlist_add_head(&xdst->anchors[i].list_node,
					       &roots[i]);
			} else {
				/* We don't have a refcount to @xdst, and
				 * assumption 1 guarantees that somebody
				 * else is going to release @xdst.
				 */
			}
		}
	}
	unlock_anchor(anchor);

	/* It is important to release @xdst's only after the main loop above
	 * to avoid a deadlock at @anchor.
	 */
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++)
		hlist_for_each_entry_safe(xdst, n, &roots[i],
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

/** xdst_clean_anchor - release all struct xip_dst entries that are attached
 *			to @anchor and have XID <@type, @xid> at one of their
 *			edges.
 * NOTE
 *	IMPORTANT! Caller must RCU synch before calling this function.
 */
static void xdst_clean_anchor(struct xip_dst_anchor *anchor, xid_type_t type,
			      const u8 *id)
{
	struct filter_from_arg arg;

	arg.type = type;
	arg.id = id;
	xdst_free_anchor_f(anchor, filter_from, &arg);
}

static struct xip_dst_anchor *find_anchor_of_rcu(struct net *net,
						 const struct xia_xid *to);

void xdst_invalidate_redirect(struct net *net, xid_type_t from_type,
			      const u8 *from_xid, const struct xia_xid *to)
{
	struct xip_dst_anchor *anchor;

	rcu_read_lock();

	anchor = find_anchor_of_rcu(net, to);
	if (IS_ERR(anchor)) {
		rcu_read_unlock();
		net_err_ratelimited("%s: XIP could not invalidate DST entries because of error %li. Clearing XIP DST cache as a last resource...\n",
				    __func__, PTR_ERR(anchor));
		clear_xdst_table(net);
		return;
	}

	BUG_ON(!anchor);
	xdst_clean_anchor(anchor, from_type, from_xid);

	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(xdst_invalidate_redirect);

int xdst_def_hop_limit_input_method(struct sk_buff *skb)
{
	/* XXX We should test that forwarding is enable per struct net.
	 * See example in net/ipv6/ip6_output.c:ip6_forward.
	 */
	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	if (skb_xdst(skb)->input) {
		struct xiphdr *xiph = xip_hdr(skb);

		if (!xiph->hop_limit) {
			/* XXX Is this warning necessary? If so,
			 * shouldn't it report more?
			 */
			net_warn_ratelimited("%s: hop limit reached\n",
					     __func__);
			goto drop;
		}
		xiph->hop_limit--;
	}

	return dst_output(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
EXPORT_SYMBOL_GPL(xdst_def_hop_limit_input_method);

/* Principal routing */

static DEFINE_MUTEX(ppal_mutex);
static struct xip_route_proc *principals[XIP_MAX_XID_TYPES] __read_mostly;

/* Implement negative dependency for unknown principals. */
struct xip_negdep_route_proc {
	struct xip_route_proc rproc;
	struct xip_dst_anchor anchor;
};

static int negdep_deliver(struct xip_route_proc *rproc, struct net *net,
			  const u8 *xid, struct xia_xid *next_xid,
			  int anchor_index, struct xip_dst *xdst);

static struct xip_negdep_route_proc negdep_rproc = {
	.rproc = {
		.xrp_ppal_type = XIDTYPE_NAT, /* Dummy value. */
		.deliver = negdep_deliver,
	},
	.anchor = XDST_ANCHOR_INIT,
};

static int negdep_deliver(struct xip_route_proc *rproc, struct net *net,
			  const u8 *xid, struct xia_xid *next_xid,
			  int anchor_index, struct xip_dst *xdst)
{
	BUG_ON(rproc != &negdep_rproc.rproc);

	/* We obviously don't know how to route this principal, so just
	 * add negative dependency.
	 */
	xdst_attach_to_anchor(xdst, anchor_index, &negdep_rproc.anchor);
	return XRP_ACT_NEXT_EDGE;
}

/* Return struct xip_route_proc associated to @ty.
 *
 * If it doesn't exist, returns @negdep_rproc.rproc to deal with
 * negative dependency on unknown principals.
 *
 * Notice that this function never fails; this is an important property
 * assumed by callers.
 */
static inline struct xip_route_proc *get_an_rproc_rcu(const xid_type_t ty)
{
	int vxt = xt_to_vxt_rcu(ty);

	if (likely(vxt >= 0)) {
		struct xip_route_proc *rproc = rcu_dereference(principals[vxt]);
		/* We do not assume that @rproc must be available even
		 * when @vxt >= 0 because virtual XID types may exist
		 * before an @rproc is registered.
		 */
		if (likely(rproc))
			return rproc;
	}
	return &negdep_rproc.rproc;
}

static int deliver_rcu(struct net *net, const struct xia_xid *xid,
		       int anchor_index, struct xip_dst *xdst);

/* Find the anchor of @to.
 *
 * Due to degative dependency, there always is an anchor.
 *
 * An RCU read lock is necessary to call this function in order to avoid
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

	switch (deliver_rcu(net, to, 0, xdst)) {
	case XRP_ACT_NEXT_EDGE:
		/* We have a negative anchor. FALL THROUGH. */
	case XRP_ACT_FORWARD:
		/* We have a positive anchor. */
		anchor = xdst->anchors[0].anchor;
		BUG_ON(!anchor);
		break;

	case XRP_ACT_ABRUPT_FAILURE:
		anchor = ERR_PTR(-EPROTO);
		break;

	default:
		BUG();
	}

	xdst_free(xdst);
	return anchor;
}

int xip_add_router(struct xip_route_proc *rproc)
{
	xid_type_t ty = rproc->xrp_ppal_type;
	int vxt = xt_to_vxt(ty);

	if (unlikely(vxt < 0))
		return -EINVAL;

	mutex_lock(&ppal_mutex);

	if (principals[vxt]) {
		BUG_ON(principals[vxt]->xrp_ppal_type != ty);
		mutex_unlock(&ppal_mutex);
		return -EEXIST;
	}
	rcu_assign_pointer(principals[vxt], rproc);

	/* One has to synchronize RCU here because another thread may have
	 * a reference to @negdep_rproc obtained from get_an_rproc_rcu() to
	 * add a negative dependency for the previously unknown principal of
	 * type @ty, and that reference may be used after we go over
	 * @negdep_rproc.
	 */
	synchronize_rcu();

	/* From here, no dependency to principal of type @ty can be added to
	 * @negdep_rproc.
	 */

	/* Free all negative dependencies on unknown principals.
	 * One cannot just filter XDST entries whose type is @ty because
	 * those entries may have come from redirects, that is,
	 * their types are known and different of @ty.
	 */
	xdst_free_anchor(&negdep_rproc.anchor);

	mutex_unlock(&ppal_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(xip_add_router);

void xip_del_router(struct xip_route_proc *rproc)
{
	int vxt;

	BUG_ON(rproc == &negdep_rproc.rproc);
	vxt = xt_to_vxt(rproc->xrp_ppal_type);
	BUG_ON(vxt < 0);

	mutex_lock(&ppal_mutex);
	BUG_ON(principals[vxt] != rproc);
	RCU_INIT_POINTER(principals[vxt], NULL);
	mutex_unlock(&ppal_mutex);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(xip_del_router);

static int deliver_rcu(struct net *net, const struct xia_xid *xid,
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
		struct xip_route_proc *rproc;
		int rc;

		rproc = get_an_rproc_rcu(ty);
		/* Make sure that @rproc handles type @ty, or
		 * negative dependency.
		 */
		BUG_ON(!rproc || (rproc->xrp_ppal_type != ty &&
				  rproc->xrp_ppal_type != XIDTYPE_NAT));

		/* Consult principal. */
		rc = rproc->deliver(rproc, net, left_xid->xid_id,
			right_xid, anchor_index, xdst);

		switch (rc) {
		case XRP_ACT_NEXT_EDGE:
		case XRP_ACT_FORWARD:
		case XRP_ACT_ABRUPT_FAILURE:
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
				/* One cannot return XRP_ACT_NEXT_EDGE here
				 * because there would be no dependency.
				 */
				return XRP_ACT_ABRUPT_FAILURE;
			}
			left_xid = right_xid;
			right_xid = left_xid == &tmp_xids[0] ? &tmp_xids[1] :
				&tmp_xids[0];
			break;

		default:
			BUG();
		}
		done--;
	} while (done > 0);
	BUG_ON(xia_xidtop(xid, from, XIA_MAX_STRXID_SIZE) < 0);
	pr_err("BUG: Principal %u is looping too deep, this search started with %s, ignoring this route\n",
	       __be32_to_cpu(xid->xid_type), from);
	/* One cannot return XRP_ACT_NEXT_EDGE here
	 * because there would be no dependency.
	 */
	return XRP_ACT_ABRUPT_FAILURE;
}

/* XXX An ICMP-like error should be genererated here. */
static inline int xip_dst_not_supported(char *direction, struct sk_buff *skb)
{
	net_warn_ratelimited("XIP: not supported address for principal on direction %s\n",
			     direction);
	return dst_discard(skb);
}

static int xip_dst_not_supported_in(struct sk_buff *skb)
{
	return xip_dst_not_supported("in", skb);
}

static int xip_dst_not_supported_out(struct sock *sk, struct sk_buff *skb)
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
	struct net *net, struct xia_row *addr, const struct xia_row *xids_addr,
	u8 num_dst, u8 *plast_node, struct xia_row **plast_row, int input)
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

		*pkey_hash = hash_edges(xids_addr, *plast_row, input);

		xdst = find_xdst_rcu(net, *pkey_hash, xids_addr,
				     *plast_row, input);
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
		xip_select_edge(plast_node, *plast_row, chosen_edge);

		/* Let the garbagge collector know that @xdst is being used. */
		dst_use_noref(&xdst->dst, jiffies);

		*plast_row = next_row;
		xdst_hint = NULL;
		goto tail_call;

	case XDA_ERROR:
		/* Help debugging. */
		xip_select_edge(plast_node, *plast_row, chosen_edge);

		return &xdst_error;

	case XDA_DROP:
		*pdrop = 1;
		return NULL;

	case XDA_METHOD_AND_SELECT_EDGE:
		xip_select_edge(plast_node, *plast_row, chosen_edge);
		/* Fall through. */

	case XDA_METHOD:
		return xdst;

	default:
		BUG();
	}
}

/* The returned reference to a struct xip_dst already has been held.
 *
 * The XIDs in @xids_addr are considered instead of the ones in @addr.
 * Only the edges of @addr are marked, but edges are read from
 * @addr AND @xids_addr.
 * Therefore, they must start identical.
 * This is meant to allow the caller to pass @addr twice if it doesn't need
 * to have different XIDs.
 */
static struct xip_dst *choose_an_edge(struct net *net,
	struct xia_row *addr, const struct xia_row *xids_addr,
	u8 num_dst, u8 *plast_node, struct xia_row *last_row, int input)
{
	struct xip_dst *xdst;
	int drop, i;
	u32 key_hash = 0xDEADBEAF;

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
				 net, addr, xids_addr, num_dst,
				 plast_node, &last_row, input);
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
	set_xdst_key(xdst, xids_addr, last_row, input, key_hash);

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		u8 e = last_row->s_edge.a[i];
		const struct xia_xid *next_xid;

		if (is_empty_edge(e)) {
			/* An empty edge is supposed to be the last edge.
			 * The destination is unreachable.
			 */
			break;
		}
		next_xid = &xids_addr[e].s_xid;

		/* Is it forwardable? */
		switch (deliver_rcu(net, next_xid, i, xdst)) {
		case XRP_ACT_NEXT_EDGE:
			/* Check negative dependency. */
			BUG_ON(!xdst->anchors[i].anchor);
			break;
		case XRP_ACT_FORWARD:
			/* We found an edge that we can use to forward. */

			/* Check positive dependency. */
			BUG_ON(!xdst->anchors[i].anchor);

			xdst = add_xdst_rcu(net, xdst, i);
			goto tail_call;
		case XRP_ACT_ABRUPT_FAILURE:
			xdst_free(xdst);
			xdst = NULL;
			goto out;
		default:
			BUG();
		}
	}

	/* Destination is unreachable. */
	make_xdst_unreachable(net, xdst);
	xdst = add_xdst_rcu(net, xdst, -1);
	goto tail_call;

ret_xdst:
	xdst_hold(xdst);
	/* Let the garbagge collector know that @xdst is being used. */
	dst_use_noref(&xdst->dst, jiffies);
out:
	rcu_read_unlock();
	return xdst;
}

static struct xip_dst *xip_mark_addr2_and_get_dst(struct net *net,
	struct xia_row *addr, const struct xia_row *xids_addr,
	int num_dst, u8 *plast_node, int input)
{
	int last_node = *plast_node;
	struct xia_row *last_row = xip_last_row(addr, num_dst, last_node);
	struct xip_dst *xdst;

	/* Basis. */
	if (unlikely(is_it_a_sink(last_row, last_node, num_dst))) {
		/* This case is undefined in XIA,
		 * so we assume that @addr is broken.
		 */
		return ERR_PTR(-EINVAL);
	}

	/* Inductive step. */
	xdst = choose_an_edge(net, addr, xids_addr,
			      num_dst, plast_node, last_row, input);
	if (unlikely(!xdst))
		return ERR_PTR(-ENETUNREACH);

	return xdst;
}

struct xip_dst *xip_mark_addr_and_get_dst(struct net *net,
					  struct xia_row *addr, int num_dst,
					  u8 *plast_node, int input)
{
	return xip_mark_addr2_and_get_dst(net, addr, addr,
		num_dst, plast_node, input);
}
EXPORT_SYMBOL_GPL(xip_mark_addr_and_get_dst);

int xip_route_with_a_redirect(struct net *net, struct sk_buff *skb,
			      const struct xia_xid *next_xid, int chosen_edge,
			      int input)
{
	struct xiphdr *xiph = xip_hdr(skb);
	struct xia_addr redirected_addr;
	struct xia_row *ra_last_row;
	struct xip_dst *xdst;
	int e;

	/* Set @redirected_addr. */

	/* @redirected_addr is on our stack, so it can't overlap with
	 * @xiph->dst_addr. Therefore, memcpy() is safe.
	 */
	memcpy(redirected_addr.s_row, xiph->dst_addr,
	       xiph->num_dst * sizeof(struct xia_row));

	/* Overwrite previous XID. */
	ra_last_row = xip_last_row(redirected_addr.s_row,
				   xiph->num_dst, xiph->last_node);
	e = ra_last_row->s_edge.a[chosen_edge];
	redirected_addr.s_row[e].s_xid = *next_xid;

	xdst = xip_mark_addr2_and_get_dst(net,
		xiph->dst_addr, redirected_addr.s_row,
		xiph->num_dst, &xiph->last_node, input);
	if (IS_ERR(xdst))
		return PTR_ERR(xdst);
	skb_dst_set(skb, &xdst->dst);
	return 0;
}
EXPORT_SYMBOL_GPL(xip_route_with_a_redirect);

int xip_route(struct net *net, struct sk_buff *skb, int input)
{
	struct xiphdr *xiph = xip_hdr(skb);
	struct xip_dst *xdst = xip_mark_addr_and_get_dst(net,
		xiph->dst_addr, xiph->num_dst, &xiph->last_node, input);

	if (IS_ERR(xdst))
		return PTR_ERR(xdst);
	skb_dst_set(skb, &xdst->dst);
	return 0;
}
EXPORT_SYMBOL_GPL(xip_route);

/* Handling XIP incoming packets */

void skb_pull_xiphdr(struct sk_buff *skb)
{
	__skb_pull(skb, xip_hdr_len(xip_hdr(skb)));

	/* Point into the XIP datagram, just past the XIP header. */
	skb_reset_transport_header(skb);
}
EXPORT_SYMBOL_GPL(skb_pull_xiphdr);

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
	if (!skb_dst(skb) && xip_route(dev_net(dev), skb, 1))
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

/* Initialization */

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

	synchronize_rcu(); /* Required by xdst_free_anchor(). */
	xdst_free_anchor(&negdep_rproc.anchor);

	unregister_pernet_subsys(&xip_route_net_ops);
	kmem_cache_destroy(xip_dst_ops_template.kmem_cachep);
	xia_lock_table_finish(&anchor_locktbl);
}

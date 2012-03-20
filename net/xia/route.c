#include <linux/export.h>
#include <net/xia_route.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>
#include <net/ip_vs.h> /* Needed for skb_net. */

/*
 *	Route cache (DST)
 */

/* DO NOT use __read_mostly on this structure due to field pcpuc_entries. */
static struct dst_ops xip_dst_ops_template = {
	.family =		AF_XIA,
	.protocol =		cpu_to_be16(ETH_P_XIP),
	/* XXX This value should be reconsidered once struct xip_dst_table
	 * is redesigned. Using the same value of
	 * net/ipv6/route.c:ip6_dst_ops_template.gc_thresh.
	 */
	.gc_thresh =		1024,
/* TODO
	.gc =			rt_garbage_collect,
	.check =		ipv4_dst_check,
	.default_advmss =	ipv4_default_advmss,
	.mtu =			ipv4_mtu,
	.cow_metrics =		ipv4_cow_metrics,
	.destroy =		ipv4_dst_destroy,
	.ifdown =		ipv4_dst_ifdown,
	.negative_advice =	ipv4_negative_advice,
	.link_failure =		ipv4_link_failure,
	.update_pmtu =		ip_rt_update_pmtu,
	.local_out =		__ip_local_out,
	.neigh_lookup =		ipv4_neigh_lookup,
*/
};

static struct xip_dst *xip_dst_alloc(struct net *net, int flags)
{
	/* The only reason we use @net->loopback_dev instead of NULL is that
	 * function net/core/dst.c:___dst_free changes @dst->input and
	 * @dst->output to dst_discard, what would lead to disrruptions for
	 * a @xdst removed from the hash table, but still being used.
	 */
	struct xip_dst *xdst = dst_alloc(&net->xia.xip_dst_ops,
		net->loopback_dev, 0, 0, flags);
	if (xdst)
		memset(xdst->after_dst, 0, sizeof(*xdst) - sizeof(xdst->dst));
	return xdst;
}

static inline u32 start_edge_hash(int input)
{
	return !!input;
}

static inline void update_edge_hash(u32 *pkey_hash, struct xia_xid *xid)
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
static void xdst_lock_bucket(struct net *net, u32 bucket)
{
	xia_lock_table_lock(&xia_main_lock_table, hash_bucket(net, bucket));
}

/* Don't make this function inline, it's bigger than it looks like! */
static void xdst_unlock_bucket(struct net *net, u32 bucket)
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

static inline void xdst_free(struct xip_dst *xdst)
{
	dst_free(&xdst->dst);
}

static inline void xdst_rcu_free(struct xip_dst *xdst)
{
	call_rcu(&xdst->dst.rcu_head, dst_rcu_free);
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
			if (memcmp(xid, &addr[e].s_xid, sizeof(*xid)))
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
	/* The trailing `h' stands for hash, since it's pointing to
	 * entry in a bucket list.
	 */
	struct dst_entry *dsth;

	for (dsth = rcu_dereference(*dsthead(net, key_hash)); dsth;
		dsth = rcu_dereference(dsth->next)) {
		struct xip_dst *xdsth = container_of(dsth, struct xip_dst, dst);
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
		if (memcmp(xid1, xid2, sizeof(*xid1)))
			return 0;
	}
	return 1;
}

static struct xip_dst *find_xdst_locked(struct dst_entry **phead,
	struct xip_dst *xdst)
{
	struct dst_entry *dsth;
	for (dsth = *phead; dsth; dsth = dsth->next) {
		struct xip_dst *xdsth = container_of(dsth, struct xip_dst, dst);
		if (xdst_matches_xdst(xdsth, xdst))
			return xdsth;
	}
	return NULL;
}

/* XXX An ICMP-like error should be genererated here. */
static inline int xip_dst_unreachable(char *direction, struct sk_buff *skb)
{
	if (net_ratelimit())
		printk("XIP: unreachable destination on direction %s\n",
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

/* add_xdst_and_hold - If @xdst is unique in XIP DST table,
 *	hold a reference to it, and add it to the table.
 *
 *	If @xdst is not unique, that is, there already is an entry
 *	in the table with the same key, xdst_free @xtbl,
 *	hold a reference to the previous entry, and return it.
 *
 * NOTE
 *	@xdst must not be already in a list!
 */
static struct xip_dst *add_xdst_and_hold(struct net *net, struct xip_dst *xdst,
	u8 dig,	s8 select_edge)
{
	struct dst_entry **phead = dsthead(net, xdst->key_hash);
	struct xip_dst *prv_xdst;
	u32 bucket;

	/* @xdst must not be already in a list. */
	BUG_ON(xdst->dst.next);

	dig = !!dig;

	bucket = get_bucket(xdst);
	xdst_lock_bucket(net, bucket);
	prv_xdst = find_xdst_locked(phead, xdst);
	if (prv_xdst) {
		/* @xdst is NOT unique, @prv_xdst is an equivalent entry. */

		/* Use @prv_xdst. */
		xdst_hold(prv_xdst); /* Reference to be returned. */
		xdst_unlock_bucket(net, bucket);
		BUG_ON(prv_xdst->dig != dig);
		BUG_ON(prv_xdst->select_edge != select_edge);

		xdst_free(xdst);

		return prv_xdst;
	}
	
	/* @xdst is unique. */

	/* Add @xdst to the table. */
	xdst->dig = dig;
	xdst->select_edge = select_edge;
	xdst->dst.next = *phead;
	xdst_hold(xdst); /* Reference to be returned. */
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

		/* Given when/where clear_xdst_table is currently called,
		 * the lock below may be unnecessary, but there's no
		 * clear way to have a coded guarantee.
		 */
		xdst_lock_bucket(net, i);
		dsth = xdst_tbl->buckets[i];
		RCU_INIT_POINTER(xdst_tbl->buckets[i], NULL);
		xdst_unlock_bucket(net, i);

		while (dsth) {
			struct dst_entry *next = dsth->next;
			RCU_INIT_POINTER(dsth->next, NULL);
			xdst_rcu_free(container_of(dsth, struct xip_dst, dst));
			dsth = next;
		}
	}
}

/*
 *	Principal routing
 */

static DEFINE_SPINLOCK(ppal_lock);
static struct hlist_head principals[NUM_PRINCIPAL_HINT];

static inline struct hlist_head *ppalhead(xid_type_t ty)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(NUM_PRINCIPAL_HINT);
	return &principals[ty & (NUM_PRINCIPAL_HINT - 1)];
}

static struct xia_route_proc *find_rproc_locked(xid_type_t ty,
	struct hlist_head *head)
{
	struct xia_route_proc *rproc;
	struct hlist_node *p;
	hlist_for_each_entry(rproc, p, head, xrp_list)
		if (rproc->xrp_ppal_type == ty)
			return rproc;
	return NULL;
}

static struct xia_route_proc *find_rproc_rcu(xid_type_t ty,
	struct hlist_head *head)
{
	struct xia_route_proc *rproc;
	struct hlist_node *p;
	hlist_for_each_entry_rcu(rproc, p, head, xrp_list)
		if (rproc->xrp_ppal_type == ty)
			return rproc;
	return NULL;
}

int rt_add_router(struct xia_route_proc *rproc)
{
	xid_type_t ty = rproc->xrp_ppal_type;
	struct hlist_head *head = ppalhead(ty);
	int rc;

	spin_lock(&ppal_lock);

	rc = -ESRCH;
	if (find_rproc_locked(ty, head))
		goto out;
	hlist_add_head_rcu(&rproc->xrp_list, head);
	rc = 0;

out:
	spin_unlock(&ppal_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(rt_add_router);

void rt_del_router(struct xia_route_proc *rproc)
{
	spin_lock(&ppal_lock);
	hlist_del_rcu(&rproc->xrp_list);
	spin_unlock(&ppal_lock);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(rt_del_router);

static int local_deliver(struct net *net, const struct xia_xid *xid,
	struct xip_dst *xdst)
{
	xid_type_t ty = xid->xid_type;
	struct hlist_head *head = ppalhead(ty);
	struct xia_route_proc *rproc;
	int rc = -ESRCH;

	rcu_read_lock();
	rproc = find_rproc_rcu(ty, head);
	if (!rproc) {
		/* We don't know how to route this principal. */
		goto out;
	}
	
	rc = rproc->local_deliver(rproc, net, xid->xid_id, xdst);

out:
	rcu_read_unlock();
	return rc;
}

static int main_deliver(struct net *net, const struct xia_xid *xid,
	struct xip_dst *xdst)
{
	xid_type_t ty = xid->xid_type;
	const struct xia_xid *left_xid;
	struct xia_xid tmp_xids[2], *right_xid;
	int done = 4; /* Bound the number of redirects. */
	char from[XIA_MAX_STRXID_SIZE];

	left_xid = xid;
	right_xid = &tmp_xids[0];
	do {
		struct hlist_head *head;
		struct xia_route_proc *rproc;
		int rc;

		/* Consult principal. */
		head = ppalhead(left_xid->xid_type);
		rcu_read_lock();
		rproc = find_rproc_rcu(ty, head);
		if (!rproc) {
			/* We don't know how to root this principal. */
			rcu_read_unlock();
			return XRP_ACT_NEXT_EDGE;
		}
		rc = rproc->main_deliver(rproc, net, left_xid->xid_id,
			right_xid, xdst);
		rcu_read_unlock();

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
				pr_err("BUG: Principal %u is redirecting to "
					"itself, %s -> %s, "
					"ignoring this route\n",
					__be32_to_cpu(ty), from, to);
				dump_stack();
				return XRP_ACT_NEXT_EDGE;
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
	pr_err("BUG: Principal %u is looping too deep, "
		"this search started with %s, ignoring this route\n",
		__be32_to_cpu(ty), from);
	dump_stack();
	return XRP_ACT_NEXT_EDGE;
}

static inline void select_edge(u8 *plast_node, struct xia_row *last_row,
	int index)
{
	u8 *pe = &last_row->s_edge.a[index];
	xia_mark_edge(pe);
	*plast_node = *pe;
}

/* This function is intended to be only used in function chose_an_edge.
 * It is here to improve chose_an_edge's readability, and was based on
 * function net/xia/dag.c:xia_test_addr.
 */
static int are_edges_valid(struct xia_row *last_row, u8 last_node, u8 num_dst)
{
	int i;
	const u8 *edge = last_row->s_edge.a;
	u32 all_edges = __be32_to_cpu(last_row->s_edge.i);
	u32 bits = 0xffffffff;

	BUILD_BUG_ON(XIA_OUTDEGREE_MAX != 4);

	if (unlikely(is_any_edge_chosen(last_row))) {
		/* Since at least an edge of last_node has already
		 * been chosen, the address is corrupted.
		 */
		return 0;
	}

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		u8 e = *edge;
		if (e == XIA_EMPTY_EDGE) {
			if (unlikely(i == 0)) {
				/* chose_an_edge can't be called on sinks! */
				BUG();
			}
			return (all_edges & bits) == (XIA_EMPTY_EDGES & bits);
		}
		if (unlikely(e >= num_dst || /* Broken address. */
			/* This address isn't topologically ordered. */
			!is_a_strictly_before_b(last_node, e, num_dst))) {
			return 0;
		}

		edge++;
		bits >>= 8;
	}

	return 1;
}

/* The returned reference to a struct xip_dst already has been held. */
static struct xip_dst *chose_an_edge(struct net *net, struct xia_row *addr,
	u8 num_dst, u8 *plast_node, struct xia_row *last_row, int input)
{
	struct xip_dst *xdst;
	int last_node, i;
	u32 key_hash;

	/* Changing parameter of the tail call: @last_row. */

tail_call:
	if (unlikely(!are_edges_valid(last_row, *plast_node, num_dst)))
		return NULL;

	key_hash = hash_edges(addr, last_row, input);
	rcu_read_lock();
	xdst = find_xdst_rcu(net, key_hash, addr, last_row, input);
	if (xdst) {
		/* Cache hit, interpret @xdst. */

		i = xdst->select_edge;
		BUG_ON(i >= XIA_OUTDEGREE_MAX);

		if (xdst->dig) {
			rcu_read_unlock();
			BUG_ON(i < 0);

			/* Record that we're going for a recursion. */
			select_edge(plast_node, last_row, i);
			
			/* Notice that *plast_node was updated by
			 * select_edge above.
			 */
			last_row = &addr[*plast_node];
			goto tail_call;
		}
		if (i >= 0)
			select_edge(plast_node, last_row, i);
		xdst_hold(xdst);
		rcu_read_unlock();
		return xdst;
	}
	rcu_read_unlock();

	/* Handle DST cache miss. */

	/* Create @xdst. */
	xdst = xip_dst_alloc(net, 0);
	if (!xdst)
		return NULL;
	set_xdst_key(xdst, addr, last_row, input, key_hash);

	last_node = *plast_node;
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		u8 *pe = &last_row->s_edge.a[i];
		u8 e = *pe;
		struct xia_row *next_row;
		const struct xia_xid *next_xid;

		if (is_empty_edge(e)) {
			/* An empty edge is supposed to be the last edge.
			 * The destination is unreachable.
			 */
			break;
		}
		next_row = &addr[e];
		next_xid = &next_row->s_xid;

		/* Is it local? */
		if (is_it_a_sink(next_row, e, num_dst)) {
			if (!local_deliver(net, next_xid, xdst)) {
				/* @next_row is a local sink. */

				/* Identify delivery in the address. */
				select_edge(plast_node, last_row, i);

				return add_xdst_and_hold(net, xdst, 0, i);
			}

			/* This sink isn't local, perhaps it's forwardable. */
		} else if (local_deliver(net, next_xid, NULL)) {
			/* @next_row is NOT a sink, but it's local,
			 * so walk through it.
			 */

			/* Record that we're going for a recursion. */
			select_edge(plast_node, last_row, i);

			xdst_put(add_xdst_and_hold(net, xdst, 1, i));

			last_row = next_row;
			goto tail_call;
		}

		/* Is it forwardable? */
		switch (main_deliver(net, next_xid, xdst)) {
		case XRP_ACT_NEXT_EDGE:
			break;
		case XRP_ACT_FORWARD:
			/* We found an edge that we can use to forward. */
			return add_xdst_and_hold(net, xdst, 0, -1);
		default:
			BUG();
		}
	}

	xdst->dst.input = xip_dst_unreachable_in;
	xdst->dst.output = xip_dst_unreachable_out;
	return add_xdst_and_hold(net, xdst, 0, -1);
}

static int xip_route(struct sk_buff *skb, struct xia_row *addr,
		int num_dst, u8 *plast_node, int input)
{
	int last_node = *plast_node;
	struct xia_row *last_row;
	struct xip_dst *xdst;

	last_row = last_node == XIA_ENTRY_NODE_INDEX ?
		&addr[num_dst - 1] : &addr[last_node];

	/* Basis. */
	if (is_it_a_sink(last_row, last_node, num_dst)) {
		/* This case is undefined in XIA,
		 * so we assume that @addr is broken.
		 */
		return -EINVAL;
	}

	/* Inductive step. */
	xdst = chose_an_edge(skb_net(skb), addr, num_dst, plast_node,
		last_row, input);
	if (likely(xdst)) {
		skb_dst_set(skb, &xdst->dst);
		return 0;
	}
	return -EINVAL;
}

/*
 *	Handling XIP incoming packets
 */

struct xiphdr {
	u8		version;
	u8		next_hdr;
	__be16		payload_len;
	u8		hop_limit;
	u8		num_dst;
	u8		num_src;
	u8		last_node;
	struct xia_row	dst_addr[0];
};

static inline struct xiphdr *xip_hdr(const struct sk_buff *skb)
{
	return (struct xiphdr *)skb_network_header(skb);
}

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

	hdr_len = sizeof(struct xiphdr);
	if (!pskb_may_pull(skb, hdr_len))
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
	hdr_len += (xiph->num_dst + xiph->num_src) * sizeof(struct xia_row);
	if (!pskb_may_pull(skb, hdr_len))
		goto drop;

	tot_len = hdr_len + ntohs(xiph->payload_len);
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

static int route_netdev_event(struct notifier_block *nb,
	unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct net *net = dev_net(dev);
	/* @dst->dev is always equal to @net->loopback_dev in XIP.
	 * See function xip_dst_alloc for details.
	 */
	if (event == NETDEV_UNREGISTER && dev == net->loopback_dev)
		clear_xdst_table(net);
	return NOTIFY_DONE;
}

static struct notifier_block route_netdev_notifier __read_mostly = {
	.notifier_call = route_netdev_event,
};

int xia_route_init(void)
{
	int rc;

	rc = -ENOMEM;
	xip_dst_ops_template.kmem_cachep =
		KMEM_CACHE(xip_dst, SLAB_HWCACHE_ALIGN);
	if (!xip_dst_ops_template.kmem_cachep)
		goto out;

	rc = register_pernet_subsys(&xip_route_net_ops);
	if (rc)
		goto out_kmem_cache;

	rc = register_netdevice_notifier(&route_netdev_notifier);
	if (rc)
		goto pernet;

	dev_add_pack(&xip_packet_type);
	return 0;

pernet:
	unregister_pernet_subsys(&xip_route_net_ops);
out_kmem_cache:
	kmem_cache_destroy(xip_dst_ops_template.kmem_cachep);
out:
	return rc;
}

void xia_route_exit(void)
{
	dev_remove_pack(&xip_packet_type);
	unregister_netdevice_notifier(&route_netdev_notifier);
	unregister_pernet_subsys(&xip_route_net_ops);
	kmem_cache_destroy(xip_dst_ops_template.kmem_cachep);
}

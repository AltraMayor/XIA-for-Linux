#include <net/xia_route.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>
#include <linux/export.h>
#include <net/ip_vs.h> /* Needed for skb_net. */

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
	struct xia_dst *xdst)
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
	struct xia_dst *xdst)
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
				printk(KERN_ERR
					"BUG: Principal %u is redirecting to "
					"itself, %s -> %s, "
					"ignoring this route\n",
					__be32_to_cpu(ty), from, to);
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
	printk(KERN_ERR "BUG: Principal %u is looping too deep, "
		"this search started with %s, ignoring this route\n",
		__be32_to_cpu(ty), from);
	return XRP_ACT_NEXT_EDGE;
}

static void copy_edge(struct xia_dst *xdst, struct xia_row *addr,
	struct xia_row *last_row, int index)
{
	struct xia_xid *xid = &xdst->xids[index];
	u8 e = last_row->s_edge.a[index];
	if (is_empty_edge(e)) {
		BUILD_BUG_ON(XIDTYPE_NAT != 0);
		memset(xid, 0, sizeof(*xid));
	} else {
		memmove(xid, &addr[e].s_xid, sizeof(*xid));
	}
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

static struct xia_dst *chose_an_edge(struct net *net, struct xia_row *addr,
	u8 num_dst, u8 *plast_node, struct xia_row *last_row, int input)
{
	struct xia_dst *xdst;
	int last_node, i;

	/* Changing parameter of the tail call: @last_row. */

tail_call:
	if (unlikely(!are_edges_valid(last_row, *plast_node, num_dst)))
		return NULL;

	xdst = /* TODO DST cache lookup goes here. */ NULL;
	if (xdst) {
		/* Cache hit, interpret @xdst. */

		i = xdst->select_edge;
		BUG_ON(i >= XIA_OUTDEGREE_MAX);

		if (xdst->dig) {
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
		return xdst;
	}

	/* Handle DST cache miss. */

	/* TODO Create an xdst. */
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++)
		copy_edge(xdst, addr, last_row, i);
	xdst->input = input;

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

				/* Store the new @xdst for future uses. */
				xdst->dig = 0;
				xdst->select_edge = i;
				/* TODO Add xdst to table. */

				return xdst;
			}

			/* This sink isn't local, perhaps it's forwardable. */
		} else if (local_deliver(net, next_xid, NULL)) {
			/* @next_row is NOT a sink, but it's local,
			 * so walk through it.
			 */

			/* Record that we're going for a recursion. */
			select_edge(plast_node, last_row, i);

			/* Store the new @xdst for future uses. */
			xdst->dig = 1;
			xdst->select_edge = i;
			/* TODO Add xdst to table. */

			last_row = next_row;
			goto tail_call;
		}

		/* Is it forwardable? */
		switch (main_deliver(net, next_xid, xdst)) {
		case XRP_ACT_NEXT_EDGE:
			break;
		case XRP_ACT_FORWARD:
			/* We found an edge that we can use to forward. */

			/* Store the new @xdst for future uses. */
			xdst->dig = 0;
			xdst->select_edge = -1;
			/* TODO Add xdst to table. */
	
			return xdst;
		default:
			BUG();
		}
	}

	/* TODO An ICMP-like error should be
	 * genererated here.
	 */
	xdst->dig = 0;
	xdst->select_edge = -1;
	/* TODO Add DST cache entry. */
	return xdst;
}

static int xip_route(struct sk_buff *skb, struct xia_row *addr,
		int num_dst, u8 *plast_node, int input)
{
	int last_node = *plast_node;
	struct xia_row *last_row;
	struct xia_dst *xdst;

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
		/* TODO set xdst in skb. */
		return -EINVAL;
		/* return 0; */
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

int xia_route_init(void)
{
	dev_add_pack(&xip_packet_type);
	return 0;
}

void xia_route_exit(void)
{
	dev_remove_pack(&xip_packet_type);
}

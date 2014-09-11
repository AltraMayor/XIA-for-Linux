#ifndef _NET_XIA_ROUTE_H
#define _NET_XIA_ROUTE_H

#include <net/xia.h>

#define XIP_MIN_MTU	1024

struct xiphdr {
	__u8	version;	/* XIP version. */
	__u8	next_hdr;	/* Next header. */
	__be16	payload_len;	/* Length of the payload in bytes. */
	__u8	hop_limit;	/* Number of remaining hops allowed. */
	__u8	num_dst;	/* Number of rows of the destination address. */
	__u8	num_src;	/* Number of rows of the source address. */
	__u8	last_node;	/* Last Node visited. */

	struct xia_row	dst_addr[0];
	/*
	 * Destination address starts here, and is followed by
	 * the source address.
	 */
};

static inline int xip_hdr_size(int num_dst, int num_src)
{
	return sizeof(struct xiphdr) +
		(num_dst + num_src) * sizeof(struct xia_row);
}

static inline int xip_hdr_len(const struct xiphdr *xiph)
{
	return xip_hdr_size(xiph->num_dst, xiph->num_src);
}

static inline struct xia_row *xip_last_row(struct xia_row *addr,
	int num_dst, int last_node)
{
	return last_node == XIA_ENTRY_NODE_INDEX
		? &addr[num_dst - 1]
		: &addr[last_node];
}

static inline void xip_select_edge(__u8 *plast_node, struct xia_row *last_row,
	int index)
{
	__u8 *pe = &last_row->s_edge.a[index];
	*plast_node = *pe;
	xia_mark_edge(pe);
}

/* Max Payload Length. */
#define XIP_MAXPLEN	0xffff

#define MIN_XIP_HEADER	(sizeof(struct xiphdr) + sizeof(struct xia_row))
#define MAX_XIP_HEADER	(sizeof(struct xiphdr) + sizeof(struct xia_addr) * 2)

/* Min Maximum Segment Size (MSS). */
#define XIA_MIN_MSS	512

#define XIA_MAX_MSS	(XIP_MAXPLEN - MAX_XIP_HEADER)

enum XDST_ACTION {
	/* The XDST entry only selects an edge, that is, a new query with
	 * the new row is necessary.
	 */
	XDA_DIG = 0,

	/* An error will be reported to the source informing that
	 * the address is ill-constructed.
	 */
	XDA_ERROR,

	/* Packet will be silently dropped. */
	XDA_DROP,

	/* The packet will receive the DST entry associated to the XDST entry,
	 * that is, it's going to use the input and output methods.
	 */
	XDA_METHOD,

	/* Same as XDA_METHOD, but before handing the DST entry, select edge
	 * in the address.
	 */
	XDA_METHOD_AND_SELECT_EDGE,
};

/* For the definition of fields, see struct xip_dst. */
struct xip_dst_cachinfo {
	__u32			key_hash;
	__u8			input;
	__u8			passthrough_action;
	__u8			sink_action;
	__s8			chosen_edge;
};

#ifdef __KERNEL__

#include <net/dst.h>

static inline struct xiphdr *xip_hdr(const struct sk_buff *skb)
{
	return (struct xiphdr *)skb_network_header(skb);
}

struct xip_dst_anchor {
	struct hlist_head	heads[XIA_OUTDEGREE_MAX];
};

#define XDST_ANCHOR_INIT { \
	.heads[BUILD_BUG_ON_ZERO(XIA_OUTDEGREE_MAX != 4)] = HLIST_HEAD_INIT, \
	.heads[1] = HLIST_HEAD_INIT, \
	.heads[2] = HLIST_HEAD_INIT, \
	.heads[3] = HLIST_HEAD_INIT, }

/** xdst_init_anchor - initialize @anchor. */
void xdst_init_anchor(struct xip_dst_anchor *anchor);

/** xdst_free_anchor - release all struct xip_dst entries that are attached
 *			to @anchor.
 * NOTE
 *	IMPORTANT! Caller must RCU synch before calling this function.
 *
 *	This function does NOT free @anchor's memory itself, but
 *	attached structs to @anchor.
 *
 *	This function is meant to be called by the host of
 *	struct xip_dst_anchor, NOT by the code that manipulates
 *	struct xip_dst.
 */
void xdst_free_anchor(struct xip_dst_anchor *anchor);

/** xdst_invalidate_redirect - invalidate DST entries that rely on the redirect
 *	from <@from_type, @from_xid> to @to.
 *
 * NOTE
 *	IMPORTANT! Caller must RCU synch before calling this function.
 *
 *	When a principal routes using XRP_ACT_REDIRECT, it must use
 *	xdst_invalidate_redirect because the last XID in the redirecting chain
 *	is the one holding the anchor for the XIP DST entries that depend on
 *	<@from_type, @from_xid>.
 */
void xdst_invalidate_redirect(struct net *net, xid_type_t from_type,
	const u8 *from_xid, const struct xia_xid *to);

struct xip_dst {
	struct dst_entry	dst;

	char			after_dst[0];

	/* Since the lookup key is big, keeping its hash is handy
	 * to minimize comparision time.
	 */
	u32			key_hash;

	/* Lookup key. */
	struct xia_xid		xids[XIA_OUTDEGREE_MAX];
	/* If true, the traffic comes from a device. */
	u8			input;

	/* Action that is taken when the chosen edge is
	 * not a sink (passthrough), and when it is a sink.
	 * See enum XDST_ACTION for possible values.
	 */
	u8			passthrough_action;
	u8			sink_action;

	/* -1				None
	 *  0				First
	 *		...		...
	 * (XIA_OUTDEGREE_MAX - 1)	Last edge
	 */
	s8			chosen_edge;

	/* Extra information for dst.input and dst.output methods.
	 * This field should only be used by the principal that sets
	 * the positive anchor.
	 */
	void			*info;

	/* When the principal that sets the positive anchor needs to
	 * release something during the release of this structure,
	 * this principal should define this method;
	 * otherwise leave it undefined.
	 * A typical use is to release a memory block held at field @info;
	 * for this case, consider using def_ppal_destroy().
	 */
	void			(*ppal_destroy)(struct xip_dst *xdst);

	struct {
		struct xip_dst_anchor		*anchor;
		struct hlist_node		list_node;
	} anchors[XIA_OUTDEGREE_MAX];
};

/* Principals can assign xdst_def_hop_limit_input_method() to
 * @xdst->dst.input whenever all that is needed is to account for
 * hop limit.
 *
 * NOTE
 *	xdst_def_hop_limit_input_method() accounts for @xdst->input,
 *	so it can be used for both cases: _input_input and
 *	_output_input sufixes.
 */
int xdst_def_hop_limit_input_method(struct sk_buff *skb);

void xdst_attach_to_anchor(struct xip_dst *xdst, int index,
	struct xip_dst_anchor *anchor);

static inline struct xip_dst *dst_xdst(struct dst_entry *dst)
{
	return likely(dst) ? container_of(dst, struct xip_dst, dst) : NULL;
}

static inline struct xip_dst *skb_xdst(struct sk_buff *skb)
{
	return dst_xdst(skb_dst(skb));
}

static inline void xdst_hold(struct xip_dst *xdst)
{
	dst_hold(&xdst->dst);
}

static inline void xdst_put(struct xip_dst *xdst)
{
	dst_release(&xdst->dst);
}

/* In case all a principal wants is to release (i.e. calling kfree())
 * @xdst->info, this function should be used for convenience.
 * If you need a personalized method, check that your DST entries
 * are freed before your module is unloaded.
 */
void def_ppal_destroy(struct xip_dst *xdst);

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
 *	See xdst_rcu_free() to release after an RCU synch.
 */
int del_xdst_and_hold(struct xip_dst *xdst);

/* @xdst must not be in any DST table!
 *
 * This function waits for RCU synchonization before releasing @xdst.
 *
 * See del_xdst_and_hold() to remove @xdst from the DST table.
 *
 * IMPORTANT: given that this function will call xdst_free_begin(),
 * which, in turn, calls detach_anchors(), one would be better off checking
 * detach_anchors()'s calling constraints before using this function.
 */
void xdst_rcu_free(struct xip_dst *xdst);

extern struct dst_ops xip_dst_ops_template;
static inline struct net *dstops_net(struct dst_ops *ops)
{
	BUG_ON(ops == &xip_dst_ops_template);
	return likely(ops)
		? container_of(ops, struct net, xia.xip_dst_ops)
		: NULL;
}

static inline struct net *xdst_net(struct xip_dst *xdst)
{
	return dstops_net(xdst->dst.ops);
}

static inline int xip_dst_hoplimit(const struct dst_entry *dst)
{
	int hoplimit = dst_metric_raw(dst, RTAX_HOPLIMIT);
	/* XXX Implement a sysctl like sysctl_ip_default_ttl.
	 * See include/net/route.h:ip4_dst_hoplimit
	 */
	return hoplimit == 0 ? 128 : hoplimit;
}

/** clear_xdst_table - Clear all entries of XIP's DST table.
 *
 * ATTENTION
 *
 * The use of this function is discouraged, and should be reserved to only
 * handle extreme conditions like knowing that the DST table may be
 * inconsistent, but not being able to fix it due to lack of memory.
 * See xdst_invalidate_redirect() for an example.
 */
void clear_xdst_table(struct net *net);

/* Possible returns for method @main_deliver in struct xip_route_proc. */
enum XRP_ACTION {
	/* If an XID is unknown, this action forces another edge of
	 * an address to be considered, or to discard a packet if there's no
	 * more edges.
	 *
	 * IMPORTANT
	 * The callee must add @xdst at @anchor_index to an anchor before
	 * returning, in other workds, the callee must implement
	 * negative dependency.
	 */
	XRP_ACT_NEXT_EDGE = 0,

	/* Parameter @next_xid received a new XID which will, in fact, handle
	 * the edge being routed.
	 */
	XRP_ACT_REDIRECT,

	/* If an XID is known, fill up @xdst's fields to make it ready
	 * to forward packets.
	 *
	 * IMPORTANT
	 * The callee must add @xdst at @anchor_index to an anchor before
	 * returning, in other workds, the callee must implement
	 * positive dependency.
	 */
	XRP_ACT_FORWARD,

	/* The use of this action is discouraged, and should be used only
	 * when none of the previous actions are possible due to an extreme
	 * condition, for example lack of memory to conclude an operation.
	 */
	XRP_ACT_ABRUPT_FAILURE,
};

/* Route processing per principal. */
struct xip_route_proc {
	/* Principal type. */
	xid_type_t		xrp_ppal_type;

	/* The return must be enum XRP_ACTION.
	 * Only non-local XIDs go through this method.
	 */
	int (*deliver)(struct xip_route_proc *rproc, struct net *net,
		const u8 *xid, struct xia_xid *next_xid, int anchor_index,
		struct xip_dst *xdst);
};

/** xip_add_router - Add @rproc to XIA routing mechanism.
 *
 * RETURN
 *	Zero on success; otherwise a negative error number.
 *
 * NOTE
 *	The XID type must be registered with virtual XID types.
 */
int xip_add_router(struct xip_route_proc *rproc);

/** xip_add_router - Remove @rproc from XIA routing mechanism.
 *
 * NOTE
 *	The XID type must be registered with virtual XID types.
 */
void xip_del_router(struct xip_route_proc *rproc);

struct xip_dst *xip_mark_addr_and_get_dst(struct net *net,
	struct xia_row *addr, int num_dst, u8 *plast_node, int input);

/* A friendlier version of xip_mark_addr_and_get_dst(). */
int xip_route(struct net *net, struct sk_buff *skb, int input);

/* Route @skb assuming that the edge @choosen_edge of the last node
 * redirects to @next_xid.
 */
int xip_route_with_a_redirect(struct net *net, struct sk_buff *skb,
	const struct xia_xid *next_xid, int chosen_edge, int input);

void skb_pull_xiphdr(struct sk_buff *skb);

#endif	/* __KERNEL__ */
#endif	/* _NET_XIA_ROUTE_H */

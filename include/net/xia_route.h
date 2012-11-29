#ifndef _NET_XIA_ROUTE_H
#define _NET_XIA_ROUTE_H

#include <net/xia.h>

#ifdef __KERNEL__
#include <net/dst.h>
#include <net/netns/xia.h>
#endif

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

	/* Extra information for dst.input and dst.output methods. */
	void			*info;

	struct {
		struct xip_dst_anchor		*anchor;
		struct hlist_node		list_node;
	} anchors[XIA_OUTDEGREE_MAX];
};

void xdst_attach_to_anchor(struct xip_dst *xdst, int index,
	struct xip_dst_anchor *anchor);

static inline struct xip_dst *dst_xdst(struct dst_entry *dst)
{
	return dst ? container_of(dst, struct xip_dst, dst) : NULL;
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

extern struct dst_ops xip_dst_ops_template;
static inline struct net *dstops_net(struct dst_ops *ops)
{
	BUG_ON(ops == &xip_dst_ops_template);
	return container_of(ops, struct net, xia.xip_dst_ops);
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
	/* Attachment to bucket list. */
	struct hlist_node	xrp_list;

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
 * RETURN
 *	Zero on success; otherwise a negative error number.
 */
int xip_add_router(struct xip_route_proc *rproc);

/** xip_add_router - Remove @rproc from XIA routing mechanism. */
void xip_del_router(struct xip_route_proc *rproc);

struct xip_dst *xip_mark_addr_and_get_dst(struct net *net,
	struct xia_row *addr, int num_dst, u8 *plast_node, int input);

void skb_pull_xiphdr(struct sk_buff *skb);

#endif	/* __KERNEL__ */
#endif	/* _NET_XIA_ROUTE_H */

#ifndef _NET_XIA_ROUTE_H
#define _NET_XIA_ROUTE_H

#include <net/xia.h>
#include <net/dst.h>
#include <net/xia_dst_table.h>

#define XIP_MIN_MTU	1500

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

static inline struct xiphdr *xip_hdr(const struct sk_buff *skb)
{
	return (struct xiphdr *)skb_network_header(skb);
}

static inline int xip_hdr_len(const struct xiphdr *xiph)
{
	return sizeof(struct xiphdr) +
		(xiph->num_dst + xiph->num_src) * sizeof(struct xia_row);
}

/* Max Payload Length. */
#define XIP_MAXPLEN	0xffff

#define MAX_XIP_HEADER	(sizeof(struct xiphdr) + sizeof(struct xia_addr) * 2)

/* Min Maximum Segment Size (MSS). */
#define XIA_MIN_MSS	512

#define XIA_MAX_MSS	(XIP_MAXPLEN - MAX_XIP_HEADER)

struct xip_dst_anchor {
	struct hlist_head	heads[XIA_OUTDEGREE_MAX];
};

/* xdst_free_anchor - release all strunct xip_dst entries that are attached
 *			to @anchor.
 * NOTE
 *	IMPORTANT! Caller must RCU synch before calling this function.
 *
 *	This is function is meant to be called by the host of
 *	struct xip_dst_anchor, NOT by the code that manipulates
 *	struct xip_dst.
 */
void xdst_free_anchor(struct xip_dst_anchor *anchor);

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

	/* Same as XDA_METHOD, but before handing  the DST entry, select edge
	 * in the address.
	 */
	XDA_METHOD_AND_SELECT_EDGE,
};

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
	return container_of(dst, struct xip_dst, dst);
}

static inline struct xip_dst *skb_xdst(struct sk_buff *skb)
{
	return dst_xdst(skb_dst(skb));
}

/* Possible returns for method @main_deliver in struct xip_route_proc. */
enum XRP_ACTION {
	/* XID is unknown, this action forces another edge of an address be
	 * considered, or to discard a packet if there's no more edges.
	 */
	XRP_ACT_NEXT_EDGE = 0,

	/* Parameter @next_xid has received a new XID. */
	XRP_ACT_REDIRECT,

	/* @xdst was filled, the packet is ready to be forwarded. */
	XRP_ACT_FORWARD,
};

/* Route processing per principal. */
struct xip_route_proc {
	/* Attachment to bucket list. */
	struct hlist_node	xrp_list;

	/* Principal type. */
	xid_type_t		xrp_ppal_type;

	/* If @xid is local for this principal, this method adds @xdst to
	 * @xid's anchor, fills @xdst's fields, and return zero.
	 *
	 * Otherwise, this method returns -ENOENT. This implies a negative
	 * dependency.
	 */
	int (*local_deliver)(struct xip_route_proc *rproc, struct net *net,
		const u8 *xid, int anchor_index, struct xip_dst *xdst);

	/* The return must be enum XRP_ACTION.
	 * Only non-local XIDs go through this method.
	 */
	int (*main_deliver)(struct xip_route_proc *rproc, struct net *net,
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

/* Initilization functions. */
int xip_route_init(void);
void xip_route_exit(void);

#endif /* _NET_XIA_ROUTE_H */

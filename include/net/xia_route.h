#ifndef _NET_XIA_ROUTE_H
#define _NET_XIA_ROUTE_H

#include <net/xia.h>

struct xia_dst {
	struct dst_entry	dst;

	/* Lookup key. */
	struct xia_xid		xids[XIA_OUTDEGREE_MAX];
	/* If true, the traffic comes from a device. */
	u8			input;

	/* If true, this cache entry only selects an edge, that is,
	 * a new query with the new row is necessary.
	 * Otherwise, this cache entry is enough to route.
	 */
	u8			dig;

	/* Does this cache entry selects an edge?
	 * -1				None
	 *  0				First
	 *		...		...
	 * (XIA_OUTDEGREE_MAX - 1)	Last edge
	 */
	s8			select_edge;
};

/* Possible returns for method @main_deliver in struct xia_route_proc. */
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
struct xia_route_proc {
	/* Attachment to bucket list. */
	struct hlist_node	xrp_list;

	/* Principal type. */
	xid_type_t		xrp_ppal_type;

	/* If @xdst is NULL, @xid is not the sink of the packet, and
	 * this method just return zero if @xid is local for this principal,
	 * or -ESRCH to express that @xid isn't local.
	 * This is equivalent to chose, or not, an edge that is local, but
	 * not a sink.
	 *
	 * If @xdst is not NULL, @xid is a sink of the packet.
	 * If @xid is local for this principal, this method must fill @xdst
	 * properly, and return zero; otherwise just return -ESRCH.
	 */
	int (*local_deliver)(struct xia_route_proc *rproc, struct net *net,
		const u8 *xid, struct xia_dst *xdst);

	/* The return must be enum XRP_ACTION.
	 * Only non-local XIDs go through this method, but potentially sinks.
	 */
	int (*main_deliver)(struct xia_route_proc *rproc, struct net *net,
		const u8 *xid, struct xia_xid *next_xid, struct xia_dst *xdst);
};

/** rt_add_router - Add @rproc to XIA routing mechanism.
 * RETURN
 *	Zero on success; otherwise a negative error number.
 */
int rt_add_router(struct xia_route_proc *rproc);

/** rt_add_router - Remove @rproc from XIA routing mechanism. */
void rt_del_router(struct xia_route_proc *rproc);

/* Initilization functions. */
int xia_route_init(void);
void xia_route_exit(void);

#endif /* _NET_XIA_ROUTE_H */

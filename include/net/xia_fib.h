#ifndef _NET_XIA_FIB_H
#define _NET_XIA_FIB_H

/* Hash of principals.
 * It has to be power of 2.
 * Until one has a significant number of principals, or a way to instantiate
 * them in user land, this fixed arrary is enough.
 */
#define NUM_PRINCIPAL_HINT	128

#define XRTABLE_LOCAL_INDEX	0
#define XRTABLE_MAIN_INDEX	1
#define XRTABLE_MAX_INDEX	2

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/xia.h>

struct xia_fib_config {
	u8			xfc_dst_len;
	u8			xfc_tos;
	u8			xfc_table;
	/* See rtm_protocol in linux/rtnetlink.h */
	u8			xfc_protocol;

	/* See rtm_scope in linux/rtnetlink.h */
	u8			xfc_scope;
	/* See rtm_type in linux/rtnetlink.h */
	u8			xfc_type;
	u8			xfc_lladdr_len;
	/* 1 byte unused */

	u32			xfc_flags;

	struct xia_xid		*xfc_dst;
	struct net_device	*xfc_odev;
	struct xia_xid		*xfc_gw;
	u8			*xfc_lladdr;

	u32			xfc_nlflags;
	struct nl_info		xfc_nlinfo;
};

/* This structure is principal independent.
 * A bucket list for a give principal should define a struct that has it
 * as fist element. */
struct fib_xid {
	struct hlist_node	fx_list;		/* Bucket list.	*/
	u8			fx_xid[XIA_XID_MAX];	/* XID		*/
};

struct xia_ppal_rt_ops;

struct fib_xid_table {
	xid_type_t		fxt_ppal_type;
	const struct xia_ppal_rt_ops	*fxt_ops;
	struct hlist_head	*fxt_buckets;	/* Heads of bucket lists. */
	int			fxt_divisor;	/* Number of buckets.	  */
	int			fxt_count;	/* Number of entries.	  */
	struct hlist_node	fxt_list; /* To be added in fib_xia_rtable. */
};

/* Operations needed to maintain a routing table of a principal. */
struct xia_ppal_rt_ops {
	int (*newroute)(struct fib_xid_table *xtbl, struct xia_fib_config *cfg);
	int (*delroute)(struct fib_xid_table *xtbl, struct xia_fib_config *cfg);
	int (*dump_xid)(struct fib_xid *fxid, struct fib_xid_table *xtbl,
		struct fib_xia_rtable *rtbl, struct sk_buff *skb,
		struct netlink_callback *cb);
};

/* One could use principal type as part of the hash function and have only
 * a big hash table, but this would require a full table scan when a principal
 * were removed from the stack.
 */
struct fib_xia_rtable {
	int			tbl_id;
	struct hlist_head	ppal[NUM_PRINCIPAL_HINT];
};

static inline struct fib_xia_rtable *xia_fib_get_table(struct net *net, u32 id)
{
	switch (id) {
	case XRTABLE_LOCAL_INDEX:
		return net->xia.local_rtbl;
	case XRTABLE_MAIN_INDEX:
		return net->xia.main_rtbl;
	default:
		return NULL;
	}
}

/* Exported by fib_frontend.c */

void xia_fib_init(void);
void xia_fib_exit(void);

/* xia_register_pernet_subsys - is just a wrapper for
 * register_pernet_subsys in order to guarantee that
 * principals are initialized after XIA's core.
 */
int xia_register_pernet_subsys(struct pernet_operations *ops);

/* xia_unregister_pernet_subsys is here just to simplify changes when it
 * becomes necessary to do something while unregistering principals.
 */
static inline void xia_unregister_pernet_subsys(struct pernet_operations *ops)
{
	unregister_pernet_subsys(ops);
}

/* Exported by fib.c */

/* Create and return a fib_xia_rtable.
 * It returns the struct, otherwise NULL.
 */
struct fib_xia_rtable *create_xia_rtable(int tbl_id);

int destroy_xia_rtable(struct fib_xia_rtable *rtbl);

int init_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty,
			const struct xia_ppal_rt_ops *ops);

void end_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty);

/* Please don't call __xia_find_xtbl directly, prefer xia_find_xtbl. */
struct fib_xid_table *__xia_find_xtbl(struct fib_xia_rtable *rtbl,
				xid_type_t ty, struct hlist_head **phead);

static inline struct fib_xid_table *xia_find_xtbl(struct fib_xia_rtable *rtbl,
					xid_type_t ty)
{
	struct hlist_head *head;
	return __xia_find_xtbl(rtbl, ty, &head);
}

int fib_add_xid(struct fib_xid_table *xtbl, struct fib_xid *fxid);

void fib_rm_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid);
struct fib_xid *fib_rm_xid(struct fib_xid_table *xtbl, const char *xid);

/* Please don't call __xia_find_xid, prefer xia_find_xid. */
struct fib_xid *__xia_find_xid(struct fib_xid_table *xtbl,
	const char *xid, struct hlist_head **phead);

static inline struct fib_xid *xia_find_xid(struct fib_xid_table *xtbl,
	const char *xid)
{
	struct hlist_head *head;
	return __xia_find_xid(xtbl, xid, &head);
}

#endif /* __KERNEL__ */
#endif /* _NET_XIA_FIB_H */

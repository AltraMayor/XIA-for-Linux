#ifndef _NET_XIA_FIB_H
#define _NET_XIA_FIB_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/netlink.h>
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
	/* 2 bytes unused */

	u32			xfc_flags;

	struct xia_xid		*xfc_dst;
	u32			xfc_oif;
	struct xia_xid		*xfc_gw;
	u32			xfc_gw_len;
	
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

struct fib_xid_table {
	xid_type_t		fxt_ppal_type;
	struct hlist_head	*fxt_buckets;	/* Heads of bucket lists. */
	int			fxt_divisor;	/* Number of buckets.	  */
	int			fxt_count;	/* Number of entries.	  */
	struct hlist_node	fxt_list; /* To be added in fib_xia_rtable. */
};

/* Hash of principals.
 * It has to be power of 2.
 * Until one has a significant number of principals, or a way to instantiate
 * them in user land, this fixed arrary is enough.
 */
#define NUM_PRINCIPAL_HINT	128

/* One could use principal type as part of the hash function and have only
 * a big hash table, but this would require a full table scan when a principal
 * were removed from the stack.
 */
struct fib_xia_rtable {
	struct hlist_head ppal[NUM_PRINCIPAL_HINT];
};

#define XRTABLE_LOCAL_INDEX	0
#define XRTABLE_MAIN_INDEX	1
#define XRTABLE_MAX_INDEX	2

static inline struct fib_xia_rtable *xia_fib_get_table(struct net *net, u32 id)
{
	switch (id) {
	case XRTABLE_LOCAL_INDEX:
		return net->xia.main_rtbl;
	case XRTABLE_MAIN_INDEX:
		return net->xia.local_rtbl;
	default:
		return NULL;
	}
}

/* Exported by fib_frontend.c */

void xia_fib_init(void);

/* Create and return a fib_xia_rtable.
 * It returns the struct, otherwise NULL.
 */
struct fib_xia_rtable *create_xia_rtable(void);

int destroy_xia_rtable(struct fib_xia_rtable *rtbl);

#endif /* _NET_XIA_FIB_H */

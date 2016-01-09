#ifndef _NET_XIA_LIST_FIB_H
#define _NET_XIA_LIST_FIB_H

#ifdef __KERNEL__

#include <net/xia_fib.h>

struct list_fib_xid {
	/* Pointers to add this struct in bucket lists of an XID table. */
	struct hlist_node	fx_branch_list[2];
};

struct fib_xid_buckets {
	/* Heads of bucket lists. */
	struct hlist_head	*buckets;
	/* Number of buckets; it is a power of 2. */
	int			divisor;
};

struct list_fib_xid_table {
	/* Buckets. */
	struct fib_xid_buckets __rcu	*fxt_active_branch;
	struct fib_xid_buckets		fxt_branch[2];
	struct xia_lock_table		*fxt_locktbl;

	/* Used to minimize collisions on the lock table. */
	u32				fxt_seed;

	struct work_struct		fxt_rehash_work;
	/* Avoid writers while rehashing table. */
	rwlock_t			fxt_writers_lock;
};

/* Return index of @branch. One must use it to scan buckets. */
static inline int lxtbl_branch_index(struct list_fib_xid_table *lxtbl,
				     struct fib_xid_buckets *branch)
{
	if (branch == &lxtbl->fxt_branch[0])
		return 0;
	else if (branch == &lxtbl->fxt_branch[1])
		return 1;
	else
		BUG();
}

/*
 *	Exported by list_fib.c
 */

int list_fib_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg);

extern const struct xia_ppal_rt_iops xia_ppal_list_rt_iops;

#define XIP_LIST_FIB_REDIRECT_MAIN [XRTABLE_MAIN_INDEX] = {		\
	.newroute = fib_mrd_newroute,					\
	.delroute = list_fib_delroute,					\
	.dump_fxid = fib_mrd_dump,					\
	.free_fxid = fib_mrd_free,					\
}

#endif /* __KERNEL__ */
#endif /* _NET_XIA_LIST_FIB_H */

#ifndef _NET_XIA_LIST_FIB_H
#define _NET_XIA_LIST_FIB_H

#ifdef __KERNEL__

#include <net/xia_fib.h>

struct list_fib_xid {
	/* Pointers to add this struct in bucket lists of an XID table. */
	struct hlist_node	fx_branch_list[2];
};

/* Return index of @branch. One must use it to scan buckets. */
static inline int xtbl_branch_index(struct fib_xid_table *xtbl,
				    struct fib_xid_buckets *branch)
{
	if (branch == &xtbl->fxt_branch[0])
		return 0;
	else if (branch == &xtbl->fxt_branch[1])
		return 1;
	else
		BUG();
}

/* This function is meant to help writing functions for field newroute of
 * struct xia_ppal_rt_eops. It deals with NLM_F_* flags and flushes negative
 * anchors when a new entry is added.
 *
 * IMPORTANT
 *	This function may sleep.
 */
int list_fib_build_newroute(struct fib_xid *new_fxid,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg, int *padded);

/* NOTE
 *	If it returns ZERO, that is, success, the entry was deleted.
 */
int list_fib_default_local_main_delroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg);

int list_fib_mrd_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg);

#define XIP_LIST_FIB_REDIRECT_MAIN [XRTABLE_MAIN_INDEX] = {		\
	.newroute = list_fib_mrd_newroute,				\
	.delroute = list_fib_default_local_main_delroute,		\
	.dump_fxid = fib_mrd_dump,					\
	.free_fxid = fib_mrd_free,					\
}

/*
 *	Exported by list_fib.c
 */

/** list_init_xid_table - create an XID table in @ctx.
 * RETURN
 *	-EEXIST in case a FIB already exists.
 *	0 on success.
 * NOTE
 *	@ctx should not haven been added to @net yet; see xip_add_ppal_ctx().
 */
int list_init_xid_table(struct xip_ppal_ctx *ctx, struct net *net,
	struct xia_lock_table *locktbl, const xia_ppal_all_rt_eops_t all_eops);

void *list_fxid_ppal_alloc(size_t ppal_entry_size, gfp_t flags);

void __list_init_fxid(struct fib_xid *fxid, int table_id, int entry_type);

static inline void list_init_fxid(struct fib_xid *fxid, const u8 *xid,
	int table_id, int entry_type)
{
	__list_init_fxid(fxid, table_id, entry_type);
	memmove(fxid->fx_xid, xid, XIA_XID_MAX);
}

/** list_xia_find_xid_rcu - Find struct fib_xid in @xtbl that has key @xid.
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 * NOTE
 *	Caller must hold an RCU read lock to be safe against paralel calls to
 *	list_fib_add_fxid, list_fib_rm_fxid, and list_fib_rm_xid.
 */
struct fib_xid *list_xia_find_xid_rcu(struct fib_xid_table *xtbl,
	const u8 *xid);

/** list_xia_find_xid_lock - Find struct fib_xid in @xtbl that has key @xid.
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 * NOTE
 *	@parg always receives the bucket to be unlocked later.
 *	Caller must always unlock with list_fib_unlock_bucket afterwards.
 *
 *	Caller should never call this function with a lock on @xtbl
 *	already held because @xtbl uses a single table lock because
 *	this MAY lead to a deadlock.
 *	The same problem happens if it's called on different @xtbl's
 *	that share the same lock table.
 */
struct fib_xid *list_xia_find_xid_lock(void *parg, struct fib_xid_table *xtbl,
	const u8 *xid) __acquires(xip_bucket_lock);

/** list_xia_iterate_xids - Visit all XIDs in @xtbl.
 * NOTE
 *	The lock is held when @locked_callback is called.
 *	@locked_callback may remove the received @fxid it received.
 *
 *	If @locked_callback returns non-zero, the iterator is aborted.
 *
 * RETURN
 *	Zero if all xids were visited, or the value that @locked_callback
 *	returned when it aborted.
 */
int list_xia_iterate_xids(struct fib_xid_table *xtbl,
	int (*locked_callback)(struct fib_xid_table *xtbl,
		struct fib_xid *fxid, const void *arg),
	const void *arg);

/** list_xia_iterate_xids_rcu - Visit all XIDs in @xtbl.
 * NOTE
 *	The caller must hold an RCU read lock.
 *
 *	If @rcu_callback returns non-zero, the iterator is aborted.
 *
 * RETURN
 *	Zero if all xids were visited, or the value that @locked_callback
 *	returned when it aborted.
 */
int list_xia_iterate_xids_rcu(struct fib_xid_table *xtbl,
	int (*rcu_callback)(struct fib_xid_table *xtbl,
		struct fib_xid *fxid, const void *arg),
	const void *arg);

/** list_fib_add_fxid - Add @fxid into @xtbl.
 * RETURN
 *	-EEXIST in case an fxid with same XID is already in @xtbl.
 *	0 on success.
 */
int list_fib_add_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/** list_fib_add_fxid_locked - Same as list_fib_add_fxid, that is,
 *		it adds @fxid into @xtbl. However, list_fib_add_fxid_locked
 *		assumes that the lock is already held.
 * NOTE
 *	BE VERY CAREFUL when calling this function because if the needed lock
 *	is not held, it may corrupt @xtbl!
 */
int list_fib_add_fxid_locked(void *parg, struct fib_xid_table *xtbl,
	struct fib_xid *fxid);

/** list_fib_rm_fxid - Remove @fxid from @xtbl. */
void list_fib_rm_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/** list_fib_rm_fxid_locked - Same as list_fib_rm_fxid, but
 *			it assumes that the lock is already held.
 * NOTE
 *	BE VERY CAREFUL when calling this function because if the needed lock
 *	is not held, it may corrupt @xtbl!
 */
void list_fib_rm_fxid_locked(void *parg, struct fib_xid_table *xtbl,
	struct fib_xid *fxid);

/** list_fib_rm_xid - Remove @xid from @xtbl.
 * RETURN
 *	It returns the fxid with same @xid on success, otherwise NULL.
 */
struct fib_xid *list_fib_rm_xid(struct fib_xid_table *xtbl, const u8 *xid);

/** Replace @old_fxid with @new_fxid.
 *
 * NOTE
 *	@old_fxid MUST be in @xtbl.
 *
 *	@new_fxid MUST not be in any table.
 *
 *	@old_fix MUST be released by caller.
 *
 *	BE VERY CAREFUL when calling this function because if the needed lock
 *	is not held, it may corrupt @xtbl!
 */
void list_fib_replace_fxid_locked(struct fib_xid_table *xtbl,
	struct fib_xid *old_fxid, struct fib_xid *new_fxid);

void list_fib_unlock_bucket(struct fib_xid_table *xtbl, void *parg)
	__releases(xip_bucket_lock);

int list_fib_dump_xtbl_rcu(struct fib_xid_table *xtbl,
	 struct xip_ppal_ctx *ctx, struct sk_buff *skb,
	 struct netlink_callback *cb);

#endif /* __KERNEL__ */
#endif /* _NET_XIA_LIST_FIB_H */

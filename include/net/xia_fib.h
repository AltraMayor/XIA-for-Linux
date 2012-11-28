#ifndef _NET_XIA_FIB_H
#define _NET_XIA_FIB_H

#define XRTABLE_LOCAL_INDEX	0
#define XRTABLE_MAIN_INDEX	1
#define XRTABLE_MAX_INDEX	2

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/xia.h>
#include <net/xia_locktbl.h>

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
 * as fist element.
 */
struct fib_xid {
	/* Pointers to add this struct in bucket lists of an XID table. */
	struct hlist_node	fx_branch_list[2];

	/* XID */
	u8			fx_xid[XIA_XID_MAX];

	/* Once function free_fxid is called the following struct is used
	 * to support function call_rcu instead of synchronize_rcu.
	 */
	struct {
		struct fib_xid_table	*xtbl;
		struct rcu_head		rcu_head;
	} dead;
};

struct fib_xid_buckets {
	/* Heads of bucket lists. */
	struct hlist_head	*buckets;
	/* Number of buckets; it is a power of 2. */
	int			divisor;
};

struct fib_xid_table {
	atomic_t			refcnt;
	int				dead;
	struct work_struct		fxt_death_work;

	/* Useful annotation. */
	xid_type_t			fxt_ppal_type;	/* Principal type. */
	struct net			*fxt_net;	/* Context. */

	/* Buckets. */
	struct fib_xid_buckets __rcu	*fxt_active_branch;
	struct fib_xid_buckets		fxt_branch[2];
	struct xia_lock_table		*fxt_locktbl;

	/* Number of struct fib_xid's in this table. */
	atomic_t			fxt_count;

	/* Used to minimize collisions on the lock table. */
	u32				fxt_seed;

	struct work_struct		fxt_rehash_work;
	/* Avoid writers while rehashing table. */
	rwlock_t			fxt_writers_lock;

	const struct xia_ppal_rt_eops	*fxt_eops;
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

static inline struct net *xtbl_net(const struct fib_xid_table *xtbl)
{
	return xtbl->fxt_net;
}

struct xip_ppal_ctx {
	/* To be added in struct fib_xip_ppal_ctx's buckets. */
	struct hlist_node	xpc_list;

	/* Principal type. */
	xid_type_t		xpc_ppal_type;

	struct fib_xid_table	*xpc_xid_tables[XRTABLE_MAX_INDEX];
};

typedef void (*free_fxid_t)(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/* Operations implemented *e*xternally by the code that instantiates an xtbl. */
struct xia_ppal_rt_eops {
	/* RTNetlink support
	 * All callbacks are required.
	 */
	int (*newroute)(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
		struct xia_fib_config *cfg);
	int (*delroute)(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
		struct xia_fib_config *cfg);
	int (*dump_fxid)(struct fib_xid *fxid, struct fib_xid_table *xtbl,
		struct xip_ppal_ctx *ctx, struct sk_buff *skb,
		struct netlink_callback *cb);

	/* Callback to release dependencies.
	 *
	 * NOTE
	 *	This callback is always called after an RCU synch, or some
	 *	other guarantee such that no RCU reader has access to @fxid.
	 *
	 *	This callback may run in atomic context.
	 *
	 *	This callback must deallocate @fxid's memory, that is,
	 *	call a function	like kfree() on @fxid.
	 *
	 *	If this callback is defined with a function in kernel
	 *	module, consider calling flush_scheduled_work() when unloading
	 *	the module.
	 */
	free_fxid_t free_fxid;
};

/* This function is meant to be a used in field delroute of
 * struct xia_ppal_rt_eops when all that is needed is to remove the entry from
 * @xtbl, and free it.
 */
int fib_default_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg);

/*
 * Exported by fib_frontend.c
 */

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

/*
 *	Exported by fib.c
 */

/** init_fib_ppal_ctx - Initilize struct fib_xip_ppal_ctx.
 * RETURN
 *	It returns 0 on success.
 * NOTE
 *	This function is only meant to be used by XIP core.
 */
int init_fib_ppal_ctx(struct fib_xip_ppal_ctx *fib_ctx);

/** release_fib_ppal_ctx - release all resources associated to @fib_ctx.
 * NOTE
 *	This function is only meant to be used by XIP core.
 *
 *	The memory pointed by @fib_ctx is not released, it's caller's
 *	resposability to release it.
 *
 *	Caller must avoid races with xip_add_ppal_ctx and xip_del_ppal_ctx.
 *
 *	If @fib_ctx's xpc_xid_tables is not empty, there's a bug somewhere,
 *	and it must be fixed. A warning message is issue is case
 *	xpc_xid_tables is not empty.
 */
void release_fib_ppal_ctx(struct fib_xip_ppal_ctx *fib_ctx);

/** xip_init_ppal_ctx - initialize a struct xip_ppal_ctx.
 * RETURN
 *	It returns 0 on success.
 */
int xip_init_ppal_ctx(struct xip_ppal_ctx *ctx, xid_type_t ty);

/** xip_release_ppal_ctx - release resources held by @ctx.
 * NOTE
 *	@ctx cannot be in a list, and must not be active, that is, the caller
 *	must hold the only reference available to @ctx.
 *
 *	All @ctx's xpc_xid_tables are released (i.e. xtbl_put()) if they exist.
 */
void xip_release_ppal_ctx(struct xip_ppal_ctx *ctx);

/** xip_add_ppal_ctx - Add @ctx to @fib_ctx.
 * RETURN
 *	-ESRCH in case of another @ctx of same type already exists in @fib_ctx.
 *	0 on success.
 * NOTE
 *	This function does not take any lock because it is expected to be only
 *	called from struct pernet_operations' init method.
 */
int xip_add_ppal_ctx(struct fib_xip_ppal_ctx *fib_ctx,
	struct xip_ppal_ctx *ctx);

/** xip_del_ppal_ctx - Find a context of type @ty in @fib_ctx, and remove it.
 * NOTE
 *	This function does not take any lock because it is expected to be only
 *	called from struct pernet_operations' methods.
 *
 *	This function sleeps.
 */
struct xip_ppal_ctx *xip_del_ppal_ctx(struct fib_xip_ppal_ctx *fib_ctx,
	xid_type_t ty);

/** init_xid_table - create a new XID table of id @tbl_id in @ctx.
 * RETURN
 *	-ESRCH in case an XID table of id @tbl_id already exists.
 *	0 on success.
 * NOTE
 *	@ctx should be in no struct fib_xip_ppal_ctx!
 */
int init_xid_table(struct xip_ppal_ctx *ctx, u32 tbl_id, struct net *net,
	struct xia_lock_table *locktbl, const struct xia_ppal_rt_eops *eops);

/** xip_find_ppal_ctx_rcu - Find context of principal of type @ty.
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 * NOTE
 *	Caller must hold an RCU read lock.
 *
 *	If the caller must keep the reference after an RCU read lock,
 *	it must call xtbl_hold before releasing the RCU lock.
 *	Perhaps, xia_find_xtbl_hold() is a better choice.
 */
struct xip_ppal_ctx *xip_find_ppal_ctx_rcu(struct fib_xip_ppal_ctx *fib_ctx,
	xid_type_t ty);

/** xip_find_my_ppal_ctx - Find context of principal of type @ty.
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 * NOTE
 *	Caller must somehow insure that the context doesn't go away
 *	during the call of this function as well as afterwards.
 *
 *	Often, principals have to do nothing to insure it for
 *	their own context since they only remove their own context
 *	while they unload themselves.
 */
struct xip_ppal_ctx *xip_find_my_ppal_ctx(struct fib_xip_ppal_ctx *fib_ctx,
	xid_type_t ty);

/** xia_find_xtbl_hold - find XID table @tbl_id for principal @ty.
 * RETURN
 *	If the table is found, xtbl_hold() is called on it, and
 *	the reference returned. Otherwise, it returns NULL.
 * NOTE
 *	DO NOT forget to call xtb_put() afterwards!
 *
 *	If this function is called two or more times, and/or more fields
 *	of context are needed, consider to replace those calls with
 *	a single call to xip_find_ppal_ctx_rcu() or xip_find_my_ppal_ctx().
 */
struct fib_xid_table *xia_find_xtbl_hold(struct fib_xip_ppal_ctx *fib_ctx,
	xid_type_t ty, u32 tbl_id);

/* Don't call this function directly, call xtbl_put() instead. */
void xtbl_finish_destroy(struct fib_xid_table *xtbl);

static inline void xtbl_put(struct fib_xid_table *xtbl)
{
	if (atomic_dec_and_test(&xtbl->refcnt))
		xtbl_finish_destroy(xtbl);
}

static inline void xtbl_hold(struct fib_xid_table *xtbl)
{
	atomic_inc(&xtbl->refcnt);
}

static inline int xia_get_fxid_count(struct fib_xid_table *xtbl)
{
	return atomic_read(&xtbl->fxt_count);
}

void init_fxid(struct fib_xid *fxid, const u8 *xid);

/* NOTE
 *	@fxid must not be in any XID table!
 *
 *	This function doesn't sleep.
 */
void free_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/* NOTE
 *	@fxid must not be in any XID table!
 *
 *	Only use this function if you can guarantee that there's no more
 *	readers, for example calling synchronize_rcu(), otherwise use
 *	free_fxid.
 */
static inline void free_fxid_norcu(struct fib_xid_table *xtbl,
	struct fib_xid *fxid)
{
	xtbl->fxt_eops->free_fxid(xtbl, fxid);
}

/** xia_find_xid_rcu - Find struct fib_xid in @xtbl that has key @xid.
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 * NOTE
 *	Caller must hold an RCU read lock to be safe against paralel calls to
 *	fib_add_fxid, fib_rm_fxid, fib_rm_xid, and end_xid_table.
 */
struct fib_xid *xia_find_xid_rcu(struct fib_xid_table *xtbl, const u8 *xid);

/** xia_find_xid_lock - Find struct fib_xid in @xtbl that has key @xid.
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 * NOTE
 *	@pbucket always receives the bucket to be unlocked later.
 *	Caller must always unlock with fib_unlock_bucket afterwards.
 *
 *	Caller should never call this function with a lock on @xtbl
 *	already held because @xtbl uses a single table lock because
 *	this MAY lead to a deadlock.
 *	The same problem happens if it's called on different @xtbl's
 *	that share the same lock table.
 */
struct fib_xid *xia_find_xid_lock(u32 *pbucket, struct fib_xid_table *xtbl,
	const u8 *xid) __acquires(xip_bucket_lock);

/** xia_iterate_xids - Visit all XIDs in @xtbl.
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
int xia_iterate_xids(struct fib_xid_table *xtbl,
	int (*locked_callback)(struct fib_xid_table *xtbl,
		struct fib_xid *fxid, void *arg),
	void *arg);

/** fib_add_fxid - Add @fxid into @xtbl.
 * RETURN
 *	-ESRCH in case an fxid with same XID is already in @xtbl.
 *	0 on success.
 */
int fib_add_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/** fib_add_fxid_locked - Same as fib_add_fxid, that is,
 *		it adds @fxid into @xtbl. However, fib_add_fxid_locked
 *		assumes that the lock is already held.
 * NOTE
 *	BE VERY CAREFUL when calling this function because if the needed lock
 *	is not held, it may corrupt @xtbl!
 */
int fib_add_fxid_locked(u32 bucket, struct fib_xid_table *xtbl,
	struct fib_xid *fxid);

/** fib_rm_fxid - Remove @fxid from @xtbl. */
void fib_rm_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/** fib_rm_fxid_locked - Same as fib_rm_fxid, but
 *			it assumes that the lock is already held.
 * NOTE
 *	BE VERY CAREFUL when calling this function because if the needed lock
 *	is not held, it may corrupt @xtbl!
 */
void fib_rm_fxid_locked(u32 bucket, struct fib_xid_table *xtbl,
	struct fib_xid *fxid);

/** fib_rm_xid - Remove @xid from @xtbl.
 * RETURN
 *	It returns the fxid with same @xid on success, otherwise NULL.
 */
struct fib_xid *fib_rm_xid(struct fib_xid_table *xtbl, const u8 *xid);

void fib_unlock_bucket(struct fib_xid_table *xtbl, u32 bucket)
	__releases(xip_bucket_lock);

/** fib_alloc_xip_upd - allocate an struct deferred_xip_update.
 * RETURN
 *	Return the struct on success; otherwise NULL.
 * NOTE
 *	The returned struct must be consumed by a call to either
 *	fib_free_xip_upd(), or fib_defer_xip_upd().
 */
struct deferred_xip_update;
struct deferred_xip_update *fib_alloc_xip_upd(gfp_t flags);

static inline void fib_free_xip_upd(struct deferred_xip_update *def_upd)
{
	kfree(def_upd);
}

/** xip_defer_update - Defer the execution of
 *			@f(@net, &{copy(@type), copy(@id)}) for
 *			an RCU synchronization.
 * NODE
 *	@f may (likely) be called from an atomic context.
 *
 *	If caller of this function resides in a kernel module,
 *	it should consider to call rcu_barrier() while unloading its module.
 *
 *	@def_upd is consumed once this function returns.
 */
typedef void (*fib_deferred_xid_upd_t)(struct net *net, struct xia_xid *xid);
void fib_defer_xip_upd(struct deferred_xip_update *def_upd,
	fib_deferred_xid_upd_t f, struct net *net,
	xid_type_t type, const u8 *id);

#endif /* __KERNEL__ */
#endif /* _NET_XIA_FIB_H */

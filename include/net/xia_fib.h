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
#include <net/xia_route.h>

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
	u8			xfc_protoinfo_len;

	u32			xfc_flags;

	struct xia_xid		*xfc_dst;
	struct net_device	*xfc_odev;
	struct xia_xid		*xfc_gw;
	u8			*xfc_lladdr;
	void			*xfc_protoinfo;

	u32			xfc_nlflags;
	struct nl_info		xfc_nlinfo;
};

/* This structure should be the first element of a struct that specializes
 * for a given principal.
 * This structure is principal independent.
 */
struct fib_xid {
	/* Pointers to add this struct in bucket lists of an XID table. */
	struct hlist_node	fx_branch_list[2];

	/* XID */
	u8			fx_xid[XIA_XID_MAX];

	/* Identifies the routing table this entry belongs. For example,
	 * local (XRTABLE_LOCAL_INDEX), or main (XRTABLE_MAIN_INDEX).
	 * See XRTABLE_*_INDEX constants.
	 */
	u8			fx_table_id;

	/* Type of this entry.
	 * This type field is meant to help principals to have different
	 * kinds of entries in a same XID tabel. 
	 */
	u8			fx_entry_type;

	/* FREE 2 bytes. */

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

	const struct xia_ppal_rt_eops	*all_eops;
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

static inline xid_type_t xtbl_ppalty(const struct fib_xid_table *xtbl)
{
	return xtbl->fxt_ppal_type;
}

static inline struct net *xtbl_net(const struct fib_xid_table *xtbl)
{
	return xtbl->fxt_net;
}

/* XIP Principal Context. */
struct xip_ppal_ctx {
	/* Principal type. */
	xid_type_t		xpc_ppal_type;

	struct fib_xid_table	*xpc_xtbl;
	struct xip_dst_anchor	negdep;
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

typedef struct xia_ppal_rt_eops xia_ppal_all_rt_eops_t[XRTABLE_MAX_INDEX];

/* This function is meant to help writing functions for field newroute of
 * struct xia_ppal_rt_eops. It deals with NLM_F_* flags and flushes negative
 * anchors when a new entry is added. 
 *
 * IMPORTANT
 *	This function may sleep.
 */
int fib_build_newroute(struct fib_xid *new_fxid, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg, int *padded);

/* NOTE
 *	If it returns ZERO, that is, success, the entry was deleted.
 */
int fib_build_delroute(int tbl_id, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg);

/* These functions are meant to be a used in field delroute of
 * struct xia_ppal_rt_eops when all that is needed is to remove the entry from
 * @xtbl, and free it.
 */
int fib_default_local_delroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg);
int fib_default_main_delroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg);

/* In case newroute and/or delroute are not supported, use these functions. */
int fib_no_newroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg);
#define fib_no_delroute	fib_no_newroute

/* Do not call these functions, use macro XIP_FIB_REDIRECT_MAIN instead. */
int fib_mrd_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg);
int fib_mrd_dump(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct xip_ppal_ctx *ctx, struct sk_buff *skb,
	struct netlink_callback *cb);
void fib_mrd_free(struct fib_xid_table *xtbl, struct fib_xid *fxid);

#define XIP_FIB_REDIRECT_MAIN [XRTABLE_MAIN_INDEX] = {			\
	.newroute = fib_mrd_newroute,					\
	.delroute = fib_default_main_delroute,				\
	.dump_fxid = fib_mrd_dump,					\
	.free_fxid = fib_mrd_free,					\
}

/* If the macro XIP_FIB_REDIRECT_MAIN is being used, call this function
 * to redirect to @fxid.
 */
void fib_mrd_redirect(struct fib_xid *fxid, struct xia_xid *next_xid);

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

/** init_fib_ppal_ctx - Initilize field @fib_ctx in @net.
 *
 * RETURN
 *	It returns 0 on success.
 *
 * NOTE
 *	This function is only meant to be used by XIP core.
 *
 *	Caller must avoid races with xip_add_ppal_ctx and xip_del_ppal_ctx.
 */
int init_fib_ppal_ctx(struct net *net);

/** release_fib_ppal_ctx - release all resources associated to field @fib_ctx
 *				in @net.
 *
 * NOTE
 *	This function is only meant to be used by XIP core.
 *
 *	Caller must avoid races with xip_add_ppal_ctx and xip_del_ppal_ctx.
 *
 *	If there is still a principal context in @net, there's a bug somewhere,
 *	and it must be fixed; a warning message is issued in this case.
 */
void release_fib_ppal_ctx(struct net *net);

/** xip_init_ppal_ctx - initialize a struct xip_ppal_ctx.
 *
 * RETURN
 *	It returns 0 on success.
 */
int xip_init_ppal_ctx(struct xip_ppal_ctx *ctx, xid_type_t ty);

/** xip_release_ppal_ctx - release resources held by @ctx.
 *
 * IMPORTANT
 *	Caller must RCU synch before calling this function.
 *	This usually is not a problem because @ctx is often obtained as
 *	the return of xip_del_ppal_ctx(), which always synchronizes.
 *
 * NOTE
 *	@ctx cannot be in a list, and must not be active, that is, the caller
 *	must hold the only reference available to @ctx.
 *
 *	All @ctx's xpc_xid_tables are released (i.e. xtbl_put()) if they exist.
 */
void xip_release_ppal_ctx(struct xip_ppal_ctx *ctx);

/** xip_add_ppal_ctx - Add @ctx to @net.
 *
 * RETURN
 *	-EINVAL in case @ctx->xpc_ppal_type doesn't have a virtual XID type.
 *	-EEXIST in case of another @ctx of same type already exists in @net.
 *	Zero on success.
 *
 * NOTE
 *	This function does not take any lock because it is expected to be only
 *	called from struct pernet_operations' init method.
 *
 *	The XID type must be registered with virtual XID types.
 */
int xip_add_ppal_ctx(struct net *net, struct xip_ppal_ctx *ctx);

/** xip_del_ppal_ctx - Find a context of type @ty in @net, and remove it.
 *
 * NOTE
 *	This function does not take any lock because it is expected to be only
 *	called from struct pernet_operations' methods.
 *
 *	The XID type must be registered with virtual XID types.
 *
 *	This function may sleep.
 */
struct xip_ppal_ctx *xip_del_ppal_ctx(struct net *net, xid_type_t ty);

/** init_xid_table - create a new XID table in @ctx.
 * RETURN
 *	-EEXIST in case an XID table already exists.
 *	0 on success.
 * NOTE
 *	@ctx should not haven been added to @net yet; see xip_add_ppal_ctx().
 */
int init_xid_table(struct xip_ppal_ctx *ctx, struct net *net,
	struct xia_lock_table *locktbl, const xia_ppal_all_rt_eops_t all_eops);

/** xip_find_ppal_ctx_vxt_rcu - Find context of principal of virtual type @vxt.
 *
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 *
 * NOTE
 *	Caller must hold an RCU read lock.
 *
 *	If the caller must keep the reference after an RCU read lock,
 *	it must call xtbl_hold before releasing the RCU lock.
 */
static inline struct xip_ppal_ctx *xip_find_ppal_ctx_vxt_rcu(struct net *net,
	int vxt)
{
	return rcu_dereference(net->xia.fib_ctx[vxt]);
}

/** xip_find_ppal_ctx_rcu - Find context of principal of type @ty.
 *
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 *
 * NOTE
 *	Caller must hold an RCU read lock.
 *
 *	If the caller must keep the reference after an RCU read lock,
 *	it must call xtbl_hold before releasing the RCU lock.
 */
struct xip_ppal_ctx *xip_find_ppal_ctx_rcu(struct net *net, xid_type_t ty);

/** xip_find_my_ppal_ctx_vxt - Find context of principal of virtual type @vxt.
 *
 * RETURN
 *	It returns the struct on success, otherwise NULL.
 *
 * NOTE
 *	Caller must somehow insure that the context doesn't go away
 *	during the call of this function as well as afterwards.
 *
 *	Often, principals have to do nothing to ensure it for
 *	their own context since they only remove their own context
 *	while they unload themselves.
 */
static inline struct xip_ppal_ctx *xip_find_my_ppal_ctx_vxt(struct net *net,
	int vxt)
{
	return net->xia.fib_ctx[vxt];
}

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

void __init_fxid(struct fib_xid *fxid, int table_id, int entry_type);

static inline void init_fxid(struct fib_xid *fxid, const u8 *xid, int table_id,
	int entry_type)
{
	__init_fxid(fxid, table_id, entry_type);
	memmove(fxid->fx_xid, xid, XIA_XID_MAX);
}

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
	xtbl->all_eops[fxid->fx_table_id].free_fxid(xtbl, fxid);
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
		struct fib_xid *fxid, const void *arg),
	const void *arg);

/** xia_iterate_xids_rcu - Visit all XIDs in @xtbl.
 * NOTE
 *	The caller must hold an RCU read lock.
 *
 *	If @rcu_callback returns non-zero, the iterator is aborted.
 *
 * RETURN
 *	Zero if all xids were visited, or the value that @locked_callback
 *	returned when it aborted.
 */
int xia_iterate_xids_rcu(struct fib_xid_table *xtbl,
	int (*rcu_callback)(struct fib_xid_table *xtbl,
		struct fib_xid *fxid, const void *arg),
	const void *arg);

/** fib_add_fxid - Add @fxid into @xtbl.
 * RETURN
 *	-EEXIST in case an fxid with same XID is already in @xtbl.
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

/** Replace @old_fxid to @new_fxid.
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
void fib_replace_fxid_locked(struct fib_xid_table *xtbl,
	struct fib_xid *old_fxid, struct fib_xid *new_fxid);

void fib_unlock_bucket(struct fib_xid_table *xtbl, u32 bucket)
	__releases(xip_bucket_lock);

/** fib_alloc_dnf - allocate an struct xip_deferred_negdep_flush.
 * RETURN
 *	Return the struct on success; otherwise NULL.
 * NOTE
 *	The returned struct must be consumed by a call to either
 *	fib_free_dnf(), or fib_defer_dnf().
 */
struct xip_deferred_negdep_flush;
struct xip_deferred_negdep_flush *fib_alloc_dnf(gfp_t flags);

static inline void fib_free_dnf(struct xip_deferred_negdep_flush *dnf)
{
	kfree(dnf);
}

/** fib_defer_dnf - Defer the flush of negdep anchor in context of principal
 *			of type @ty in @net for an RCU synchronization.
 *
 * NOTE
 *	@dnf is consumed once this function returns.
 */
void fib_defer_dnf(struct xip_deferred_negdep_flush *dnf,
	struct net *net, xid_type_t ty);

#endif /* __KERNEL__ */
#endif /* _NET_XIA_FIB_H */

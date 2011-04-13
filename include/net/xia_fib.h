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
 * The true size of this structure varies depending on the type of FIB
 * it is used for. When using struct fib_xid as a member in other structs,
 * it must be placed last.
 */
struct fib_xid {
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

	/* Extra data that needs to go with every struct fib_xid,
	 * depending on the type of FIB used.
	 */
	void			*fx_data[0];
};

struct fib_xid_table {
	atomic_t			refcnt;
	int				dead;
	struct work_struct		fxt_death_work;

	/* Useful annotation. */
	xid_type_t			fxt_ppal_type;	/* Principal type. */
	struct net			*fxt_net;	/* Context. */

	/* Number of struct fib_xid's in this table. */
	atomic_t			fxt_count;

	const struct xia_ppal_rt_eops	*all_eops;
	const struct xia_ppal_rt_iops	*all_iops;

	/* Extra data that needs to go with every struct fib_xid_table,
	 * depending on the type of FIB used.
	 */
	void				*fxt_data[0];
};

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

/* Operations implemented *i*nternally by the code that instantiates an xtbl. */
struct xia_ppal_rt_iops {
	/* All callbacks are required. */

	/* xtbl_init - initialize FIB-specific memory. */
	int (*xtbl_init)(struct xip_ppal_ctx *ctx, struct net *net,
		struct xia_lock_table *locktbl,
		const xia_ppal_all_rt_eops_t all_eops,
		const struct xia_ppal_rt_iops *all_iops);

	/* xtbl_death_work - destroy FIB-specific memory.
	 *
	 * NOTE
	 *	Don't call this function directly,
	 *	call xtbl_put() instead.
	 */
	void (*xtbl_death_work)(struct work_struct *work);

	/* fxid_ppal_alloc - allocate FIB entry-specific memory.
	 *
	 * NOTE
	 *	Parameter @ppal_entry_size represents the size of the
	 *	base principal-specific structure that needs to be
	 *	allocated, which should be added to the size of
	 *	the FIB-specific memory.
	 */
	void *(*fxid_ppal_alloc)(size_t ppal_entry_size, gfp_t flags);

	/* fxid_init - initialize the fields of an @fxid.
	 *
	 * NOTE
	 *	Don't call this function directly,
	 *	call the general purpose fxid_init().
	 *
	 *	This function assumes that the XID in @fxid, @table_id, and
	 *	@entry_type have already been error-checked.
	 */
	void (*fxid_init)(struct fib_xid *fxid, int table_id, int entry_type);

	/** fxid_find_rcu - Find struct fib_xid in @xtbl that has key @xid.
	 *
	 * RETURN
	 *	It returns the struct on success, otherwise NULL.
	 * NOTE
	 *	Caller must hold a read lock (RCU or otherwise) to be safe
	 *	against parallel calls to fxid_add, fxid_rm, and xid_rm.
	 */
	struct fib_xid *(*fxid_find_rcu)(struct fib_xid_table *xtbl,
		const u8 *xid);

	/** fxid_find_lock - Find struct fib_xid in @xtbl that has key @xid.
	 *
	 * RETURN
	 *	It returns the struct on success, otherwise NULL.
	 * NOTE
	 *	@parg is a pointer to FIB-specific data.
	 *	Caller must always unlock with fib_unlock afterwards.
	 *
	 *	Caller should never call this function with a lock on @xtbl
	 *	already held because @xtbl uses a single table lock because
	 *	this MAY lead to a deadlock.
	 *	The same problem happens if it's called on different @xtbl's
	 *	that share the same lock table.
	 */
	struct fib_xid *(*fxid_find_lock)(void *parg,
					  struct fib_xid_table *xtbl,
					  const u8 *xid);

	/** iterate_xids - Visit all XIDs in @xtbl.
	 * NOTE
	 *	The lock is held when @locked_callback is called.
	 *	@locked_callback may remove the received @fxid it received.
	 *
	 *	If @locked_callback returns non-zero, the iterator is aborted.
	 *
	 * RETURN
	 *	Zero if all xids were visited, or the value that
	 *	@locked_callback returned when it aborted.
	 */
	int (*iterate_xids)(struct fib_xid_table *xtbl,
		int (*locked_callback)(struct fib_xid_table *xtbl,
				       struct fib_xid *fxid,
				       const void *arg),
		const void *arg);

	/** iterate_xids_rcu - Visit all XIDs in @xtbl.
	 *
	 * NOTE
	 *	The caller must hold an RCU read lock.
	 *
	 *	If @rcu_callback returns non-zero, the iterator is aborted.
	 *
	 * RETURN
	 *	Zero if all xids were visited, or the value that
	 *	@locked_callback returned when it aborted.
	 */
	int (*iterate_xids_rcu)(struct fib_xid_table *xtbl,
		int (*rcu_callback)(struct fib_xid_table *xtbl,
				    struct fib_xid *fxid,
				    const void *arg),
		const void *arg);

	/** fxid_add - Add @fxid to @xtbl.
	 *
	 * RETURN
	 *	-EEXIST in case an fxid with same XID is already in @xtbl.
	 *	0 on success.
	 */
	int (*fxid_add)(struct fib_xid_table *xtbl, struct fib_xid *fxid);

	/** fxid_add_locked - Same as fxid_add, that is, it adds @fxid
	 *	to @xtbl. However, fxid_add_locked assumes that the lock
	 *	is already held.
	 * NOTE
	 *	BE VERY CAREFUL when calling this function because if the
	 *	needed lock is not held, it may corrupt @xtbl!
	 */
	int (*fxid_add_locked)(void *parg, struct fib_xid_table *xtbl,
		struct fib_xid *fxid);

	/** fxid_rm - Remove @fxid from @xtbl. */
	void (*fxid_rm)(struct fib_xid_table *xtbl, struct fib_xid *fxid);

	/** fxid_rm_locked - Same as fxid_rm, but it assumes that
	 *	the lock is already held.
	 *
	 * NOTE
	 *	BE VERY CAREFUL when calling this function because if the
	 *	needed lock is not held, it may corrupt @xtbl!
	 */
	void (*fxid_rm_locked)(void *parg, struct fib_xid_table *xtbl,
		struct fib_xid *fxid);

	/** xid_rm - Remove @xid from @xtbl.
	 *
	 * RETURN
	 *	It returns the fxid with same @xid on success, otherwise NULL.
	 */
	struct fib_xid *(*xid_rm)(struct fib_xid_table *xtbl, const u8 *xid);

	/** fxid_replace_locked - Replace @old_fxid with @new_fxid.
	 *
	 * NOTE
	 *	@old_fxid MUST be in @xtbl.
	 *
	 *	@new_fxid MUST not be in any table.
	 *
	 *	@old_fix MUST be released by caller.
	 *
	 *	BE VERY CAREFUL when calling this function because if the
	 *	needed lock is not held, it may corrupt @xtbl!
	 */
	void (*fxid_replace_locked)(struct fib_xid_table *xtbl,
		struct fib_xid *old_fxid, struct fib_xid *new_fxid);

	/** fib_unlock - Unlock some FIB-specific data.
	 *
	 * NOTE
	 *	Callers of fxid_find_lock must call this function
	 *	with an appropriate parameter when done with
	 *	the FIB entry.
	 */
	void (*fib_unlock)(struct fib_xid_table *xtbl, void *parg);

	/** fib_newroute - build a new FIB entry.
	 *
	 * NOTE
	 *	This function is meant to help writing functions for field
	 *	newroute of struct xia_ppal_rt_eops. It deals with NLM_F_*
	 *	flags and flushes negative anchors when a new entry is added.
	 *
	 * IMPORTANT
	 *	This function may sleep.
	 */
	int (*fib_newroute)(struct fib_xid *new_fxid,
		struct fib_xid_table *xtbl, struct xia_fib_config *cfg,
		int *padded);

	/** fib_delroute - delete a FIB entry.
	 *
	 * NOTE
	 *	If it returns ZERO, that is, success, the entry was deleted.
	 */
	int (*fib_delroute)(struct xip_ppal_ctx *ctx,
		struct fib_xid_table *xtbl, struct xia_fib_config *cfg);

	/** xtbl_dump_rcu - dump all entries in the given @xtbl.
	 *
	 * NOTE
	 *	This function may use the dumproute field of
	 *	struct xia_ppal_rt_eops to dump each entry.
	 *
	 * RETURN
	 *	Zero if all entries were dumped, or a negative
	 *	value on error.
	 */
	int (*xtbl_dump_rcu)(struct fib_xid_table *xtbl,
		struct xip_ppal_ctx *ctx, struct sk_buff *skb,
		struct netlink_callback *cb);

};

int all_fib_newroute(struct fib_xid *new_fxid, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg, int *padded, void *plock);

int all_fib_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg, void *plock);

/* In case newroute and/or delroute are not supported,
 * use these functions to avoid adding more empty functions in
 * the kernel's image.
 */
int fib_no_newroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg);
#define fib_no_delroute	fib_no_newroute

/* Main entries that only redirect */

struct fib_xid_redirect_main {
	struct xia_xid		gw;

	/* WARNING: @common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		common;
};

static inline struct fib_xid_redirect_main *fxid_mrd(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_redirect_main, common)
		: NULL;
}

/* Do not call these functions, use a macro of
 * the form XIP_*_FIB_REDIRECT_MAIN instead.
 */
int fib_mrd_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg);

int fib_mrd_dump(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct xip_ppal_ctx *ctx, struct sk_buff *skb,
	struct netlink_callback *cb);
void fib_mrd_free(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/* If a macro XIP_*_FIB_REDIRECT_MAIN is being used, call this function
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

void xtbl_destroy(struct fib_xid_table *xtbl);

static inline void xtbl_put(struct fib_xid_table *xtbl)
{
	if (atomic_dec_and_test(&xtbl->refcnt))
		xtbl_destroy(xtbl);
}

static inline void xtbl_hold(struct fib_xid_table *xtbl)
{
	atomic_inc(&xtbl->refcnt);
}

static inline int xia_get_fxid_count(struct fib_xid_table *xtbl)
{
	return atomic_read(&xtbl->fxt_count);
}

static inline void fxid_init(struct fib_xid_table *xtbl,
	struct fib_xid *fxid, const u8 *xid, int table_id, int entry_type)
{
	memmove(fxid->fx_xid, xid, XIA_XID_MAX);
	xtbl->all_iops->fxid_init(fxid, table_id, entry_type);
}

/* NOTE
 *	@fxid must not be in any XID table!
 *
 *	This function doesn't sleep.
 */
void fxid_free(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/* NOTE
 *	@fxid must not be in any XID table!
 *
 *	Only use this function if you can guarantee that there's no more
 *	readers, for example calling synchronize_rcu(), otherwise use
 *	free_fxid.
 */
static inline void fxid_free_norcu(struct fib_xid_table *xtbl,
	struct fib_xid *fxid)
{
	xtbl->all_eops[fxid->fx_table_id].free_fxid(xtbl, fxid);
}

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

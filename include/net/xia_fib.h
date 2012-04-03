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
	union {
		/* Pointers to add this struct in bucket lists of
		 * an XID table.
		 */
		struct hlist_node	fx_branch_list[2];

		/* Once function free_fxid is called, the previous struct
		 * isn't being used anymore, so the following struct is used
		 * to support function call_rcu instead of synchronize_rcu.
		 */
		struct {
			struct fib_xid_table	*xtbl;
			struct rcu_head		rcu_head;
		} dead;
	} u;

	/* XID */
	u8			fx_xid[XIA_XID_MAX];
};

struct fib_xid_buckets {
	/* Heads of bucket lists. */
	struct hlist_head	*buckets;
	/* Number of buckets; it is a power of 2. */
	int			divisor;
	/* Index of this branch. One should use it to scan struct fib_xid's. */
	int			index;
};

struct fib_xid_table {
	atomic_t			refcnt;
	int				dead;
	struct work_struct 		fxt_death_work;

	/* Principal type. */
	xid_type_t			fxt_ppal_type;

	/* Context. */
	struct net			*fxt_net;

	/* Buckets. */
	struct fib_xid_buckets __rcu	*fxt_active_branch;
	struct fib_xid_buckets		fxt_branch[2];
	struct xia_lock_table		*fxt_locktbl;

	/* Number of struct fib_xid's in this table. */
	atomic_t			fxt_count;

	/* Used to minimize collisions on the lock table. */
	u32				fxt_seed;

	struct work_struct 		fxt_rehash_work;
	/* Avoid writers while rehashing table. */
	rwlock_t			fxt_writers_lock;

	/* To be added in fib_xia_rtable. */
	struct hlist_node		fxt_list;

	const struct xia_ppal_rt_eops	*fxt_eops;
};

static inline struct net *xtbl_net(struct fib_xid_table *xtbl)
{
	return xtbl->fxt_net;
}

typedef void (*free_fxid_t)(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/* Operations implemented *e*xternally by the code that instantiates an xtbl. */
struct xia_ppal_rt_eops {
	/* RTNetlink support
	 * All callbacks are required.
	 */
	int (*newroute)(struct fib_xid_table *xtbl, struct xia_fib_config *cfg);
	int (*delroute)(struct fib_xid_table *xtbl, struct xia_fib_config *cfg);
	int (*dump_fxid)(struct fib_xid *fxid, struct fib_xid_table *xtbl,
		struct fib_xia_rtable *rtbl, struct sk_buff *skb,
		struct netlink_callback *cb);

	/* Optional callback to release dependencies.
	 * Please notice that this callback runs in atomic context.
	 * If this callback is defined, consider call flush_scheduled_work()
	 * when unloading your module.
	 */
	free_fxid_t free_fxid;
};

/* This function is meant to be a used in field delroute of
 * struct xia_ppal_rt_eops when all that is needed is to remove the entry from
 * @xtbl, and free it.
 */
int fib_default_delroute(struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg);

/* XIA Routing Table
 *
 * One could use principal type as part of the hash function and have only
 * a big hash table, but this would require a full table scan when a principal
 * were removed from the stack.
 */
struct fib_xia_rtable {
	/* Context. */
	struct net		*tbl_net;
	int			tbl_id;

	struct hlist_head	ppal[NUM_PRINCIPAL_HINT];
	struct rcu_head		rcu_head;
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

/*
 * Exported by fib_frontend.c
 */

int xia_fib_init(void);
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

/*
 *	Exported by fib.c
 */

/** create_xia_rtable - Create and return a fib_xia_rtable.
 * RETURN
 * 	It returns the struct on success, otherwise NULL.
 * NOTE
 *	Caller should use RCU_INIT_POINTER to assign it to the final pointer.
 */
struct fib_xia_rtable *create_xia_rtable(struct net *net, int tbl_id);

/** destroy_xia_rtable - destroy @rtbl.
 * NOTE
 *	Caller must hold lock to avoid races with init_xid_table and
 *	end_xid_table.
 */
void destroy_xia_rtable(struct fib_xia_rtable **prtbl);

/** init_xid_table - create a new XID table for type @ty.
 * RETURN
 *	-ESRCH in case an XID table for type @ty already exists.
 *	0 on success.
 * NOTE
 *	Caller must hold lock to avoid races with end_xid_table and
 *	destroy_xia_rtable.
 */
int init_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty,
	struct xia_lock_table *locktbl, const struct xia_ppal_rt_eops *eops);

/** end_xid_table - terminate XID table for type @ty.
 * NOTE
 *	Caller must hold lock to avoid races with init_xid_table and
 *	destroy_xia_rtable.
 */
void end_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty);

/** xia_find_xtbl_rcu - Find XID table of type @ty.
 * RETURN
 * 	It returns the struct on success, otherwise NULL.
 * NOTE
 * 	Caller must hold an RCU read lock to be safe against paralel calls to
 * 	init_xid_table, end_xid_table, and destroy_xia_rtable.
 *
 *	If the caller must keep the reference after an RCU read lock,
 *	it must call xtbl_hold before releasing the RCU lock.
 */
struct fib_xid_table *xia_find_xtbl_rcu(struct fib_xia_rtable *rtbl,
	xid_type_t ty);

/* Don't call this function directly, use xtbl_put instead. */
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

struct fib_xid_table *xia_find_xtbl_hold(struct fib_xia_rtable *rtbl,
	xid_type_t ty);

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
void free_fxid_norcu(struct fib_xid_table *xtbl, struct fib_xid *fxid);

/** xia_find_xid_rcu - Find struct fib_xid in @xtbl that has key @xid.
 * RETURN
 * 	It returns the struct on success, otherwise NULL.
 * NOTE
 * 	Caller must hold an RCU read lock to be safe against paralel calls to
 * 	fib_add_fxid, fib_rm_fxid, fib_rm_xid, and end_xid_table.
 */
struct fib_xid *xia_find_xid_rcu(struct fib_xid_table *xtbl, const u8 *xid);

/** xia_find_xid_lock - Find struct fib_xid in @xtbl that has key @xid.
 * RETURN
 * 	It returns the struct on success, otherwise NULL.
 * NOTE
 * 	@pbucket always receives the bucket to be unlocked later.
 *	Caller must always unlock with fib_unlock_bucket afterwards.
 *
 *	Caller should never call this function with a lock on @xtbl
 *	already held because @xtbl uses a single table lock because
 *	this MAY lead to a deadlock.
 *	The same problem happens if it's called on different @xtbl's
 *	that share the same lock table.
 */
struct fib_xid *xia_find_xid_lock(u32 *pbucket, struct fib_xid_table *xtbl,
	const u8 *xid);

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

/** fib_add_fxid_locked - Same as fib_add_fxid, but
 *		it assumes that the lock is already held.Add @fxid into @xtbl.
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
 * 	It returns the fxid with same @xid on success, otherwise NULL.
 */
struct fib_xid *fib_rm_xid(struct fib_xid_table *xtbl, const u8 *xid);

void fib_unlock_bucket(struct fib_xid_table *xtbl, u32 bucket);

#endif /* __KERNEL__ */
#endif /* _NET_XIA_FIB_H */

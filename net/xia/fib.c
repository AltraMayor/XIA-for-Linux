#include <linux/export.h>
#include <linux/jhash.h>
#include <net/xia_locktbl.h>
#include <net/xia_vxidty.h>
#include <net/xia_fib.h>

/*
 *	Lock tables
 */

static inline u32 xtbl_hash_mix(struct fib_xid_table *xtbl)
{
	return (u32)(((unsigned long)xtbl) >> L1_CACHE_SHIFT);
}

/* @divisor *MUST* be a power of 2. */
static inline u32 get_bucket(const u8 *xid, int divisor)
{
	BUILD_BUG_ON(XIA_XID_MAX != sizeof(u32) * 5);
	return jhash2((const u32 *)xid, 5, 0) & (divisor - 1);
}

static inline u32 hash_bucket(struct fib_xid_table *xtbl, u32 bucket)
{
	return xtbl_hash_mix(xtbl) * bucket + xtbl->fxt_seed;
}

/* Don't make this function inline, it's bigger than it looks like! */
static void bucket_lock(struct fib_xid_table *xtbl, u32 bucket)
	__acquires(bucket)
{
	xia_lock_table_lock(xtbl->fxt_locktbl, hash_bucket(xtbl, bucket));
}

/* Don't make this function inline, it's bigger than it looks like! */
static void bucket_unlock(struct fib_xid_table *xtbl, u32 bucket)
	__releases(bucket)
{
	xia_lock_table_unlock(xtbl->fxt_locktbl, hash_bucket(xtbl, bucket));
}

/*
 *	Principal context
 */

int init_fib_ppal_ctx(struct net *net)
{
	memset(net->xia.fib_ctx, 0, sizeof(net->xia.fib_ctx));
	return 0;
}

int xip_init_ppal_ctx(struct xip_ppal_ctx *ctx, xid_type_t ty)
{
	ctx->xpc_ppal_type = ty;
	ctx->xpc_xtbl = NULL;
	xdst_init_anchor(&ctx->negdep);
	return 0;
}
EXPORT_SYMBOL_GPL(xip_init_ppal_ctx);

void xip_release_ppal_ctx(struct xip_ppal_ctx *ctx)
{
	struct fib_xid_table *xtbl;

	/* It's assumed that synchronize_rcu() has been called before. */
	xdst_free_anchor(&ctx->negdep);

	xtbl = ctx->xpc_xtbl;
	if (xtbl) {
		ctx->xpc_xtbl = NULL;
		xtbl_put(xtbl);
	}
}
EXPORT_SYMBOL_GPL(xip_release_ppal_ctx);

int xip_add_ppal_ctx(struct net *net, struct xip_ppal_ctx *ctx)
{
	xid_type_t ty = ctx->xpc_ppal_type;
	int vxt = xt_to_vxt(ty);

	if (unlikely(vxt < 0))
		return -EINVAL;

	if (net->xia.fib_ctx[vxt]) {
		BUG_ON(net->xia.fib_ctx[vxt]->xpc_ppal_type != ty);
		return -EEXIST;
	}
	rcu_assign_pointer(net->xia.fib_ctx[vxt], ctx);
		
	return 0;
}
EXPORT_SYMBOL_GPL(xip_add_ppal_ctx);

struct xip_ppal_ctx *xip_del_ppal_ctx(struct net *net, xid_type_t ty)
{
	int vxt = xt_to_vxt(ty);
	struct xip_ppal_ctx *ctx;

	BUG_ON(vxt < 0);
	ctx = net->xia.fib_ctx[vxt];
	BUG_ON(!ctx);
	BUG_ON(ctx->xpc_ppal_type != ty);
	RCU_INIT_POINTER(net->xia.fib_ctx[vxt], NULL);
	synchronize_rcu();
	return ctx;
}
EXPORT_SYMBOL_GPL(xip_del_ppal_ctx);

struct xip_ppal_ctx *xip_find_ppal_ctx_rcu(struct net *net, xid_type_t ty)
{
	int vxt = xt_to_vxt_rcu(ty);
	return likely(vxt >= 0)
		? xip_find_ppal_ctx_vxt_rcu(net, vxt)
		: NULL;
}
EXPORT_SYMBOL_GPL(xip_find_ppal_ctx_rcu);

/*
 *	Routing tables
 */

/* This function must be called in process context due to virtual memory. */
static int alloc_buckets(struct fib_xid_buckets *branch, size_t num)
{
	struct hlist_head *buckets;
	size_t size = sizeof(*buckets) * num;
	buckets = kmalloc(size, GFP_KERNEL);
	if (unlikely(!buckets)) {
		buckets = vmalloc(size);
		if (!buckets)
			return -ENOMEM;
		pr_warn("XIP %s: the kernel is running out of memory and/or memory is too fragmented. Allocated virtual memory for now; hopefully, it's going to gracefully degrade packet forwarding performance.\n",
			__func__);
	}
	memset(buckets, 0, size);
	branch->buckets = buckets;
	branch->divisor = num;
	return 0;
}

/* This function must be called in process context due to virtual memory. */
static inline void free_buckets(struct fib_xid_buckets *branch)
{
	if (unlikely(is_vmalloc_addr(branch->buckets)))
		vfree(branch->buckets);
	else
		kfree(branch->buckets);
	branch->buckets = NULL;
	branch->divisor = 0;
}

/* XTBL_INITIAL_DIV must be a power of 2. */
#define XTBL_INITIAL_DIV 1

static void xtbl_death_work(struct work_struct *work);
static void rehash_work(struct work_struct *work);

int init_xid_table(struct xip_ppal_ctx *ctx, struct net *net,
	struct xia_lock_table *locktbl, const xia_ppal_all_rt_eops_t all_eops)
{
	struct fib_xid_table *new_xtbl;
	struct fib_xid_buckets *abranch;
	int rc;

	if (ctx->xpc_xtbl) {
		rc = -EEXIST;
		goto out; /* Duplicate. */
	}

	rc = -ENOMEM;
	new_xtbl = kzalloc(sizeof(*new_xtbl), GFP_KERNEL);
	if (!new_xtbl)
		goto out;
	abranch = &new_xtbl->fxt_branch[0];
	new_xtbl->fxt_active_branch = abranch;
	BUILD_BUG_ON_NOT_POWER_OF_2(XTBL_INITIAL_DIV);
	if (alloc_buckets(abranch, XTBL_INITIAL_DIV))
		goto new_xtbl;

	new_xtbl->fxt_ppal_type = ctx->xpc_ppal_type;
	new_xtbl->fxt_net = net;
	hold_net(net);
	new_xtbl->fxt_locktbl = locktbl;
	atomic_set(&new_xtbl->fxt_count, 0);
	get_random_bytes(&new_xtbl->fxt_seed, sizeof(new_xtbl->fxt_seed));
	INIT_WORK(&new_xtbl->fxt_rehash_work, rehash_work);
	rwlock_init(&new_xtbl->fxt_writers_lock);
	new_xtbl->all_eops = all_eops;

	atomic_set(&new_xtbl->refcnt, 1);
	INIT_WORK(&new_xtbl->fxt_death_work, xtbl_death_work);
	ctx->xpc_xtbl = new_xtbl;

	rc = 0;
	goto out;

new_xtbl:
	kfree(new_xtbl);
out:
	return rc;
}
EXPORT_SYMBOL_GPL(init_xid_table);

void __init_fxid(struct fib_xid *fxid, int table_id, int entry_type)
{
	INIT_HLIST_NODE(&fxid->fx_branch_list[0]);
	INIT_HLIST_NODE(&fxid->fx_branch_list[1]);

	BUILD_BUG_ON(XRTABLE_MAX_INDEX > 0x100);
	BUG_ON(table_id >= XRTABLE_MAX_INDEX);
	fxid->fx_table_id = table_id;

	BUG_ON(entry_type > 0xff);
	fxid->fx_entry_type = entry_type;

	fxid->dead.xtbl = NULL;
}
EXPORT_SYMBOL_GPL(__init_fxid);

static void __free_fxid(struct rcu_head *head)
{
	struct fib_xid *fxid =
		container_of(head, struct fib_xid, dead.rcu_head);
	struct fib_xid_table *xtbl = fxid->dead.xtbl;
	free_fxid_norcu(xtbl, fxid);
	xtbl_put(xtbl);
}

void free_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	fxid->dead.xtbl = xtbl;
	xtbl_hold(xtbl);
	call_rcu(&fxid->dead.rcu_head, __free_fxid);
}
EXPORT_SYMBOL_GPL(free_fxid);

static void xtbl_death_work(struct work_struct *work)
{
	struct fib_xid_table *xtbl = container_of(work, struct fib_xid_table,
		fxt_death_work);
	struct fib_xid_buckets *abranch;
	int adivisor, aindex;
	int rm_count = 0;
	int i, c;

	cancel_work_sync(&xtbl->fxt_rehash_work);
	/* Now it's safe to obtain the following variables. */
	abranch = xtbl->fxt_active_branch;
	adivisor = abranch->divisor;
	aindex = xtbl_branch_index(xtbl, abranch);

	/* Make sure that we don't have any reader. */
	synchronize_rcu();

	for (i = 0; i < adivisor; i++) {
		struct fib_xid *fxid;
		struct hlist_node *n;
		struct hlist_head *head = &abranch->buckets[i];
		hlist_for_each_entry_safe(fxid, n, head,
					fx_branch_list[aindex]) {
			hlist_del(&fxid->fx_branch_list[aindex]);
			free_fxid_norcu(xtbl, fxid);
			rm_count++;
		}
	}

	/* It doesn't return an error here because there's nothing
	 * the caller can do about this error/bug.
	 */
	c = atomic_read(&xtbl->fxt_count);
	if (c != rm_count) {
		pr_err("While freeing XID table of principal %x, %i entries were found, whereas %i are counted! Ignoring it, but it's a serious bug!\n",
			__be32_to_cpu(xtbl->fxt_ppal_type), rm_count, c);
		dump_stack();
	}

	release_net(xtbl->fxt_net);
	free_buckets(abranch);
	xtbl->fxt_locktbl = NULL; /* Being redundant. */
	kfree(xtbl);
}

void xtbl_finish_destroy(struct fib_xid_table *xtbl)
{
	xtbl->dead = 1;
	barrier(); /* Announce that @xtbl is dead as soon as possible. */

	if (in_interrupt())
		schedule_work(&xtbl->fxt_death_work);
	else
		xtbl_death_work(&xtbl->fxt_death_work);
}
EXPORT_SYMBOL_GPL(xtbl_finish_destroy);

void release_fib_ppal_ctx(struct net *net)
{
	int i;

	for (i = 0; i < XIP_MAX_XID_TYPES; i++) {
		struct xip_ppal_ctx *ctx = net->xia.fib_ctx[i];
		if (!ctx)
			continue;

		pr_crit("BUG: Principal 0x%x did not release its context\n",
			__be32_to_cpu(ctx->xpc_ppal_type));
		break;
	}
}

static inline struct hlist_head *__xidhead(struct hlist_head *buckets,
					u32 bucket)
{
	return &buckets[bucket];
}

static inline struct hlist_head *xidhead(struct fib_xid_buckets *branch,
					const u8 *xid)
{
	return __xidhead(branch->buckets, get_bucket(xid, branch->divisor));
}

static struct fib_xid *find_xid_locked(struct fib_xid_table *xtbl,
	u32 bucket, const u8 *xid, struct hlist_head **phead)
{
	struct fib_xid *fxid;
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	int aindex = xtbl_branch_index(xtbl, abranch);
	*phead = __xidhead(abranch->buckets, bucket);
	hlist_for_each_entry(fxid, *phead, fx_branch_list[aindex]) {
		if (are_xids_equal(fxid->fx_xid, xid))
			return fxid;
	}
	return NULL;
}

struct fib_xid *xia_find_xid_rcu(struct fib_xid_table *xtbl, const u8 *xid)
{
	struct fib_xid_buckets *abranch;
	int aindex;
	struct fib_xid *fxid;
	struct hlist_head *head;
	abranch = rcu_dereference(xtbl->fxt_active_branch);
	aindex = xtbl_branch_index(xtbl, abranch);
	head = xidhead(abranch, xid);
	hlist_for_each_entry_rcu(fxid, head, fx_branch_list[aindex]) {
		if (are_xids_equal(fxid->fx_xid, xid))
			return fxid;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(xia_find_xid_rcu);

static u32 fib_lock_bucket_xid(struct fib_xid_table *xtbl, const u8 *xid)
	__acquires(xip_bucket_lock)
{
	u32 bucket;
	read_lock(&xtbl->fxt_writers_lock);
	bucket = get_bucket(xid, xtbl->fxt_active_branch->divisor);
	bucket_lock(xtbl, bucket);

	/* Make sparse happy with only one __acquires. */
	__release(bucket);

	return bucket;
}

static inline u32 fib_lock_bucket(struct fib_xid_table *xtbl,
	struct fib_xid *fxid) __acquires(xip_bucket_lock)
{
	return fib_lock_bucket_xid(xtbl, fxid->fx_xid);
}

void fib_unlock_bucket(struct fib_xid_table *xtbl, u32 bucket)
	__releases(xip_bucket_lock)
{

	/* Make sparse happy with only one __releases. */
	__acquire(bucket);

	bucket_unlock(xtbl, bucket);
	read_unlock(&xtbl->fxt_writers_lock);
}
EXPORT_SYMBOL_GPL(fib_unlock_bucket);

struct fib_xid *xia_find_xid_lock(u32 *pbucket, struct fib_xid_table *xtbl,
	const u8 *xid) __acquires(xip_bucket_lock)
{
	struct hlist_head *head;
	*pbucket = fib_lock_bucket_xid(xtbl, xid);
	return find_xid_locked(xtbl, *pbucket, xid, &head);
}
EXPORT_SYMBOL_GPL(xia_find_xid_lock);

int xia_iterate_xids(struct fib_xid_table *xtbl,
	int (*locked_callback)(struct fib_xid_table *xtbl,
		struct fib_xid *fxid, void *arg),
	void *arg)
{
	struct fib_xid_buckets *abranch;
	int aindex;
	u32 bucket;
	int rc = 0;

	read_lock(&xtbl->fxt_writers_lock);
	abranch = xtbl->fxt_active_branch;
	aindex = xtbl_branch_index(xtbl, abranch);

	for (bucket = 0; bucket < abranch->divisor; bucket++) {
		struct fib_xid *fxid;
		struct hlist_node *nxt;
		struct hlist_head *head = __xidhead(abranch->buckets, bucket);
		bucket_lock(xtbl, bucket);
		hlist_for_each_entry_safe(fxid, nxt, head,
			fx_branch_list[aindex]) {
			rc = locked_callback(xtbl, fxid, arg);
			if (rc) {
				bucket_unlock(xtbl, bucket);
				goto out;
			}
		}
		bucket_unlock(xtbl, bucket);
	}

out:
	read_unlock(&xtbl->fxt_writers_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(xia_iterate_xids);

int xia_iterate_xids_rcu(struct fib_xid_table *xtbl,
	int (*rcu_callback)(struct fib_xid_table *xtbl,
		struct fib_xid *fxid, const void *arg),
	const void *arg)
{
	struct fib_xid_buckets *abranch;
	int aindex;
	u32 bucket;
	int rc = 0;

	abranch = rcu_dereference(xtbl->fxt_active_branch);
	aindex = xtbl_branch_index(xtbl, abranch);
	for (bucket = 0; bucket < abranch->divisor; bucket++) {
		struct fib_xid *fxid;
		struct hlist_head *head = __xidhead(abranch->buckets, bucket);
		hlist_for_each_entry_rcu(fxid, head, fx_branch_list[aindex]) {
			rc = rcu_callback(xtbl, fxid, arg);
			if (rc)
				goto out;
		}
	}

out:
	return rc;
}
EXPORT_SYMBOL_GPL(xia_iterate_xids_rcu);

/* Grow table as needed. */
static void rehash_work(struct work_struct *work)
{
	struct fib_xid_table *xtbl = container_of(work, struct fib_xid_table,
		fxt_rehash_work);
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	int aindex = xtbl_branch_index(xtbl, abranch);
	int nindex = 1 - aindex;
	/* The next branch. */
	struct fib_xid_buckets *nbranch = &xtbl->fxt_branch[nindex];
	int old_divisor = abranch->divisor;
	int new_divisor = old_divisor * 2;
	int mv_count = 0;
	int rc, i, c, should_rehash;

	/* Allocate memory before aquiring write lock because it sleeps. */
	BUG_ON(!is_power_of_2(new_divisor));
	rc = alloc_buckets(nbranch, new_divisor);
	if (rc) {
		pr_err(
		"Rehashing XID table %x was not possible due to error %i.\n",
			__be32_to_cpu(xtbl->fxt_ppal_type), rc);
		dump_stack();
		return;
	}

	write_lock(&xtbl->fxt_writers_lock);

	/* We must test if we @should_rehash again because we may be
	 * following another rehash_work that just finished.
	 * Even if we're not following another rehash_work, fxt_count may have
	 * changed while we waited on write_lock() or to be scheduled, and
	 * a rehash became unnecessary.
	 */
	should_rehash = atomic_read(&xtbl->fxt_count) / old_divisor > 2;
	if (!should_rehash) {
		/* The calling order here is very important because
		 * function free_buckets sleeps.
		 */
		write_unlock(&xtbl->fxt_writers_lock);
		free_buckets(nbranch);
		return;
	}

	/* Add entries to @nbranch. */
	for (i = 0; i < old_divisor; i++) {
		struct fib_xid *fxid;
		struct hlist_head *head = &abranch->buckets[i];
		hlist_for_each_entry(fxid, head, fx_branch_list[aindex]) {
			struct hlist_head *new_head =
				xidhead(nbranch, fxid->fx_xid);
			hlist_add_head(&fxid->fx_branch_list[nindex], new_head);
			mv_count++;
		}
	}
	rcu_assign_pointer(xtbl->fxt_active_branch, nbranch);

	/* It doesn't return an error here because there's nothing
	 * the caller can do about this error/bug.
	 */
	c = atomic_read(&xtbl->fxt_count);
	if (c != mv_count) {
		pr_err("While rehashing XID table of principal %x, %i entries were found, whereas %i are registered! Fixing the counter for now, but it's a serious bug!\n",
			__be32_to_cpu(xtbl->fxt_ppal_type), mv_count, c);
		dump_stack();
		/* "Fixing" bug. */
		atomic_set(&xtbl->fxt_count, mv_count);
	}

	write_unlock(&xtbl->fxt_writers_lock);

	/* Make sure that there's no reader in @abranch. */
	synchronize_rcu();

	/* From now on, all readers are using @nbranch. */

	free_buckets(abranch);
}

int fib_add_fxid_locked(u32 bucket, struct fib_xid_table *xtbl,
	struct fib_xid *fxid)
{
	struct hlist_head *head;
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	int aindex = xtbl_branch_index(xtbl, abranch);
	int should_rehash;

	if (find_xid_locked(xtbl, bucket, fxid->fx_xid, &head))
		return -EEXIST;

	hlist_add_head_rcu(&fxid->fx_branch_list[aindex], head);
	should_rehash =
		atomic_inc_return(&xtbl->fxt_count) / abranch->divisor > 2;

	/* Grow table as needed. */
	if (should_rehash && !xtbl->dead)
		schedule_work(&xtbl->fxt_rehash_work);

	return 0;
}
EXPORT_SYMBOL_GPL(fib_add_fxid_locked);

int fib_add_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	u32 bucket;
	int rc;

	bucket = fib_lock_bucket(xtbl, fxid);
	rc = fib_add_fxid_locked(bucket, xtbl, fxid);
	fib_unlock_bucket(xtbl, bucket);
	return rc;
}
EXPORT_SYMBOL_GPL(fib_add_fxid);

static inline void __rm_fxid_locked(struct fib_xid_table *xtbl,
	struct fib_xid_buckets *abranch, struct fib_xid *fxid)
{
	hlist_del_rcu(&fxid->fx_branch_list[xtbl_branch_index(xtbl, abranch)]);
	atomic_dec(&xtbl->fxt_count);
}

void fib_rm_fxid_locked(u32 bucket, struct fib_xid_table *xtbl,
	struct fib_xid *fxid)
{
	/* Currently, @bucket is not necessary. */

	/* Notice that calling fib_rm_fxid_locked is different of calling
	 * __rm_fxid_locked because the latter is inline.
	 */
	__rm_fxid_locked(xtbl, xtbl->fxt_active_branch, fxid);
}
EXPORT_SYMBOL_GPL(fib_rm_fxid_locked);

struct fib_xid *fib_rm_xid(struct fib_xid_table *xtbl, const u8 *xid)
{
	u32 bucket;
	struct fib_xid *fxid = xia_find_xid_lock(&bucket, xtbl, xid);
	if (!fxid) {
		fib_unlock_bucket(xtbl, bucket);
		return NULL;
	}
	__rm_fxid_locked(xtbl, xtbl->fxt_active_branch, fxid);
	fib_unlock_bucket(xtbl, bucket);
	return fxid;
}
EXPORT_SYMBOL_GPL(fib_rm_xid);

void fib_rm_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	u32 bucket = fib_lock_bucket(xtbl, fxid);
	__rm_fxid_locked(xtbl, xtbl->fxt_active_branch, fxid);
	fib_unlock_bucket(xtbl, bucket);
}
EXPORT_SYMBOL_GPL(fib_rm_fxid);

void fib_replace_fxid_locked(struct fib_xid_table *xtbl,
	struct fib_xid *old_fxid, struct fib_xid *new_fxid)
{
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	int aindex = xtbl_branch_index(xtbl, abranch);
	hlist_replace_rcu(&old_fxid->fx_branch_list[aindex],
		&new_fxid->fx_branch_list[aindex]);
}
EXPORT_SYMBOL_GPL(fib_replace_fxid_locked);

int fib_build_delroute(int tbl_id, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	struct fib_xid *fxid;
	u32 bucket;
	int rc;

	fxid = xia_find_xid_lock(&bucket, xtbl, cfg->xfc_dst->xid_id);
	if (!fxid) {
		rc = -ENOENT;
		goto unlock_bucket;
	}
	if (fxid->fx_table_id != tbl_id) {
		rc = -EINVAL;
		goto unlock_bucket;
	}

	fib_rm_fxid_locked(bucket, xtbl, fxid);
	fib_unlock_bucket(xtbl, bucket);
	free_fxid(xtbl, fxid);
	return 0;

unlock_bucket:
	fib_unlock_bucket(xtbl, bucket);
	return rc;
}
EXPORT_SYMBOL_GPL(fib_build_delroute);

int fib_default_local_delroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	return fib_build_delroute(XRTABLE_LOCAL_INDEX, xtbl, cfg);
}
EXPORT_SYMBOL_GPL(fib_default_local_delroute);

int fib_default_main_delroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	return fib_build_delroute(XRTABLE_MAIN_INDEX, xtbl, cfg);
}
EXPORT_SYMBOL_GPL(fib_default_main_delroute);

int fib_no_newroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(fib_no_newroute);

struct xip_deferred_negdep_flush {
	struct rcu_head		rcu_head;
	struct net		*net;
	xid_type_t		ty;
};

struct xip_deferred_negdep_flush *fib_alloc_dnf(gfp_t flags)
{
	return kmalloc(sizeof(struct xip_deferred_negdep_flush), flags);
}
EXPORT_SYMBOL_GPL(fib_alloc_dnf);

static void __fib_defer_dnf(struct rcu_head *head)
{
	struct xip_deferred_negdep_flush *dnf =
		container_of(head, struct xip_deferred_negdep_flush, rcu_head);
	struct xip_ppal_ctx *ctx;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_rcu(dnf->net, dnf->ty);
	if (likely(ctx)) { /* Principal could be unloading. */
		/* Flush @negdep. */
		xdst_free_anchor(&ctx->negdep);
	}
	rcu_read_unlock();

	release_net(dnf->net);
	fib_free_dnf(dnf);
}

void fib_defer_dnf(struct xip_deferred_negdep_flush *dnf,
	struct net *net, xid_type_t ty)
{
	dnf->net = net;
	hold_net(net);
	dnf->ty = ty;
	call_rcu(&dnf->rcu_head, __fib_defer_dnf);
}
EXPORT_SYMBOL_GPL(fib_defer_dnf);

int fib_build_newroute(struct fib_xid *new_fxid, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg, int *padded)
{
	struct xip_deferred_negdep_flush *dnf;
	struct fib_xid *cur_fxid;
	const u8 *id;
	u32 bucket;
	int rc;

	if (padded)
		*padded = 0;

	/* Allocate memory before acquiring lock because we can sleep now. */
	dnf = fib_alloc_dnf(GFP_KERNEL);
	if (!dnf)
		return -ENOMEM;

	/* Acquire lock. */
	id = cfg->xfc_dst->xid_id;
	cur_fxid = xia_find_xid_lock(&bucket, xtbl, id);

	if (cur_fxid) {
		if ((cfg->xfc_nlflags & NLM_F_EXCL) ||
			!(cfg->xfc_nlflags & NLM_F_REPLACE)) {
			rc = -EEXIST;
			goto unlock_bucket;
		}

		if (cur_fxid->fx_table_id != new_fxid->fx_table_id) {
			rc = -EINVAL;
			goto unlock_bucket;
		}

		/* Replace entry.
		 * Notice that @cur_fxid and @new_fxid may be of different
		 * types
		 */
		rc = 0;
		fib_replace_fxid_locked(xtbl, cur_fxid,	new_fxid);
		fib_unlock_bucket(xtbl, bucket);
		free_fxid(xtbl, cur_fxid);
		goto def_upd;
	}

	if (!(cfg->xfc_nlflags & NLM_F_CREATE)) {
		rc = -ENOENT;
		goto unlock_bucket;
	}

	/* Add new entry. */
	BUG_ON(fib_add_fxid_locked(bucket, xtbl, new_fxid));
	fib_unlock_bucket(xtbl, bucket);

	/* Before invalidating old anchors to force dependencies to
	 * migrate to @new_fxid, wait an RCU synchronization to make sure that
	 * every thread see @new_fxid.
	 */
	fib_defer_dnf(dnf, xtbl_net(xtbl), xtbl_ppalty(xtbl));

	if (padded)
		*padded = 1;
	return 0;

unlock_bucket:
	fib_unlock_bucket(xtbl, bucket);
def_upd:
	fib_free_dnf(dnf);
	return rc;
}
EXPORT_SYMBOL_GPL(fib_build_newroute);

/*
 *	Main entries that only redirect.
 */

struct fib_xid_redirect_main {
	struct fib_xid		common;
	struct xia_xid		gw;
};

static inline struct fib_xid_redirect_main *fxid_mrd(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_redirect_main, common)
		: NULL;
}

int fib_mrd_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	struct fib_xid_redirect_main *new_mrd;
	int rc;

	if (!cfg->xfc_gw || cfg->xfc_gw->xid_type == xtbl_ppalty(xtbl))
		return -EINVAL;

	new_mrd = kmalloc(sizeof(*new_mrd), GFP_KERNEL);
	if (!new_mrd)
		return -ENOMEM;
	init_fxid(&new_mrd->common, cfg->xfc_dst->xid_id,
		XRTABLE_MAIN_INDEX, 0);
	new_mrd->gw = *cfg->xfc_gw;

	rc = fib_build_newroute(&new_mrd->common, xtbl, cfg, NULL);
	if (rc)
		free_fxid_norcu(xtbl, &new_mrd->common);
	return rc;
}
EXPORT_SYMBOL_GPL(fib_mrd_newroute);

int fib_mrd_dump(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct xip_ppal_ctx *ctx, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_redirect_main *mrd = fxid_mrd(fxid);
	struct xia_xid dst;

	nlh = nlmsg_put(skb, portid, seq, RTM_NEWROUTE, sizeof(*rtm),
		NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = XRTABLE_MAIN_INDEX;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl_ppalty(xtbl);
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);

	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst) ||
			nla_put(skb, RTA_GATEWAY, sizeof(mrd->gw), &mrd->gw)
		))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}
EXPORT_SYMBOL_GPL(fib_mrd_dump);

/* Don't call this function! Use free_fxid instead. */
void fib_mrd_free(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_redirect_main *mrd = fxid_mrd(fxid);
	xdst_invalidate_redirect(xtbl_net(xtbl), xtbl_ppalty(xtbl),
		mrd->common.fx_xid, &mrd->gw);
	kfree(mrd);
}
EXPORT_SYMBOL_GPL(fib_mrd_free);

void fib_mrd_redirect(struct fib_xid *fxid, struct xia_xid *next_xid)
{
	*next_xid = fxid_mrd(fxid)->gw;
}
EXPORT_SYMBOL_GPL(fib_mrd_redirect);

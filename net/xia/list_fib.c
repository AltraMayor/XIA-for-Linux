#include <linux/export.h>
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <net/xia_locktbl.h>
#include <net/xia_vxidty.h>
#include <net/xia_list_fib.h>

static inline struct fib_xid *lfxid_fxid(struct list_fib_xid *lfxid)
{
	return likely(lfxid)
		? container_of((void *)lfxid, struct fib_xid, fx_data)
		: NULL;
}

static inline struct list_fib_xid *fxid_lfxid(struct fib_xid *fxid)
{
	return (struct list_fib_xid *)fxid->fx_data;
}

static inline struct fib_xid_table *lxtbl_xtbl(struct list_fib_xid_table *lxtbl)
{
	return likely(lxtbl)
		? container_of((void *)lxtbl, struct fib_xid_table, fxt_data)
		: NULL;
}

static inline struct list_fib_xid_table *xtbl_lxtbl(struct fib_xid_table *xtbl)
{
	return (struct list_fib_xid_table *)xtbl->fxt_data;
}

/* Lock tables */

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

static inline u32 hash_bucket(struct list_fib_xid_table *lxtbl, u32 bucket)
{
	return xtbl_hash_mix(lxtbl_xtbl(lxtbl)) * bucket + lxtbl->fxt_seed;
}

/* Don't make this function inline, it's bigger than it looks like! */
static void bucket_lock(struct list_fib_xid_table *lxtbl, u32 bucket)
	__acquires(bucket)
{
	xia_lock_table_lock(lxtbl->fxt_locktbl, hash_bucket(lxtbl, bucket));
}

/* Don't make this function inline, it's bigger than it looks like! */
static void bucket_unlock(struct list_fib_xid_table *lxtbl, u32 bucket)
	__releases(bucket)
{
	xia_lock_table_unlock(lxtbl->fxt_locktbl, hash_bucket(lxtbl, bucket));
}

/* Routing tables */

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

static void rehash_work(struct work_struct *work);
static void list_xtbl_death_work(struct work_struct *work);

static int list_xtbl_init(struct xip_ppal_ctx *ctx, struct net *net,
			  struct xia_lock_table *locktbl,
			  const xia_ppal_all_rt_eops_t all_eops,
			  const struct xia_ppal_rt_iops *all_iops)
{
	struct fib_xid_table *new_xtbl;
	struct list_fib_xid_table *lxtbl;
	struct fib_xid_buckets *abranch;
	int rc;

	if (ctx->xpc_xtbl) {
		rc = -EEXIST;
		goto out; /* Duplicate. */
	}

	rc = -ENOMEM;
	new_xtbl = kzalloc(sizeof(*new_xtbl) + sizeof(*lxtbl), GFP_KERNEL);
	if (!new_xtbl)
		goto out;
	lxtbl = xtbl_lxtbl(new_xtbl);
	abranch = &lxtbl->fxt_branch[0];
	lxtbl->fxt_active_branch = abranch;
	BUILD_BUG_ON_NOT_POWER_OF_2(XTBL_INITIAL_DIV);
	if (alloc_buckets(abranch, XTBL_INITIAL_DIV))
		goto new_xtbl;

	new_xtbl->fxt_ppal_type = ctx->xpc_ppal_type;
	new_xtbl->fxt_net = net;
	hold_net(net);
	lxtbl->fxt_locktbl = locktbl;
	atomic_set(&new_xtbl->fxt_count, 0);
	get_random_bytes(&lxtbl->fxt_seed, sizeof(lxtbl->fxt_seed));
	INIT_WORK(&lxtbl->fxt_rehash_work, rehash_work);
	rwlock_init(&lxtbl->fxt_writers_lock);
	new_xtbl->all_eops = all_eops;
	new_xtbl->all_iops = all_iops;

	atomic_set(&new_xtbl->refcnt, 1);
	INIT_WORK(&new_xtbl->fxt_death_work, list_xtbl_death_work);
	ctx->xpc_xtbl = new_xtbl;

	rc = 0;
	goto out;

new_xtbl:
	kfree(new_xtbl);
out:
	return rc;
}

static void *list_fxid_ppal_alloc(size_t ppal_entry_size, gfp_t flags)
{
	return kmalloc(ppal_entry_size + sizeof(struct list_fib_xid), flags);
}

static void list_fxid_init(struct fib_xid *fxid, int table_id, int entry_type)
{
	struct list_fib_xid *lfxid = fxid_lfxid(fxid);
	INIT_HLIST_NODE(&lfxid->fx_branch_list[0]);
	INIT_HLIST_NODE(&lfxid->fx_branch_list[1]);

	BUILD_BUG_ON(XRTABLE_MAX_INDEX >= 0x100);
	BUG_ON(table_id >= XRTABLE_MAX_INDEX);
	fxid->fx_table_id = table_id;

	BUG_ON(entry_type > 0xff);
	fxid->fx_entry_type = entry_type;

	fxid->dead.xtbl = NULL;
}

static void list_xtbl_death_work(struct work_struct *work)
{
	struct fib_xid_table *xtbl = container_of(work, struct fib_xid_table,
		fxt_death_work);
	struct list_fib_xid_table *lxtbl = xtbl_lxtbl(xtbl);
	struct fib_xid_buckets *abranch;
	int adivisor, aindex;
	int rm_count = 0;
	int i, c;

	cancel_work_sync(&lxtbl->fxt_rehash_work);
	/* Now it's safe to obtain the following variables. */
	abranch = lxtbl->fxt_active_branch;
	adivisor = abranch->divisor;
	aindex = lxtbl_branch_index(lxtbl, abranch);

	/* Make sure that we don't have any reader. */
	synchronize_rcu();

	for (i = 0; i < adivisor; i++) {
		struct list_fib_xid *lfxid;
		struct hlist_node *n;
		struct hlist_head *head = &abranch->buckets[i];

		hlist_for_each_entry_safe(lfxid, n, head,
					  fx_branch_list[aindex]) {
			hlist_del(&lfxid->fx_branch_list[aindex]);
			fxid_free_norcu(xtbl, lfxid_fxid(lfxid));
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
	lxtbl->fxt_locktbl = NULL; /* Being redundant. */
	kfree(xtbl);
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

static struct fib_xid *list_fxid_find_locked(struct fib_xid_table *xtbl,
					     u32 bucket, const u8 *xid,
					     struct hlist_head **phead)
{
	struct list_fib_xid_table *lxtbl = xtbl_lxtbl(xtbl);
	struct list_fib_xid *lfxid;
	struct fib_xid_buckets *abranch = lxtbl->fxt_active_branch;
	int aindex = lxtbl_branch_index(lxtbl, abranch);
	*phead = __xidhead(abranch->buckets, bucket);
	hlist_for_each_entry(lfxid, *phead, fx_branch_list[aindex]) {
		if (are_xids_equal(lfxid_fxid(lfxid)->fx_xid, xid))
			return lfxid_fxid(lfxid);
	}
	return NULL;
}

static struct fib_xid *list_fxid_find_rcu(struct fib_xid_table *xtbl,
					  const u8 *xid)
{
	struct list_fib_xid_table *lxtbl = xtbl_lxtbl(xtbl);
	struct fib_xid_buckets *abranch;
	int aindex;
	struct list_fib_xid *lfxid;
	struct hlist_head *head;

	abranch = rcu_dereference(lxtbl->fxt_active_branch);
	aindex = lxtbl_branch_index(lxtbl, abranch);
	head = xidhead(abranch, xid);
	hlist_for_each_entry_rcu(lfxid, head, fx_branch_list[aindex]) {
		if (are_xids_equal(lfxid_fxid(lfxid)->fx_xid, xid))
			return lfxid_fxid(lfxid);
	}
	return NULL;
}

static u32 list_fib_lock_bucket_xid(struct fib_xid_table *xtbl, const u8 *xid)
	__acquires(xip_bucket_lock)
{
	struct list_fib_xid_table *lxtbl = xtbl_lxtbl(xtbl);
	u32 bucket;

	read_lock(&lxtbl->fxt_writers_lock);
	bucket = get_bucket(xid, lxtbl->fxt_active_branch->divisor);
	bucket_lock(lxtbl, bucket);

	/* Make sparse happy with only one __acquires. */
	__release(bucket);

	return bucket;
}

static inline u32 list_fib_lock(struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
				__acquires(xip_bucket_lock)
{
	return list_fib_lock_bucket_xid(xtbl, fxid->fx_xid);
}

/* For the list FIB, @parg represents a u32 bucket. */
static inline u32 parg_bucket(void *parg)
{
	if (unlikely(!parg))
		BUG();
	return *(u32 *)parg;
}

static void list_fib_unlock(struct fib_xid_table *xtbl, void *parg)
	__releases(xip_bucket_lock)
{
	struct list_fib_xid_table *lxtbl = xtbl_lxtbl(xtbl);
	u32 bucket = parg_bucket(parg);

	/* Make sparse happy with only one __releases. */
	__acquire(bucket);

	bucket_unlock(lxtbl, bucket);
	read_unlock(&lxtbl->fxt_writers_lock);
}

static struct fib_xid *list_fxid_find_lock(void *parg,
	struct fib_xid_table *xtbl, const u8 *xid) __acquires(xip_bucket_lock)
{
	struct hlist_head *head;
	u32 *pbucket = parg;
	*pbucket = list_fib_lock_bucket_xid(xtbl, xid);
	return list_fxid_find_locked(xtbl, *pbucket, xid, &head);
}

static int list_iterate_xids(struct fib_xid_table *xtbl,
			     int (*locked_callback)(struct fib_xid_table *xtbl,
						    struct fib_xid *fxid,
						    const void *arg),
			     const void *arg)
{
	struct list_fib_xid_table *lxtbl = xtbl_lxtbl(xtbl);
	struct fib_xid_buckets *abranch;
	int aindex;
	u32 bucket;
	int rc = 0;

	read_lock(&lxtbl->fxt_writers_lock);
	abranch = lxtbl->fxt_active_branch;
	aindex = lxtbl_branch_index(lxtbl, abranch);

	for (bucket = 0; bucket < abranch->divisor; bucket++) {
		struct list_fib_xid *lfxid;
		struct hlist_node *nxt;
		struct hlist_head *head = __xidhead(abranch->buckets, bucket);

		bucket_lock(lxtbl, bucket);
		hlist_for_each_entry_safe(lfxid, nxt, head,
					  fx_branch_list[aindex]) {
			rc = locked_callback(xtbl, lfxid_fxid(lfxid), arg);
			if (rc) {
				bucket_unlock(lxtbl, bucket);
				goto out;
			}
		}
		bucket_unlock(lxtbl, bucket);
	}

out:
	read_unlock(&lxtbl->fxt_writers_lock);
	return rc;
}

static int list_iterate_xids_rcu(struct fib_xid_table *xtbl,
				 int (*rcu_callback)(struct fib_xid_table *xtbl,
						     struct fib_xid *fxid,
						     const void *arg),
				 const void *arg)
{
	struct list_fib_xid_table *lxtbl = xtbl_lxtbl(xtbl);
	struct fib_xid_buckets *abranch;
	int aindex;
	u32 bucket;
	int rc = 0;

	abranch = rcu_dereference(lxtbl->fxt_active_branch);
	aindex = lxtbl_branch_index(lxtbl, abranch);
	for (bucket = 0; bucket < abranch->divisor; bucket++) {
		struct list_fib_xid *lfxid;
		struct hlist_head *head = __xidhead(abranch->buckets, bucket);

		hlist_for_each_entry_rcu(lfxid, head, fx_branch_list[aindex]) {
			rc = rcu_callback(xtbl, lfxid_fxid(lfxid), arg);
			if (rc)
				goto out;
		}
	}

out:
	return rc;
}

/* Grow table as needed. */
static void rehash_work(struct work_struct *work)
{
	struct list_fib_xid_table *lxtbl = container_of(work,
		struct list_fib_xid_table, fxt_rehash_work);
	struct fib_xid_buckets *abranch = lxtbl->fxt_active_branch;
	int aindex = lxtbl_branch_index(lxtbl, abranch);
	int nindex = 1 - aindex;
	/* The next branch. */
	struct fib_xid_buckets *nbranch = &lxtbl->fxt_branch[nindex];
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
			__be32_to_cpu(lxtbl_xtbl(lxtbl)->fxt_ppal_type), rc);
		dump_stack();
		return;
	}

	write_lock(&lxtbl->fxt_writers_lock);

	/* We must test if we @should_rehash again because we may be
	 * following another rehash_work that just finished.
	 * Even if we're not following another rehash_work, fxt_count may have
	 * changed while we waited on write_lock() or to be scheduled, and
	 * a rehash became unnecessary.
	 */
	should_rehash = atomic_read(&lxtbl_xtbl(lxtbl)->fxt_count) /
				    old_divisor > 2;
	if (!should_rehash) {
		/* The calling order here is very important because
		 * function free_buckets sleeps.
		 */
		write_unlock(&lxtbl->fxt_writers_lock);
		free_buckets(nbranch);
		return;
	}

	/* Add entries to @nbranch. */
	for (i = 0; i < old_divisor; i++) {
		struct list_fib_xid *lfxid;
		struct hlist_head *head = &abranch->buckets[i];

		hlist_for_each_entry(lfxid, head, fx_branch_list[aindex]) {
			struct hlist_head *new_head =
				xidhead(nbranch, lfxid_fxid(lfxid)->fx_xid);
			hlist_add_head(&lfxid->fx_branch_list[nindex],
				       new_head);
			mv_count++;
		}
	}
	rcu_assign_pointer(lxtbl->fxt_active_branch, nbranch);

	/* It doesn't return an error here because there's nothing
	 * the caller can do about this error/bug.
	 */
	c = atomic_read(&lxtbl_xtbl(lxtbl)->fxt_count);
	if (c != mv_count) {
		pr_err("While rehashing XID table of principal %x, %i entries were found, whereas %i are registered! Fixing the counter for now, but it's a serious bug!\n",
		       __be32_to_cpu(lxtbl_xtbl(lxtbl)->fxt_ppal_type),
				     mv_count, c);
		dump_stack();
		/* "Fixing" bug. */
		atomic_set(&lxtbl_xtbl(lxtbl)->fxt_count, mv_count);
	}

	write_unlock(&lxtbl->fxt_writers_lock);

	/* Make sure that there's no reader in @abranch. */
	synchronize_rcu();

	/* From now on, all readers are using @nbranch. */

	free_buckets(abranch);
}

static int list_fxid_add_locked(void *parg, struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
{
	struct list_fib_xid *lfxid = fxid_lfxid(fxid);
	struct list_fib_xid_table *lxtbl = xtbl_lxtbl(xtbl);
	struct hlist_head *head;
	struct fib_xid_buckets *abranch = lxtbl->fxt_active_branch;
	int aindex = lxtbl_branch_index(lxtbl, abranch);
	int should_rehash;
	u32 bucket = parg_bucket(parg);

	if (list_fxid_find_locked(xtbl, bucket, fxid->fx_xid, &head))
		return -EEXIST;

	hlist_add_head_rcu(&lfxid->fx_branch_list[aindex], head);
	should_rehash =
		atomic_inc_return(&xtbl->fxt_count) / abranch->divisor > 2;

	/* Grow table as needed. */
	if (should_rehash && !xtbl->dead)
		schedule_work(&lxtbl->fxt_rehash_work);

	return 0;
}

static int list_fxid_add(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	u32 bucket;
	int rc;

	bucket = list_fib_lock(xtbl, fxid);
	rc = list_fxid_add_locked(&bucket, xtbl, fxid);
	list_fib_unlock(xtbl, &bucket);
	return rc;
}

static inline void __list_fxid_rm_locked(struct fib_xid_table *xtbl,
					 struct fib_xid_buckets *abranch,
					 struct fib_xid *fxid)
{
	hlist_del_rcu(&(fxid_lfxid(fxid))->
		fx_branch_list[lxtbl_branch_index(xtbl_lxtbl(xtbl), abranch)]);
	atomic_dec(&xtbl->fxt_count);
}

static void list_fxid_rm_locked(void *parg, struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
{
	/* Currently, @parg is not necessary, but if it is, one should
	 * call parg_bucket() instead of dereferencing it directly.
	 */

	/* Notice that calling list_fib_rm_fxid_locked is different from
	 * calling __list_rm_fxid_locked because the latter is inline.
	 */
	__list_fxid_rm_locked(xtbl, xtbl_lxtbl(xtbl)->fxt_active_branch, fxid);
}

static struct fib_xid *list_xid_rm(struct fib_xid_table *xtbl, const u8 *xid)
{
	u32 bucket;
	struct fib_xid *fxid = list_fxid_find_lock(&bucket, xtbl, xid);

	if (!fxid) {
		list_fib_unlock(xtbl, &bucket);
		return NULL;
	}
	__list_fxid_rm_locked(xtbl, xtbl_lxtbl(xtbl)->fxt_active_branch, fxid);
	list_fib_unlock(xtbl, &bucket);
	return fxid;
}

static void list_fxid_rm(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	u32 bucket = list_fib_lock(xtbl, fxid);

	__list_fxid_rm_locked(xtbl, xtbl_lxtbl(xtbl)->fxt_active_branch, fxid);
	list_fib_unlock(xtbl, &bucket);
}

static void list_fxid_replace_locked(struct fib_xid_table *xtbl,
				     struct fib_xid *old_fxid,
				     struct fib_xid *new_fxid)
{
	struct list_fib_xid *old_lfxid = fxid_lfxid(old_fxid);
	struct list_fib_xid *new_lfxid = fxid_lfxid(new_fxid);
	struct fib_xid_buckets *abranch = xtbl_lxtbl(xtbl)->fxt_active_branch;
	int aindex = lxtbl_branch_index(xtbl_lxtbl(xtbl), abranch);

	hlist_replace_rcu(&old_lfxid->fx_branch_list[aindex],
			  &new_lfxid->fx_branch_list[aindex]);
}

int list_fib_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
		      struct xia_fib_config *cfg)
{
	u32 bucket;
	return all_fib_delroute(ctx, xtbl, cfg, &bucket);
}
EXPORT_SYMBOL_GPL(list_fib_delroute);

static int list_fib_newroute(struct fib_xid *new_fxid,
			     struct fib_xid_table *xtbl,
			     struct xia_fib_config *cfg, int *padded)
{
	u32 bucket;
	return all_fib_newroute(new_fxid, xtbl, cfg, padded, &bucket);
}

static int list_xtbl_dump_rcu(struct fib_xid_table *xtbl,
			      struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			      struct netlink_callback *cb)
{
	struct fib_xid_buckets *abranch;
	long i, j = 0;
	long first_j = cb->args[2];
	int divisor, aindex;
	int rc;

	abranch = rcu_dereference(xtbl_lxtbl(xtbl)->fxt_active_branch);
	divisor = abranch->divisor;
	aindex = lxtbl_branch_index(xtbl_lxtbl(xtbl), abranch);
	for (i = cb->args[1]; i < divisor; i++, first_j = 0) {
		struct list_fib_xid *lfxid;
		struct hlist_head *head = &abranch->buckets[i];

		j = 0;
		hlist_for_each_entry_rcu(lfxid, head,
					 fx_branch_list[aindex]) {
			if (j < first_j)
				goto next;
			rc = xtbl->all_eops[lfxid_fxid(lfxid)->fx_table_id].
			     dump_fxid(lfxid_fxid(lfxid), xtbl, ctx, skb, cb);
			if (rc < 0)
				goto out;
next:
			j++;
		}
	}
	rc = 0;

out:
	cb->args[1] = i;
	cb->args[2] = j;
	return rc;
}

const struct xia_ppal_rt_iops xia_ppal_list_rt_iops = {
	.xtbl_init = list_xtbl_init,
	.xtbl_death_work = list_xtbl_death_work,

	.fxid_ppal_alloc = list_fxid_ppal_alloc,
	.fxid_init = list_fxid_init,

	.fxid_find_rcu = list_fxid_find_rcu,
	.fxid_find_lock = list_fxid_find_lock,
	.iterate_xids = list_iterate_xids,
	.iterate_xids_rcu = list_iterate_xids_rcu,

	.fxid_add = list_fxid_add,
	.fxid_add_locked = list_fxid_add_locked,

	.fxid_rm = list_fxid_rm,
	.fxid_rm_locked = list_fxid_rm_locked,
	.xid_rm = list_xid_rm,

	.fxid_replace_locked = list_fxid_replace_locked,

	.fib_unlock = list_fib_unlock,

	.fib_newroute = list_fib_newroute,
	.fib_delroute = list_fib_delroute,

	.xtbl_dump_rcu = list_xtbl_dump_rcu,
};
EXPORT_SYMBOL_GPL(xia_ppal_list_rt_iops);

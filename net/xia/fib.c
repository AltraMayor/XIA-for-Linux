#include <linux/export.h>
#include <linux/jhash.h>
#include <net/xia_locktbl.h>
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
{
	xia_lock_table_lock(xtbl->fxt_locktbl, hash_bucket(xtbl, bucket));
}

/* Don't make this function inline, it's bigger than it looks like! */
static void bucket_unlock(struct fib_xid_table *xtbl, u32 bucket)
{
	xia_lock_table_unlock(xtbl->fxt_locktbl, hash_bucket(xtbl, bucket));
}

/*
 *	Routing tables
 */

struct fib_xia_rtable *create_xia_rtable(struct net *net, int tbl_id)
{
	struct fib_xia_rtable *rtbl = kzalloc(sizeof(*rtbl), GFP_KERNEL);

	if (!rtbl)
		return NULL;

	rtbl->tbl_net = net;
	hold_net(net);
	rtbl->tbl_id = tbl_id;
	return rtbl;
}

static inline struct hlist_head *ppalhead(struct fib_xia_rtable *rtbl,
						xid_type_t ty)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(NUM_PRINCIPAL_HINT);
	return &rtbl->ppal[ty & (NUM_PRINCIPAL_HINT - 1)];
}

static struct fib_xid_table *__xia_find_xtbl(struct fib_xia_rtable *rtbl,
	xid_type_t ty, struct hlist_head **phead)
{
	struct fib_xid_table *xtbl;
	struct hlist_node *p;
	*phead = ppalhead(rtbl, ty);
	hlist_for_each_entry(xtbl, p, *phead, fxt_list) {
		if (xtbl->fxt_ppal_type == ty)
			return xtbl;
	}
	return NULL;
}

struct fib_xid_table *xia_find_xtbl_rcu(struct fib_xia_rtable *rtbl,
					xid_type_t ty)
{
	struct fib_xid_table *xtbl;
	struct hlist_node *p;
	struct hlist_head *head = ppalhead(rtbl, ty);
	hlist_for_each_entry_rcu(xtbl, p, head, fxt_list) {
		if (xtbl->fxt_ppal_type == ty)
			return xtbl;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(xia_find_xtbl_rcu);

struct fib_xid_table *xia_find_xtbl_hold(struct fib_xia_rtable *rtbl,
	xid_type_t ty)
{
	struct fib_xid_table *xtbl;
	rcu_read_lock();
	xtbl = xia_find_xtbl_rcu(rtbl, ty);
	if (xtbl)
		xtbl_hold(xtbl);
	rcu_read_unlock();
	return xtbl;
}
EXPORT_SYMBOL_GPL(xia_find_xtbl_hold);

/* This function must be called in process context due to virtual memory. */
static int alloc_buckets(struct fib_xid_buckets *abranch, size_t num)
{
	struct hlist_head *buckets;
	size_t size = sizeof(*buckets) * num;
	buckets = vmalloc(size);
	if (!buckets)
		return -ENOMEM;
	memset(buckets, 0, size);
	abranch->buckets = buckets;
	abranch->divisor = num;
	return 0;
}

/* This function must be called in process context due to virtual memory. */
static inline void free_buckets(struct fib_xid_buckets *abranch)
{
	vfree(abranch->buckets);
	abranch->buckets = NULL;
	abranch->divisor = 0;
}

/* XTBL_INITIAL_DIV must be a power of 2. */
#define XTBL_INITIAL_DIV 1

static void xtbl_death_work(struct work_struct *work);
static void rehash_work(struct work_struct *work);

int init_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty,
	struct xia_lock_table *locktbl, const struct xia_ppal_rt_eops *eops)
{
	struct hlist_head *head;
	struct fib_xid_table *new_xtbl;
	struct fib_xid_buckets *abranch;
	int rc;

	rc = -EEXIST;
	if (__xia_find_xtbl(rtbl, ty, &head))
		goto out; /* Duplicate. */

	rc = -ENOMEM;
	new_xtbl = kzalloc(sizeof(*new_xtbl), GFP_KERNEL);
	if (!new_xtbl)
		goto out;
	abranch = &new_xtbl->fxt_branch[0];
	new_xtbl->fxt_active_branch = abranch;
	BUILD_BUG_ON_NOT_POWER_OF_2(XTBL_INITIAL_DIV);
	if (alloc_buckets(abranch, XTBL_INITIAL_DIV))
		goto new_xtbl;

	new_xtbl->fxt_ppal_type = ty;
	new_xtbl->fxt_net = rtbl->tbl_net;
	hold_net(new_xtbl->fxt_net);
	new_xtbl->fxt_locktbl = locktbl;
	atomic_set(&new_xtbl->fxt_count, 0);
	get_random_bytes(&new_xtbl->fxt_seed, sizeof(new_xtbl->fxt_seed));
	INIT_WORK(&new_xtbl->fxt_rehash_work, rehash_work);
	rwlock_init(&new_xtbl->fxt_writers_lock);
	new_xtbl->fxt_eops = eops;

	atomic_set(&new_xtbl->refcnt, 1);
	INIT_WORK(&new_xtbl->fxt_death_work, xtbl_death_work);
	hlist_add_head_rcu(&new_xtbl->fxt_list, head);

	rc = 0;
	goto out;

new_xtbl:
	kfree(new_xtbl);
out:
	return rc;
}
EXPORT_SYMBOL_GPL(init_xid_table);

void init_fxid(struct fib_xid *fxid, const u8 *xid)
{
	INIT_HLIST_NODE(&fxid->u.fx_branch_list[0]);
	INIT_HLIST_NODE(&fxid->u.fx_branch_list[1]);
	memmove(fxid->fx_xid, xid, XIA_XID_MAX);
}
EXPORT_SYMBOL_GPL(init_fxid);

static void free_fxid_rcu(struct rcu_head *head)
{
	struct fib_xid *fxid =
		container_of(head, struct fib_xid, u.dead.rcu_head);
	struct fib_xid_table *xtbl = fxid->u.dead.xtbl;
	free_fxid_t f = xtbl->fxt_eops->free_fxid;

	if (f)
		f(xtbl, fxid);

	xtbl_put(xtbl);
	kfree(fxid);
}

void free_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	fxid->u.dead.xtbl = xtbl;
	xtbl_hold(xtbl);
	call_rcu(&fxid->u.dead.rcu_head, free_fxid_rcu);
}
EXPORT_SYMBOL_GPL(free_fxid);

void free_fxid_norcu(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	free_fxid_t f = xtbl->fxt_eops->free_fxid;
	if (f)
		f(xtbl, fxid);
	kfree(fxid);
}
EXPORT_SYMBOL_GPL(free_fxid_norcu);

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
		struct hlist_node *p, *n;
		struct hlist_head *head = &abranch->buckets[i];
		hlist_for_each_entry_safe(fxid, p, n, head,
					u.fx_branch_list[aindex]) {
			hlist_del(p);
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

void end_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty)
{
	struct hlist_head *head;
	struct fib_xid_table *xtbl = __xia_find_xtbl(rtbl, ty, &head);
	if (!xtbl) {
		pr_err("Not found XID table %x when running %s. Ignoring it, but it's a serious bug!\n",
			__be32_to_cpu(ty), __func__);
		dump_stack();
		return;
	}
	hlist_del_rcu(&xtbl->fxt_list);
	xtbl_put(xtbl);
}
EXPORT_SYMBOL_GPL(end_xid_table);

static void end_rtbl_rcu(struct rcu_head *head)
{
	struct fib_xia_rtable *rtbl =
		container_of(head, struct fib_xia_rtable, rcu_head);
	int i;

	/* This loop is here for redundancy, the most appropriate case
	 * is calling destroy_xia_rtable with an empty routing table.
	 */
	for (i = 0; i < NUM_PRINCIPAL_HINT; i++) {
		struct fib_xid_table *xtbl;
		struct hlist_node *p, *n;
		struct hlist_head *head = &rtbl->ppal[i];
		hlist_for_each_entry_safe(xtbl, p, n, head, fxt_list) {
			/* Notice that hlist_del_rcu(p) is not necessary
			 * because we are inside an RCU call.
			 */
			hlist_del(p);
			xtbl_put(xtbl);
		}
	}
	release_net(rtbl->tbl_net);
	kfree(rtbl);
}

void destroy_xia_rtable(struct fib_xia_rtable **prtbl)
{
	struct fib_xia_rtable *rtbl = *prtbl;
	RCU_INIT_POINTER(*prtbl, NULL);
	call_rcu(&rtbl->rcu_head, end_rtbl_rcu);
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

static inline int are_xids_equal(const u8 *xid1, const u8 *xid2)
{
	const u32 *n1 = (const u32 *)xid1;
	const u32 *n2 = (const u32 *)xid2;
	BUILD_BUG_ON(XIA_XID_MAX != sizeof(const u32) * 5);
	return	n1[0] == n2[0] &&
		n1[1] == n2[1] &&
		n1[2] == n2[2] &&
		n1[3] == n2[3] &&
		n1[4] == n2[4];
}

static struct fib_xid *find_xid_locked(struct fib_xid_table *xtbl,
	u32 bucket, const u8 *xid, struct hlist_head **phead)
{
	struct fib_xid *fxid;
	struct hlist_node *p;
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	int aindex = xtbl_branch_index(xtbl, abranch);
	*phead = __xidhead(abranch->buckets, bucket);
	hlist_for_each_entry(fxid, p, *phead, u.fx_branch_list[aindex]) {
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
	struct hlist_node *p;
	struct hlist_head *head;
	abranch = rcu_dereference(xtbl->fxt_active_branch);
	aindex = xtbl_branch_index(xtbl, abranch);
	head = xidhead(abranch, xid);
	hlist_for_each_entry_rcu(fxid, p, head, u.fx_branch_list[aindex]) {
		if (are_xids_equal(fxid->fx_xid, xid))
			return fxid;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(xia_find_xid_rcu);

static u32 fib_lock_bucket_xid(struct fib_xid_table *xtbl, const u8 *xid)
{
	u32 bucket;
	read_lock(&xtbl->fxt_writers_lock);
	bucket = get_bucket(xid, xtbl->fxt_active_branch->divisor);
	bucket_lock(xtbl, bucket);
	return bucket;
}

static inline u32 fib_lock_bucket(struct fib_xid_table *xtbl,
	struct fib_xid *fxid)
{
	return fib_lock_bucket_xid(xtbl, fxid->fx_xid);
}

void fib_unlock_bucket(struct fib_xid_table *xtbl, u32 bucket)
{
	bucket_unlock(xtbl, bucket);
	read_unlock(&xtbl->fxt_writers_lock);
}
EXPORT_SYMBOL_GPL(fib_unlock_bucket);

struct fib_xid *xia_find_xid_lock(u32 *pbucket, struct fib_xid_table *xtbl,
	const u8 *xid)
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
		struct hlist_node *p, *nxt;
		struct hlist_head *head = __xidhead(abranch->buckets, bucket);
		bucket_lock(xtbl, bucket);
		hlist_for_each_entry_safe(fxid, p, nxt, head,
			u.fx_branch_list[aindex]) {
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
	int new_divisor = abranch->divisor * 2;
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
	should_rehash = atomic_read(&xtbl->fxt_count) /
		xtbl->fxt_active_branch->divisor > 2;
	if (!should_rehash) {
		/* The calling order here is very important because
		 * function free_buckets sleeps.
		 */
		write_unlock(&xtbl->fxt_writers_lock);
		free_buckets(abranch);
		return;
	}

	/* Add entries to @nbranch. */
	for (i = 0; i < abranch->divisor; i++) {
		struct fib_xid *fxid;
		struct hlist_node *p;
		struct hlist_head *head = &abranch->buckets[i];
		hlist_for_each_entry(fxid, p, head, u.fx_branch_list[aindex]) {
			struct hlist_head *new_head =
				xidhead(nbranch, fxid->fx_xid);
			hlist_add_head(&fxid->u.fx_branch_list[nindex],
				new_head);
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

	hlist_add_head_rcu(&fxid->u.fx_branch_list[aindex], head);
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
	hlist_del_rcu(&fxid->u.fx_branch_list[
		xtbl_branch_index(xtbl, abranch)]);
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

int fib_default_delroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid *fxid = fib_rm_xid(xtbl, cfg->xfc_dst->xid_id);
	if (!fxid)
		return -ENOENT;
	free_fxid(xtbl, fxid);
	return 0;
}
EXPORT_SYMBOL_GPL(fib_default_delroute);

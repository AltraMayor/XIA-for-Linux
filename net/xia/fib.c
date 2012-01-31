#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/jhash.h>
#include <linux/cpumask.h>
#include <asm/atomic.h>
#include <asm/cache.h>
#include <net/xia_fib.h>

/*
 *	Lock tables
 */

struct xia_lock_table {
	spinlock_t	*locks;
	int		mask;
};

/* RETURN
 *	Return the size in bytes of the vector of locks; otherwise a negative
 *	number with the error.
 * NOTE
 *	The number of locks in the table is a power of two, and
 *	depends on the number of CPUS.
 */
static int xia_lock_table_init(struct xia_lock_table *lock_table)
{
	int cpus = num_possible_cpus();
	int i, nlocks;
	size_t size;
	spinlock_t *locks;

	BUG_ON(cpus <= 0);
	nlocks = roundup_pow_of_two(cpus) * 0x100;
	BUG_ON(!is_power_of_2(nlocks));

	size = sizeof(spinlock_t) * nlocks;
	locks = kmalloc(size, GFP_KERNEL);
	if (!locks)
		return -ENOMEM;
	for (i = 0; i < nlocks; i++)
		spin_lock_init(&locks[i]);

	lock_table->locks = locks;
	lock_table->mask = nlocks - 1;
	return size;
}

/* NOTE
 *	It does NOT free @lock_table since this function can be used on
 *	static and stack-allocated structures.
 *
 *	Caller must make sure that the table is NOT being used anymore.
 */
static void xia_lock_table_finish(struct xia_lock_table *lock_table)
{
	spinlock_t *locks = lock_table->locks;
	int i, n, warn;

	if (!locks)
		return;

	n = lock_table->mask + 1;
	warn = 0;
	for (i = 0; i < n; n++)
		if (spin_is_locked(&locks[i])) {
			warn = 1;
			break;
		}
	if (warn)
		pr_err("Freeing alive lock table %p\n", lock_table);

	kfree(locks);
	lock_table->locks = NULL;
	lock_table->mask = 0;
}

static inline void xia_lock_table_lock(struct xia_lock_table *lock_table,
	u32 hash)
{
	spin_lock(&lock_table->locks[hash & lock_table->mask]);
}

static inline void xia_lock_table_unlock(struct xia_lock_table *lock_table,
	u32 hash)
{
	spin_unlock(&lock_table->locks[hash & lock_table->mask]);
}

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

static struct xia_lock_table xia_lock_table __read_mostly;

/* Don't make this function inline, it's bigger than it looks like! */
static void bucket_lock(struct fib_xid_table *xtbl, u32 bucket)
{
	xia_lock_table_lock(&xia_lock_table, hash_bucket(xtbl, bucket));
}

/* Don't make this function inline, it's bigger than it looks like! */
static void bucket_unlock(struct fib_xid_table *xtbl, u32 bucket)
{
	xia_lock_table_unlock(&xia_lock_table, hash_bucket(xtbl, bucket));
}

int init_main_lock_table(int *size_byte, int *n)
{
	int rc = xia_lock_table_init(&xia_lock_table);
	if (rc < 0)
		return rc;
	*size_byte = rc;
	*n = xia_lock_table.mask + 1;
	return 0;
}

void destroy_main_lock_table(void)
{
	xia_lock_table_finish(&xia_lock_table);
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

static const struct xia_ppal_rt_iops single_writer_ops;
static const struct xia_ppal_rt_iops multi_writers_ops;

static void xtbl_death_work(struct work_struct *work);
static void rehash_work(struct work_struct *work);

int init_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty,
	const struct xia_ppal_rt_eops *eops, int single_writer)
{
	struct hlist_head *head;
	struct fib_xid_table *new_xtbl;
	struct fib_xid_buckets *abranch;
	int size;
	int rc;
	
	rc = -ESRCH;
	if (__xia_find_xtbl(rtbl, ty, &head))
		goto out; /* Duplicate. */

	size = single_writer ?
		offsetof(typeof(*new_xtbl), extra) : sizeof(*new_xtbl);
	rc = -ENOMEM;
	new_xtbl = kzalloc(size, GFP_KERNEL);
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
	abranch->index = 0;
	new_xtbl->fxt_branch[1].index = 1;
	atomic_set(&new_xtbl->fxt_count, 0);

	new_xtbl->fxt_eops = eops;
	if (!single_writer) {
		new_xtbl->fxt_iops = &multi_writers_ops;
		get_random_bytes(&new_xtbl->fxt_seed,
			sizeof(new_xtbl->fxt_seed));
		rwlock_init(&new_xtbl->fxt_writers_lock);
		INIT_WORK(&new_xtbl->fxt_rehash_work, rehash_work);
	} else {
		new_xtbl->fxt_iops = &single_writer_ops;
		/* The following forces an exception if there is a bug. */
		INIT_WORK(&new_xtbl->fxt_rehash_work, NULL);
	}

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
	aindex = abranch->index;

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
	if (c != rm_count)
		printk(KERN_ERR "While freeing XID table of principal %x "
			"%i entries were found, whereas %i are counted! "
			"Ignoring it, but it's a serious bug!\n",
			__be32_to_cpu(xtbl->fxt_ppal_type), rm_count, c);

	release_net(xtbl->fxt_net);
	free_buckets(abranch);
	kfree(xtbl);
}

void xtbl_finish_destroy(struct fib_xid_table *xtbl)
{
	xtbl->dead = 1;
	barrier(); /* Announce that @xtbl is dead as soon as possible. */

	if (in_interrupt()) {
		schedule_work(&xtbl->fxt_death_work);
	} else {
		xtbl_death_work(&xtbl->fxt_death_work);
	}
}
EXPORT_SYMBOL_GPL(xtbl_finish_destroy);

void end_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty)
{
	struct hlist_head *head;
	struct fib_xid_table *xtbl = __xia_find_xtbl(rtbl, ty, &head);
	if (!xtbl) {
		printk(KERN_ERR "Not found XID table %x when running %s. "
			"Ignoring it, but it's a serious bug!\n",
			__be32_to_cpu(ty), __FUNCTION__);
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

static struct fib_xid *find_xid_locked(struct fib_xid_buckets *abranch,
	u32 bucket, const u8 *xid, struct hlist_head **phead)
{
	struct fib_xid *fxid;
	struct hlist_node *p;
	int aindex = abranch->index;
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
	aindex = abranch->index;
	head = xidhead(abranch, xid);
	hlist_for_each_entry_rcu(fxid, p, head, u.fx_branch_list[aindex]) {
		if (are_xids_equal(fxid->fx_xid, xid))
			return fxid;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(xia_find_xid_rcu);

static void rehash_xtbl(struct fib_xid_table *xtbl)
{
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	int aindex = abranch->index;
	int nindex = 1 - aindex;
	/* Next branch. */
	struct fib_xid_buckets *nbranch = &xtbl->fxt_branch[nindex];
	int new_divisor = abranch->divisor * 2;
	int mv_count1 = 0;
	int mv_count2 = 0;
	int rc, i, c;

	BUG_ON(!is_power_of_2(new_divisor));
	rc = alloc_buckets(nbranch, new_divisor);
	if (rc) {
		printk(KERN_ERR
		"Rehashing XID table %x was not possible due to error %i.\n",
			__be32_to_cpu(xtbl->fxt_ppal_type), rc);
		return;
	}

	for (i = 0; i < abranch->divisor; i++) {
		struct fib_xid *fxid;
		struct hlist_node *p;
		struct hlist_head *head = &abranch->buckets[i];
		hlist_for_each_entry(fxid, p, head, u.fx_branch_list[aindex]) {
			struct hlist_head *new_head = xidhead(nbranch,
				fxid->fx_xid);
			hlist_add_head(&fxid->u.fx_branch_list[nindex],
				new_head);
			mv_count1++;
		}
	}
	rcu_assign_pointer(xtbl->fxt_active_branch, nbranch);

	/* In order to speed up the "update", we have used hlist_add_head
	 * instead of hlist_add_head_rcu to add fxid's in the next branch,
	 * so in order to be safe, we must synchronize.
	 *
	 * Also, the synchronize_rcu() is necessary to clean
	 * fxid->u.fx_branch_list[aindex]'s below.
	 */
	/* XXX This is called under a spinlock when it's in multiple writers
	 * mode!
	 */
	synchronize_rcu();

	/* From now on, readers are using nbranch. */

	/* The following isn't strictly necessary, but having
	 * fxid->u.fx_branch_list[aindex]'s clean may help finding bugs.
	 */
	for (i = 0; i < abranch->divisor; i++) {
		struct fib_xid *fxid;
		struct hlist_node *p, *n;
		struct hlist_head *head = &abranch->buckets[i];
		hlist_for_each_entry_safe(fxid, p, n, head,
				u.fx_branch_list[aindex]) {
			hlist_del(p);
			mv_count2++;
		}
	}

	/* XXX This is called under a spinlock when it's in multiple writers
	 * mode!
	 */
	free_buckets(abranch);

	/* It doesn't return an error here because there's nothing
         * the caller can do about this error/bug.
	 */
	c = atomic_read(&xtbl->fxt_count);
	if (mv_count1 != mv_count2) {
		printk(KERN_ERR "While rehashing XID table of principal %x, "
			"the counters didn't match %i != %i, whereas "
			"the table has %i registered entries. "
			"Ignoreing for now, but it's a serious bug!\n",
			__be32_to_cpu(xtbl->fxt_ppal_type),
			mv_count1, mv_count2, c);
	}
	if (c != mv_count1) {
		printk(KERN_ERR "While rehashing XID table of principal %x, "
			"%i entries were found, whereas %i are registered! "
			"Fixing the counter for now, but it's a serious bug!\n",
			__be32_to_cpu(xtbl->fxt_ppal_type), mv_count1, c);
		/* "Fixing" bug. */
		atomic_set(&xtbl->fxt_count, mv_count1);
	}
}

int fib_add_fxid_locked(u32 bucket, struct fib_xid_table *xtbl,
	struct fib_xid *fxid)
{
	struct hlist_head *head;
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	int should_rehash;

	if (find_xid_locked(abranch, bucket, fxid->fx_xid, &head))
		return -ESRCH;

	hlist_add_head_rcu(&fxid->u.fx_branch_list[abranch->index], head);
	should_rehash =
		atomic_inc_return(&xtbl->fxt_count) / abranch->divisor > 2;

	/* Grow table as needed. */
	if (should_rehash && !xtbl->dead)
		xtbl->fxt_iops->need_to_rehash(xtbl);
	
	return 0;
}
EXPORT_SYMBOL_GPL(fib_add_fxid_locked);

static inline void __rm_fxid(struct fib_xid_table *xtbl,
	struct fib_xid_buckets *abranch, struct fib_xid *fxid)
{
	hlist_del_rcu(&fxid->u.fx_branch_list[abranch->index]);
	atomic_dec(&xtbl->fxt_count);
}

void fib_rm_fxid_locked(u32 bucket, struct fib_xid_table *xtbl,
	struct fib_xid *fxid)
{
	/* Currently, @bucket is not necessary. */
	__rm_fxid(xtbl, xtbl->fxt_active_branch, fxid);
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
	__rm_fxid(xtbl, xtbl->fxt_active_branch, fxid);
	fib_unlock_bucket(xtbl, bucket);
	return fxid;
}
EXPORT_SYMBOL_GPL(fib_rm_xid);

/*
 *	Single Writer (SW)
 */

static struct fib_xid *sw_find_xid_lock(u32 *pbucket,
	struct fib_xid_table *xtbl, const u8 *xid)
{
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	struct hlist_head *head;
	*pbucket = get_bucket(xid, abranch->divisor);
	return find_xid_locked(abranch, *pbucket, xid, &head);
}

static int sw_iterate_xids(struct fib_xid_table *xtbl,
	int (*locked_callback)(struct fib_xid_table *xtbl,
		struct fib_xid *fxid, void *arg),
	void *arg)
{
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	int aindex = abranch->index;
	u32 bucket;
	int rc = 0;

	for (bucket = 0; bucket < abranch->divisor; bucket++) {
		struct fib_xid *fxid;
		struct hlist_node *p, *nxt;
		struct hlist_head *head = __xidhead(abranch->buckets, bucket);
		hlist_for_each_entry_safe(fxid, p, nxt, head,
			u.fx_branch_list[aindex]) {
			rc = locked_callback(xtbl, fxid, arg);
			if (rc)
				goto out;
		}
	}

out:
	return rc;
}

static int sw_add_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_buckets *abranch = xtbl->fxt_active_branch;
	u32 bucket = get_bucket(fxid->fx_xid, abranch->divisor);
	return fib_add_fxid_locked(bucket, xtbl, fxid);
}

static void sw_rm_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	__rm_fxid(xtbl, xtbl->fxt_active_branch, fxid);
}

static void sw_unlock_bucket(struct fib_xid_table *xtbl, u32 bucket)
{
	/* Empty. */
}

static void sw_need_to_rehash(struct fib_xid_table *xtbl)
{
	/* One cannot defer work here because the lock is managed
	 * outside of @xtbl.
	 */
	rehash_xtbl(xtbl);
}

static const struct xia_ppal_rt_iops single_writer_ops = {
	.find_xid_lock	= sw_find_xid_lock,
	.iterate_xids	= sw_iterate_xids,
	.add_fxid	= sw_add_fxid,
	.rm_fxid	= sw_rm_fxid,
	.unlock_bucket	= sw_unlock_bucket,
	.need_to_rehash	= sw_need_to_rehash,
};

/*
 *	Multiple Writers (MW)
 */

static inline u32 mw_lock_xid(struct fib_xid_table *xtbl, const u8 *xid)
{
	u32 bucket;
	read_lock(&xtbl->fxt_writers_lock);
	bucket = get_bucket(xid, xtbl->fxt_active_branch->divisor);
	bucket_lock(xtbl, bucket);
	return bucket;
}

static inline u32 mw_lock(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	return mw_lock_xid(xtbl, fxid->fx_xid);
}

static inline void mw_unlock(struct fib_xid_table *xtbl, u32 bucket)
{
	bucket_unlock(xtbl, bucket);
	read_unlock(&xtbl->fxt_writers_lock);
}

static struct fib_xid *mw_find_xid_lock(u32 *pbucket,
	struct fib_xid_table *xtbl, const u8 *xid)
{
	struct fib_xid_buckets *abranch;
	struct hlist_head *head;
	*pbucket = mw_lock_xid(xtbl, xid);
	abranch = xtbl->fxt_active_branch;
	return find_xid_locked(abranch, *pbucket, xid, &head);
}

static int mw_iterate_xids(struct fib_xid_table *xtbl,
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
	aindex = abranch->index;

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

static void rehash_work(struct work_struct *work)
{
	struct fib_xid_table *xtbl = container_of(work, struct fib_xid_table,
		fxt_rehash_work);
	int should_rehash;

	/* Grow table as needed. */

	write_lock(&xtbl->fxt_writers_lock);

	/* We must test if we @should_rehash again because we may be
	 * following another rehash_work that just finished.
	 * Even if we're not following another rehash_work, fxt_count may have
	 * changed while we waited on write_lock() or to be scheduled, and
	 * a rehash became unnecessary.
	 */
	should_rehash = atomic_read(&xtbl->fxt_count) /
		xtbl->fxt_active_branch->divisor > 2;

	if (should_rehash)
		rehash_xtbl(xtbl);

	write_unlock(&xtbl->fxt_writers_lock);
}

static int mw_add_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	u32 bucket;
	int rc;

	bucket = mw_lock(xtbl, fxid);
	rc = fib_add_fxid_locked(bucket, xtbl, fxid);
	mw_unlock(xtbl, bucket);
	return rc;
}

static void mw_rm_fxid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	u32 bucket = mw_lock(xtbl, fxid);
	__rm_fxid(xtbl, xtbl->fxt_active_branch, fxid);
	mw_unlock(xtbl, bucket);
}

static void mw_unlock_bucket(struct fib_xid_table *xtbl, u32 bucket)
{
	mw_unlock(xtbl, bucket);
}

static void mw_need_to_rehash(struct fib_xid_table *xtbl)
{
	schedule_work(&xtbl->fxt_rehash_work);
}

static const struct xia_ppal_rt_iops multi_writers_ops = {
	.find_xid_lock	= mw_find_xid_lock,
	.iterate_xids	= mw_iterate_xids,
	.add_fxid	= mw_add_fxid,
	.rm_fxid	= mw_rm_fxid,
	.unlock_bucket	= mw_unlock_bucket,
	.need_to_rehash	= mw_need_to_rehash,
};

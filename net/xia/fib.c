#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <net/xia_fib.h>

/* TODO Review the code for concorrency! */
/* TODO Some structures may need a slab for better performance. */

struct fib_xia_rtable *create_xia_rtable(void)
{
	struct fib_xia_rtable *rtbl = kmalloc(sizeof(*rtbl), GFP_KERNEL);

	if (!rtbl)
		return NULL;

	memset(rtbl, 0, sizeof(*rtbl));
	return rtbl;
}

static inline struct hlist_head *ppalhead(struct fib_xia_rtable *rtbl,
						xid_type_t ty)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(NUM_PRINCIPAL_HINT);
	return &rtbl->ppal[ty & (NUM_PRINCIPAL_HINT - 1)];
}

static struct fib_xid_table *find_xtbl(struct fib_xia_rtable *rtbl,
					xid_type_t ty,
					struct hlist_head **phead)
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

static inline int alloc_buckets(struct hlist_head **pbuckets, size_t num)
{
	size_t size = sizeof(**pbuckets) * num;
	*pbuckets = kmalloc(size, GFP_KERNEL);
	if (!*pbuckets)
		return -ENOMEM;
	memset(*pbuckets, 0, size);
	return 0;
}

#define XTBL_INITIAL_DIV 8

static int init_xid_table(struct fib_xia_rtable *rtbl, xid_type_t ty)
{
	struct hlist_head *head;
	struct fib_xid_table *new_xtbl;
	int rc;
	
	rc = -EINVAL;
	if (find_xtbl(rtbl, ty, &head))
		goto out; /* Duplicate. */

	rc = -ENOMEM;
	new_xtbl = kmalloc(sizeof(*new_xtbl), GFP_KERNEL);
	if (!new_xtbl)
		goto out;
	if (alloc_buckets(&new_xtbl->fxt_buckets, XTBL_INITIAL_DIV))
		goto new_xtbl;

	new_xtbl->fxt_ppal_type = ty;
	new_xtbl->fxt_divisor = XTBL_INITIAL_DIV;
	new_xtbl->fxt_count = 0;
	hlist_add_head(&new_xtbl->fxt_list, head);

	rc = 0;
	goto out;
	
new_xtbl:
	kfree(new_xtbl);
out:
	return rc;
}

static int end_xid_table(struct fib_xid_table *xtbl)
{
	int rm_count = 0;
	int i;

	hlist_del(&xtbl->fxt_list);
	for (i = 0; i < xtbl->fxt_divisor; i++) {
		struct fib_xid *fxid;
		struct hlist_node *p, *n;
		struct hlist_head *head = &xtbl->fxt_buckets[i];
		hlist_for_each_entry_safe(fxid, p, n, head, fx_list) {
			hlist_del(p);
			kfree(fxid);
			rm_count++;
		}
	}
	kfree(xtbl->fxt_buckets);

	/* It doesn't return an error here because there's nothing
         * the caller can do about this error/bug.
	 */
	if (xtbl->fxt_count != rm_count)
		printk(KERN_ERR "While freeing XID table of principal %u "
			"%i entries were found, whereas %i are counted! "
			"Ignoring it, but it's a serious bug!\n",
			__be32_to_cpu(xtbl->fxt_ppal_type), rm_count,
			xtbl->fxt_count);

	return 0;
}

int destroy_xia_rtable(struct fib_xia_rtable *rtbl)
{
	int i;
	for (i = 0; i < NUM_PRINCIPAL_HINT; i++) {
		struct fib_xid_table *xtbl;
		struct hlist_node *p, *n;
		struct hlist_head *head = &rtbl->ppal[i];
		hlist_for_each_entry_safe(xtbl, p, n, head, fxt_list) {
			hlist_del(p);
			end_xid_table(xtbl);
		}
	}
	kfree(rtbl);
	return 0;
}

static inline u32 sum_xid(const char *xid)
{
	const u32 *n = (const u32 *)xid;
	BUILD_BUG_ON(XIA_XID_MAX != sizeof(const u32) * 5);
	return n[0] + n[1] + n[2] + n[3] + n[4];
}

static inline struct hlist_head *xidhead(struct hlist_head *buckets,
					const char *xid, int divisor)
{
	return &buckets[sum_xid(xid) % divisor];
}

static inline int are_xids_equal(const char *xid1, const char *xid2)
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

static struct fib_xid *find_xid(struct fib_xid_table *xtbl,
					const char *xid,
					struct hlist_head **phead)
{
	struct fib_xid *fxid;
	struct hlist_node *p;
	*phead = xidhead(xtbl->fxt_buckets, xid, xtbl->fxt_divisor);
	hlist_for_each_entry(fxid, p, *phead, fx_list) {
		if (are_xids_equal(fxid->fx_xid, xid))
			return fxid;
	}
	return NULL;
}

static int rehash_xtbl(struct fib_xid_table *xtbl)
{
	struct hlist_head *new_buckets;
	int rc, i;
	int old_divisor = xtbl->fxt_divisor;
	int new_divisor = old_divisor * 2;
	int mv_count = 0;

	rc = alloc_buckets(&new_buckets, new_divisor);
	if (rc)
		return rc;

	for (i = 0; i < old_divisor; i++) {
		struct fib_xid *fxid;
		struct hlist_node *p, *n;
		struct hlist_head *head = &xtbl->fxt_buckets[i];
		hlist_for_each_entry_safe(fxid, p, n, head, fx_list) {
			struct hlist_head *new_head = xidhead(new_buckets,
				fxid->fx_xid, new_divisor);
			hlist_del(p);
			hlist_add_head(p, new_head);
			mv_count++;
		}
	}
	xtbl->fxt_buckets = new_buckets;
	xtbl->fxt_divisor = new_divisor;

	/* It doesn't return an error here because there's nothing
         * the caller can do about this error/bug.
	 */
	if (xtbl->fxt_count != mv_count) {
		printk(KERN_ERR "While rehashing XID table of principal %u "
			"%i entries were found, whereas %i are counted! "
			"Fixing the counter for now, but it's a serious bug!\n",
			__be32_to_cpu(xtbl->fxt_ppal_type), mv_count,
			xtbl->fxt_count);
		xtbl->fxt_count = mv_count;
	}

	return 0;
}

static int fib_add_xid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct hlist_head *head;
	struct fib_xid *old_fxid = find_xid(xtbl, fxid->fx_xid, &head);

	if (old_fxid)
		return -EINVAL;

	hlist_add_head(&fxid->fx_list, head);
	xtbl->fxt_count++;

	/* Grow table as needed. */
	if (xtbl->fxt_count / xtbl->fxt_divisor > 2)
		return rehash_xtbl(xtbl);

	return 0;
}

static struct fib_xid *fib_rm_xid(struct fib_xid_table *xtbl, const char *xid)
{
	struct hlist_head *head;
	struct fib_xid *fxid = find_xid(xtbl, xid, &head);

	if (!fxid)
		return NULL;

	hlist_del(&fxid->fx_list);
	xtbl->fxt_count--;
	return fxid;
}

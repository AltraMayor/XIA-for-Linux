#include <linux/export.h>
#include <linux/slab.h>
#include <net/xia_locktbl.h>

int xia_lock_table_init(struct xia_lock_table *lock_table, int spread)
{
	int cpus = num_possible_cpus();
	int i, nlocks;
	size_t size;
	spinlock_t *locks;	/* Table locks. */

	BUG_ON(cpus <= 0);
	nlocks = roundup_pow_of_two(cpus * spread);

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
EXPORT_SYMBOL_GPL(xia_lock_table_init);

void xia_lock_table_finish(struct xia_lock_table *lock_table)
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
	if (warn) {
		pr_err("Freeing alive lock table %p\n", lock_table);
		dump_stack();
	}

	kfree(locks);
	lock_table->locks = NULL;
	lock_table->mask = 0;
}
EXPORT_SYMBOL_GPL(xia_lock_table_finish);

struct xia_lock_table xia_main_lock_table __read_mostly;
EXPORT_SYMBOL_GPL(xia_main_lock_table);

int __init init_main_lock_table(int *size_byte, int *n)
{
	int rc = xia_lock_table_init(&xia_main_lock_table,
		XIA_LTBL_SPREAD_LARGE);

	if (rc < 0)
		return rc;
	*size_byte = rc;
	*n = xia_main_lock_table.mask + 1;
	return 0;
}

void destroy_main_lock_table(void)
{
	xia_lock_table_finish(&xia_main_lock_table);
}

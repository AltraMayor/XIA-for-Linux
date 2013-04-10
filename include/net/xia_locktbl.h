#ifndef	_NET_XIA_LOCKTBL_H
#define	_NET_XIA_LOCKTBL_H

#include <linux/spinlock.h>

struct xia_lock_table {
	spinlock_t	*locks;
	int		mask;
};

static inline void xia_lock_table_lock(struct xia_lock_table *lock_table,
	u32 hash)
{
	spin_lock_bh(&lock_table->locks[hash & lock_table->mask]);
}

static inline void xia_lock_table_unlock(struct xia_lock_table *lock_table,
	u32 hash)
{
	spin_unlock_bh(&lock_table->locks[hash & lock_table->mask]);
}

/* Constants to be used as the second parameter of xia_lock_table_init. */
#define XIA_LTBL_SPREAD_LARGE	256
#define XIA_LTBL_SPREAD_MEDIUM	64
#define XIA_LTBL_SPREAD_SMALL	1

/* RETURN
 *	Return the size in bytes of the vector of locks; otherwise a negative
 *	number with the error.
 * NOTE
 *	The number of locks in the table is a power of two, and
 *	depends on the number of CPUS.
 */
int xia_lock_table_init(struct xia_lock_table *lock_table, int spread);

/* NOTE
 *	It does NOT free @lock_table since this function can be used on
 *	static and stack-allocated structures.
 *
 *	Caller must make sure that the table is NOT being used anymore.
 */
void xia_lock_table_finish(struct xia_lock_table *lock_table);

/* Main lock table to be shared by XIA stack. */
extern struct xia_lock_table xia_main_lock_table;

#endif	/* _NET_XIA_LOCKTBL_H */

#ifdef __KERNEL__

#include <linux/ctype.h>
#include <linux/spinlock.h>
#include <linux/export.h>

#define mymalloc(n)	kmalloc(n, GFP_ATOMIC)
#define myfree(p)	kfree(p)

#else /* Userland */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <asm-generic/errno-base.h>

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member)*__mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_rcu	hlist_for_each_entry

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

#define hlist_add_head_rcu	hlist_add_head

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

#define LIST_POISON1	NULL
#define LIST_POISON2	NULL
static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

#define hlist_del_rcu		hlist_del

#define mymalloc(n)	malloc(n)
#define myfree(p)	free(p)

#define BUG_ON(b)	assert(!(b))

/* Force a compilation error if a constant expression is not a power of 2 */
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))

#define EXPORT_SYMBOL(x)

#define spin_lock(x)
#define spin_unlock(x)

static inline void rcu_read_lock(void)		{ }
static inline void rcu_read_unlock(void)	{ }
static inline void synchronize_rcu(void)	{ }

#define likely(b) (b)
#define unlikely(b) (b)

#endif /* __KERNEL__ */

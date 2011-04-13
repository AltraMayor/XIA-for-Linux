#include <asm/byteorder.h>
#include <linux/kernel.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>

/* IMPORTANT
 *
 * This file is intended to be used by userland applications without editing!
 *
 * For userland uses, copy the following files:
 * net/xia/dag.c		This file!
 * net/xia/dag_userland.h	Defines for userland.
 * include/net/xia.h		Header file.
 * include/net/xia_dag.h	Header file.
 *
 */

#include "dag_userland.h"

/* Map beween principal names and numbers */

struct ppal_node {
	struct hlist_node	lst_per_name;
	struct hlist_node	lst_per_type;
	char			name[MAX_PPAL_NAME_SIZE];
	xid_type_t		type;
};

/* This constant must be a power of 2. */
#define PPAL_MAP_SIZE	128

#ifdef __KERNEL__
static DEFINE_SPINLOCK(map_lock);
#endif
static struct hlist_head ppal_head_per_name[PPAL_MAP_SIZE];
static struct hlist_head ppal_head_per_type[PPAL_MAP_SIZE];

static __u32 djb_case_hash(const char *str)
{
	__u32 hash = 5381;
	/* The typecast avoids a warning.
	 * Notice that this function expects that chars are unsigned.
	 */
	const __u8 *p = (const __u8 *)str;

	while (*p) {
		hash = ((hash << 5) + hash) + tolower(*p);
		p++;
	}
	return hash;
}

static inline struct hlist_head *head_per_name(const char *name)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(PPAL_MAP_SIZE);
	return &ppal_head_per_name[djb_case_hash(name) & (PPAL_MAP_SIZE - 1)];
}

static inline struct hlist_head *head_per_type(xid_type_t type)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(PPAL_MAP_SIZE);
	return &ppal_head_per_type[__be32_to_cpu(type) & (PPAL_MAP_SIZE - 1)];
}

int ppal_name_to_type(const char *name, xid_type_t *pty)
{
	const struct ppal_node *map;
	int rc = -ENOENT;

	rcu_read_lock();
	hlist_for_each_entry_rcu(map, head_per_name(name), lst_per_name)
		if (!strcasecmp(map->name, name)) {
			*pty = map->type;
			rc = 0;
			goto out;
		}

out:
	rcu_read_unlock();
	return rc;
}
EXPORT_SYMBOL(ppal_name_to_type);

int ppal_type_to_name(xid_type_t type, char *name)
{
	const struct ppal_node *map;
	int rc = -ENOENT;

	rcu_read_lock();
	hlist_for_each_entry_rcu(map, head_per_type(type), lst_per_type)
		if (map->type == type) {
			strcpy(name, map->name);
			rc = 0;
			goto out;
		}

out:
	rcu_read_unlock();
	return rc;
}
EXPORT_SYMBOL(ppal_type_to_name);

static inline int isname(char ch)
{
	return isgraph(ch) && ch != '-';
}

static int is_name_valid(const char *name)
{
	int left = MAX_PPAL_NAME_SIZE;

	/* Avoid empty names, and numbers. */
	if ((*name == '\0') ||
	    (*name == '0' && (name[1] == 'x' || name[1] == 'X')))
		return 0;

	while (left > 0 && isname(*name)) {
		name++;
		left--;
	}

	if (left > 0 && *name == '\0')
		return 1;
	return 0;
}

static inline void lowerstr(char *s)
{
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

int ppal_add_map(const char *name, xid_type_t type)
{
	struct hlist_head *h_per_name, *h_per_type;
	struct ppal_node *map;
	int rc;

	if (!is_name_valid(name))
		return -EINVAL;

	/* This can be done before the lock because
	 * this addresses don't change.
	 */
	h_per_name = head_per_name(name);
	h_per_type = head_per_type(type);

	spin_lock(&map_lock);

	/* Avoid duplicates. */
	rc = -EEXIST;
	hlist_for_each_entry(map, h_per_name, lst_per_name)
		if (!strcasecmp(map->name, name))
			goto out;
	hlist_for_each_entry(map, h_per_type, lst_per_type)
		if (map->type == type)
			goto out;

	/* Initialize new entry. */
	rc = -ENOMEM;
	map = mymalloc(sizeof(*map));
	if (!map)
		goto out;
	/* It is safe to call strcpy because we validated name before. */
	strcpy(map->name, name);
	lowerstr(map->name);
	map->type = type;

	/* Add entry to lists. */
	hlist_add_head_rcu(&map->lst_per_name, h_per_name);
	hlist_add_head_rcu(&map->lst_per_type, h_per_type);
	rc = 0;

out:
	spin_unlock(&map_lock);
	return rc;
}
EXPORT_SYMBOL(ppal_add_map);

int ppal_del_map(xid_type_t type)
{
	struct ppal_node *map;

	spin_lock(&map_lock);

	hlist_for_each_entry(map, head_per_type(type), lst_per_type)
		if (map->type == type) {
			hlist_del_rcu(&map->lst_per_name);
			hlist_del_rcu(&map->lst_per_type);

			spin_unlock(&map_lock);

			synchronize_rcu();
			myfree(map);
			return 0;
		}

	spin_unlock(&map_lock);
	return -ENOENT;
}
EXPORT_SYMBOL(ppal_del_map);

/* Validating addresses */

int xia_are_edges_valid(const struct xia_row *row,
			__u8 node, __u8 num_node, __u32 *pvisited)
{
	const __u8 *edge;
	__u32 all_edges, bits;
	int i;

	BUILD_BUG_ON(XIA_OUTDEGREE_MAX != 4);

	/* The plus one is just to make sure that the following number
	 * is valid ((1U << num_node) - 1).
	 */
	BUILD_BUG_ON(XIA_NODES_MAX + 1 > sizeof(*pvisited) * 8);

	if (unlikely(is_any_edge_chosen(row))) {
		/* Since at least an edge of last_node has already
		 * been chosen, the address is corrupted.
		 */
		return -XIAEADDR_CHOSEN_EDGE;
	}

	edge = row->s_edge.a;
	all_edges = __be32_to_cpu(row->s_edge.i);
	bits = 0xffffffff;
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++, edge++) {
		__u8 e = *edge;

		if (e == XIA_EMPTY_EDGE) {
			if ((all_edges & bits) !=
				(XIA_EMPTY_EDGES & bits))
				return -XIAEADDR_EE_MISPLACED;
			else
				break;
		} else if (e >= num_node) {
			return -XIAEADDR_EDGE_OUT_RANGE;
		} else if (node < (num_node - 1) && e <= node) {
			/* Notice that if (node == XIA_ENTRY_NODE_INDEX)
			 * it still works fine because XIA_ENTRY_NODE_INDEX
			 * is greater than (num_node - 1).
			 */
			return -XIAEADDR_NOT_TOPOLOGICAL;
		}
		bits >>= 8;
		*pvisited |= 1 << e;
	}
	return 0;
}
EXPORT_SYMBOL(xia_are_edges_valid);

int xia_test_addr(const struct xia_addr *addr)
{
	int i, n;
	int saw_nat = 0;
	__u32 visited = 0;

	/* Test that XIDTYPE_NAT is present only on last rows. */
	n = XIA_NODES_MAX;
	for (i = 0; i < XIA_NODES_MAX; i++) {
		xid_type_t ty = addr->s_row[i].s_xid.xid_type;

		if (saw_nat) {
			if (!xia_is_nat(ty))
				return -XIAEADDR_NAT_MISPLACED;
		} else if (xia_is_nat(ty)) {
			n = i;
			saw_nat = 1;
		}
	}
	/* n = number of nodes from here. */

	/* Test edges are well formed. */
	for (i = 0; i < n; i++) {
		int rc = xia_are_edges_valid(&addr->s_row[i], i, n, &visited);

		if (rc)
			return rc;
	}

	if (n >= 1) {
		/* Test entry point is present. Notice that it's just a
		 * friendlier error since it's also XIAEADDR_MULTI_COMPONENTS.
		 */
		__be32 all_edges = addr->s_row[n - 1].s_edge.i;

		if (__be32_to_raw_cpu(all_edges) == XIA_EMPTY_EDGES)
			return -XIAEADDR_NO_ENTRY;

		if (visited != ((1U << n) - 1))
			return -XIAEADDR_MULTI_COMPONENTS;
	}

	return n;
}
EXPORT_SYMBOL(xia_test_addr);

/* Printing addresses out */

/* Empty edges are represented by '*'.
 * Edges' indexes greater than 'z' are made equal to '+'.
 */
#define INDEX_BASE 36
static inline char edge_to_char(__u8 e)
{
	char *ch_edge = "0123456789abcdefghijklmnopqrstuvwxyz";
		/*       0123456789012345678901234567890123456789 */
	e &= ~XIA_CHOSEN_EDGE;
	if (likely(e < INDEX_BASE))
		return ch_edge[e];
	else if (is_empty_edge(e))
		return '*';
	else
		return '+';
}

/* Perform s >= u.
 * It's useful to avoid compiling warnings, and be sure what's going on
 * when numbers are large.
 */
static inline int su_ge(signed int s, unsigned int u)
{
	return (s >= 0) && ((unsigned int)s >= u);
}

static inline int add_str(char *dst, size_t dstlen, char *s)
{
	int rc = snprintf(dst, dstlen, "%s", s);

	if (su_ge(rc, dstlen))
		return -ENOSPC;
	return rc;
}

static inline int add_char(char *dst, size_t dstlen, char ch)
{
	if (dstlen <= 1)
		return -ENOSPC;
	dst[0] = ch;
	dst[1] = '\0';
	return 1;
}

static inline void move_buf(char **dst, size_t *dstlen, int *tot, int step)
{
	(*dst) += step;
	(*dstlen) -= step;
	(*tot) += step;
}

static int edges_to_str(int valid, char *dst, size_t dstlen, const __u8 *edges)
{
	int tot = 0;
	char *begin = dst;
	int rc, i;

	rc = add_char(dst, dstlen, '-');
	if (rc < 0)
		return rc;
	move_buf(&dst, &dstlen, &tot, rc);

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		if (valid && edges[i] == XIA_EMPTY_EDGE) {
			if (i == 0) {
				*begin = '\0';
				return 0;
			}
			break;
		}

		if (is_edge_chosen(edges[i])) {
			rc = add_char(dst, dstlen, '>');
			if (rc < 0)
				return rc;
			move_buf(&dst, &dstlen, &tot, rc);
		}

		rc = add_char(dst, dstlen, edge_to_char(edges[i]));
		if (rc < 0)
			return rc;
		move_buf(&dst, &dstlen, &tot, rc);
	}
	return tot;
}

int xia_tytop(xid_type_t ty, char *dst, size_t dstlen)
{
	if (dstlen < MAX_PPAL_NAME_SIZE)
		return -ENOSPC;
	if (ppal_type_to_name(ty, dst)) {
		/* Number format. */
		int rc = snprintf(dst, dstlen, "0x%x", __be32_to_cpu(ty));

		BUILD_BUG_ON(sizeof(xid_type_t) != 4);
		if (su_ge(rc, dstlen))
			return -ENOSPC;
		return rc;
	} else {
		return strlen(dst);
	}
}
EXPORT_SYMBOL(xia_tytop);

int xia_idtop(const struct xia_xid *src, char *dst, size_t dstlen)
{
	const __be32 *pxid = (const __be32 *)src->xid_id;
	__u32 a = __be32_to_cpu(pxid[0]);
	__u32 b = __be32_to_cpu(pxid[1]);
	__u32 c = __be32_to_cpu(pxid[2]);
	__u32 d = __be32_to_cpu(pxid[3]);
	__u32 e = __be32_to_cpu(pxid[4]);
	int rc;

	BUILD_BUG_ON(XIA_XID_MAX != 20);

	rc = snprintf(dst, dstlen, "%08x%08x%08x%08x%08x", a, b, c, d, e);
	if (su_ge(rc, dstlen))
		return -ENOSPC;
	return rc;
}
EXPORT_SYMBOL(xia_idtop);

int xia_xidtop(const struct xia_xid *src, char *dst, size_t dstlen)
{
	int tot = 0;
	int rc;

	rc = xia_tytop(src->xid_type, dst, dstlen);
	if (rc < 0)
		return rc;
	move_buf(&dst, &dstlen, &tot, rc);

	rc = add_char(dst, dstlen, '-');
	if (rc < 0)
		return rc;
	move_buf(&dst, &dstlen, &tot, rc);

	rc = xia_idtop(src, dst, dstlen);
	if (rc < 0)
		return rc;
	move_buf(&dst, &dstlen, &tot, rc);

	return tot;
}
EXPORT_SYMBOL(xia_xidtop);

int xia_ntop(const struct xia_addr *src, char *dst, size_t dstlen,
	     int include_nl)
{
	int tot = 0;
	char *node_sep = include_nl ? ":\n" : ":";
	int valid = xia_test_addr(src) >= 1;
	int rc, i;

	if (!valid) {
		rc = add_char(dst, dstlen, '!');
		if (rc < 0)
			return rc;
		move_buf(&dst, &dstlen, &tot, rc);
	}

	for (i = 0; i < XIA_NODES_MAX; i++) {
		const struct xia_row *row = &src->s_row[i];

		if (xia_is_nat(row->s_xid.xid_type))
			break;

		if (i > 0) {
			rc = add_str(dst, dstlen, node_sep);
			if (rc < 0)
				return rc;
			move_buf(&dst, &dstlen, &tot, rc);
		}

		rc = xia_xidtop(&row->s_xid, dst, dstlen);
		if (rc < 0)
			return rc;
		move_buf(&dst, &dstlen, &tot, rc);

		rc = edges_to_str(valid, dst, dstlen, row->s_edge.a);
		if (rc < 0)
			return rc;
		move_buf(&dst, &dstlen, &tot, rc);
	}

	return tot;
}
EXPORT_SYMBOL(xia_ntop);

/* xia_pton and its auxiliares functions */

static inline void next(const char **pp, size_t *pleft)
{
	(*pp)++;
	(*pleft)--;
}

static inline int read_sep(const char **pp, size_t *pleft, char sep)
{
	if (*pleft <= 0 || **pp != sep)
		return -1;
	next(pp, pleft);
	return 0;
}

static int read_invalid_flag(const char **pp, size_t *pleft, int *invalid_flag)
{
	int inv_flag;

	if (*pleft <= 0) /* No XIA address is an empty string. */
		return -1;
	inv_flag = **pp == '!';
	if (inv_flag)
		next(pp, pleft);
	if (invalid_flag)
		*invalid_flag = inv_flag;
	return 0;
}

static inline int ascii_to_int(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	else if (ch >= 'A' && ch <= 'Z')
		return ch - 'A' + 10;
	else if (ch >= 'a' && ch <= 'z')
		return ch - 'a' + 10;
	else
		return 64;
}

static int read_be32(const char **pp, size_t *pleft, __be32 *value)
{
	__u32 result = 0;
	int i = 0;

	while (*pleft >= 1 && isxdigit(**pp) && i < 8) {
		result = (result << 4) + ascii_to_int(**pp);
		next(pp, pleft);
		i++;
	}
	*value = __cpu_to_be32(result);
	return i;
}

static int read_name(const char **pp, size_t *pleft, char *name, int len)
{
	int i = 0;
	int last = len - 1;

	BUG_ON(len < 1);

	while (*pleft >= 1 && isname(**pp) && i < last) {
		name[i] = **pp;
		next(pp, pleft);
		i++;
	}
	/* It's safer to terminate the string before returning. */
	name[i] = '\0';
	if (*pleft >= 1 && isname(**pp) && i >= last)
		return -1;
	return i;
}

static int read_0x(const char **pp, size_t *pleft)
{
	char ch1, ch2;

	if (*pleft < 2)
		return -1;
	ch1 = (*pp)[0];
	/* Can't fetch ch2 here because it may beyond string limits! */
	if (ch1 != '0')
		return -1;
	ch2 = (*pp)[1];
	if (ch2 != 'x' && ch2 != 'X')
		return -1;

	(*pp) += 2;
	(*pleft) -= 2;
	return 0;
}

static int read_type(const char **pp, size_t *pleft, xid_type_t *pty)
{
	if (read_0x(pp, pleft) < 0) {
		/* It must be a name. */
		char name[MAX_PPAL_NAME_SIZE];

		if (read_name(pp, pleft, name, sizeof(name)) < 0)
			return -1;
		/* One does not need to test if @name is valid here because
		 * all mapped names are valid.
		 */
		if (ppal_name_to_type(name, pty) < 0)
			return -1;
		return 0;
	}

	/* Handle numbers. */
	BUILD_BUG_ON(sizeof(xid_type_t) != 4);
	/* There must be at least a digit! */
	if (read_be32(pp, pleft, pty) < 1)
		return -1;
	return 0;
}

static int read_xid(const char **pp, size_t *pleft, __u8 *xid)
{
	int i;
	__be32 *pxid = (__be32 *)xid;

	BUILD_BUG_ON(XIA_XID_MAX != 20);

	for (i = 0; i < 5; i++) {
		if (read_be32(pp, pleft, pxid++) != 8)
			return -1;
	}
	return 0;
}

static int read_edges(const char **pp, size_t *pleft, __u8 *edges,
		      int ignore_ce)
{
	int i;

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++)
		edges[i] = XIA_EMPTY_EDGE;
	if (read_sep(pp, pleft, '-')) {
		/* No edges, we're done. */
		return 0;
	}

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		int ce = 0;
		int e = XIA_EMPTY_EDGE;

		if (!read_sep(pp, pleft, '>'))
			ce = ignore_ce ? 0 : XIA_CHOSEN_EDGE;

		if (*pleft >= 1 && isalnum(**pp)) {
			e = ascii_to_int(**pp);
			next(pp, pleft);
		} else if (!read_sep(pp, pleft, '*')) {
			/* e is already equal to XIA_EMPTY_EDGE. */
		} else if (i == 0) {
			/* At least an edge is necessary since we saw a '-'.
			 * We don't support '+' because
			 * one cannot know which value to associate to it.
			 */
			return -1;
		} else {
			break;
		}
		edges[i] = ce | e;
	}
	return 0;
}

static int read_row(const char **pp, size_t *pleft, struct xia_row *row,
		    int ignore_ce)
{
	if (read_type(pp, pleft, &row->s_xid.xid_type))
		return -1;
	if (read_sep(pp, pleft, '-'))
		return -1;
	if (read_xid(pp, pleft, row->s_xid.xid_id))
		return -1;
	if (read_edges(pp, pleft, row->s_edge.a, ignore_ce))
		return -1;
	return 0;
}

static int read_node_sep(const char **pp, size_t *pleft)
{
	if (read_sep(pp, pleft, ':'))
		return -1;
	read_sep(pp, pleft, '\n');
	return 0;
}

int xia_pton(const char *src, size_t srclen, struct xia_addr *dst,
	     int ignore_ce, int *invalid_flag)
{
	const char *p = src;
	size_t left = srclen;
	int i = 0;

	memset(dst, 0, sizeof(*dst));

	if (read_invalid_flag(&p, &left, invalid_flag))
		return -1;

	do {
		if (read_row(&p, &left, &dst->s_row[i], ignore_ce))
			return -1;
		if (++i >= XIA_NODES_MAX)
			return -1;
	} while (!read_node_sep(&p, &left));

	/* It's okay to have a newline on the last line. */
	read_sep(&p, &left, '\n');

	/* A whole address must be parsed. */
	if (left != 0 && *p != '\0')
		return -1;
	return srclen - left;
}
EXPORT_SYMBOL(xia_pton);

int xia_ptoxid(const char *src, size_t srclen, struct xia_xid *dst)
{
	const char *p = src;
	size_t left = srclen;

	if (read_type(&p, &left, &dst->xid_type))
		return -1;
	if (read_sep(&p, &left, '-'))
		return -1;
	if (read_xid(&p, &left, dst->xid_id))
		return -1;

	/* A whole XID must be parsed. */
	if (left != 0 && *p != '\0')
		return -1;
	return srclen - left;
}
EXPORT_SYMBOL(xia_ptoxid);

int xia_ptoid(const char *src, size_t srclen, struct xia_xid *dst)
{
	const char *p = src;
	size_t left = srclen;

	if (read_xid(&p, &left, dst->xid_id))
		return -1;

	/* A whole ID must be parsed. */
	if (left != 0 && *p != '\0')
		return -1;
	return srclen - left;
}
EXPORT_SYMBOL(xia_ptoid);

#include <asm/byteorder.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <net/xia.h>

#define EMPTY_EDGES 	(XIA_EMPTY_EDGE << 24 | XIA_EMPTY_EDGE << 16 |\
			 XIA_EMPTY_EDGE <<  8 | XIA_EMPTY_EDGE)
int xia_test_addr(const struct xia_addr *addr)
{
	int i, j, n;
	int saw_nat = 0;

	/* Test that XIDTYPE_NAT is present only on last rows. */
	n = XIA_NODES_MAX;
	for (i = 0; i < XIA_NODES_MAX; i++) {
		xid_type_t ty = addr->s_row[i].s_xid_type;
		if (saw_nat) {
			if (ty != XIDTYPE_NAT)
				return -XIAEADDR_NAT_MISPLACED;
		} else if (ty == XIDTYPE_NAT) {
			n = i;
			saw_nat = 1;
		}
	}
	/* n = number of nodes from here. */

	BUILD_BUG_ON(XIA_OUTDEGREE_MAX != 4);

	/* Test edges are well formed. */
	for (i = 0; i < n; i++) {
		const struct xia_row *row = &addr->s_row[i];
		const u8 *edge = row->s_edge.a;
		u32 all_edges = __be32_to_cpu(row->s_edge.i);
		u32 bits = 0xffffffff;
		for (j = 0; j < XIA_OUTDEGREE_MAX; j++, edge++) {
			u8 e = *edge;
			if (e & XIA_CHOSEN_EDGE) {
				return -XIAEADDR_CHOSEN_EDGE;
			} else if (e == XIA_EMPTY_EDGE) {
				if ((all_edges & bits) != (EMPTY_EDGES & bits))
					return -XIAEADDR_EE_MISPLACED;
				else
					break;
			} else if (e >= n) {
				return -XIAEADDR_EDGE_OUT_RANGE;
			}
			bits >>= 8;
		}
	}

	if (n >= 1) {
		__be32 all_edges = addr->s_row[n - 1].s_edge.i;
		
		/* Test entry point is present. */
		/* __be32_to_cpu is not necessary here! */
		if (all_edges == EMPTY_EDGES) {
			return -XIAEADDR_NO_ENTRY;
		}

		/* XXX Test the graph is connected and acyclic. */
	}

	return n;
}
EXPORT_SYMBOL(xia_test_addr);

#define INDEX_BASE 36
static inline char edge_to_char(u8 e)
{
	char *ch_edge = "0123456789abcdefghijklmnopqrstuvwxyz";
		/*       0123456789012345678901234567890123456789 */
	if (likely(e < INDEX_BASE))
		return ch_edge[e];
	else if (is_empty_edge(e))
		return '*';
	else
		return '+';
}

int xia_ntop(const struct xia_addr *src, char *dst, size_t dstlen,
	int include_nl)
{
	int i;
	size_t left = dstlen;
	char *p = dst;
	size_t tot = 0;
	char *node_sep = include_nl ? ":\n" : ":";

	BUILD_BUG_ON(sizeof(xid_type_t) != 4);
	BUILD_BUG_ON(XIA_XID_MAX != 20);
	BUILD_BUG_ON(XIA_OUTDEGREE_MAX != 4);

	if (xia_test_addr(src) < 1) {
		/* The DAG is invalid or empty. */
		if (left <= 0)
			return -ENOSPC;
		*p = '!';
		left--;
		p++;
		tot++;
	}
	
	for (i = 0; i < XIA_NODES_MAX && left > 0; i++) {
		const struct xia_row *row = &src->s_row[i];
		xid_type_t ty = row->s_xid_type;
		const __be32 *pxid = (const __be32 *)row->s_xid;
		u32 a = __be32_to_cpu(pxid[0]);
		u32 b = __be32_to_cpu(pxid[1]);
		u32 c = __be32_to_cpu(pxid[2]);
		u32 d = __be32_to_cpu(pxid[3]);
		u32 e = __be32_to_cpu(pxid[4]);
		const u8 *edge = row->s_edge.a;
		/* TODO When the address is valid, listing only the present
                 * edges would be better.
		 */
		char e0 = edge_to_char(edge[0]);
		char e1 = edge_to_char(edge[1]);
		char e2 = edge_to_char(edge[2]);
		char e3 = edge_to_char(edge[3]);
		char *se0 = is_edge_chosen(edge[0]) ? ">" : "";
		char *se1 = is_edge_chosen(edge[1]) ? ">" : "";
		char *se2 = is_edge_chosen(edge[2]) ? ">" : "";
		char *se3 = is_edge_chosen(edge[3]) ? ">" : "";
		char *sep = i > 0 ? node_sep : "";
		int count;
		if (ty == XIDTYPE_NAT)
			break;
		count = snprintf(p, left,
			"%s%x-%.8x%.8x%.8x%.8x%.8x-%s%c%s%c%s%c%s%c",
			sep, __be32_to_cpu(ty), a, b, c, d, e,
			se0, e0, se1, e1, se2, e2, se3, e3);
		if (count < 0)
			return -EINVAL;
		left -= count;
		p += count;
		tot += count;
	}

	if (left <= 0)
		return -ENOSPC;
	*p = '\0';
	return tot;
}
EXPORT_SYMBOL(xia_ntop);

/*
 * xia_pton and its auxiliares functions
 */

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
	if (*pleft <= 0) /* No XIA address is an empty string. */
		return -1;
	*invalid_flag = **pp == '!';
	if (*invalid_flag)
		next(pp, pleft);
	return 0;
}

static inline int ascii_to_int(char ch)
{
	if (ch >= '0' && ch <= '9') {
		return ch - '0';
	} else if (ch >= 'A' && ch <= 'Z') {
		return ch - 'A'; 
	} else if (ch >= 'a' && ch <= 'z') {
		return ch - 'a';
	} else
		return 64;
}

static int read_be32(const char **pp, size_t *pleft, __be32 *value)
{
	u32 result = 0;
	int i = 0;

	while (*pleft >= 1 && isxdigit(**pp) && i < 8) {
		result = (result << 4) + ascii_to_int(**pp);
		next(pp, pleft);
		i++;
	}
	*value = __cpu_to_be32(result);
	return i;
}

static int read_type(const char **pp, size_t *pleft, xid_type_t *pty)
{
	BUILD_BUG_ON(sizeof(xid_type_t) != 4);

	/* There must be at least a digit! */
	if (read_be32(pp, pleft, pty) < 1)
		return -1;
	/* Not A Type is not a type!
         * Notice that byte order doesn't matter here.
	 */
	if (*pty == XIDTYPE_NAT)
		return -1;

	return 0;
}

static int read_xid(const char **pp, size_t *pleft, u8 *xid)
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

static int read_edges(const char **pp, size_t *pleft, u8 *edge, int ignore_ce)
{
	int i;

	for (i = 0; i < XIA_OUTDEGREE_MAX; i++)
		edge[i] = XIA_EMPTY_EDGE;
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
		edge[i] = ce | e;
	}
	return 0;
}

static int read_row(const char **pp, size_t *pleft, struct xia_row *row,
	int ignore_ce)
{
	if (read_type(pp, pleft, &row->s_xid_type))
		return -1;
	if (read_sep(pp, pleft, '-'))
		return -1;
	if (read_xid(pp, pleft, row->s_xid))
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

	if (read_invalid_flag(&p, &left, invalid_flag))
		return -1;

	do {
		if (read_row(&p, &left, &dst->s_row[i], ignore_ce))
			return -1;
		if (++i >= XIA_NODES_MAX)
			return -1;
	} while (!read_node_sep(&p, &left));

	/* A whole address must be parsed. */
	if (left != 0 && *p != '\0')
		return -1;
	return srclen - left;
}
EXPORT_SYMBOL(xia_pton);

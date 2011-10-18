#include <asm/byteorder.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <net/xia_dag.h>

#define EMPTY_EDGES 	(XIA_EMPTY_EDGE << 24 | XIA_EMPTY_EDGE << 16 |\
			 XIA_EMPTY_EDGE <<  8 | XIA_EMPTY_EDGE)
int xia_test_addr(const struct xia_addr *addr)
{
	int i, j, n;
	int saw_nat = 0;
	u32 visited = 0;

	/* Test that XIDTYPE_NAT is present only on last rows. */
	n = XIA_NODES_MAX;
	for (i = 0; i < XIA_NODES_MAX; i++) {
		xid_type_t ty = addr->s_row[i].s_xid_type;
		if (saw_nat) {
			if (!xia_is_nat(ty))
				return -XIAEADDR_NAT_MISPLACED;
		} else if (xia_is_nat(ty)) {
			n = i;
			saw_nat = 1;
		}
	}
	/* n = number of nodes from here. */

	BUILD_BUG_ON(XIA_OUTDEGREE_MAX != 4);
	BUILD_BUG_ON(XIA_NODES_MAX + 1 > sizeof(visited) * 8);

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
			} else if (i < (n - 1) && e <= i) {
				return -XIAEADDR_NOT_TOPOLOGICAL;
			}
			bits >>= 8;
			visited |= 1 << e;
		}
	}

	if (n >= 1) {
		/* Test entry point is present. Notice that it's just a
		 * friendlier error since it's also XIAEADDR_MULTI_COMPONENTS.
		 */
		/* __be32_to_cpu is not necessary here! */
		__be32 all_edges = addr->s_row[n - 1].s_edge.i;
		if (all_edges == EMPTY_EDGES)
			return -XIAEADDR_NO_ENTRY;

		if (visited != ((1 << n) - 1))
			return -XIAEADDR_MULTI_COMPONENTS;
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

#define EDGES_STR_SIZE (XIA_OUTDEGREE_MAX * 2 + 2)
static void edges_to_str(int valid, char *str, int len, const u8 *edges)
{
	char *p = str;
	int i;

	BUG_ON(len < EDGES_STR_SIZE);

	*(p++) = '-';
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		if (valid && edges[i] == XIA_EMPTY_EDGE) {
			if (i == 0) {
				*str = '\0';
				return;
			}
			break;
		}
		if (is_edge_chosen(edges[i]))
			*(p++) = '>';
		*(p++) = edge_to_char(edges[i]);
	}
	*p = '\0';
}

int xia_ntop(const struct xia_addr *src, char *dst, size_t dstlen,
	int include_nl)
{
	int i;
	size_t left = dstlen;
	char *p = dst;
	size_t tot = 0;
	char *node_sep = include_nl ? ":\n" : ":";
	int valid = xia_test_addr(src) >= 1;

	BUILD_BUG_ON(sizeof(xid_type_t) != 4);
	BUILD_BUG_ON(XIA_XID_MAX != 20);

	if (!valid) {
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
		char str_edges[EDGES_STR_SIZE];
		char *sep = i > 0 ? node_sep : "";
		int count;

		if (xia_is_nat(ty))
			break;
		edges_to_str(valid, str_edges, EDGES_STR_SIZE, row->s_edge.a);
		count = snprintf(p, left,
			"%s%x-%.8x%.8x%.8x%.8x%.8x%s",
			sep, __be32_to_cpu(ty), a, b, c, d, e, str_edges);
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

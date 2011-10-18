#ifndef _XIA_DAG_H
#define _XIA_DAG_H

#include <net/xia.h>

/*
 * Address-handling functions
 */

enum xia_addr_error {
	/* There's a non-XIDTYPE_NAT node after an XIDTYPE_NAT node. */
	XIAEADDR_NAT_MISPLACED = 1,
	/* Edge-selected bit is only valid in packets. */
	XIAEADDR_CHOSEN_EDGE,
	/* There's a non-empty edge after an Empty Edge.
	 * This error can also occur if an empty edge is selected. */
	XIAEADDR_EE_MISPLACED,
	/* An edge of a node is out of range. */
	XIAEADDR_EDGE_OUT_RANGE,
	/* The nodes are not in topological order. Notice that being in
	 * topological guarntees that the graph is acyclic, and has a simple,
	 * cheap test. */
	XIAEADDR_NOT_TOPOLOGICAL,
	/* No single component. */
	XIAEADDR_MULTI_COMPONENTS,
	/* Entry node is not present. */
	XIAEADDR_NO_ENTRY,
};

/** xia_test_addr - test addr.
 * RETURN
 *	Negative enum xia_addr_error - there is an error.
 *	Greater or equal to zero - Number of nodes.
 */
extern int xia_test_addr(const struct xia_addr *addr);

/** XIA_MAX_STRADDR_SIZE - The maximum size of an XIA address as a string
 *			   in bytes. It's a recomended size to call xia_ntop.
 * It includes space for the type and name of a nodes
 * in hexadecimal, the out-edges, the two separators (i.e. '-') per node,
 * the edge-chosen sign (i.e. '>') for each selected edge,
 * the node separators (i.e. ':'), and a string terminator (i.e. '\0').
 */
#define XIA_MAX_STRADDR_SIZE (1 + XIA_NODES_MAX * \
	((sizeof(xid_type_t) + XIA_XID_MAX + XIA_OUTDEGREE_MAX) * 2 + 3) + \
	XIA_NODES_MAX)

/** xia_ntop - convert an XIA address to a string.
 * src can be ill-formed, but xia_ntop won't report error and will return
 * a string that `approximates' that ill-formed address.
 * If include_nl is non-zero, '\n' is added after ':'.
 * RETURN
 * 	-ENOSPC - The converted address string is truncated. It may, or not,
 *		include the trailing '\0'.
 *	-EINVAL - For unexpected cases; it shouldn't happen.
 *	Total number of written bytes, NOT including the trailing '\0'.
 */
extern int xia_ntop(const struct xia_addr *src, char *dst, size_t dstlen,
		int include_nl);

#endif	/* _XIA_DAG_H	*/

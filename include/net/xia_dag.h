#ifndef _XIA_DAG_H
#define _XIA_DAG_H

#ifndef __KERNEL__
#include <stdio.h>
#endif

#include <net/xia.h>

/* It is assumed to be greater than, or equal to 4; it includes '\0'. */
#define MAX_PPAL_NAME_SIZE	32

/* ppal_name_to_type - provides the principal type for @name.
 *
 * NOTES
 *	In Kernel, it can be called concurrently with calls of
 *	ppal_add_map and ppal_del_map.
 *	In userland, the caller must manage a lock.
 *	If @name is not in the map, it returns -ESRCH; otherwise zero.
 */
extern int ppal_name_to_type(const char *name, xid_type_t *pty);

/* ppal_type_to_name - provides the principal name for @type.
 *
 * NOTES
 *	In Kernel, it can be called concurrently with calls of
 *	ppal_add_map and ppal_del_map.
 *	In userland, the caller must manage a lock.
 *	@name must be at least MAX_PPAL_NAME_SIZE large.
 *	If @type is not in the map, it returns -ESRCH; otherwise zero.
 */
extern int ppal_type_to_name(xid_type_t type, char *name);

/* ppal_add_map - Maps @name and @type.
 *
 * NOTES
 *	In Kernel, ppal_add_map and ppal_del_map share a lock to make
 *	current changes safe.
 *	In userland, the caller must manage a lock.
 *	@name and @type must be unique.
 */
extern int ppal_add_map(const char *name, xid_type_t type);

/* ppal_del_map - Removes map for @type.
 *
 * NOTES
 *	In Kernel, ppal_add_map and ppal_del_map share a lock to make
 *	current changes safe.
 *	In userland, the caller must manage a lock.
 *	Caller must have a lock that guarantees multual exclusion.
 */
extern int ppal_del_map(xid_type_t type);

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
 * a string that 'approximates' that ill-formed address.
 * If include_nl is non-zero, '\n' is added after ':', but not at the end of
 * the address because it's easier to add a '\n' than remove it.
 * RETURN
 * 	-ENOSPC - The converted address string is truncated. It may, or not,
 *		include the trailing '\0'.
 *	-EINVAL - For unexpected cases; it shouldn't happen.
 *	Total number of written bytes, NOT including the trailing '\0'.
 */
extern int xia_ntop(const struct xia_addr *src, char *dst, size_t dstlen,
		int include_nl);

/** xia_pton - Convert a string that represents an XIA addressesng into
 *	binary (network) form.
 * It doesn't not require the string @src to be terminated by '\0'.
 * If @ignore_ce is true, the chosen edges are not marked in @dst.
 * 	It's useful to obtain an address that will be used in a header.
 * @invalid_flag is set true if '!' begins the string;
 * 	otherwise it is set false.
 * RETURN
 * 	-1 if the string can't be converted.
 *	Number of parsed chars, not couting trailing '\0' if it exists.
 * NOTES
 *	Even if the function is successful, the address may
 *	still be invalid according to xia_test_addr.
 *	INT_MAX<limits.h> could be passed in srclen if src includes a '\0'.
 *
 * IMPORTANT
 *	init_ppal_map<ppal_map.h> must be called first before this function
 *	in order to recognize principal names!
 */
extern int xia_pton(const char *src, size_t srclen, struct xia_addr *dst,
		int ignore_ce, int *invalid_flag);

/** xia_ptoxid - works as xia_pton, but only parses a single XID. */
extern int xia_ptoxid(const char *src, size_t srclen, struct xia_xid *dst);

/** xia_ptoid - works as xia_ptoxid, but only parses a single ID.
 *  NOTE
 *	dst->xid_type is not modified.
 */
extern int xia_ptoid(const char *src, size_t srclen, struct xia_xid *dst);

#endif	/* _XIA_DAG_H	*/

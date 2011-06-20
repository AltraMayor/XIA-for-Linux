#ifndef _XIA_H
#define _XIA_H

#include <linux/socket.h>
#include <net/sock.h>

/** struct xia_sock - representation of XIA sockets
 *
 * @sk - ancestor class
 * XXX Add the needed fields.
 * @pinet6 - pointer to IPv6 control block
 * @inet_daddr - Foreign IPv4 addr
 * @inet_rcv_saddr - Bound local IPv4 addr
 * @inet_dport - Destination port
 * @inet_num - Local port
 * @inet_saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @inet_sport - Source port
 * @inet_id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
struct xia_sock {
	/* sk has to be the first member of xia_sock. */
	struct sock		sk;
	
	/* Protocol specific data members per socket from here on. */

	/* EMPTY */
};

/*
 * Raw socket
 */

struct xia_raw_sock {
	/* xia_sock has to be the first member */
	struct xia_sock		xia;

	/* Raw specific data members per socket from here on. */

	/* EMPTY */
};

extern struct proto xia_raw_prot;

/*
 * XIA address
 */

/* XID types. */
enum {
  XIDTYPE_NAT = 0,		/* Not A Type				*/

  				/* 0x01--0x0f reserved for future use	*/

  XIDTYPE_AD  = 0x10,		/* Autonomous Domain			*/
  XIDTYPE_HID = 0x11,		/* Host					*/
  XIDTYPE_CID = 0x12,		/* Content				*/
  XIDTYPE_SID = 0x13,		/* Service				*/

  XIDTYPE_USER = 0xffffff00,	/* User defined XID			*/
  XIDTYPE_MAX
};

/* Row or a node in a DAG. */
#define XIA_OUTDEGREE_MAX	4
#define XIA_XID_MAX		20
typedef __be32 xid_type_t;
struct xia_row {
	xid_type_t	s_xid_type;		/* XID type		*/
	__u8		s_xid[XIA_XID_MAX];	/* eXpressive IDentifier*/
	union {
		__u8	a[XIA_OUTDEGREE_MAX];
		__be32	i;
	} s_edge;				/* Out edges		*/
};
#define XIA_CHOSEN_EDGE		0x80
#define XIA_EMPTY_EDGE		0x7f

/* XIA address. */
#define XIA_NODES_MAX		9
struct xia_addr {
	struct xia_row s_row[XIA_NODES_MAX];
}; 

/* Structure describing an XIA socket address. */
struct sockaddr_xia {
  sa_family_t		sxia_family;	/* Address family		*/
  __u8			__pad0[2];	/* Ensure 32-bit alignment	*/
  struct xia_addr	sxia_addr;	/* XIA address			*/

  /* Pad to size of `struct __kernel_sockaddr_storage'. */
  unsigned char		__pad1[_K_SS_MAXSIZE - sizeof(sa_family_t) -
			sizeof(unsigned char) - sizeof(struct xia_addr)];
};

enum xia_addr_error {
	XIAEADDR_OK = 0,
	/* There's a non-XIDTYPE_NAT node after an XIDTYPE_NAT node. */
	XIAEADDR_NAT_MISPLACED,
	/* There is no nodes, address is empty. */
	XIAEADDR_EMPTY,
	/* Edge-selected bit is only valid in packets. */
	XIAEADDR_CHOSEN_EDGE,
	/* There's a non-empty edge after an Empty Edge.
	 * This error can also occur if an empty edge is selected. */
	XIAEADDR_EE_MISPLACED,
	/* An edge of a node is out of range. */
	XIAEADDR_EDGE_OUT_RANGE,
	/* Entry node is not present. */
	XIAEADDR_NO_ENTRY,
};

extern int xia_test_addr(const struct xia_addr *addr);

/** XIA_MAX_STRADDR_SIZE - The maximum size of an XIA address as a string
 *			   in bytes. It's a recomended size to call xia_ntop.
 * It includes space for the type and name of a nodes
 * in hexadecimal, the out-edges, the two separators (i.e. '-') per node,
 * the edge-chosen sign (i.e. '>') for each selected edge,
 * the node separators (i.e. ':'), and a string terminator (i.e. '\0').
 */
#define XIA_MAX_STRADDR_SIZE (XIA_NODES_MAX * \
	((sizeof(xid_type_t) + XIA_XID_MAX + XIA_OUTDEGREE_MAX) * 2 + 2) + \
	XIA_NODES_MAX)

/** xia_ntop - convert an XIA address to a string.
 * src can be ill-formed, but xia_ntop won't report error and will return
 * a string that `approximates' that ill-formed address.
 * Return
 * 	-ENOSPC - The converted address string is truncated. It may, or not,
 *		include the trailing '\0'.
 *	Total number of written bytes, NOT including the trailing '\0'.
 */
extern int xia_ntop(const struct xia_addr *src, char *dst, int dstlen);

/** xia_pton - Convert a string that represents an XIA addressesng into
 *	binary (network) form.
 * It doesn't not require the string src to be terminated by '\0'.
 * If ignore_ce is true, the chosen edges are not marked in dst.
 * Return
 * 	-1 if the string can't be converted; zero otherwise.
 *	Notice that even if the function is successful, the address may
 *	still be invalid according to xia_test_addr.
 */
extern int xia_pton(const char *src, int srclen, struct xia_addr *dst,
		int ignore_ce);

#endif	/* _XIA_H */

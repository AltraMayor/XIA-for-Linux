#ifndef _XIA_H
#define _XIA_H

#include <linux/socket.h>
#include <net/sock.h>

/*
 * XIA address
 */

/* XID types. */
enum {
  XIDTYPE_NAT = 0,		/* Not A Type				*/

  				/* 0x01--0x0f reserved for future use	*/

  XIDTYPE_AD  = 0x10,		/* Autonomous Domain			*/
  XIDTYPE_HID,			/* Host					*/
  XIDTYPE_CID,			/* Content				*/
  XIDTYPE_SID,			/* Service				*/

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

static inline int is_edge_chosen(u8 e)
{
	return e & XIA_CHOSEN_EDGE;
}

static inline int is_empty_edge(u8 e)
{
	return (e & XIA_EMPTY_EDGE) == XIA_EMPTY_EDGE;
}

/* XIA address. */
#define XIA_NODES_MAX		9
struct xia_addr {
	struct xia_row s_row[XIA_NODES_MAX];
}; 

static inline void xia_null_addr(struct xia_addr *addr)
{
	addr->s_row[0].s_xid_type = __cpu_to_be32(XIDTYPE_NAT);
}

static inline int xia_is_nat(xid_type_t ty)
{
	return ty == __cpu_to_be32(XIDTYPE_NAT);
}

/* Structure describing an XIA socket address. */
struct sockaddr_xia {
  sa_family_t		sxia_family;	/* Address family		*/
  __u16			__pad0;		/* Ensure 32-bit alignment	*/
  struct xia_addr	sxia_addr;	/* XIA address			*/

  /* Pad to size of `struct __kernel_sockaddr_storage'. */
  __u8			__pad1[_K_SS_MAXSIZE - sizeof(sa_family_t) -
			sizeof(__u16) - sizeof(struct xia_addr)];
};

/*
 * sock structs
 */

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

	/* XID type, XID, and full address of source socket. */
	xid_type_t 		xia_sxid_type;
	u8			xia_sxid[XIA_XID_MAX];
	struct xia_addr		xia_saddr; /* It's used for transmission. */

	/* XID type, and full address of destination socket. */
	xid_type_t 		xia_dxid_type;
	struct xia_addr		xia_daddr; /* It's used for transmission. */
};

static inline struct xia_sock *xia_sk(const struct sock *sk)
{
	return (struct xia_sock *)sk;
}

/*
 * Raw socket
 */

struct xia_raw_sock {
	/* xia_sock has to be the first member */
	struct xia_sock		xia;

	/* Raw specific data members per socket from here on. */

	/* EMPTY */
};

static inline struct xia_raw_sock *xia_raw_sk(const struct sock *sk)
{
	return (struct xia_raw_sock *)sk;
}

extern struct proto xia_raw_prot;

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

/** xia_pton - Convert a string that represents an XIA addressesng into
 *	binary (network) form.
 * It doesn't not require the string src to be terminated by '\0'.
 * If ignore_ce is true, the chosen edges are not marked in dst.
 * 	It's useful to obtain an address that will be used in a header.
 * invalid_flag is set true if '!' begins the string;
 * 	otherwise it is set false.
 * RETURN
 * 	-1 if the string can't be converted.
 *	Number of parsed chars, not couting trailing '\0' if it exists.
 * NOTES
 *	Even if the function is successful, the address may
 *	still be invalid according to xia_test_addr.
 *	XIA_MAX_STRADDR_SIZE could be passed in srclen if src includes a '\0'.
 */
extern int xia_pton(const char *src, size_t srclen, struct xia_addr *dst,
		int ignore_ce, int *invalid_flag);

#endif	/* _XIA_H */

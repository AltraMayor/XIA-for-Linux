#ifndef _XIA_H
#define _XIA_H

#include <linux/types.h>
#include <linux/socket.h>
#include <asm/byteorder.h>

#ifdef __KERNEL__
#include <net/sock.h>
#endif

/*
 * XIA address
 */

/* Not A Type.
 * Notice that this constant is little and big endian at same time. */
#define XIDTYPE_NAT 0
/* The range 0x01--0x0f is reserved for future use.
 * Identification numbers for new principals should be requested from
 * Michel Machado <michel@digirati.com.br>.
 */

/* Row or a node in a DAG. */
#define XIA_OUTDEGREE_MAX	4
#define XIA_XID_MAX		20
typedef __be32 xid_type_t;

struct xia_xid {
	xid_type_t	xid_type;		/* XID type		*/
	__u8		xid_id[XIA_XID_MAX];	/* eXpressive IDentifier*/
};

struct xia_row {
	struct xia_xid	s_xid;
	union {
		__u8	a[XIA_OUTDEGREE_MAX];
		__be32	i;
	} s_edge;				/* Out edges		*/
};

#define XIA_CHOSEN_EDGE		0x80
#define XIA_EMPTY_EDGE		0x7f

/* Notice that this constant is little and big endian
 * at same time up to 32bits.
 */
#define XIA_EMPTY_EDGES	(XIA_EMPTY_EDGE << 24 | XIA_EMPTY_EDGE << 16 |\
			 XIA_EMPTY_EDGE <<  8 | XIA_EMPTY_EDGE)

static inline int is_edge_chosen(__u8 e)
{
	return e & XIA_CHOSEN_EDGE;
}

static inline int is_empty_edge(__u8 e)
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
	addr->s_row[0].s_xid.xid_type = XIDTYPE_NAT;
}

static inline int xia_is_nat(xid_type_t ty)
{
	return ty == XIDTYPE_NAT;
}

/* XXX This is only needed for applications.
 * Isn't there a clearer way to do it?
 */
#ifndef __KERNEL__
/* sa_family_t is not available to applications. */
typedef unsigned short sa_family_t;
/* _K_SS_MAXSIZE is redefined because we want to compile with
 * old kernels installed.
 */
#undef	_K_SS_MAXSIZE
#define	_K_SS_MAXSIZE 256
#endif

/* Structure describing an XIA socket address. */
struct sockaddr_xia {
  sa_family_t		sxia_family;	/* Address family		*/
  __u16			__pad0;		/* Ensure 32-bit alignment	*/
  struct xia_addr	sxia_addr;	/* XIA address			*/

  /* Pad to size of `struct __kernel_sockaddr_storage'. */
  __u8			__pad1[_K_SS_MAXSIZE - sizeof(sa_family_t) -
			sizeof(__u16) - sizeof(struct xia_addr)];
};

#ifdef __KERNEL__

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

#endif	/* __KERNEL__	*/
#endif	/* _XIA_H	*/

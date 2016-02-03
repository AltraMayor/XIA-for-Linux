#ifndef _NET_XIA_SOCKET_H
#define _NET_XIA_SOCKET_H

#include <linux/net.h>
#include <net/sock.h>
#include <net/xia.h>
#include <net/xia_route.h>

/*
 *	Register a principal with XIA socket
 */

/* Implementation of a type/protocol pair. */
struct xia_socket_type_proc {
	struct proto		*proto;
	bool			alloc_slab;
	const struct proto_ops	*ops;
};

/* Socket processing per principal. */
struct xia_socket_proc {
	const char		*name;

	/* This field is used to check that xia_del_socket_begin() and
	 * xia_del_socket_end() are called in order.
	 *
	 * 0 -> It hasn't been added by xia_add_socket()
	 * 1 -> It was added by xia_add_socket()
	 * 2 -> xia_del_socket_begin() was called
	 * 3 -> xia_del_socket_end() was called
	 */
	int			dead;

	/* Principal type. */
	const xid_type_t	ppal_type;

	/* Supported socket types. */
	const struct xia_socket_type_proc *procs[SOCK_MAX];

	/* Counter for all socket types in this struct. */
	struct percpu_counter	sockets_allocated;
};

/* Registering and unregistering new socket interfaces for PF_XIA family. */
int xia_add_socket(struct xia_socket_proc *sproc);

/* Drop @sproc as an option for creating new sockets. */
void xia_del_socket_begin(struct xia_socket_proc *sproc);
/* Unregister @sprocs->procs[i]->proto for all i. */
void xia_del_socket_end(struct xia_socket_proc *sproc);

/*
 *	Helpers to implement principals' struct proto_ops' methods
 */

/* This function makes (struct proto).close() required. */
int xia_release(struct socket *sock);

/* This function makes (struct proto).bind() required. */
int xia_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);

/* This function makes (struct proto).connect() required. */
int xia_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
	int addr_len, int flags);

int xia_getname(struct socket *sock, struct sockaddr *uaddr,
	int *uaddr_len, int peer);

int xia_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

int xia_shutdown(struct socket *sock, int how);

/* This function makes (struct proto).sendmsg() required. */
int xia_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);

/* This function makes (struct proto).recvmsg() required. */
int xia_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags);

ssize_t xia_sendpage(struct socket *sock, struct page *page,
	int offset, size_t size, int flags);

/*
 *	Helpers to implement principals' struct proto's methods
 */

static inline int xip_setsockopt(struct sock *sk, int level, int optname,
	char __user *optval, unsigned int optlen)
{
	/* XXX Implement some options that make sense to XIA. */
	return -ENOPROTOOPT;
}

static inline int xip_getsockopt(struct sock *sk, int level, int optname,
	char __user *optval, int __user *optlen)
{
	/* XXX Implement some options that make sense to XIA.
	 * See net/ipv4/ip_sockglue.c:do_ip_getsockopt and
	 * net/ipv4/ip_sockglue.c:ip_getsockopt.
	 */
	return -ENOPROTOOPT;
}

int check_sockaddr_xia(struct sockaddr *uaddr, int addr_len);
int check_type_of_all_sinks(struct sockaddr_xia *addr, xid_type_t ty);

/** copy_n_and_shade_xia_addr - Copy the first @n rows of @rsrc to @dst, and
 *				zero (shade) the not used rows in @dst.
 *
 *  This function is useful when passing a struct xia_addr to userland
 *  because it ensures that there's no information leak due to
 *  uninitialized memory.
 */
void copy_n_and_shade_xia_addr(struct xia_addr *dst,
	const struct xia_row *rsrc, int n);

static inline void copy_n_and_shade_xia_addr_from_addr(struct xia_addr *dst,
	const struct xia_addr *src, int n)
{
	copy_n_and_shade_xia_addr(dst, src->s_row, n);
}

/** copy_n_and_shade_sockaddr_xia - Initialize @dst's fields,
 *				copy the first @n rows of @rsrc to @dst, and
 *				zero (shade) the not used rows in @dst.
 *
 *  This function is useful when passing a struct sockaddr_xia to userland
 *  because it ensures that there's no information leak due to
 *  uninitialized memory.
 */
void copy_n_and_shade_sockaddr_xia(struct sockaddr_xia *dst,
	const struct xia_row *rsrc, int n);

static inline void copy_n_and_shade_sockaddr_xia_from_addr(
	struct sockaddr_xia *dst, const struct xia_addr *src, int n)
{
	copy_n_and_shade_sockaddr_xia(dst, src->s_row, n);
}

/* Handle MSG_ERRQUEUE. */
int xip_recv_error(struct sock *sk, struct msghdr *msg, int len);

/*
 *	XIA Sock
 */

/* All XIA sockets should `inherit' from this struct. */
struct xia_sock {
	/* struct sock must be the first member to work with sk_alloc(). */
	struct sock		sk;

	/* General XIA socket data members per socket from here on. */

	/* Source address
	 *
	 * The source address must have exactly one sink.
	 */

	/* XXX xia_ssink and xia_daddr_set are being read without locks,
	 * is it safe?
	 */

	/* XID type, XID, and full address of source socket. */
	struct xia_row		*xia_ssink;
	struct xia_addr		xia_saddr; /* It's used for transmission. */
	u8			xia_snum; /* Number of nodes in @xia_saddr. */

	/* XXX Not only DST entries have dependencies on anchors,
	 * but XIP addresses too! This happens because addresses may use
	 * multiple DST entries to be routed.
	 * This implies that the destination address here must carry
	 * the dependencies as well.
	 */

	/* Destination address
	 *
	 * If @xia_daddr_set is true, fields @xia_dlast_node and @xia_daddr
	 * have valid values.
	 *
	 * Why isn't there a field xia_dsink analogue to @xia_ssink instead of
	 * @xia_daddr_set?
	 * The source address must have a single sink because
	 * this address is used to bind a listening socket to
	 * the routing table. Whereas, the destination address may have
	 * multiple sinks. Thus, the field xia_dsink would point to a single
	 * sink independently how many sinks exit in an address.
	 */
	u8			xia_daddr_set;
	/* Number of nodes in @xia_daddr. */
	u8			xia_dnum;
	/* Index of the last node of @xia_daddr. */
	u8			xia_dlast_node;
	struct xia_addr		xia_daddr; /* It's used for transmission. */
};

static inline struct xia_sock *xia_sk(const struct sock *sk)
{
	return likely(sk)
		? container_of(sk, struct xia_sock, sk)
		: NULL;
}

static inline bool xia_sk_bound(const struct xia_sock *xia)
{
	return !!xia->xia_ssink;
}

static inline void xia_reset_src(struct xia_sock *xia)
{
	xia->xia_ssink = NULL;
}

void xia_reset_dest(struct xia_sock *xia);

/** xia_set_src - Set source of packets sent from @xia.
 *			@n is the number of nodes in @src.
 */
void xia_set_src(struct xia_sock *xia, struct xia_addr *src, int n);

void __xia_set_dest(struct xia_sock *xia, const struct xia_row *dest, int n,
	int last_node, struct xip_dst *xdst);

/** xia_set_dest - Set destination of packets sent from @xia.
 *			@n is the number of nodes in @dest.
 */
int xia_set_dest(struct xia_sock *xia, const struct xia_row *dest, int n);

#endif /* _NET_XIA_SOCKET_H */

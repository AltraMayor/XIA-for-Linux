#ifndef _NET_XIA_SOCKET_H
#define _NET_XIA_SOCKET_H

#include <linux/net.h>
#include <net/sock.h>
#include <net/xia.h>

/* Implementation of a type/protocol pair. */
struct xia_socket_type_proc {
	struct proto		*prot;
	const struct proto_ops	*ops;
};

/* Socket processing per principal. */
struct xia_socket_proc {
	/* Attachment to bucket list. */
	struct hlist_node	list;

	/* Principal type. */
	xid_type_t		ppal_type;

	const struct xia_socket_type_proc *procs[SOCK_MAX];
};

/* Registering and unregistering new socket interfaces for PF_XIA family. */
int xia_add_socket(struct xia_socket_proc *sproc);
void xia_del_socket(struct xia_socket_proc *sproc);

/* Support functions for principals */
int xia_release(struct socket *sock);
int xia_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int xia_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
	int addr_len, int flags);
int xia_getname(struct socket *sock, struct sockaddr *uaddr,
	int *uaddr_len, int peer);
int xia_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);
int xia_shutdown(struct socket *sock, int how);
int xia_sendmsg(struct kiocb *iocb, struct socket *sock,
	struct msghdr *msg, size_t size);
int xia_recvmsg(struct kiocb *iocb, struct socket *sock,
	struct msghdr *msg, size_t size, int flags);
ssize_t xia_sendpage(struct socket *sock, struct page *page,
	int offset, size_t size, int flags);

/* All XIA sockets should `inherit' from this struct. */
struct xia_sock {
	struct sock		sk;

	/* General XIA socket data members per socket from here on. */

	/* Source address
	 *
	 * The source address must have exactly one sink.
	 */

	/* XID type, XID, and full address of source socket. */
	struct xia_row		*xia_ssink;
	struct xia_addr		xia_saddr; /* It's used for transmission. */

	/* Destination address
	 *
	 * If @xia_daddr_set is true, fields @xia_dlast_node and @xia_daddr
	 * have valid values.
	 */
	u8			xia_daddr_set;
	/* Index of the last node of @xia_daddr. */
	u8			xia_dlast_node;
	/* 2 bytes free. */
	struct xia_addr		xia_daddr; /* It's used for transmission. */
};

static inline struct xia_sock *xia_sk(const struct sock *sk)
{
	return likely(sk)
		? container_of(sk, struct xia_sock, sk)
		: NULL;
}

#endif /* _NET_XIA_SOCKET_H */

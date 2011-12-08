/*
 * XIA 		An implementation of the XIA protocol suite for the LINUX
 *		operating system.  XIA is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_XIA protocol family socket handler.
 *
 * Author:	Michel Machado, <michel@digirati.com.br>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/xia.h>
#include <net/xia.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>
#include <net/sock.h>

static void xia_sock_destruct(struct sock *sk)
{
	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);

	sk_mem_reclaim(sk);

	/* TODO How to include similar warning?
	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		pr_err("Attempt to release TCP socket in state %d %p\n",
		       sk->sk_state, sk);
		return;
	} */
	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to release alive xia socket %p\n", sk);
		return;
	}

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(atomic_read(&sk->sk_wmem_alloc));
	WARN_ON(sk->sk_wmem_queued);
	WARN_ON(sk->sk_forward_alloc);

	dst_release(rcu_dereference_check(sk->sk_dst_cache, 1));
	sk_refcnt_debug_dec(sk);
}

/*
 * The routines beyond this point handle the behaviour of an AF_XIA
 * socket object. Mostly it punts to the subprotocols of XIP to do
 * the work.
 */

/*
 * The peer socket should always be NULL (or else). When we call this
 * function we are destroying the object and from then on nobody
 * should refer to it.
 */
static int xia_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		long timeout;

		sock_rps_reset_flow(sk);

		/* If linger is set, we don't return until the close
		 * is complete. Otherwise we return immediately.
		 * The actually closing is done the same either way.
		 *
		 * If the close is due to the process exiting, we never
		 * linger..
		 */
		timeout = 0;
		if (sock_flag(sk, SOCK_LINGER) &&
		    !(current->flags & PF_EXITING))
			timeout = sk->sk_lingertime;
		sock->sk = NULL;
		sk->sk_prot->close(sk, timeout);
	}
	return 0;
}

/* XXX This code should be moved to an SID module. */
#define XIDTYPE_SID (__cpu_to_be32(0x13))
static int xia_bind(struct socket *sock, struct sockaddr *uaddr,
		int addr_len)
{
	struct sock *sk = sock->sk;
	struct sockaddr_xia *addr = (struct sockaddr_xia *)uaddr;
	struct xia_sock *xia = xia_sk(sk);
	int rc;

	/* If the socket has its own bind function then use it. (RAW) */
	if (sk->sk_prot->bind) {
		rc = sk->sk_prot->bind(sk, uaddr, addr_len);
		goto out;
	}

	rc = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_xia))
		goto out;
	if (addr->sxia_family != AF_XIA)
		goto out;
	/* XXX We should support specific addresses, but for now
	 * only autocomposed addresses are supported because
	 * one has to still decide what is allowed.
	 */
	if (xia_test_addr(&addr->sxia_addr) != 1)
		goto out;

	/* XXX The only XID type supported now is XIDTYPE_SID. */
	rc = -EXTYNOSUPPORT;
	if (addr->sxia_addr.s_row[0].s_xid.xid_type != XIDTYPE_SID)
		goto out;

	lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	rc = -EINVAL;
	/* XXX How to add `sk->sk_state != TCP_CLOSE ||' for active socket? */
	if (!xia_is_nat(xia->xia_sxid_type)) /* Double bind. */
		goto out_release_sk;

	xia->xia_sxid_type = addr->sxia_addr.s_row[0].s_xid.xid_type;
	memmove(xia->xia_sxid, addr->sxia_addr.s_row[0].s_xid.xid_id,
		sizeof(xia->xia_sxid));
	/* Make sure we are allowed to bind here. */
	rc = -EADDRINUSE;
	/* The second parameter of method get_port is zero because XIA
	 * doesn't use port numbers, and this method is shared with TCP/IP.
	 */
	if (sk->sk_prot->get_port(sk, 0)) {
		xia->xia_sxid_type = __cpu_to_be32(XIDTYPE_NAT);
		goto out_release_sk;
	}

	/* XXX A full address must be built not just copy the sink! */
	xia->xia_saddr = addr->sxia_addr;

	sk->sk_userlocks |= SOCK_BINDADDR_LOCK | SOCK_BINDPORT_LOCK;
	xia->xia_dxid_type = __cpu_to_be32(XIDTYPE_NAT);
	sk_dst_reset(sk);
	rc = 0;
out_release_sk:
	release_sock(sk);
out:
	return rc;
}

static int xia_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
		int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (addr_len < sizeof(uaddr->sa_family))
		return -EINVAL;
	if (uaddr->sa_family == AF_UNSPEC)
		return sk->sk_prot->disconnect(sk, flags);

	if (xia_is_nat(xia_sk(sk)->xia_sxid_type))
		return -ESNOTBOUND;

	return sk->sk_prot->connect(sk, uaddr, addr_len);
}

/** copy_and_shade - Copy @src to @dst. The not used rows in @src are
 *  zeroed (shaded) in dst.
 *  This function is useful when passing an XIA address to userland because
 *  it ensures that there's no information leak due to unitilized memory.
 */
static void copy_and_shade(struct xia_addr *dst, struct xia_addr *src)
{
	int i;
	struct xia_row *rdst = dst->s_row;
	struct xia_row *rsrc = src->s_row;

	for (i = 0; i < XIA_NODES_MAX; i++) {
		if (xia_is_nat(rsrc[i].s_xid.xid_type)) {
			memset(&rdst[i], 0,
				(XIA_NODES_MAX - i) * sizeof(struct xia_row));
			break;
		}
	}
	memmove(rdst, rsrc, i * sizeof(struct xia_row));
}

/*
 * This does both peername and sockname.
 */
static int xia_getname(struct socket *sock, struct sockaddr *uaddr,
		int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct xia_sock *xia	= xia_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_xia *, sxia, uaddr);

	sxia->sxia_family = AF_XIA;
	sxia->__pad0 = 0;
	if (peer) {
		/* XXX Is the following test copied from IPv4 necessary?
		 || (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) &&
		     peer == 1)
		*/
		if (xia_is_nat(xia->xia_dxid_type))
			return -ENOTCONN;
		copy_and_shade(&sxia->sxia_addr, &xia->xia_daddr);
	} else {
		if (xia_is_nat(xia->xia_sxid_type))
			memset(&sxia->sxia_addr, 0, sizeof(sxia->sxia_addr));
		else
			copy_and_shade(&sxia->sxia_addr, &xia->xia_saddr);
	}
	memset(sxia->__pad1, 0, sizeof(sxia->__pad1));
	*uaddr_len = sizeof(*sxia);
	return 0;
}

static int xia_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int rc = -ENOIOCTLCMD;
	if (sk->sk_prot->ioctl)
		rc = sk->sk_prot->ioctl(sk, cmd, arg);
	return rc;
}

static int xia_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;

	/* The following trick is standard to map the following constants:
	 * SHUT_RD	= 0 => RCV_SHUTDOWN	= 1
	 * SHUT_WR	= 1 => SEND_SHUTDOWN	= 2
	 * SHUT_RDWR	= 2 => SHUTDOWN_MASK	= 3
	 *
	 * The constants on the left side are userland
	 * constants (see shutdown(3)), whereas the constants on
	 * the right side are defined in <net/sock.h>.
	 */
	how++;
	/* The second clause handles wraparounds from MAXINT to zero. */
	if ((how & ~SHUTDOWN_MASK) || !how)
		return -EINVAL;

	lock_sock(sk);
	sk->sk_shutdown |= how;
	if (sk->sk_prot->shutdown)
		sk->sk_prot->shutdown(sk, how);
	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);
	release_sock(sk);

	return 0;
}

static int xia_sendmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	if (xia_is_nat(xia_sk(sk)->xia_sxid_type))
		return -ESNOTBOUND;

	sock_rps_record_flow(sk);

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}

static int xia_recvmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	int rc;

	sock_rps_record_flow(sk);

	rc = sk->sk_prot->recvmsg(iocb, sk, msg, size, flags & MSG_DONTWAIT,
				   flags & ~MSG_DONTWAIT, &addr_len);
	if (rc >= 0)
		msg->msg_namelen = addr_len;
	return rc;
}

static ssize_t	xia_sendpage(struct socket *sock, struct page *page,
		int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;

	if (xia_is_nat(xia_sk(sk)->xia_sxid_type))
		return -ESNOTBOUND;

	sock_rps_record_flow(sk);

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);
	return sock_no_sendpage(sock, page, offset, size, flags);
}

/*
 * For SOCK_RAW sockets; should be the same as xia_dgram_ops but without
 * XXX udp_poll
 */
static const struct proto_ops xia_sockraw_ops = {
	.family		   = PF_XIA,
	.owner		   = THIS_MODULE,
	.release	   = xia_release,
	.bind		   = xia_bind,
	.connect	   = xia_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = xia_getname,
	.poll		   = datagram_poll,
	.ioctl		   = xia_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = xia_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = xia_sendmsg,
	.recvmsg	   = xia_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = xia_sendpage,
};

static int xia_create(struct net *net, struct socket *sock,
		int protocol, int kern)
{
	struct sock *sk;
	struct xia_sock *xia;
	int rc;

	sock->state = SS_UNCONNECTED;

	rc = -ESOCKTNOSUPPORT;
	if (sock->type != SOCK_RAW)
		goto out;
	rc = -EPROTONOSUPPORT;
	if (protocol != XIPPROTO_XIP && protocol != XIPPROTO_RAW)
		goto out;
	protocol = XIPPROTO_RAW;

	rc = -EPERM;
	if (sock->type == SOCK_RAW && !kern && !capable(CAP_NET_RAW))
		goto out;

	/*
	 * There's no reason why XIA doesn't support Network Namespaces
	 * but implementation.
	 */
	rc = -EAFNOSUPPORT;
	if (!net_eq(net, &init_net))
		goto out;

	WARN_ON(xia_raw_prot.slab == NULL);

	rc = -ENOBUFS;
	sk = sk_alloc(net, PF_XIA, GFP_KERNEL, &xia_raw_prot);
	if (!sk)
		goto out;

	sock_init_data(sock, sk);
	sk->sk_destruct	   = xia_sock_destruct;
	sk->sk_protocol	   = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
	sk->sk_no_check = 1;		/* Checksum off by default */
	sk_refcnt_debug_inc(sk);
	sock->ops = &xia_sockraw_ops;

	xia = xia_sk(sk);
	xia->xia_sxid_type = __cpu_to_be32(XIDTYPE_NAT);
	xia->xia_dxid_type = __cpu_to_be32(XIDTYPE_NAT);

	rc = 0;
	if (sk->sk_prot->init) {
		rc = sk->sk_prot->init(sk);
		if (rc)
			goto out_release_sk;
	}
out:
	return rc;
out_release_sk:
	sk_common_release(sk);
	goto out;
}

static const struct net_proto_family xia_family_ops = {
	.family = PF_XIA,
	.create = xia_create,
	.owner	= THIS_MODULE,
};

/*
 * xia_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_init(void)
{
	int rc;

	/* Add Not A Type principal. */
	rc = ppal_add_map("nat", XIDTYPE_NAT);
	if (rc)
		goto out;

	rc = xia_fib_init();
	if (rc)
		goto nat;

	rc = proto_register(&xia_raw_prot, 1);
	if (rc)
		goto fib;

	/*
	 *	Tell SOCKET that we are alive...
	 */
	rc = sock_register(&xia_family_ops);
	if (rc)
		goto raw_prot;

	printk(KERN_ALERT "XIA loaded\n");
	goto out;

/*
sock:
	sock_unregister(PF_XIA);
*/
raw_prot:
	proto_unregister(&xia_raw_prot);
fib:
	xia_fib_exit();
nat:
	ppal_del_map(XIDTYPE_NAT);
out:
	return rc;
}

/*
 * xia_exit - this function is called when the modlule is removed.
 */
static void __exit xia_exit(void)
{
	sock_unregister(PF_XIA);
	proto_unregister(&xia_raw_prot);
	xia_fib_exit();
	ppal_del_map(XIDTYPE_NAT);

	/* TODO check if rc_barrier must be called here, and principals.
	rcu_barrier();
	*/

	printk(KERN_ALERT "XIA UNloaded\n");
}

module_init(xia_init);
module_exit(xia_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Network Stack");
MODULE_ALIAS_NETPROTO(PF_XIA);

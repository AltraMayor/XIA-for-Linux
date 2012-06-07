#include <linux/module.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>
#include <net/xia_socket.h>

/*
 *	Support functions for principals
 *
 * The routines beyond this point handle the behaviour of an AF_XIA
 * socket object. Mostly it punts to the subprotocols of XIP to do
 * the work.
 */

/*
 * The peer socket should always be NULL (or else). When we call this
 * function we are destroying the object and from then on nobody
 * should refer to it.
 */
int xia_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		long timeout;

		/* XXX Review this RPS call. */
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
EXPORT_SYMBOL_GPL(xia_release);

static int check_sockaddr_xia(struct sockaddr *uaddr, int addr_len)
{
	if (addr_len != sizeof(struct sockaddr_xia))
		return -EINVAL;
	if (uaddr->sa_family != AF_XIA)
		return -EAFNOSUPPORT;
	return 0;
}

static int check_valid_single_sink(struct sockaddr_xia *addr)
{
	int i;
	int n = xia_test_addr(&addr->sxia_addr);

	if (n < 1) {
		/* Invalid address since it's empty. */
		return -EINVAL;
	}

	/* Verify that there's only one sink. */
	i = n - 2;
	while (i >= 0) {
		__be32 all_edges = addr->sxia_addr.s_row[i].s_edge.i;
		if (be32_to_raw_cpu(all_edges) == XIA_EMPTY_EDGES)
			return -EINVAL; /* There's more than a sink. */
	}
		
	return n;
}

int xia_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	DECLARE_SOCKADDR(struct sockaddr_xia *, addr, uaddr);
	struct sock *sk;
	struct xia_sock *xia;
	int n, rc;

	rc = check_sockaddr_xia(uaddr, addr_len);
	if (rc)
		goto out;

	rc = check_valid_single_sink(addr);
	if (rc < 0)
		goto out;
	n = rc;

	sk = sock->sk;
	xia = xia_sk(sk);

	lock_sock(sk);

	if (xia->xia_ssink) {
		/* Double bind. */
		rc = -EINVAL;
		goto out_release_sk;
	}
	xia->xia_saddr = addr->sxia_addr;
	xia->xia_ssink = &xia->xia_saddr.s_row[n - 1];

	rc = sk->sk_prot->bind(sk, uaddr, addr_len);
	if (likely(!rc)) {
		xia->xia_daddr_set = 0;
		sk_dst_reset(sk);
	} else {
		xia->xia_ssink = NULL;
	}

out_release_sk:
	release_sock(sk);
out:
	return rc;
}
EXPORT_SYMBOL_GPL(xia_bind);

int xia_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
	int addr_len, int flags)
{
	struct sock *sk;
	struct xia_sock *xia;
	int rc;

	rc = check_sockaddr_xia(uaddr, addr_len);
	if (rc)
		return -EINVAL;

	sk = sock->sk;
	xia = xia_sk(sk);

	if (!xia->xia_ssink)
		return -ESNOTBOUND; /* Please bind first! */

	return sk->sk_prot->connect(sk, uaddr, addr_len);
}
EXPORT_SYMBOL_GPL(xia_dgram_connect);

/** copy_and_shade - Copy @src to @dst. The not used rows in @src are
 *  zeroed (shaded) in dst.
 *  This function is useful when passing an XIA address to userland because
 *  it ensures that there's no information leak due to uninitialized memory.
 */
static void copy_and_shade(struct xia_addr *dst, struct xia_addr *src)
{
	struct xia_row *rdst = dst->s_row;
	struct xia_row *rsrc = src->s_row;
	int i;

	for (i = 0; i < XIA_NODES_MAX; i++) {
		if (xia_is_nat(rsrc[i].s_xid.xid_type)) {
			/* Shade it. */
			memset(&rdst[i], 0,
				(XIA_NODES_MAX - i) * sizeof(struct xia_row));
			break;
		}
	}
	/* Copy it. */
	memmove(rdst, rsrc, i * sizeof(struct xia_row));
}

/* This does both peername and sockname. */
int xia_getname(struct socket *sock, struct sockaddr *uaddr,
	int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct xia_sock *xia	= xia_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_xia *, sxia, uaddr);

	sxia->sxia_family = AF_XIA;
	sxia->__pad0 = 0;
	if (peer) {
		if (!xia->xia_daddr_set)
			return -ENOTCONN;
		copy_and_shade(&sxia->sxia_addr, &xia->xia_daddr);
	} else {
		if (xia->xia_ssink)
			copy_and_shade(&sxia->sxia_addr, &xia->xia_saddr);
		else
			memset(&sxia->sxia_addr, 0, sizeof(sxia->sxia_addr));
	}

	BUILD_BUG_ON(sizeof(sxia->__pad1));
	/* If the previous build test fails, remove it, and uncomment
	 * the following line:
	 * memset(sxia->__pad1, 0, sizeof(sxia->__pad1));
	 */

	*uaddr_len = sizeof(*sxia);
	return 0;
}
EXPORT_SYMBOL_GPL(xia_getname);

int xia_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int rc;

	switch (cmd) {
	case SIOCGSTAMP:
		rc = sock_get_timestamp(sk, (struct timeval __user *)arg);
		break;
	case SIOCGSTAMPNS:
		rc = sock_get_timestampns(sk, (struct timespec __user *)arg);
		break;
	default:
		if (sk->sk_prot->ioctl)
			rc = sk->sk_prot->ioctl(sk, cmd, arg);
		else
			rc = -ENOIOCTLCMD;
		break;
	}
	return rc;
}
EXPORT_SYMBOL_GPL(xia_ioctl);

int xia_shutdown(struct socket *sock, int how)
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
EXPORT_SYMBOL_GPL(xia_shutdown);

int xia_sendmsg(struct kiocb *iocb, struct socket *sock,
	struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	/* XXX Review RPS calls. */
	sock_rps_record_flow(sk);

	if (!xia_sk(sk)->xia_ssink)
		return -ESNOTBOUND;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}
EXPORT_SYMBOL_GPL(xia_sendmsg);

int xia_recvmsg(struct kiocb *iocb, struct socket *sock,
	struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	int rc;

	/* XXX Review RPS calls. */
	sock_rps_record_flow(sk);

	rc = sk->sk_prot->recvmsg(iocb, sk, msg, size, flags & MSG_DONTWAIT,
				   flags & ~MSG_DONTWAIT, &addr_len);
	if (rc >= 0)
		msg->msg_namelen = addr_len;
	return rc;
}
EXPORT_SYMBOL_GPL(xia_recvmsg);

ssize_t xia_sendpage(struct socket *sock, struct page *page,
	int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;

	/* XXX Review RPS calls. */
	sock_rps_record_flow(sk);

	if (!xia_sk(sk)->xia_ssink)
		return -ESNOTBOUND;

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);
	return sock_no_sendpage(sock, page, offset, size, flags);
}
EXPORT_SYMBOL_GPL(xia_sendpage);

/*
 *	Principal-socket registering
 */

/* XXX This section is mostly copied from route.c for now, but
 * I expect they will diverge as both, route.c and here, will evolve in
 * different directions. If it doesn't happen, one should create
 * a library to be used by both.	-- Michel Machado
 */

static DEFINE_SPINLOCK(ppal_lock);
static struct hlist_head principals[NUM_PRINCIPAL_HINT];

static inline struct hlist_head *ppalhead(xid_type_t ty)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(NUM_PRINCIPAL_HINT);
	return &principals[__be32_to_cpu(ty) & (NUM_PRINCIPAL_HINT - 1)];
}

static struct xia_socket_proc *find_sproc_locked(xid_type_t ty,
	struct hlist_head *head)
{
	struct xia_socket_proc *sproc;
	struct hlist_node *p;
	hlist_for_each_entry(sproc, p, head, list)
		if (sproc->ppal_type == ty)
			return sproc;
	return NULL;
}

static struct xia_socket_proc *find_sproc_rcu(xid_type_t ty,
	struct hlist_head *head)
{
	struct xia_socket_proc *sproc;
	struct hlist_node *p;
	hlist_for_each_entry_rcu(sproc, p, head, list)
		if (sproc->ppal_type == ty)
			return sproc;
	return NULL;
}

int xia_add_socket(struct xia_socket_proc *sproc)
{
	xid_type_t ty = sproc->ppal_type;
	struct hlist_head *head = ppalhead(ty);
	int rc;

	spin_lock(&ppal_lock);

	rc = -EEXIST;
	if (find_sproc_locked(ty, head))
		goto out;
	hlist_add_head_rcu(&sproc->list, head);
	rc = 0;

out:
	spin_unlock(&ppal_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(xia_add_socket);

void xia_del_socket(struct xia_socket_proc *sproc)
{
	spin_lock(&ppal_lock);
	hlist_del_rcu(&sproc->list);
	spin_unlock(&ppal_lock);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(xia_del_socket);

/*
 *	Integration with socket API
 */

static void xia_sock_destruct(struct sock *sk)
{
	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);

	sk_mem_reclaim(sk);

	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to release alive xia socket %p\n", sk);
		dump_stack();
		return;
	}

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(atomic_read(&sk->sk_wmem_alloc));
	WARN_ON(sk->sk_wmem_queued);
	WARN_ON(sk->sk_forward_alloc);

	dst_release(rcu_dereference_check(sk->sk_dst_cache, 1));
	sk_refcnt_debug_dec(sk);
}

static int xia_create(struct net *net, struct socket *sock,
		int protocol, int kern)
{
	xid_type_t ty = __cpu_to_be32(protocol);
	struct hlist_head *head = ppalhead(ty);
	struct xia_socket_proc *sproc;
	const struct xia_socket_type_proc *stproc;
	struct proto *chosen_prot;
	struct sock *sk;
	struct xia_sock *xia;
	int rc;

	sock->state = SS_UNCONNECTED;

	/* Look for the requested type/protocol pair. */
	rc = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	sproc = find_sproc_rcu(ty, head);
	if (!sproc)
		goto out_rcu_unlock;
	stproc = sproc->procs[sock->type];
	if (!stproc)
		goto out_rcu_unlock;
	chosen_prot = stproc->prot;
	sock->ops = stproc->ops;
	rcu_read_unlock();

	WARN_ON(chosen_prot->slab == NULL);

	rc = -ENOBUFS;
	sk = sk_alloc(net, PF_XIA, GFP_KERNEL, chosen_prot);
	if (!sk)
		goto out;

	sock_init_data(sock, sk);
	sk->sk_destruct		= xia_sock_destruct;
	sk->sk_protocol		= protocol;
	sk->sk_backlog_rcv	= sk->sk_prot->backlog_rcv;
	sk->sk_no_check		= 1;	/* Checksum off by default */
	sk_refcnt_debug_inc(sk);

	xia = xia_sk(sk);
	xia->xia_ssink = NULL;
	xia->xia_daddr_set = 0;

	rc = 0;
	if (sk->sk_prot->init) {
		rc = sk->sk_prot->init(sk);
		if (rc)
			sk_common_release(sk);
	}
	goto out;

out_rcu_unlock:
	rcu_read_unlock();
out:
	return rc;
}

static const struct net_proto_family xia_family_ops = {
	.family = PF_XIA,
	.create = xia_create,
	.owner	= THIS_MODULE,
};

int __init xia_socket_init(void)
{
	return sock_register(&xia_family_ops);
}

void xia_socket_exit(void)
{
	sock_unregister(PF_XIA);
}

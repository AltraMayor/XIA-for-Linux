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

static int xia_release(struct socket *sock)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return -1;
}

static int xia_bind(struct socket *sock, struct sockaddr *myaddr,
		int sockaddr_len)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return -1;
}

static int xia_dgram_connect(struct socket *sock, struct sockaddr *vaddr,
		int sockaddr_len, int flags)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return -1;
}

static int xia_getname(struct socket *sock, struct sockaddr *addr,
		int *sockaddr_len, int peer)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return -1;
}

static int xia_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return -1;
}

static int xia_shutdown(struct socket *sock, int flags)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return -1;
}

static int xia_sendmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *m, size_t total_len)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return -1;
}

static int xia_recvmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *m, size_t total_len, int flags)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return -1;
}

static ssize_t	xia_sendpage(struct socket *sock, struct page *page,
		int offset, size_t size, int flags)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function af_xia.c:%s not implemented\n", __func__);
	return 0;
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
	int rc;

	sock->state = SS_UNCONNECTED;

	rc = -ESOCKTNOSUPPORT;
	if (sock->type != SOCK_RAW ||
		!(protocol == XIPPROTO_XIP || protocol == XIPPROTO_RAW))
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

	rc = -ENOBUFS;
	sk = sk_alloc(net, PF_XIA, GFP_KERNEL, &xia_raw_prot);
	if (!sk)
		goto out;

	sock_init_data(sock, sk);
	sk->sk_protocol	   = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
	sk->sk_no_check = 1;		/* Checksum off by default */
	sk_refcnt_debug_inc(sk);
	sock->ops = &xia_sockraw_ops;

	if (sk->sk_prot->init) {
		rc = sk->sk_prot->init(sk);
		if (rc)
			goto out_release_sk;
	}
	rc = 0;
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
static int xia_init(void)
{
	int rc;

	rc = proto_register(&xia_raw_prot, 1);
	if (rc)
		goto out;

	/*
	 *	Tell SOCKET that we are alive...
	 */

	rc = sock_register(&xia_family_ops);
	if (rc)
		goto out_unregister_raw_prot;

	rc = 0;
	printk(KERN_ALERT "XIA loaded\n");
out:
	return rc;
out_unregister_raw_prot:
	proto_unregister(&xia_raw_prot);
	goto out;
}

/*
 * xia_exit - this function is called when the modlule is removed.
 */
static void xia_exit(void)
{
	sock_unregister(PF_XIA);
	proto_unregister(&xia_raw_prot);
	printk(KERN_ALERT "XIA UNloaded\n");
}

module_init(xia_init);
module_exit(xia_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Network Protocol Suite");
MODULE_ALIAS_NETPROTO(PF_XIA);

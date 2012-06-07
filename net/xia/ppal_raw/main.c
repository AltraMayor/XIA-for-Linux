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

static int __init xia_raw_init(void)
{
	rc = proto_register(&xia_raw_prot, 1);
	if (rc)
		goto XXX;

raw_prot:
	proto_unregister(&xia_raw_prot);
}

static void __exit xia_raw_exit(void)
{
	proto_unregister(&xia_raw_prot);
}

module_init(xia_raw_init);
module_exit(xia_raw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Raw Principal");

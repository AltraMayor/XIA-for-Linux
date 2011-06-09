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
#include <net/xia_sock.h>

/* Create an XIA socket. */
static int xia_create(struct net *net, struct socket *sock,
		int protocol, int kern)
{
	int err = -1;

	printk(KERN_ALERT "xia_create: net=%p sock=%p proto=%i, kern=%i",
		net, sock, protocol, kern);

	sock->state = SS_UNCONNECTED;
	/* FIXME net/ipv4/af_inet.c:inet_create does more things. */
	return err;
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
	int rc = -EINVAL;

	rc = proto_register(&xia_raw_prot, 1);
	if (rc)
		goto out;

	/*
	 *	Tell SOCKET that we are alive...
	 */

	(void)sock_register(&xia_family_ops);

	rc = 0;
out:
	printk(KERN_ALERT "XIA loaded\n");
	return rc;
}

/*
 * xia_exit - this function is called when the modlule is removed.
 */
static void xia_exit(void)
{
	/* FIXME How to undo xia_init? Specially sock_register. */
	printk(KERN_ALERT "XIA UNloaded\n");
}

module_init(xia_init);
module_exit(xia_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Network Protocol Suite");

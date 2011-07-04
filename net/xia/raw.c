#include <net/sock.h>
#include <net/xia.h>
#include <linux/module.h>

static void raw_close(struct sock *sk, long timeout)
{
	printk(KERN_ALERT "Function xia/raw.c:%s called\n", __func__);
	sk_common_release(sk);
}

static int raw_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static int raw_disconnect(struct sock *sk, int flags)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static int raw_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static int raw_init(struct sock *sk)
{
	printk(KERN_ALERT "Function xia/raw.c:%s called\n", __func__);
	/* Do nothing. TODO Should I remove this method? */
	return 0;
}

static void raw_destroy(struct sock *sk)
{
	printk(KERN_ALERT "Function xia/raw.c:%s called\n", __func__);
	/* Do nothing. TODO Should I remove this method? */
}

static int raw_setsockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static int raw_getsockopt(struct sock *sk, int level, int optname,
		char __user *optval, int __user *option)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static int raw_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static int raw_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int noblock, int flags, int *addr_len)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static int raw_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static int raw_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static void xia_raw_hash_sk(struct sock *sk)
{
	/* Functions xia_raw_hash_sk and xia_raw_unhash_sk seem to be necessary
         * only for /proc filesystem.
	 * TODO Should them be implemented? If not, shouldn't there be
	 * a dummy function for both?
	 */
	printk(KERN_ALERT "Function xia/raw.c:%s called\n", __func__);
}

static void xia_raw_unhash_sk(struct sock *sk)
{
	/* TODO See comment in xia_raw_hash_sk. */
	printk(KERN_ALERT "Function xia/raw.c:%s called\n", __func__);
}

struct proto xia_raw_prot = {
	.name			= "XIA_RAW",
	.owner			= THIS_MODULE,
	.close			= raw_close,		/* Required */
	.connect		= raw_connect,		/* Required */
	.disconnect		= raw_disconnect,	/* Required */
	.ioctl			= raw_ioctl,
	.init			= raw_init,
	.destroy		= raw_destroy,
	.setsockopt		= raw_setsockopt,
	.getsockopt		= raw_getsockopt,
	.sendmsg		= raw_sendmsg,		/* Required */
	.recvmsg		= raw_recvmsg,		/* Required */
	.bind			= raw_bind,
	.backlog_rcv		= raw_backlog_rcv,
	.hash			= xia_raw_hash_sk,	/* Required */
	.unhash			= xia_raw_unhash_sk,	/* Required */
	.obj_size		= sizeof(struct xia_raw_sock),
};

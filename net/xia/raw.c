#include <net/sock.h>
#include <net/raw.h>
#include <net/xia.h>
#include <linux/module.h>

static void raw_close(struct sock *sk, long timeout)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
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
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
	return -1;
}

static void raw_destroy(struct sock *sk)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
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
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
}

static void xia_raw_unhash_sk(struct sock *sk)
{
	/* FIXME Write me! */
	printk(KERN_ALERT "Function xia/raw.c:%s not implemented\n", __func__);
}

/* FIXME A new hashinfo is likely necessary.
 * The one used here is reused from IP raw; once this issue has been addressed,
 * please verify if header <net/raw.h> should be removed from this file.
 * This code was copied from net/ipv4/raw.c, look for `raw_v4_hashinfo'.
 */
static struct raw_hashinfo xia_raw_hashinfo = {
	.lock = __RW_LOCK_UNLOCKED(xia_raw_hashinfo.lock),
};

struct proto xia_raw_prot = {
	.name			= "XIA_RAW",
	.owner			= THIS_MODULE,
	.close			= raw_close,
	.connect		= raw_connect,
	.disconnect		= raw_disconnect,
	.ioctl			= raw_ioctl,
	.init			= raw_init,
	.destroy		= raw_destroy,
	.setsockopt		= raw_setsockopt,
	.getsockopt		= raw_getsockopt,
	.sendmsg		= raw_sendmsg,
	.recvmsg		= raw_recvmsg,
	.bind			= raw_bind,
	.backlog_rcv		= raw_backlog_rcv,
	.hash			= xia_raw_hash_sk,	/* Required */
	.unhash			= xia_raw_unhash_sk,	/* Required */
	.obj_size		= sizeof(struct xia_raw_sock),
	.h.raw_hash		= &xia_raw_hashinfo,
};

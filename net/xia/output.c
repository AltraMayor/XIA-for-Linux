#include <linux/export.h>
#include <net/xia_route.h>
#include <net/xia_socket.h>
#include <net/xia_output.h>

int __xip_local_out(struct sk_buff *skb)
{
	struct xiphdr *xiph = xip_hdr(skb);
	int len = skb->len - xip_hdr_len(xiph);
	BUG_ON(len < 0);
	BUG_ON(len > XIP_MAXPLEN);
	xiph->payload_len = cpu_to_be16(len);
	return 1;
}

int xip_local_out(struct sk_buff *skb)
{
	int rc = __xip_local_out(skb);
	return likely(rc == 1) ? dst_output(skb) : rc;
}
EXPORT_SYMBOL_GPL(xip_local_out);

int xip_send_skb(struct sk_buff *skb)
{
	int rc = xip_local_out(skb);
	return rc > 0 ? net_xmit_errno(rc) : rc;
}
EXPORT_SYMBOL_GPL(xip_send_skb);

struct sk_buff *xip_trim_packet_if_needed(struct sk_buff *skb, u32 mtu)
{
	if (likely(skb->len <= mtu))
		return skb;

	BUG_ON(mtu < XIP_MIN_MTU);
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (likely(skb))
		__skb_trim(skb, mtu);
	return skb;
}
EXPORT_SYMBOL_GPL(xip_trim_packet_if_needed);

static inline void copy_xia_addr_to(const struct xia_addr *addr, int n,
	struct xia_row *to)
{
	int len = sizeof(struct xia_row) * n;
	BUG_ON(n < 0 || n > XIA_NODES_MAX);
	memmove(to, addr, len);
}

void xip_flush_pending_frames(struct sock *sk)
{
	struct sk_buff_head *queue = &sk->sk_write_queue;
	struct sk_buff *skb;
	while ((skb = __skb_dequeue_tail(queue)) != NULL)
		kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(xip_flush_pending_frames);

static struct sk_buff *__xip_start_skb(struct sock *sk, struct xip_dst *xdst,
	const struct xia_addr *src, int src_n,
	const struct xia_addr *dest, int dest_n, u8 dest_last_node,
	int transhdrlen, int noblock)
{
	struct net_device *dev = xdst->dst.dev;
	struct sk_buff *skb;
	struct xiphdr *xiph;
	u32 mtu, alloclen;
	int hh_len, xh_len, rc;

	if (!dev) {
		LIMIT_NETDEBUG(KERN_WARNING pr_fmt("XIP %s: there is a bug somewhere, tried to senda datagram, but dst.dev is NULL\n"),
			__func__);
		return ERR_PTR(-ENODEV);
	}

	mtu = dst_mtu(&xdst->dst);
	if (mtu < XIP_MIN_MTU) {
		LIMIT_NETDEBUG(KERN_WARNING pr_fmt("XIP %s: cannot send datagram out because mtu (= %u) of dev %s is less than minimum MTU (= %u)\n"),
			__func__, mtu, dev->name, XIP_MIN_MTU);
		return ERR_PTR(-EMSGSIZE);
	}

	hh_len = LL_RESERVED_SPACE(dev);
	alloclen = hh_len + mtu;
	skb = sock_alloc_send_skb(sk, alloclen, noblock, &rc);
	if (unlikely(!skb))
		return ERR_PTR(rc);

	/* Fill in the control structures. */

	/* Reserve space for the link layer header */
	skb_reserve(skb, hh_len);

	/* Fill XIP header. */
	skb_reset_network_header(skb);
	xh_len = xip_hdr_size(dest_n, src_n);
	xiph = (struct xiphdr *)skb_put(skb, xh_len);
	xiph->version = 1;
	xiph->next_hdr = 0;
	xiph->hop_limit = xip_dst_hoplimit(&xdst->dst);
	xiph->num_dst = dest_n;
	xiph->num_src = src_n;
	xiph->last_node = dest_last_node;
	copy_xia_addr_to(dest, dest_n, &xiph->dst_addr[0]);
	copy_xia_addr_to(src,  src_n,  &xiph->dst_addr[dest_n]);

	skb_set_transport_header(skb, xh_len);
	skb_put(skb, transhdrlen);

	/* XXX Does we need to set skb_shinfo(skb)->tx_flags? */
	
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	xdst_hold(xdst);
	skb_dst_set(skb, &xdst->dst);
	return skb;
}

static int __xip_append_data(struct sk_buff *skb,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length)
{
	int copy;
	unsigned int offset;

	/* Copy data into packet. */
	copy = min_t(int, skb_tailroom(skb), length);
	offset = skb->len;
	if (getfrag(from, skb_put(skb, copy), 0, copy, offset, skb) < 0) {
		__skb_trim(skb, offset);
		return -EFAULT;
	}

	return 0;
}

int xip_start_skb(struct sock *sk, struct xip_dst *xdst,
	const struct xia_addr *dest, int dest_n, u8 dest_last_node,
	int transhdrlen, unsigned int flags)
{
	struct xia_sock *xia = xia_sk(sk);
	struct sk_buff *skb;

	if (!xia_sk_bound(xia))
		return -ESNOTBOUND;

	skb = __xip_start_skb(sk, xdst, &xia->xia_saddr, xia->xia_snum,
		dest, dest_n, dest_last_node, transhdrlen,
		(flags & MSG_DONTWAIT));
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	/* Put the packet on the pending queue. */
	__skb_queue_tail(&sk->sk_write_queue, skb);

	return 0;
}
EXPORT_SYMBOL_GPL(xip_start_skb);

int xip_append_data(struct sock *sk,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, unsigned int flags)
{
	struct sk_buff *skb;

	if (flags & MSG_PROBE)
		return 0;

	skb = skb_peek_tail(&sk->sk_write_queue);
	BUG_ON(!skb);

	return __xip_append_data(skb, getfrag, from, length);
}
EXPORT_SYMBOL_GPL(xip_append_data);

struct sk_buff *xip_finish_skb(struct sock *sk)
{
	struct sk_buff_head *queue;
	struct sk_buff *skb;

	queue = &sk->sk_write_queue;
	skb = __skb_dequeue(queue);
	if (!skb)
		return NULL;

	/* XIP, by design, does not support fragmentation. */
	BUG_ON(skb_peek_tail(queue));

	return skb;
}
EXPORT_SYMBOL_GPL(xip_finish_skb);

struct sk_buff *xip_make_skb(struct sock *sk,
	const struct xia_addr *dest, int dest_n, u8 dest_last_node,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, int transhdrlen, struct xip_dst *xdst,
	unsigned int flags)
{
	struct xia_sock *xia;
	struct sk_buff *skb;
	int rc;

	if (flags & MSG_PROBE)
		return NULL;

	xia = xia_sk(sk);
	if (!xia_sk_bound(xia))
		return ERR_PTR(-ESNOTBOUND);

	skb = __xip_start_skb(sk, xdst, &xia->xia_saddr, xia->xia_snum,
		dest, dest_n, dest_last_node, transhdrlen,
		(flags & MSG_DONTWAIT));
	if (IS_ERR(skb))
		return skb;

	rc = __xip_append_data(skb, getfrag, from, length);
	if (rc) {
		kfree_skb(skb);
		return ERR_PTR(rc);
	}

	return skb;
}
EXPORT_SYMBOL_GPL(xip_make_skb);

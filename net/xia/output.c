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

static inline void copy_xia_addr_to(const struct xia_addr *addr, int n,
	struct xia_row *to)
{
	int len = sizeof(struct xia_row) * n;
	BUG_ON(n < 0 || n > XIA_NODES_MAX);
	memmove(to, addr, len);
}

/* Combine all pending XIP fragments on @queue into one XIP datagram
 * and return it.
 */
static struct sk_buff *__xip_make_skb(struct sock *sk,
	const struct xia_addr *dest, int dest_n, u8 dest_last_node,
	struct xip_dst *xdst, struct sk_buff_head *queue)
{
	struct xia_sock *xia = xia_sk(sk);
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct xiphdr *xiph;

	if (!xia_sk_bound(xia))
		return ERR_PTR(-ESNOTBOUND);

	skb = __skb_dequeue(queue);
	if (!skb)
		return NULL;

	/* TODO Review it and next block!
	 * Move skb->data to xip header from ext header.
	 */
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));

	/* Move XIP fragments from @queue to @frag_list.
	 *
	 * XXX XIP, by design, does not support fragmentation, so the following
	 * loop is more of a placeholder for now.
	 */
	tail_skb = &(skb_shinfo(skb)->frag_list);
	BUG_ON(*tail_skb);
	while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
		__skb_pull(tmp_skb, skb_network_header_len(skb));
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Fill XIP header. */
	xiph = (struct xiphdr *)skb->data;
	xiph->version = 1;
	xiph->next_hdr = 0;
	xiph->hop_limit = xip_dst_hoplimit(&xdst->dst);
	xiph->num_dst = dest_n;
	xiph->num_src = xia->xia_snum;
	xiph->last_node = dest_last_node;
	copy_xia_addr_to(dest, dest_n, &xiph->dst_addr[0]);
	copy_xia_addr_to(&xia->xia_saddr, xia->xia_snum,
		&xiph->dst_addr[dest_n]);

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	xdst_hold(xdst);
	skb_dst_set(skb, &xdst->dst);
	return skb;
}

struct sk_buff *xip_finish_skb(struct sock *sk)
{
	struct xia_sock *xia = xia_sk(sk);
	struct dst_entry *dst;
	struct sk_buff *ret;

	if (!xia->xia_daddr_set)
		return ERR_PTR(-ENOTCONN);

	dst = sk_dst_get(sk);
	if (!dst) {
		if (net_ratelimit())
			pr_warn("XIP %s: connected socket doesn't have a DST entry associated to it\n",
				__func__);
		ret = ERR_PTR(-ENOTCONN);
		goto out;
	}

	ret = __xip_make_skb(sk, &xia->xia_daddr, xia->xia_dnum,
		xia->xia_dlast_node, dst_xdst(dst), &sk->sk_write_queue);

out:
	dst_release(dst);
	return ret;
}
EXPORT_SYMBOL_GPL(xip_finish_skb);

static void __xip_flush_pending_frames(struct sock *sk,
	struct sk_buff_head *queue)
{
	struct sk_buff *skb;
	while ((skb = __skb_dequeue_tail(queue)) != NULL)
		kfree_skb(skb);
}

void xip_flush_pending_frames(struct sock *sk)
{
	__xip_flush_pending_frames(sk, &sk->sk_write_queue);
}
EXPORT_SYMBOL_GPL(xip_flush_pending_frames);

/* If it's not the first chunk of data, @xdst may be NULL. */
static int __xip_append_data(struct sock *sk, struct sk_buff_head *queue,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, int transhdrlen,
	struct xip_dst *xdst, unsigned int flags)
{
	struct sk_buff *skb;
	int copy;
	unsigned int offset;

	skb = skb_peek_tail(queue);

	if (!skb) {
		/* TODO This part should really be another function. */
		struct net_device *dev = xdst->dst.dev;
		u32 mtu, alloclen;
		int hh_len, rc;

		if (!dev) {
			if (net_ratelimit())
				pr_warn("XIP %s: there is a bug somewhere, tried to senda datagram, but dst.dev is NULL\n",
					__func__);
			return -ENODEV;
		}

		mtu = dst_mtu(&xdst->dst);
		if (mtu < XIP_MIN_MTU) {
			if (net_ratelimit())
				pr_warn("XIP %s: cannot send datagram out because mtu (= %u) of dev %s is less than minimum MTU (= %u)\n",
					__func__, mtu, dev->name, XIP_MIN_MTU);
			return -EMSGSIZE;
		}

		/* One must reserve space for the link layer header;
		 * Perhaps a full-size XIP header will be used; and 
		 * reserve space for the largest payload possible.
		 */
		hh_len = LL_RESERVED_SPACE(dev);
		alloclen = hh_len + MAX_XIP_HEADER +
			(mtu - MIN_XIP_HEADER - transhdrlen);

		skb = sock_alloc_send_skb(sk, alloclen,
			(flags & MSG_DONTWAIT), &rc);
		if (unlikely(!skb))
			return rc;

		/* Fill in the control structures. */
		skb_reserve(skb, hh_len + MAX_XIP_HEADER);
		/* TODO Where will network header be added? */
		skb_set_transport_header(skb, 0);
		skb_put(skb, transhdrlen);
		/* XXX Does we need to set skb_shinfo(skb)->tx_flags? */
		
		/* Put the packet on the pending queue. */
		__skb_queue_tail(queue, skb);
	}

	/* Copy data into packet. */
	copy = min_t(int, skb_tailroom(skb), length);
	offset = skb->len;
	if (getfrag(from, skb_put(skb, copy), 0, copy, offset, skb) < 0) {
		__skb_trim(skb, offset);
		return -EFAULT;
	}

	return 0;
}

/* xip_append_data() makes one large XIP datagram from many pieces of data.
 *
 * Once all pieces of data are added, which are held on the socket,
 * one must call xip_finish_skb() before consuming the datagram.
 */
int xip_append_data(struct sock *sk,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, int transhdrlen,
	struct xip_dst *xdst, unsigned int flags)
{
	if (flags & MSG_PROBE)
		return 0;
	return __xip_append_data(sk, &sk->sk_write_queue, getfrag, from,
		length, transhdrlen, xdst, flags);
}
EXPORT_SYMBOL_GPL(xip_append_data);

struct sk_buff *xip_make_skb(struct sock *sk,
	const struct xia_addr *dest, int dest_n, u8 dest_last_node,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, int transhdrlen, struct xip_dst *xdst,
	unsigned int flags)
{
	struct sk_buff_head queue;
	int rc;

	if (flags & MSG_PROBE)
		return NULL;

	__skb_queue_head_init(&queue);

	rc = __xip_append_data(sk, &queue, getfrag, from, length, transhdrlen,
		xdst, flags);
	if (rc) {
		__xip_flush_pending_frames(sk, &queue);
		return ERR_PTR(rc);
	}

	return __xip_make_skb(sk, dest, dest_n, dest_last_node, xdst, &queue);
}
EXPORT_SYMBOL_GPL(xip_make_skb);

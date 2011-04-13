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

static inline void copy_xia_addr_to(const struct xia_row *addr, int n,
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

/* Fill in the XIP header.
 *
 * NOTE
 *	This function doesn't set payload length field because it's meant to
 *	be filled at transmission time to cope with different MTUs.
 *
 *	Although source address length is filled, the address itself is left
 *	untouched to be filled by caller.
 *
 * RETURN
 *	Address where source address should be filled.
 */
static inline struct xia_row *__xip_fill_in_hdr(struct sk_buff *skb,
	struct xip_dst *xdst, int src_n, const struct xia_row *dest,
	int dest_n, int dest_last_node)
{
	struct xiphdr *xiph = xip_hdr(skb);

	BUG_ON(dest_n < 1);
	xiph->version = 1;
	xiph->next_hdr = 0;
	xiph->hop_limit = xip_dst_hoplimit(&xdst->dst);
	xiph->num_dst = dest_n;
	xiph->num_src = src_n;
	xiph->last_node = dest_last_node;
	copy_xia_addr_to(dest, dest_n, &xiph->dst_addr[0]);
	return &xiph->dst_addr[dest_n];
}

void xip_fill_in_hdr_bsrc(struct sk_buff *skb, struct xip_dst *xdst,
			  const struct xia_row *src, xid_type_t sink_type,
			  const __u8 *sink_id, int src_n,
			  const struct xia_row *dest, int dest_n,
			  int dest_last_node)
{
	struct xia_row *src_row = __xip_fill_in_hdr(skb, xdst, src_n,
		dest, dest_n, dest_last_node);
	int last = src_n - 1;

	BUG_ON(src_n < 1);
	copy_xia_addr_to(src,  last,  src_row);
	src_row[last].s_xid.xid_type = sink_type;
	memmove(src_row[last].s_xid.xid_id, sink_id, XIA_XID_MAX);
	src_row[last].s_edge.i = src[last].s_edge.i;
}
EXPORT_SYMBOL_GPL(xip_fill_in_hdr_bsrc);

void xip_fill_in_hdr(struct sk_buff *skb, struct xip_dst *xdst,
		     const struct xia_row *src, int src_n,
		     const struct xia_row *dest, int dest_n,
		     int dest_last_node)
{
	struct xia_row *src_row = __xip_fill_in_hdr(skb, xdst, src_n,
		dest, dest_n, dest_last_node);
	copy_xia_addr_to(src, src_n, src_row);
}
EXPORT_SYMBOL_GPL(xip_fill_in_hdr);

static struct sk_buff *__xip_start_skb(struct sock *sk, struct xip_dst *xdst,
	const struct xia_addr *src, int src_n, const struct xia_addr *dest,
	int dest_n, u8 dest_last_node, int transhdrlen, int noblock)
{
	struct net_device *dev = xdst->dst.dev;
	struct sk_buff *skb;
	u32 mtu, alloclen;
	int hh_len, xh_len, rc;

	if (!dev) {
		net_warn_ratelimited("XIP %s: there is a bug somewhere, tried to send a datagram, but dst.dev is NULL\n",
				     __func__);
		return ERR_PTR(-ENODEV);
	}

	mtu = dst_mtu(&xdst->dst);
	if (mtu < XIP_MIN_MTU) {
		net_warn_ratelimited("XIP %s: cannot send datagram out because mtu (= %u) of dev %s is less than minimum MTU (= %u)\n",
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
	skb_put(skb, xh_len);
	xip_fill_in_hdr(skb, xdst, src->s_row, src_n,
			dest->s_row, dest_n, dest_last_node);

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
	struct msghdr *from, int length)
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
	struct msghdr *from, int length, unsigned int flags)
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
	struct msghdr *from, int length, int transhdrlen, struct xip_dst *xdst,
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

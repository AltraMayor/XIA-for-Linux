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

/* Combined all pending XIP fragments on the socket as one XIP datagram
 * and push them out.
 * This function was based on include/net/ip.h:ip_finish_skb.
 */
struct sk_buff *xip_finish_skb(struct sock *sk)
{
	struct xia_sock *xia = xia_sk(sk);
	struct sk_buff_head *queue = &sk->sk_write_queue;
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct xiphdr *xiph;

	skb = __skb_dequeue(queue);
	if (!skb)
		return NULL;

	/* Move skb->data to xip header from ext header. */
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));

	/* Move XIP fragments from @queue to @frag_list. */
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

	/* XXX Remove these limitations! */
	BUG_ON(!xia_sk_bound(xia));
	BUG_ON(xia->xia_daddr_set);

	xiph = (struct xiphdr *)skb->data;
	xiph->version = 1;
	xiph->next_hdr = 0;
	/* TODO
	xiph->hop_limit = xip_dst_hoplimit(XXXdst);
	xiph->num_dst = xia->xia_dlast_node;
	xiph->num_src = XXX;
	xiph->last_node = xia->xia_dlast_node;
	XXXCopyAddresses
	*/

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	/* TODO Add ref! and
	skb_dst_set(skb, &rt->dst);
	*/

	return skb;
}
EXPORT_SYMBOL_GPL(xip_finish_skb);

void xip_flush_pending_frames(struct sock *sk)
{
	struct sk_buff_head *queue = &sk->sk_write_queue;
	struct sk_buff *skb;
	while ((skb = __skb_dequeue_tail(queue)) != NULL)
		kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(xip_flush_pending_frames);

#ifndef _NET_XIA_OUTPUT_H
#define _NET_XIA_OUTPUT_H

#include <linux/skbuff.h>
#include <net/sock.h>

/* Don't call this function, prefer xip_local_out(). */
int __xip_local_out(struct sk_buff *skb);

int xip_local_out(struct sk_buff *skb);

int xip_send_skb(struct sk_buff *skb);

struct sk_buff *xip_finish_skb(struct sock *sk);

/* Throw away all pending outbound data on the socket. */
void xip_flush_pending_frames(struct sock *sk);

struct xip_dst;

int xip_append_data(struct sock *sk,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, int transhdrlen,
	struct xip_dst *xdst, unsigned int flags);

struct sk_buff *xip_make_skb(struct sock *sk,
	struct xia_addr *dest, int dest_n, u8 dest_last_node,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, int transhdrlen, struct xip_dst *xdst);

#endif /* _NET_XIA_OUTPUT_H */

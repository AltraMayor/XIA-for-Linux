#ifndef _NET_XIA_OUTPUT_H
#define _NET_XIA_OUTPUT_H

#include <linux/skbuff.h>
#include <net/sock.h>

/* Don't call this function, prefer xip_local_out(). */
int __xip_local_out(struct sk_buff *skb);

int xip_local_out(struct sk_buff *skb);

int xip_send_skb(struct sk_buff *skb);

/* @skb must already have XIP header, and not have link layer header. */
struct sk_buff *xip_trim_packet_if_needed(struct sk_buff *skb, u32 mtu);

/* Throw away all pending outbound data on the socket. */
void xip_flush_pending_frames(struct sock *sk);

struct xip_dst;

/* xip_start_skb() creates a sock buffer and associates it to @sk.
 *
 * Call xip_append_data() to add data to the sock buffer.
 *
 * Once all pieces of data are added, call xip_finish_skb()
 * before consuming the datagram.
 */
int xip_start_skb(struct sock *sk, struct xip_dst *xdst,
	const struct xia_addr *dest, int dest_n, u8 dest_last_node,
	int transhdrlen, unsigned int flags);
int xip_append_data(struct sock *sk,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, unsigned int flags);
struct sk_buff *xip_finish_skb(struct sock *sk);

struct sk_buff *xip_make_skb(struct sock *sk,
	const struct xia_addr *dest, int dest_n, u8 dest_last_node,
	int getfrag(void *from, char *to, int offset,
		int len, int odd, struct sk_buff *skb),
	struct iovec *from, int length, int transhdrlen, struct xip_dst *xdst,
	unsigned int flags);

#endif /* _NET_XIA_OUTPUT_H */

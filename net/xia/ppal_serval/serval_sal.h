#ifndef _SERVAL_SAL_H_
#define _SERVAL_SAL_H_

#include <net/xia_serval.h>
#include <net/xia_route.h>

/* Service Access Layer (SAL) socket states used for, e.g., migration. */
enum {
	SAL_RSYN_INITIAL = 0,
	SAL_RSYN_SENT,
	SAL_RSYN_RECV,
	SAL_RSYN_SENT_RECV, /* Receive RSYN after having sent RSYN */
	__SAL_RSYN_MAX_STATE,
};

struct serval_sock_af_ops {
	int	(*receive)(struct sock *sk, struct sk_buff *skb);
	void	(*send_check)(struct sock *sk, struct sk_buff *skb);
	int	(*setsockopt)(struct sock *sk, int level, int optname,
			char __user *optval, unsigned int optlen);
	int	(*getsockopt)(struct sock *sk, int level, int optname,
			char __user *optval, int __user *optlen);
	int	(*conn_build_syn)(struct sock *sk, struct sk_buff *skb);
	int	(*conn_build_synack)(struct sock *sk, struct dst_entry *dst,
			struct request_sock *rsk, struct sk_buff *skb);
	int	(*conn_build_ack)(struct sock *sk, struct sk_buff *skb);
	int	(*conn_request)(struct sock *sk, struct request_sock *rsk,
			struct sk_buff *skb);
	int	(*conn_close)(struct sock *sk);
	int	(*request_state_process)(struct sock *sk, struct sk_buff *skb);
	int	(*respond_state_process)(struct sock *sk, struct sk_buff *skb);
	int	(*conn_child_sock)(struct sock *sk, struct sk_buff *skb,
			struct request_sock *rsk, struct sock *child,
			struct dst_entry *dst);
	int	(*migration_completed)(struct sock *sk);
	int	(*freeze_flow)(struct sock *sk);
	void	(*done)(struct sock *sk);
	u16	net_header_len;
	u16	sockaddr_len;
};

int serval_sock_refresh_dest(struct sock *sk);

int serval_sal_xmit_skb(struct sk_buff *skb);

/* 
   NOTE:
   
   We must be careful that this struct does not overflow the 48 bytes
   that the skb struct gives us in the cb field.
   
   Transport protocols (i.e., in most cases TCP) reserve some room for
   lower layer control blocks (e.g., IPv4/IPv6) at the head of their
   own control block. This is done in order to keep the lower layer
   information when processing incoming packets. We should therefore
   be careful not to overwrite the IP control block in incoming
   packets in case TCP expects it to be there.

   For outgoing packets, we are free to overwrite the control block
   with our own information. Any packets queued by the transport
   protocol are cloned before transmission, so the original
   information will be preserved in the queued packet.

   We should be careful to do the same in the SAL layer when queuing
   packets; i.e., we should always clone queued packets before we
   transmit.
 */
/* XXX Is this struct needed at all? Isn't there a simpler solution? */
struct sal_skb_cb {
	u8 flags;
	u32 verno;
	u32 when;
};

enum sal_ctrl_flags {
	SVH_SYN       = 1 << 0,
	SVH_RSYN      = 1 << 1,
	SVH_ACK       = 1 << 2,

	/* XXX This flag isn't used, implement it or drop it. */
	SVH_NACK      = 1 << 3,

	SVH_RST       = 1 << 4,
	SVH_FIN       = 1 << 5,

	/* XXX This flag is only used internally, so it should be implemented
	 * somewhere else.
	 */
	SVH_RETRANS   = 1 << 6,
};

#define sal_time_stamp ((u32)(jiffies))

static inline struct sal_skb_cb *__sal_skb_cb(struct sk_buff *skb)
{
        return (struct sal_skb_cb *)&(skb)->cb[0];
}

#define SAL_SKB_CB(__skb) __sal_skb_cb(__skb)

extern int sysctl_tcp_fin_timeout;

/* XXX Given that the control queue only holds a sk_buff at a time,
 * couldn't it be just a pointer?
 */

/* control queue abstraction */
static inline void serval_sal_ctrl_queue_purge(struct sock *sk)
{
    struct sk_buff *skb = sk_ssk(sk)->ctrl_queue;
    if (skb) {
            kfree_skb(skb);
            sk_ssk(sk)->ctrl_queue = NULL;
    }
}

static inline struct sk_buff *serval_sal_ctrl_queue_head(struct sock *sk)
{
    return sk_ssk(sk)->ctrl_queue;
}

static inline struct sk_buff *serval_sal_send_head(struct sock *sk)
{
	return sk_ssk(sk)->ctrl_send_head;
}

static inline int serval_sal_skb_is_last(const struct sock *sk,
					 const struct sk_buff *skb)
{
    return skb == sk_ssk(sk)->ctrl_queue;
}

static inline void serval_sal_advance_send_head(struct sock *sk, 
						struct sk_buff *skb)
{
	if (serval_sal_skb_is_last(sk, skb))
		sk_ssk(sk)->ctrl_send_head = NULL;
	else
		sk_ssk(sk)->ctrl_send_head = sk_ssk(sk)->ctrl_queue;
}

static inline void serval_sal_init_send_head(struct sock *sk)
{
	sk_ssk(sk)->ctrl_send_head = NULL;
}

static inline void serval_sal_init_ctrl_queue(struct sock *sk)
{
        sk_ssk(sk)->ctrl_queue = NULL;
        serval_sal_init_send_head(sk);
}

static inline void __serval_sal_add_ctrl_queue_tail(struct sock *sk, 
						    struct sk_buff *skb)
{
	sk_ssk(sk)->ctrl_queue = skb;
}

static inline void serval_sal_add_ctrl_queue_tail(struct sock *sk, 
						  struct sk_buff *skb)
{
	__serval_sal_add_ctrl_queue_tail(sk, skb);

	if (sk_ssk(sk)->ctrl_send_head == NULL)
		sk_ssk(sk)->ctrl_send_head = skb;
}

static inline void serval_sal_unlink_ctrl_queue(struct sk_buff *skb, 
						struct sock *sk)
{
	if (skb == sk_ssk(sk)->ctrl_queue)
		sk_ssk(sk)->ctrl_queue = NULL;
}

int serval_sal_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
void serval_sal_close(struct sock *sk, long timeout);
int serval_sal_migrate(struct sock *sk);
void serval_sal_rexmit_timeout(unsigned long data);
void serval_sal_timewait_timeout(unsigned long data);
int serval_sal_send_shutdown(struct sock *sk);
int serval_sal_recv_shutdown(struct sock *sk);
void serval_sal_done(struct sock *sk);

int serval_sal_rcv(struct sk_buff *skb);
int serval_sal_rsk_rcv(struct sk_buff *skb);

void serval_sal_rcv_reset(struct sock *sk);
void serval_sal_send_active_reset(struct sock *sk, gfp_t priority);

static inline struct sal_hdr *sal_hdr(struct sk_buff *skb)
{
        return (struct sal_hdr *)skb_transport_header(skb);
}

int serval_sal_send_fin(struct sock *sk);
void serval_sal_update_rtt(struct sock *sk, const s32 seq_rtt);

/* These extra bytes are to accomodate the maximum minimum transport header.
 * In the current implementation, TCP has the largest minimum header.
 * XXX This size should be obtained automatically.
 */
#define EXTRA_HDR_SIZE 20

/* LL + XIP + SAL + SAL extensions + extra */
#define MAX_SAL_HDR (MAX_HEADER + MAX_XIP_HEADER + sizeof(struct sal_hdr) + \
	 sizeof(struct sal_control_ext) + EXTRA_HDR_SIZE)

#define SAL_NET_HEADER_LEN (MAX_XIP_HEADER + sizeof(struct sal_hdr))

#define SAL_RTO_MAX	((unsigned)(120*HZ))
#define SAL_RTO_MIN	((unsigned)(HZ/5))
#define SAL_TIMEOUT_INIT ((unsigned)(3*HZ))
#define SAL_RETRANSMITS_MAX 15

/* How long to wait to destroy TIME-WAIT state? About 60 seconds. */
#define SAL_TIMEWAIT_LEN (60*HZ)

/* BSD style FIN_WAIT2 deadlock breaker. It used to be 3min,
 * new value is 60sec, to combine FIN-WAIT-2 timeout with TIME-WAIT timer.
 */
#define SAL_FIN_TIMEOUT	SAL_TIMEWAIT_LEN

#endif /* _SERVAL_SAL_H_ */

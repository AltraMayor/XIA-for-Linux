/* The Service Access Layer (SAL).
 *
 * Authors:	Erik Nordström <enordstr@cs.princeton.edu>
 *		David Shue <dshue@cs.princeton.edu>
 *		Rob Kiefer <rkiefer@cs.princeton.edu>
 *		Michel Machado <michel@digirati.com.br>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <net/xia_serval.h>
#include <net/xia_output.h>
#include "af_serval.h"
#include "serval_sal.h"

int sysctl_sal_fin_timeout __read_mostly = SAL_FIN_TIMEOUT;

/*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 * Taken from linux/net/tcp.h.
 */
static inline int before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}

#define after(seq2, seq1) 	before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

/* Context for parsed Serval headers. */
struct sal_context {
        struct sal_hdr *hdr;

	/* SAL header length + lenght of all extension headers present */
        unsigned short length;

	/* These three fields are host-endian copies of respective fields
	 * in @ctrl_ext when it exists.
	 */
        unsigned short flags;
        uint32_t verno;
        uint32_t ackno;

        struct sal_control_ext *ctrl_ext;
};

static int serval_sal_state_process(struct sock *sk, struct sk_buff *skb,
	const struct sal_context *ctx);

static int serval_sal_transmit_skb(struct sock *sk, struct sk_buff *skb,
	int use_copy, gfp_t gfp_mask);

static size_t verify_ext_length[] = {
        [SAL_CONTROL_EXT] = sizeof(struct sal_control_ext),
};

static int parse_control_ext(struct sal_context *sal_ctx, struct sal_ext *ext)
{
	struct sal_control_ext *cext;

	if (sal_ctx->ctrl_ext)
		return -1;

	cext = (struct sal_control_ext *)ext;
	sal_ctx->ctrl_ext = cext;
	sal_ctx->verno = ntohl(cext->verno);
	sal_ctx->ackno = ntohl(cext->ackno);

        /* Parse flags */
	if (cext->syn)
		sal_ctx->flags |= SVH_SYN; 
	if (cext->rsyn)
		sal_ctx->flags |= SVH_RSYN;
	if (cext->ack)
		sal_ctx->flags |= SVH_ACK;
	if (cext->nack)
		sal_ctx->flags |= SVH_NACK;
	if (cext->rst)
		sal_ctx->flags |= SVH_RST;
	if (cext->fin)
		sal_ctx->flags |= SVH_FIN;

        return sizeof(struct sal_control_ext);
}

typedef int (*parse_ext_func_t)(struct sal_context *sal_ctx,
	struct sal_ext *ext);

static parse_ext_func_t parse_ext_func[] = {
	[SAL_CONTROL_EXT]	= parse_control_ext,
};

static int parse_ext(struct sal_context *sal_ctx, struct sal_ext *ext, int rest)
{
	int ext_len = ext->length;

	if (ext_len > rest || ext->type >= __SAL_EXT_TYPE_MAX ||
		ext_len != verify_ext_length[ext->type])
		return -1;

	return parse_ext_func[ext->type](sal_ctx, ext);
}

/* Parse Serval header and all extension doing basic sanity checks.
 *
 * RETURN
 *	0 on success.
 *	> 0 otherwise; that is the number of not-parsed bytes.
 *
 * NOTE
 *	All by the extensions of @shdr must be valid, that is, the length of
 *	the whole header, and the checksum are valid.
 */
#define MAX_NUM_SAL_EXTENSIONS __SAL_EXT_TYPE_MAX
static int serval_sal_parse_hdr(struct sal_context *sal_ctx,
	struct sal_hdr *shdr)
{
	struct sal_ext *ext;
	int rest, i;

	memset(sal_ctx, 0, sizeof(struct sal_context));
	sal_ctx->hdr = shdr;
	rest = shdr->shl << 2;
	sal_ctx->length = rest;

	if (rest < sizeof(struct sal_hdr)) {
		/* Once can't just return @rest because it could be zero,
		 * which would mean no error.
		 */
		return rest ? rest : -1;
	}

        /* Parse extensions */
	i = 0;
	rest -= sizeof(struct sal_hdr);
	ext = SAL_EXT_FIRST(shdr);
	while (rest > 0 && i < MAX_NUM_SAL_EXTENSIONS) {
		int ext_len = parse_ext(sal_ctx, ext, rest);

		if (ext_len <= 0)
			break;

		i++;
		rest -= ext_len;
		ext = SAL_EXT_NEXT(ext);
        }
        return rest;
}

static inline int has_valid_verno(uint32_t seg_seq, struct sock *sk)
{        
	if ((1 << sk->sk_state) & (SALF_LISTEN | SALF_REQUEST))
                return 1;
        return !before(seg_seq, sk_ssk(sk)->rcv_seq.nxt);
}

static inline int packet_has_transport_hdr(const struct sk_buff *skb,
	const struct sal_hdr *sh)
{
	/* Have we pulled the serval header already? */
	return (unsigned char *)sh == skb_transport_header(skb)
		? skb->len > (sh->shl << 2)	/* No.	*/
		: skb->len > 0;			/* Yes.	*/
}

static inline int has_valid_control_extension(struct sock *sk, 
                                              const struct sal_context *ctx)
{
        /* Check nonce for all control extensions except SYNs, since
	 * those are actually establishing nonces.
	 */
        return ctx->ctrl_ext && (ctx->ctrl_ext->syn ||
		!memcmp(ctx->ctrl_ext->nonce, sk_ssk(sk)->peer_nonce,
			SAL_NONCE_SIZE));
}

static inline __sum16 serval_sal_csum(struct sal_hdr *sh, int len)
{
	return ip_compute_csum(sh, len);
}

static inline void serval_sal_send_check(struct sal_hdr *sh)
{
	sh->check = 0;
	sh->check = serval_sal_csum(sh, sh->shl << 2);
}

/* Compute the actual rto_min value */
static inline u32 serval_sal_rto_min(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	if (dst && dst_metric_locked(dst, RTAX_RTO_MIN))
		return dst_metric_rtt(dst, RTAX_RTO_MIN);
	return SAL_RTO_MIN;
}

/* The RTO estimation for the SAL is taken directly from the Linux
   kernel TCP code. */
/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
static void serval_sal_rtt_estimator(struct sock *sk, const __u32 mrtt)
{
	struct serval_sock *ssk = sk_ssk(sk);
	long m = mrtt; /* RTT */

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be increased quickly, decrease too quickly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	if (m == 0)
		m = 1;
	if (ssk->srtt != 0) {
		m -= (ssk->srtt >> 3);	/* m is now error in rtt est */
		ssk->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
		if (m < 0) {
			m = -m;		/* m is now abs(error) */
			m -= (ssk->mdev >> 2);   /* similar update on mdev */
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
			if (m > 0)
				m >>= 3;
		} else {
			m -= (ssk->mdev >> 2);   /* similar update on mdev */
		}
		ssk->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
		if (ssk->mdev > ssk->mdev_max) {
			ssk->mdev_max = ssk->mdev;
			if (ssk->mdev_max > ssk->rttvar)
				ssk->rttvar = ssk->mdev_max;
		}
		if (after(ssk->snd_seq.una, ssk->rtt_seq)) {
			if (ssk->mdev_max < ssk->rttvar)
				ssk->rttvar -= (ssk->rttvar - ssk->mdev_max) >> 2;
			ssk->rtt_seq = ssk->snd_seq.nxt;
			ssk->mdev_max = serval_sal_rto_min(sk);
		}
	} else {
		/* no previous measure. */
		ssk->srtt = m << 3;	/* take the measured time to be rtt */
		ssk->mdev = m << 1;	/* make sure rto = 3*rtt */
		ssk->mdev_max = ssk->rttvar = max(ssk->mdev, 
                                                  serval_sal_rto_min(sk));
		ssk->rtt_seq = ssk->snd_seq.nxt;
	}
}

static inline void serval_sal_bound_rto(const struct sock *sk)
{
	if (sk_ssk(sk)->rto > SAL_RTO_MAX)
		sk_ssk(sk)->rto = SAL_RTO_MAX;
}

static inline u32 __serval_sal_set_rto(const struct serval_sock *ssk)
{
	return (ssk->srtt >> 3) + ssk->rttvar;
}

/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
static inline void serval_sal_set_rto(struct sock *sk)
{
	struct serval_sock *ssk = sk_ssk(sk);
	/* Old crap is replaced with new one. 8)
	 *
	 * More seriously:
	 * 1. If rtt variance happened to be less 50msec, it is hallucination.
	 *    It cannot be less due to utterly erratic ACK generation made
	 *    at least by solaris and freebsd. "Erratic ACKs" has _nothing_
	 *    to do with delayed acks, because at cwnd>2 true delack timeout
	 *    is invisible. Actually, Linux-2.4 also generates erratic
	 *    ACKs in some circumstances.
	 */
	ssk->rto = __serval_sal_set_rto(ssk);

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exactly, which we pretend to do.
	 */

	/* NOTE: clamping at SAL_RTO_MIN is not required, current algo
	 * guarantees that rto is higher.
	 */
	serval_sal_bound_rto(sk);
}

static void serval_sal_rearm_rto(struct sock *sk)
{
	struct serval_sock *ssk = sk_ssk(sk);

	if (!serval_sal_ctrl_queue_head(sk)) {
		serval_sock_clear_xmit_timer(sk);
	} else {
		serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);
	}
}

void serval_sal_update_rtt(struct sock *sk, const s32 seq_rtt)
{
        serval_sal_rtt_estimator(sk, seq_rtt);
	serval_sal_set_rto(sk);
        sk_ssk(sk)->backoff = 0;
}

/* Given an ACK, clean all packets from the control queue that this ACK
 * acknowledges. Or, alternatively, clean all packets if indicated by
 * the 'all' argument.
 *
 * Reschedule retransmission timer as neccessary, i.e., if there are
 * still unacked packets in the queue and we removed the first packet
 * in the queue.
 */
static int serval_sal_clean_rtx_queue(struct sock *sk, uint32_t ackno, int all, 
                                      struct sal_skb_cb *cb_out)
{
        struct serval_sock *ssk = sk_ssk(sk);
        struct sk_buff *skb, *fskb = serval_sal_ctrl_queue_head(sk);
        unsigned int num = 0;
        u32 now = sal_time_stamp;
        s32 seq_rtt = -1;
       
        while ((skb = serval_sal_ctrl_queue_head(sk))) {
                if (after(ackno, SAL_SKB_CB(skb)->verno) || all) {
                        serval_sal_unlink_ctrl_queue(skb, sk);

                        if (cb_out) {
                                /* merge the state */
                                cb_out->flags |= SAL_SKB_CB(skb)->flags;
                        }

                        if (SAL_SKB_CB(skb)->flags & SVH_RETRANS) {
                                seq_rtt = -1;
                        } else if (!all) {
                                seq_rtt = now - SAL_SKB_CB(skb)->when;
                                serval_sal_update_rtt(sk, seq_rtt);
                                serval_sal_rearm_rto(sk);
                        }

                        if (skb == serval_sal_send_head(sk))
                                serval_sal_advance_send_head(sk, skb);

                        kfree_skb(skb);
                        skb = serval_sal_ctrl_queue_head(sk);
                        if (skb)
                                ssk->snd_seq.una = SAL_SKB_CB(skb)->verno;
                        num++;                        
                } else {
                        break;
                }
        }

        /* If we removed the first packet in the queue, we should also
         * clear the retransmit timer since it is no longer valid.
	 */
        if (serval_sal_ctrl_queue_head(sk) != fskb) {
                serval_sock_clear_xmit_timer(sk);
                ssk->retransmits = 0;
        }

        if (serval_sal_ctrl_queue_head(sk))
                serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);

        return 0;
}

static void serval_sal_queue_ctrl_skb(struct sock *sk, struct sk_buff *skb)
{
        /* Cannot release header here in case this is an unresolved
         * packet. We need the skb_transport_header() pointer to
         * calculate checksum.
	 */

	serval_sal_add_ctrl_queue_tail(sk, skb);
        
        /* Check if the skb became first in queue, in that case update
         * unacknowledged verno.
	 */
        if (skb == serval_sal_ctrl_queue_head(sk))
                sk_ssk(sk)->snd_seq.una = SAL_SKB_CB(skb)->verno;
}

/* This function writes packets in the control queue to the
 * network. It will write up to the current send window or the limit
 * given as argument.
 */
static int serval_sal_write_xmit(struct sock *sk, unsigned int limit, gfp_t gfp)
{
        struct serval_sock *ssk = sk_ssk(sk);
        struct sk_buff *skb;
        unsigned int num = 0;
        int err = 0;
        
	while ((skb = serval_sal_send_head(sk)) && 
               (ssk->snd_seq.nxt - ssk->snd_seq.una) <= ssk->snd_seq.wnd) {
                
                if (limit && num == limit)
                        break;

                SAL_SKB_CB(skb)->when = sal_time_stamp;
                                
                err = serval_sal_transmit_skb(sk, skb, 1, gfp);
                if (err < 0)
                        break;
                serval_sal_advance_send_head(sk, skb);
                num++;
        }

        return err;
}

/* Queue SAL control packets for the purpose of doing retransmissions
 * and socket buffer accounting. The TCP SYN is piggy-backed on the
 * SAL control SYN and should take one byte send buffer
 * space. Therefore, we need to keep the SYN until it is ACKed or
 * freed due to reaching max retransmissions.
 */
static int serval_sal_queue_and_push(struct sock *sk, struct sk_buff *skb)
{
        struct serval_sock *ssk = sk_ssk(sk);
        struct sal_skb_cb cb;
        
        memset(&cb, 0, sizeof(cb));

        /* Remove previously queued control packet(s). We currently
         * only queue one control packet at a time, allowing control
         * packets to override each other (necessary for, e.g.,
         * (re)migration). It is not strictly necessary to use a queue
         * for this, but we use it anyway for convenience and future
         * proofness (in case we want to implement a send window).
	 */
        serval_sal_clean_rtx_queue(sk, 0, 1, &cb);

        /* We need to merge the state in unacknowledged packets with
         * the our new state when we are overriding (currently
         * previous flags).
	 */
        SAL_SKB_CB(skb)->flags |= cb.flags;

        /* Queue the new packet. */
        serval_sal_queue_ctrl_skb(sk, skb);

        /* Set retransmission timer. */
        if (skb == serval_sal_ctrl_queue_head(sk))
                serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);
        
        /* Write packets in queue to network. */
        return serval_sal_write_xmit(sk, 1, GFP_ATOMIC);
}

/* This function is equivalent to sock.c:sock_wfree().
 * However, this one can be used as destructor for an skb to
 * free up associated sock state and bindings specific to Serval and
 * control packets, when an skb is freed.
 *
 * This function will be pointed to by skb->destructor and set by
 * skb_serval_set_owner_w().
 */
void serval_sock_wfree(struct sk_buff *skb)
{
	sock_put(skb->sk);
}

/* XXX Why can't one just use skb_set_owner_w()? */
static void skb_serval_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = serval_sock_wfree;
	/* Guarantees the socket is not free'd for in-flight packets */
	sock_hold(sk);
}

static inline void prepare_skb_to_send(struct sk_buff *skb, struct sock *sk)
{
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	skb_serval_set_owner_w(skb, sk);
}

static struct sk_buff *sk_sal_alloc_skb(struct sock *sk, gfp_t gfp)
{
	struct sk_buff *skb = alloc_skb(sk->sk_prot->max_header, gfp);
	if (!skb)
		return NULL;
	prepare_skb_to_send(skb, sk);
	skb_reserve(skb, sk->sk_prot->max_header);
	return skb;
}

static int serval_sal_send_syn(struct sock *sk, u32 verno)
{
        struct serval_sock *ssk = sk_ssk(sk);
        struct sk_buff *skb;

        skb = sk_sal_alloc_skb(sk, GFP_ATOMIC);
        if (!skb)
                return -ENOMEM;

        /* Ask transport to fill in */
        if (ssk->af_ops->conn_build_syn) {
                int err = ssk->af_ops->conn_build_syn(sk, skb);
                if (err) {
                        /* Transport protocol returned error. */
                        __kfree_skb(skb);
                        return err;
                }
        }

        SAL_SKB_CB(skb)->flags = SVH_SYN;
        SAL_SKB_CB(skb)->verno = verno;
        ssk->snd_seq.nxt = verno + 1;

        return serval_sal_queue_and_push(sk, skb);
}

static void set_peer_srvc_xdst(struct serval_sock *ssk, struct xip_dst *xdst)
{
	struct xip_dst *prv_xdst = ssk->peer_srvc_xdst;
	ssk->peer_srvc_xdst = xdst;
	if (prv_xdst)
		xdst_put(prv_xdst);
}

static void __set_peer_srvc(struct serval_sock *ssk,
	const struct xia_row *dest, int n, int last_node, struct xip_dst *xdst)
{
	ssk->peer_srvc_num = n;
	ssk->peer_srvc_last_node = last_node;
	copy_n_and_shade_xia_addr(&ssk->peer_srvc_addr, dest, n);
	set_peer_srvc_xdst(ssk, xdst);
	ssk->peer_srvc_set = true;
}

static int set_peer_srvc(struct serval_sock *ssk, const struct xia_row *dest,
	int n)
{
	struct xip_dst *xdst;

	ssk->peer_srvc_num = n;
	ssk->peer_srvc_last_node = XIA_ENTRY_NODE_INDEX;
	copy_n_and_shade_xia_addr(&ssk->peer_srvc_addr, dest, n);

	xdst = xip_mark_addr_and_get_dst(sock_net(&ssk->xia_sk.sk),
		ssk->peer_srvc_addr.s_row, n, &ssk->peer_srvc_last_node, 0);
	if (IS_ERR(xdst))
		return PTR_ERR(xdst);

	set_peer_srvc_xdst(ssk, xdst);
	ssk->peer_srvc_set = true;
	return 0;
}

int serval_sal_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	DECLARE_SOCKADDR(struct sockaddr_xia *, daddr, uaddr);
	struct serval_sock *ssk;
	int rc, n;

	rc = check_type_of_all_sinks(daddr, XIDTYPE_SRVCID);
	if (rc < 0)
		return rc;
	n = rc;

	ssk = sk_ssk(sk);
	rc = set_peer_srvc(ssk, daddr->sxia_addr.s_row, n);
	if (rc)
		return rc;

        /* Disable segmentation offload */
        sk->sk_gso_type = 0;

        return serval_sal_send_syn(sk, ssk->snd_seq.iss);
}

static void serval_sal_timewait(struct sock *sk, int state, int timeo)
{
        unsigned long timeout = jiffies + timeo;
        struct serval_sock *ssk = sk_ssk(sk);
        const int rto = (ssk->rto << 2) - (ssk->rto >> 1);

        serval_sock_set_state(sk, state);
        
        if (timeo < rto)
                timeout = jiffies + rto;

        sk_reset_timer(sk, &ssk->tw_timer, timeout); 
}

void serval_sal_done(struct sock *sk)
{
	if (sk_ssk(sk)->af_ops->done)
		sk_ssk(sk)->af_ops->done(sk);
	serval_sock_done(sk);
}

static inline int serval_sock_set_sal_state(struct sock *sk,
	unsigned int new_state)
{ 
        BUG_ON(new_state >= __SAL_RSYN_MAX_STATE);
        sk_ssk(sk)->sal_state = new_state;
        return new_state;
}

static int serval_sal_send_rsyn(struct sock *sk, u32 verno)
{
        struct serval_sock *ssk = sk_ssk(sk);
        struct sk_buff *skb;

	if ((1 << sk->sk_state) & (SALF_REQUEST | SALF_LISTEN | SALF_CLOSED))
		return 0;

        switch (ssk->sal_state) {
        case SAL_RSYN_INITIAL:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT);
                break;
        case SAL_RSYN_RECV:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT_RECV);
                break;
        case SAL_RSYN_SENT:
        case SAL_RSYN_SENT_RECV:
                /* Here we just move to the same state again, so
                   nothing to do. */
                break;
        }

        for (;;) {
                skb = sk_sal_alloc_skb(sk, GFP_ATOMIC);
                if (skb)
                        break;
                yield();
        }

        /* Use same sequence number as previous packet for migration
	 * requests.
	 */
        SAL_SKB_CB(skb)->flags = SVH_RSYN;
        SAL_SKB_CB(skb)->verno = verno;

	if ((1 << sk->sk_state) &
		(SALF_FINWAIT1 | SALF_CLOSING | SALF_LASTACK)) {
		/* We have sent our FIN, but not received the ACK.
		 * We need to add the FIN bit.
		 */
                SAL_SKB_CB(skb)->flags |= SVH_FIN;
	}

        return serval_sal_queue_and_push(sk, skb);
}

int serval_sal_migrate(struct sock *sk)
{
        return serval_sal_send_rsyn(sk, sk_ssk(sk)->snd_seq.nxt++);
}

int serval_sal_send_fin(struct sock *sk)
{
        struct serval_sock *ssk = sk_ssk(sk);
        struct sk_buff *skb;

        /* We are under lock, so allocation must be atomic */
        /* Socket is locked, keep trying until memory is available. */
        for (;;) {
                skb = sk_sal_alloc_skb(sk, GFP_ATOMIC);
                
                if (skb)
                        break;
                yield();
        }

        SAL_SKB_CB(skb)->flags = SVH_FIN;
        SAL_SKB_CB(skb)->verno = ssk->snd_seq.nxt++;

	/* If we are in the process of migrating, then we should
	 * probably add also the RSYN flag. Otherwise, if the previous
	 * RSYN was lost, this FIN packet will "override" the RSYN and
	 * the migration will never happen. XXX: verify that this is
	 * really the way to handle this situation.
	 */
        if (ssk->sal_state == SAL_RSYN_SENT) {
		/* RSYN was in progress, adding RSYN flag. */
                SAL_SKB_CB(skb)->flags |= SVH_RSYN;
        } else if (sk_ssk(sk)->sal_state == SAL_RSYN_RECV) {
                SAL_SKB_CB(skb)->flags |= SVH_RSYN | SVH_ACK;
        }

        return serval_sal_queue_and_push(sk, skb);
}

/* XXX Verify that this function handles all possible cases.
 * See net/ipv4/tcp.c:tcp_close() for a reference.
 */
/* Called when application calls close(), or terminates. */
void serval_sal_close(struct sock *sk, long timeout)
{
        struct serval_sock *ssk = sk_ssk(sk);
        int state;

	if ((1 << sk->sk_state) & (SALF_FINWAIT1 | SALF_FINWAIT2 |
		SALF_TIMEWAIT | SALF_CLOSING)) {
		LIMIT_NETDEBUG(KERN_ERR pr_fmt("XIP/Serval: close() called in post close state (= %i)\n"),
			sk->sk_state);
		return;
	}

	lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

        switch (sk->sk_state) {
        case SAL_CLOSEWAIT:
                serval_sock_set_state(sk, SAL_LASTACK);
                break;

        case SAL_CONNECTED:
        case SAL_RESPOND:
		serval_sock_set_state(sk, SAL_FINWAIT1);
		break;

	case SAL_LISTEN:
		serval_listen_stop(sk);
		sk->sk_prot->unhash(sk);
		serval_sock_set_state(sk, SAL_CLOSED);
		/* Fall through. */

	case SAL_CLOSED:
		goto adjudge_to_death;

	case SAL_REQUEST:
	case SAL_LASTACK:
		serval_sal_done(sk);
        	release_sock(sk);
		return;

	case SAL_FINWAIT1:
	case SAL_FINWAIT2:
	case SAL_TIMEWAIT:
	case SAL_CLOSING:
		/* Unexpected state. */
		BUG();

	default:
		/* Either someone forgot to deal with a state,
		 * @sk is not valid at all, or the memory is corrupted.
		 */
		BUG();
	}

        if (ssk->af_ops->conn_close) {
		ssk->af_ops->conn_close(sk);
        } else {
		serval_sal_send_fin(sk);
        }
	sk_mem_reclaim(sk);

        sk_stream_wait_close(sk, timeout);

adjudge_to_death:
        state = sk->sk_state;

        /* Hold reference so that the sock is not destroyed by a bh
	 * when we release lock.
	 */
        sock_hold(sk);

        /* Orphaning will mark the sock with flag DEAD,
	 * what allows it to be destroyed.
	 */
        sock_orphan(sk);

        release_sock(sk);

        /* Now socket is owned by kernel and we acquire BH lock to finish
	 * the close. No need to check for user refs.
         */
        local_bh_disable();
        bh_lock_sock(sk);

        /* Have we already been destroyed by a softirq or backlog? */
        if (state != SAL_CLOSED && sk->sk_state == SAL_CLOSED)
                goto out;

        /* Other cleanup stuff goes here */
        if (sk->sk_state == SAL_CLOSED)
                serval_sock_destroy(sk);

	/* XXX What if @sk->sk_state isn't SAL_CLOSED?
	 * tcp_close() deals with it for the sake of avoiding a resource leak.
	 */

out:
        bh_unlock_sock(sk);
        local_bh_enable();
        sock_put(sk);
}

static int serval_sal_send_ack(struct sock *sk)
{
        struct serval_sock *ssk = sk_ssk(sk);
        struct sk_buff *skb;

        skb = sk_sal_alloc_skb(sk, GFP_ATOMIC);
        if (!skb)
                return -ENOMEM;

        SAL_SKB_CB(skb)->flags = SVH_ACK;
        /* Do not increment sequence numbers for pure ACKs */
        SAL_SKB_CB(skb)->verno = ssk->snd_seq.nxt;
        /* Do not queue pure ACKs */
        return serval_sal_transmit_skb(sk, skb, 0, GFP_ATOMIC);
}

/* Kill this socket if we receive a reset. */
void serval_sal_rcv_reset(struct sock *sk)
{
	/* We want the right error as BSD sees it (and indeed as we do). */
	switch (sk->sk_state) {
	case SAL_REQUEST:
		sk->sk_err = ECONNREFUSED;
		break;
	case SAL_CLOSEWAIT:
		sk->sk_err = EPIPE;
		break;
	case SAL_CLOSED:
		return;
	default:
		sk->sk_err = ECONNRESET;
	}

	/* This barrier is coupled with smp_rmb() in serval_tcp_poll() */
	smp_wmb();

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_error_report(sk);

	serval_sal_done(sk);
}

static void push_sal_hdr(struct sk_buff *skb, u8 protocol, int ext_len)
{
	struct sal_hdr *sh = (struct sal_hdr *)skb_push(skb, sizeof(*sh));
	skb_reset_transport_header(skb);
	BUILD_BUG_ON(sizeof(*sh) % 4);
	BUG_ON(ext_len % 4);
	sh->shl = (sizeof(*sh) + ext_len) >> 2;
	sh->protocol = protocol;
	serval_sal_send_check(sh); /* Calculate SAL header checksum. */
}

static struct sal_control_ext *push_ctrl_ext_hdr(struct sk_buff *skb)
{
	struct sal_control_ext *ctrl_ext =
		(struct sal_control_ext *)skb_push(skb, sizeof(*ctrl_ext));
	memset(ctrl_ext, 0, sizeof(*ctrl_ext));
	ctrl_ext->ext_type = SAL_CONTROL_EXT;
	ctrl_ext->ext_length = sizeof(*ctrl_ext);
	return ctrl_ext;
}

/* If there is a source address in @skb, mark and route it if possible.
 * If routable, return @xdst for it, otherwise return NULL.
 *
 * NOTE
 *	Caller must have write access to the data pointed by @skb.
 *
 *	Caller must xdst_put().
 */
static struct xip_dst *route_src_addr(struct net *net, struct sk_buff *skb,
	struct xia_row **psrc, u8 *pnum_src, u8 *psrc_last_node)
{
	struct xiphdr *xiph = xip_hdr(skb);
	struct xip_dst *xdst;

	if (xiph->num_src < 1)
		return NULL;

	*psrc = &xiph->dst_addr[xiph->num_dst]; 
	*pnum_src = xiph->num_src;
	*psrc_last_node = XIA_ENTRY_NODE_INDEX;
	xdst = xip_mark_addr_and_get_dst(net, *psrc, *pnum_src,
		psrc_last_node, 0);
	return !IS_ERR(xdst) ? xdst : NULL;
}

static inline void push_xip_hdr(struct sk_buff *skb, struct xip_dst *xdst,
	const struct xia_row *src, int src_n,
	const struct xia_row *dest, int dest_n, int dest_last_node)
{
	skb_push(skb, xip_hdr_size(dest_n, src_n));
	skb_reset_network_header(skb);
	xip_fill_in_hdr(skb, xdst, src, src_n, dest, dest_n, dest_last_node);
}

static inline void push_xip_hdr_bsrc(struct sk_buff *skb, struct xip_dst *xdst,
	const struct xia_row *src, xid_type_t sink_type, const __u8 *sink_id,
	int src_n, const struct xia_row *dest, int dest_n, int dest_last_node)
{
	skb_push(skb, xip_hdr_size(dest_n, src_n));
	skb_reset_network_header(skb);
	xip_fill_in_hdr_bsrc(skb, xdst, src, sink_type, sink_id, src_n,
		dest, dest_n, dest_last_node);
}

/* Ir an error is found, this function will ignore it, and not send
 * a reset packet.
 */
static void serval_sal_send_reset(struct sock *sk, struct sk_buff *skb,
	const struct sal_context *ctx)
{
	struct xip_dst *xdst;
	struct xia_row *dest;
	struct sk_buff *rskb;
	struct sal_control_ext *ctrl_ext;
	struct serval_sock *ssk;
	u8 num_dest, dest_last_node;

	/* We don't reply reset packets. */
	if (ctx->ctrl_ext && ctx->ctrl_ext->rst)
		return;

	if (skb_cow(skb, 0))
		return; /* We cannot mark the source address. */
	xdst = route_src_addr(sock_net(sk), skb, &dest, &num_dest,
		&dest_last_node);
	if (!xdst)
		return; /* Packet @skb is not routable back. */

	/* Allocate RESPONSE reply. */
	rskb = alloc_skb(MAX_SAL_HDR, GFP_ATOMIC);
	if (!rskb) {
		xdst_put(xdst);
		return;
	}

	prepare_skb_to_send(rskb, sk);
	skb_dst_set(rskb, &xdst->dst);
	skb_reserve(rskb, MAX_SAL_HDR);

	/* Add control extension */
	ctrl_ext = push_ctrl_ext_hdr(rskb);
	ctrl_ext->rst = 1;
	if (ctx->flags & SVH_ACK) {
		ctrl_ext->verno = htonl(ctx->ackno);
	} else {
		ctrl_ext->ack = 1;
		ctrl_ext->ackno = htonl(ctx->verno + (ctx->flags & SVH_SYN) +
			(ctx->flags & SVH_FIN));
	}
	if (ctx->ctrl_ext) {
		/* Copy our nonce to control extension. */
		memcpy(ctrl_ext->nonce, ctx->ctrl_ext->nonce, SAL_NONCE_SIZE);
	}

	/* Add Serval header */
	push_sal_hdr(rskb, ctx->hdr->protocol, sizeof(*ctrl_ext));

	/* We cannot use serval_sal_transmit_skb() here since we do not yet
	 * have a full accepted socket (@sk is the listening sock).
	 */

	/* Push the XIP header with the source using the ServiceID of
	 * the listening socket @sk, and the destination the source
	 * address in @skb, which should have a FlowID.
	 */
	ssk = sk_ssk(sk);
	push_xip_hdr(rskb, xdst, ssk->xia_sk.xia_saddr.s_row,
		ssk->xia_sk.xia_snum, dest, num_dest, dest_last_node);

	xip_local_out(rskb);
}

void serval_sal_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;
        struct serval_sock *ssk = sk_ssk(sk);

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_SAL_HDR, priority);
	if (!skb)
		return;

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_SAL_HDR);
        prepare_skb_to_send(skb, sk);
        SAL_SKB_CB(skb)->flags = SVH_RST | SVH_ACK;
	SAL_SKB_CB(skb)->when = sal_time_stamp;
        SAL_SKB_CB(skb)->verno = ssk->snd_seq.nxt;

	serval_sal_transmit_skb(sk, skb, 0, priority);
}

static int serval_sal_send_synack(struct sock *sk,
	struct serval_request_sock *srsk, struct sk_buff *skb,
	const struct sal_context *ctx)
{
	struct xip_dst *xdst;
	struct xia_row *dest, *dest_sink;
	struct sk_buff *rskb;
	struct serval_sock *ssk;
	struct sal_control_ext *ctrl_ext;
	u8 num_dest, dest_last_node;

	if (skb_cow(skb, 0))
		return -ENOMEM; /* We cannot mark the source address. */
	xdst = route_src_addr(sock_net(sk), skb, &dest, &num_dest,
		&dest_last_node);
	if (!xdst)
		return -ENETUNREACH; /* Packet @skb is not routable back. */

	/* Check that source address matches @srsk. */
	dest_sink = &dest[num_dest - 1];
	BUILD_BUG_ON(sizeof(dest_sink->s_xid.xid_id) != XIA_XID_MAX);
	BUILD_BUG_ON(sizeof(srsk->peer_srvcid) != XIA_XID_MAX);
	if (dest_sink->s_xid.xid_type != XIDTYPE_SRVCID ||
		memcmp(dest_sink->s_xid.xid_id, &srsk->peer_srvcid,
			XIA_XID_MAX)) {
		xdst_put(xdst);
		return -EINVAL;
	}

	/* Allocate RESPONSE reply. */
	rskb = alloc_skb(sk->sk_prot->max_header, GFP_ATOMIC);
	if (!rskb) {
		xdst_put(xdst);
		return -ENOMEM;
	}

	prepare_skb_to_send(rskb, sk);
	skb_dst_set(rskb, &xdst->dst);
	skb_reserve(rskb, sk->sk_prot->max_header);

	/* Let transport chip in. */
	ssk = sk_ssk(sk);
	if (ssk->af_ops->conn_build_synack) {
		/* XXX Pass @srsk directly. */
		BUG_ON(ssk->af_ops->conn_build_synack(sk, &xdst->dst,
			&srsk->req, rskb));
	}

        /* Add control extensions */
	ctrl_ext = push_ctrl_ext_hdr(rskb);
        ctrl_ext->verno = htonl(srsk->iss_seq);
        ctrl_ext->ackno = htonl(srsk->rcv_seq + 1);
        ctrl_ext->syn = 1;
        ctrl_ext->ack = 1;
        memcpy(ctrl_ext->nonce, srsk->local_nonce, SAL_NONCE_SIZE);
        
        /* Add Serval header */
	push_sal_hdr(rskb, ctx->hdr->protocol, sizeof(*ctrl_ext));

	/* We cannot use serval_sal_transmit_skb() here since we do not yet
	 * have a full accepted socket (@sk is the listening sock).
	 */

	/* Push the XIP header with the source using the FlowID of @srsk,
	 * and the destination the source address in @skb, which has a FlowID.
	 */
	push_xip_hdr_bsrc(rskb, xdst, ssk->xia_sk.xia_saddr.s_row,
		XIDTYPE_FLOWID, srsk->flow_fxid.fx_xid, ssk->xia_sk.xia_snum,
		dest, num_dest, dest_last_node);

	return xip_local_out(rskb);
}

static struct xia_row *xip_dst_sink(struct sk_buff *skb)
{
	struct xiphdr *xiph = xip_hdr(skb);
	if (xiph->num_dst < 1)
		return NULL;
	return &xiph->dst_addr[xiph->last_node];
}

static struct xia_row *xip_src_sink(struct sk_buff *skb)
{
	struct xiphdr *xiph = xip_hdr(skb);
	if (xiph->num_src < 1)
		return NULL;
	return &xiph->dst_addr[xiph->num_dst + xiph->num_src - 1];
}

static struct serval_request_sock *serval_reqsk_alloc(
	const struct request_sock_ops *ops)
{
	struct serval_request_sock *srsk = serval_rsk(reqsk_alloc(ops));
	if (unlikely(!srsk))
		return NULL;

	atomic_set(&srsk->refcnt, 1);
	serval_sock_get_flowid(srsk->flow_fxid.fx_xid);
	xdst_init_anchor(&srsk->flow_anchor);
	get_random_bytes(srsk->local_nonce, sizeof(srsk->local_nonce));
	get_random_bytes(&srsk->iss_seq, sizeof(srsk->iss_seq));
	srsk->parent_ssk = NULL;
	INIT_LIST_HEAD(&srsk->lh);
	return srsk;
}

void srsk_put(struct serval_request_sock *srsk)
{
	int newrefcnt = atomic_dec_return(&srsk->refcnt);
	BUG_ON(newrefcnt < 0);
	if (!newrefcnt)
		reqsk_free(&srsk->req);
}

static int serval_sal_rcv_syn(struct sock *sk, struct sk_buff *skb,
	const struct sal_context *sal_ctx)
{
        struct serval_request_sock *srsk;
	static struct xia_row *src_sink;
        struct serval_sock *ssk;
        int rc = 0;

        if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) {
		rc = -EINVAL; /* XXX Isn't there a better error? */
                goto drop;
	}

        srsk = serval_reqsk_alloc(sk->sk_prot->rsk_prot);
        if (!srsk) {
		rc = -ENOMEM;
		goto drop;
	}
        /* Copy fields in request packet into request sock. */
	src_sink = xip_src_sink(skb);
	memcpy(&srsk->peer_srvcid, src_sink->s_xid.xid_id,
		sizeof(srsk->peer_srvcid));
        memcpy(srsk->peer_nonce, sal_ctx->ctrl_ext->nonce, SAL_NONCE_SIZE);
        srsk->rcv_seq = sal_ctx->verno;

        /* Call upper transport protocol handler */
        ssk = sk_ssk(sk);
        if (ssk->af_ops->conn_request) {
		/* XXX Pass @srsk directly. */
                rc = ssk->af_ops->conn_request(sk, &srsk->req, skb);
                if (rc) {
                        /* Transport will free the skb on error. */
			srsk_put(srsk);
                        return rc;
                }
        }

	/* Hash @srsk. */
	__init_fxid(&srsk->flow_fxid, XRTABLE_LOCAL_INDEX, REQUEST_SOCK_TYPE);
	srsk_hold(srsk);
	/* No error should be possible because FlowIDs should be kernel-wide
	 * unique.
	 */
	BUG_ON(__serval_sock_hash_flowid(sock_net(sk), &srsk->flow_fxid));
	
	/* Add the new request socket to the SYN queue.
	 *
	 * We only add @srsk to @ssk->syn_queue when it's fully set, so
	 * any piece of code that finds @srsk while browsing @ssk->syn_queue
	 * can assume that it's ready to use.
	 */
	srsk->parent_ssk = ssk;
	list_add(&srsk->lh, &ssk->syn_queue);
	sk->sk_ack_backlog++;

        rc = serval_sal_send_synack(sk, srsk, skb, sal_ctx);

drop:
        kfree_skb(skb); /* Free the SYN request. */
        return rc;
}

/* Find a request sock that has previously been created by a SYN. */
static struct serval_request_sock *find_srsk_for_syn(struct serval_sock *ssk,
	const u8 *peer_srvcid, const u8 *peer_nonce)
{
        struct serval_request_sock *srsk;
        list_for_each_entry(srsk, &ssk->syn_queue, lh) {
                if (!memcmp(&srsk->peer_srvcid, peer_srvcid,
				sizeof(srsk->peer_srvcid)) &&
			/* Also compare nonce because ServiceID may open
			 * multiple connections at once, or be replicated
			 * in the network.
			 */
			!memcmp(srsk->peer_nonce, peer_nonce, SAL_NONCE_SIZE))
                        return srsk;
        }
        return NULL;
}

/* Find a request sock that has previously been created by a SYN using
 * the local FlowID.
 */
static struct serval_request_sock *find_srsk_for_ack(struct serval_sock *ssk,
	const u8 *local_flowid)
{
        struct serval_request_sock *srsk;
        list_for_each_entry(srsk, &ssk->syn_queue, lh) {
                if (!memcmp(srsk->flow_fxid.fx_xid, local_flowid, XIA_XID_MAX))
                        return srsk;
        }
        return NULL;
}

static struct xip_dst *update_xdst(struct net *net, struct xia_row *addr,
	int n, u8 *plast_node, xid_type_t new_sink_type, const u8 *new_sink_id)
{
	struct xia_row *last_row;
	struct xip_dst *xdst;

	/* Update sink. */
	last_row = &addr[n - 1];
	last_row->s_xid.xid_type = new_sink_type;
	memmove(last_row->s_xid.xid_id, new_sink_id, XIA_XID_MAX);

	*plast_node = XIA_ENTRY_NODE_INDEX;
	unmark_xia_rows(addr, n);
	xdst = xip_mark_addr_and_get_dst(net, addr, n, plast_node, 0);
	return !IS_ERR(xdst) ? xdst : NULL;
}

/* This function is called as a result of receiving an ACK in response
 * to a SYNACK that was sent by a "parent" sock in LISTEN state (the sk
 * argument).
 *
 * The objective is to initiate processing on the serval_request_sock sock that
 * corresponds to the ACK just received.
 * Such processing includes transforming the request sock into a
 * regular sock and putting it on the parent sock's accept queue.
 */
static struct serval_sock *serval_sal_request_sock_handle(
	struct serval_sock *ssk, struct serval_request_sock *srsk,
	struct sk_buff *skb, const struct sal_context *ctx)
{
	struct xiphdr *xiph = xip_hdr(skb);
	struct xia_addr addr;
	struct net *net;
	struct xia_row *dest;
	struct xip_dst *xdst;
	struct sock *nsk;
	struct serval_sock *nssk;
	u8 num_dest, dest_last_node;

	if (	/* There's no return address. */
		xiph->num_src < 1 ||
		/* Bad nonce. */
		memcmp(srsk->peer_nonce, ctx->ctrl_ext->nonce,
			SAL_NONCE_SIZE) ||
		/* Bad verno. */
		(ctx->verno != srsk->rcv_seq + 1) ||
		/* Bad ackno. */
		(ctx->ackno != srsk->iss_seq + 1)) {
		return NULL;
	}

	/* Obtain @xdst for source address of packet. */
	num_dest = xiph->num_src;
	copy_n_and_shade_xia_addr(&addr, &xiph->dst_addr[xiph->num_dst],
		num_dest);
	net = sock_net(&ssk->xia_sk.sk);
	dest = addr.s_row;
	dest_last_node = XIA_ENTRY_NODE_INDEX;
	xdst = xip_mark_addr_and_get_dst(net, dest, num_dest,
		&dest_last_node, 0);
	if (IS_ERR(xdst))
		return NULL; /* Packet @skb is not routable back. */

	/* Create new serval socket from @ssk. */
	nsk = sk_clone_lock(&ssk->xia_sk.sk, GFP_ATOMIC);
	if (!nsk) {
		xdst_put(xdst);
		return NULL;
	}
	nssk = sk_ssk(nsk);
	serval_sock_init(nssk);
	__xia_set_dest(&nssk->xia_sk, dest, num_dest, dest_last_node, xdst);

	/* Transport protocol specific init. */
	if (ssk->af_ops->conn_child_sock(&ssk->xia_sk.sk, skb, &srsk->req, nsk,
		&xdst->dst) < 0) {
		/* Transport child sock init failed. */
		goto nssk;
	}

	/* Emulate connect() from @nssk to the peer.
	 * Build peer's full ServiceID address from full FlowID address.
	 */
	/* XXX Make the typecast unnecessary. */
	xdst = update_xdst(net, dest, num_dest, &dest_last_node, XIDTYPE_SRVCID,
		(u8 *)&srsk->peer_srvcid);
	if (!xdst)
		goto nssk;
	__set_peer_srvc(nssk, dest, num_dest, dest_last_node, xdst);

	/* Emulate bind() on @nssk, but don't hash the ServiceID. */
	BUG_ON(!xia_sk_bound(&ssk->xia_sk));
	xia_set_src(&nssk->xia_sk, &ssk->xia_sk.xia_saddr,
		ssk->xia_sk.xia_snum);
	nssk->local_srvcid_hashed = false;

	/* Set up control fields. */
	memcpy(nssk->local_nonce, srsk->local_nonce, SAL_NONCE_SIZE);
	memcpy(nssk->peer_nonce, srsk->peer_nonce, SAL_NONCE_SIZE);
	nssk->snd_seq.iss = srsk->iss_seq;
	nssk->snd_seq.una = srsk->iss_seq;
	nssk->snd_seq.nxt = srsk->iss_seq + 1;
	nssk->rcv_seq.iss = srsk->rcv_seq;
	nssk->rcv_seq.nxt = srsk->rcv_seq + 1;
	nssk->xia_sk.sk.sk_ack_backlog = 0;
	serval_sock_set_state(&nssk->xia_sk.sk, SAL_RESPOND);

	/* Hash the sock to make it demuxable */
	init_fxid(&nssk->flow_fxid, srsk->flow_fxid.fx_xid,
		XRTABLE_LOCAL_INDEX, SOCK_TYPE);
	if (serval_swap_srsk_ssk_flowid(&srsk->flow_fxid, nssk))
		goto nssk;

	/* This is the only reference to @nssk that will be kept. */
	srsk->req.sk = &nssk->xia_sk.sk;
	/* Move request sock to accept queue. */
	list_move_tail(&srsk->lh, &ssk->accept_queue);
	return nssk;

nssk:
	BUG_ON(atomic_read(&nssk->xia_sk.sk.sk_refcnt) != 2);
	sock_set_flag(nsk, SOCK_DEAD);
	bh_unlock_sock(&nssk->xia_sk.sk);
	sock_put(&nssk->xia_sk.sk);
	sock_put(&nssk->xia_sk.sk);
	return NULL;
}

/* This function works as the initial receive function for a child
 * socket that has just been created by a parent (as a result of
 * successful connection handshake).
 *
 * The processing resembles what happened for the parent socket
 * when this packet was first received by the parent.
 */
static int serval_sal_child_process(struct sock *parent,
	struct serval_sock *child, struct sk_buff *skb,
	const struct sal_context *ctx)
{
        int state = child->xia_sk.sk.sk_state;
        int rc;

        /* @child sock is already locked here */

        /* Check lock on @child socket, similarly to how we handled the
         * @parent sock for the incoming @skb.
	 */
        if (!sock_owned_by_user(&child->xia_sk.sk)) {
                rc = serval_sal_state_process(&child->xia_sk.sk, skb, ctx);
                if (rc == 0 && state == SAL_RESPOND &&
			child->xia_sk.sk.sk_state != state) {
                        /* Waking up parent (listening) sock. */
                        parent->sk_data_ready(parent, 0);
                }
        } else {
                /* User got lock, add skb to backlog so that it will
		 * be processed in user context when the lock is released.
		 */
                __sk_add_backlog(&child->xia_sk.sk, skb);
		rc = 0;
        }

        bh_unlock_sock(&child->xia_sk.sk);
        sock_put(&child->xia_sk.sk);
        return rc;
}

/* Deal with the last step of a three-way handshake, that it, the ACK packet
 * that arrives at the server coming from the cliente.
 */
static int do_rcv_for_srsk(struct sock *sk, struct sk_buff *skb,
	const struct sal_context *ctx)
{
	const struct xia_row *dst_sink = xip_dst_sink(skb);
	const struct xia_row *src_sink = xip_src_sink(skb);
	struct serval_sock *ssk;
	struct serval_request_sock *srsk;
        struct serval_sock *nssk;

	/* If there is no sink in the destination address,
	 * @skb shouldn't ever reach this execution point because would've
	 * been dropped.
	 */
	BUG_ON(!dst_sink);
	/* If the destination sink isn't a FlowID, this function shouldn't
	 * be called because it only handles FlowIDs.
	 */
	BUG_ON(dst_sink->s_xid.xid_type != XIDTYPE_FLOWID);

	ssk = sk_ssk(sk);
	if (!src_sink || src_sink->s_xid.xid_type != XIDTYPE_FLOWID ||
		!ctx->ctrl_ext || ctx->flags & SVH_SYN ||
		!(ctx->flags & SVH_ACK) ||
		!(srsk = find_srsk_for_ack(ssk, dst_sink->s_xid.xid_id)) ||
        	!(nssk = serval_sal_request_sock_handle(ssk, srsk, skb, ctx))) {
		/* We don't send a reset packet here because we don't want to
		 * help an adversary scanning for peding connections.
		 */
        	kfree_skb(skb);
	        return -EINVAL;
	}

        /* The new sock is already locked here */
	return serval_sal_child_process(sk, nssk, skb, ctx);
}

static int serval_sal_ack_process(struct sock *sk, struct sk_buff *skb,
	const struct sal_context *ctx)
{
        struct serval_sock *ssk = sk_ssk(sk);
        
        if (!(ctx->flags & SVH_ACK) ||
		/* If the ack is older than previous acks, ignore it. */
		before(ctx->ackno, ssk->snd_seq.una) ||
		/* If the ack corresponds to something we haven't sent yet,
		 * ignore it.
		 */
		after(ctx->ackno, ssk->snd_seq.nxt))
                return -EINVAL;

        serval_sal_clean_rtx_queue(sk, ctx->ackno, 0, NULL);
        ssk->snd_seq.una = ctx->ackno;

/* XXX Implement socket migration. */
#if 0
        /* Check for migration handshake ACK. */
        switch (ssk->sal_state) {
        case SAL_RSYN_RECV:
                if (!(ctx->flags & SVH_RSYN))
                        serval_sock_set_sal_state(sk, SAL_RSYN_INITIAL);
                break;
        case SAL_RSYN_SENT_RECV:
                if (!(ctx->flags & SVH_RSYN))
                        serval_sock_set_sal_state(sk, SAL_RSYN_SENT);
                break;
        default:
                return 0;
        }
        
        if (!(ctx->flags & SVH_RSYN)) {
                /* Migration complete for @ssk's flow. */
		/* XXX Replace IP code. */
                memcpy(&inet_sk(sk)->inet_daddr, &ssk->mig_daddr, 4);
                memset(&ssk->mig_daddr, 0, 4);
		/* XXX Route again, don't wait. Shouldn't peer's address
		 * be redone?
		 */
                sk_dst_reset(sk);

                if (ssk->af_ops->migration_completed)
			ssk->af_ops->migration_completed(sk);
        }
#endif

	return 0;
}

/* XXX This function is kept here just for reference. Once socket migration
 * is implemented, please drop it.
 */
#if 0
static int dev_get_ipv4_addr(struct net_device *dev, void *addr)
{
        struct in_device *in_dev;
        int ret = 0;
        
	rcu_read_lock();

	in_dev = __in_dev_get_rcu(dev);

        if (in_dev) {
                for_primary_ifa(in_dev) {
			memcpy(addr, &ifa->ifa_local, 4);
                        ret = 1;
                        break;
                }
                endfor_ifa(indev);
        }
	rcu_read_unlock();

        return ret;
}
#endif

static int serval_sal_rcv_rsynack(struct sock *sk,
                                  struct sk_buff *skb,
                                  const struct sal_context *ctx)
{
	return -1;

/* XXX Implement socket migration. */
#if 0
        struct serval_sock *ssk = sk_ssk(sk);
        struct net_device *mig_dev = dev_get_by_index(sock_net(sk), 
                                                      ssk->mig_dev_if);
        int rc = 0;

        if (!mig_dev) {
		/* No migration device set. */
                return -1;
        }

        switch (ssk->sal_state) {
        case SAL_RSYN_SENT:
                /* Migration complete for FlowID. */
                serval_sock_set_sal_state(sk, SAL_RSYN_INITIAL);
                
                dev_get_ipv4_addr(mig_dev, &inet_sk(sk)->inet_saddr);
                serval_sock_set_mig_dev(sk, 0);
                sk_dst_reset(sk);

                if (ssk->af_ops->migration_completed)
                        ssk->af_ops->migration_completed(sk);
                break;

        case SAL_RSYN_SENT_RECV:
                serval_sock_set_sal_state(sk, SAL_RSYN_RECV);
                memcpy(&ssk->mig_daddr, &ip_hdr(skb)->saddr, 4);
                sk_dst_reset(sk);
                break;

        default:
                goto out;
        }
        
        ssk->rcv_seq.nxt = ctx->verno + 1;

        rc = serval_sal_send_ack(sk);

out:        
        dev_put(mig_dev);
        return rc;
#endif
}

/* This function handles the case when we received an RSYN (without ACK). */
static int serval_sal_rcv_rsyn(struct sock *sk, struct sk_buff *skb,
	const struct sal_context *ctx)
{
	return -1;
/* XXX Implement socket migration. */
#if 0
        struct serval_sock *ssk = sk_ssk(sk);
        struct sk_buff *rskb = NULL;
        
        if (!has_valid_control_extension(sk, ctx)) {
                /* Bad migration control packet. */
                return -1;
        }
       
        /* We ignore migrations in these states */
	if ((1 << sk->sk_state) & (SALF_CLOSED | SALF_LISTEN | SALF_REQUEST))
		return -1;
                
        switch(ssk->sal_state) {
        case SAL_RSYN_INITIAL:
                serval_sock_set_sal_state(sk, SAL_RSYN_RECV);
                break;
        case SAL_RSYN_SENT:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT_RECV);
                break;
        case SAL_RSYN_RECV:
        case SAL_RSYN_SENT_RECV:
		/* Just send another RSYN+ACK to acknowledge the new
		 * address change.
		 */
                break;
        default:
                return 0;
        }
        
        if (ssk->af_ops->freeze_flow)
                ssk->af_ops->freeze_flow(sk);
        
        ssk->rcv_seq.nxt = ctx->verno + 1;        
        memcpy(&ssk->mig_daddr, &ip_hdr(skb)->saddr, 4);
        rskb = sk_sal_alloc_skb(sk, GFP_ATOMIC);
        if (!rskb)
                return -ENOMEM;
        
        SAL_SKB_CB(rskb)->flags = SVH_RSYN | SVH_ACK;
        SAL_SKB_CB(rskb)->verno = ssk->snd_seq.nxt++;
        SAL_SKB_CB(rskb)->when = sal_time_stamp;

        return serval_sal_queue_and_push(sk, rskb);
#endif
}

static int serval_sal_rcv_fin(struct sock *sk, 
                              struct sk_buff *skb,
                              const struct sal_context *ctx)
{
        struct serval_sock *ssk = sk_ssk(sk);
        int err = 0;

        if (!has_valid_control_extension(sk, ctx)) {
                /* Bad control extension. */
                return -1;
        }
        
        sk->sk_shutdown |= RCV_SHUTDOWN;
        sock_set_flag(sk, SOCK_DONE);

        ssk->rcv_seq.nxt = ctx->verno + 1;
        
        /* If there is still an application attached to the
           sock, then wake it up. */
        if (!sock_flag(sk, SOCK_DEAD)) {
		/* Wake user up. */
                sk->sk_state_change(sk);
                
                /* Do not send POLL_HUP for half
                   duplex close. */
                if (sk->sk_shutdown == SHUTDOWN_MASK ||
                    sk->sk_state == SAL_CLOSED)
                        sk_wake_async(sk, SOCK_WAKE_WAITD, 
                                      POLL_HUP);
                else
                        sk_wake_async(sk, SOCK_WAKE_WAITD, 
                                      POLL_IN);
        }

        err = serval_sal_send_ack(sk);
        
        return err;
}

static int serval_sal_connected_state_process(struct sock *sk,
                                              struct sk_buff *skb,
                                              const struct sal_context *ctx)
{
        struct serval_sock *ssk = sk_ssk(sk);
        int err = 0;
        char should_drop = 0, should_close = 0;

        err = serval_sal_ack_process(sk, skb, ctx);

        if (ctx->flags & SVH_FIN) {
                err = serval_sal_rcv_fin(sk, skb, ctx);
                
                if (err == 0)
                        should_close = 1;
        }

        /* Should pass FINs to transport and ultimately the user, as
         * it needs to pick it off its receive queue to notice EOF. */
        if (packet_has_transport_hdr(skb, ctx->hdr) || (ctx->flags & SVH_FIN)) {
                ssk->last_rcv_tstamp = sal_time_stamp;
                err = ssk->af_ops->receive(sk, skb);
        } else {
                /* No transport header, so we just drop the packet
                 * since there is nothing more to do with it. */
                err = 0;
                should_drop = 1;
        }

        if (should_close)
                serval_sock_set_state(sk, SAL_CLOSEWAIT);

        if (should_drop)
                kfree_skb(skb);

        return err;
}

static int serval_sal_closewait_state_process(struct sock *sk,
	struct sk_buff *skb, const struct sal_context *ctx)
{
        if (ctx->flags & SVH_FIN)
                serval_sal_send_ack(sk);

        serval_sal_ack_process(sk, skb, ctx);

	if (packet_has_transport_hdr(skb, ctx->hdr))
		return sk_ssk(sk)->af_ops->receive(sk, skb);

        kfree_skb(skb);
        return 0;
}

static int serval_sal_listen_state_process(struct sock *sk,
	struct sk_buff *skb, const struct sal_context *ctx)
{
	const struct xia_row *src_sink = xip_src_sink(skb);
	struct serval_request_sock *srsk;
	int rc;

	if (!src_sink || src_sink->s_xid.xid_type != XIDTYPE_SRVCID ||
		!ctx->ctrl_ext || !(ctx->flags & SVH_SYN) ||
		ctx->flags & SVH_ACK) {
		serval_sal_send_reset(sk, skb, ctx);
		rc = -EINVAL;
		goto drop;
	}

        srsk = find_srsk_for_syn(sk_ssk(sk), src_sink->s_xid.xid_id,
		ctx->ctrl_ext->nonce);
        if (srsk) {
		/* SYN already received, dropping @skb. */
                serval_sal_send_synack(sk, srsk, skb, ctx);
		rc = 0;
                goto drop;
        }
        return serval_sal_rcv_syn(sk, skb, ctx);

drop:
        kfree_skb(skb);
        return rc;
}

/* This function is called at the client side that is trying to connect to a
 * server when it receives a SYN+ACK packet from the server.
 * A SYN+ACK packet is a reply for a SYN packet.
 * The client will send an ACK packet to establish the connection.
 */
static int serval_sal_request_state_process(struct sock *sk,
	struct sk_buff *skb, const struct sal_context *ctx)
{
        struct serval_sock *ssk = sk_ssk(sk);
	struct xiphdr *xiph;
        struct sk_buff *rskb;
        int rc;

        if (!has_valid_control_extension(sk, ctx) ||
		!(ctx->flags & SVH_SYN) || !(ctx->flags & SVH_ACK) ||
		serval_sal_ack_process(sk, skb, ctx)) {
		/* Packet @skb is not a SYN-ACK response and/or
		 * the ACK is invalid.
		*/
		rc = -EINVAL;
                goto drop;
	}

	/* Save peer's FlowID at @ssk->peer_flowid if the source address of
	 * @skb is routable.
	 */
	xiph = xip_hdr(skb);
	if (xia_set_dest(&ssk->xia_sk, &xiph->dst_addr[xiph->num_dst],
		xiph->num_src)) {
		rc = -EINVAL;
		goto drop;
	}

        /* Save nonce. */
        memcpy(ssk->peer_nonce, ctx->ctrl_ext->nonce, SAL_NONCE_SIZE);

        /* Update expected rcv sequence number. */
        ssk->rcv_seq.nxt = ctx->verno + 1;
        
        /* Let transport know about the response. */
        if (ssk->af_ops->request_state_process) {
                rc = ssk->af_ops->request_state_process(sk, skb);
                if (rc) {
                        /* Transport drops the packet. */
                        return rc;
                }
        }

        /* Move to connected state. */
        serval_sock_set_state(sk, SAL_CONNECTED);
        
        /* Let application know we are connected. */
	if (!sock_flag(sk, SOCK_DEAD)) {
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        }

        /* Allocate ACK. */
        rskb = sk_sal_alloc_skb(sk, GFP_ATOMIC);
        if (!rskb) {
		rc = -ENOMEM;
		goto drop;
	}

        /* Ask transport to fill in. */
        if (ssk->af_ops->conn_build_ack) {
                rc = ssk->af_ops->conn_build_ack(sk, rskb);
                if (rc) {
			kfree_skb(rskb);
			goto drop;
                }
        }

        /* Update control block. */
        SAL_SKB_CB(rskb)->flags = SVH_ACK;
        /* Do not increase sequence number for pure ACK. */
        SAL_SKB_CB(rskb)->verno = ssk->snd_seq.nxt;

        /* Transmit, do not queue a pure ACK. */
        rc = serval_sal_transmit_skb(sk, rskb, 0, GFP_ATOMIC);

drop: 
        kfree_skb(skb);
        return rc;
}

static int serval_sal_respond_state_process(struct sock *sk,
	struct sk_buff *skb, const struct sal_context *ctx)
{
        struct serval_sock *ssk = sk_ssk(sk);

        if (!has_valid_control_extension(sk, ctx))
                goto drop;

        /* Process ACK */
        if (serval_sal_ack_process(sk, skb, ctx) == 0) {
                if (ssk->af_ops->respond_state_process &&
			ssk->af_ops->respond_state_process(sk, skb)) {
			/* Transport drops ACK. */
			return 0;
                }

                /* Valid ACK */
                serval_sock_set_state(sk, SAL_CONNECTED);

                /* Let user know */
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        }

drop:
        kfree_skb(skb);
        return 0;
}

static int serval_sal_finwait1_state_process(struct sock *sk, 
                                             struct sk_buff *skb,
                                             const struct sal_context *ctx)
{
        int ack_ok = (ctx->flags & SVH_ACK) &&
		!serval_sal_ack_process(sk, skb, ctx);

        if (ctx->flags & SVH_FIN) {
                if (serval_sal_rcv_fin(sk, skb, ctx) == 0) {
                        if (ack_ok)
                                serval_sal_timewait(sk, SAL_TIMEWAIT, 
                                                    SAL_TIMEWAIT_LEN);
                        else
                                serval_sock_set_state(sk, SAL_CLOSING);
                }
        } else if (ack_ok) {
                serval_sal_timewait(sk, SAL_FINWAIT2, SAL_FIN_TIMEOUT);
        }

        if (packet_has_transport_hdr(skb, ctx->hdr) || ctx->flags & SVH_FIN)
		return sk_ssk(sk)->af_ops->receive(sk, skb);

	kfree_skb(skb);
	return 0;
}

static int serval_sal_finwait2_state_process(struct sock *sk, 
                                             struct sk_buff *skb,
                                             const struct sal_context *ctx)
{
        struct serval_sock *ssk = sk_ssk(sk);

        /* We've received our FIN-ACK already */
        if (ctx->flags & SVH_FIN) {
		int err = serval_sal_rcv_fin(sk, skb, ctx);
		if (!err)
			serval_sal_timewait(sk, SAL_TIMEWAIT, SAL_TIMEWAIT_LEN);
        }

	if (packet_has_transport_hdr(skb, ctx->hdr) || ctx->flags & SVH_FIN)
		return ssk->af_ops->receive(sk, skb);

	kfree_skb(skb);
	return 0;
}

static int serval_sal_closing_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            const struct sal_context *ctx)
{
        struct serval_sock *ssk = sk_ssk(sk);
                
        if ((ctx->flags & SVH_ACK) &&
		serval_sal_ack_process(sk, skb, ctx) == 0) {
                /* ACK was valid */
                serval_sal_timewait(sk, SAL_TIMEWAIT, SAL_TIMEWAIT_LEN);
        }

	if (ctx->flags & SVH_FIN)
                serval_sal_send_ack(sk);

	if (packet_has_transport_hdr(skb, ctx->hdr))
		return ssk->af_ops->receive(sk, skb);

        kfree_skb(skb);
        return 0;
}

static int serval_sal_lastack_state_process(struct sock *sk,
	struct sk_buff *skb, const struct sal_context *ctx)
{
        struct serval_sock *ssk = sk_ssk(sk);
        int err = 0, ack_ok;
        
        if (ctx->flags & SVH_FIN)
                serval_sal_send_ack(sk);

        ack_ok = serval_sal_ack_process(sk, skb, ctx) == 0;

        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                err = ssk->af_ops->receive(sk, skb);
        } else {
                err = 0;
                kfree_skb(skb);
        }

        if (ack_ok) {
                /* ACK was valid, close socket. */
                serval_sal_done(sk);
        }

        return err;
}

/* Receive for datagram sockets that are not connected. */
static int serval_sal_init_state_process(struct sock *sk, struct sk_buff *skb,
	const struct sal_context *ctx)
{
	struct xia_row *src_sink = xip_src_sink(skb);

	if (!src_sink || src_sink->s_xid.xid_type != XIDTYPE_SRVCID) {
		/* Cannot send a packet back. */
		return -EINVAL;
	}

	if (packet_has_transport_hdr(skb, ctx->hdr))
		return sk_ssk(sk)->af_ops->receive(sk, skb);

	kfree_skb(skb);
	return 0;
}

int serval_sal_state_process(struct sock *sk, struct sk_buff *skb,
	const struct sal_context *ctx)
{
        int err = 0;

        if (ctx->ctrl_ext) {                
                if (!has_valid_verno(ctx->verno, sk))
                        goto drop;

                /* Is this a reset packet */
                if (ctx->ctrl_ext->rst) {
                        serval_sal_rcv_reset(sk);
                        goto drop;
                }
                
                /* Check for migration */
                if (ctx->ctrl_ext->rsyn) {
                        if (ctx->ctrl_ext->ack)
                                err = serval_sal_rcv_rsynack(sk, skb, ctx);
                        else
                                err = serval_sal_rcv_rsyn(sk, skb, ctx);
                }
        }

        switch (sk->sk_state) {
        case SAL_INIT:
                if (sk->sk_type == SOCK_DGRAM) 
                        err = serval_sal_init_state_process(sk, skb, ctx);
                else
                        goto drop;
                break;
        case SAL_CONNECTED:
                err = serval_sal_connected_state_process(sk, skb, ctx);
                break;
        case SAL_REQUEST:
                err = serval_sal_request_state_process(sk, skb, ctx);
                break;
        case SAL_RESPOND:
                err = serval_sal_respond_state_process(sk, skb, ctx);
                break;
        case SAL_LISTEN:
                err = serval_sal_listen_state_process(sk, skb, ctx);
                break;
        case SAL_FINWAIT1:
                err = serval_sal_finwait1_state_process(sk, skb, ctx);
                break;
        case SAL_FINWAIT2:
                err = serval_sal_finwait2_state_process(sk, skb, ctx);
                break;
        case SAL_CLOSING:
                err = serval_sal_closing_state_process(sk, skb, ctx);
                break;
        case SAL_LASTACK:
                err = serval_sal_lastack_state_process(sk, skb, ctx);
                break;
        case SAL_TIMEWAIT:
                /* Resend ACK of FIN in case our previous one got lost */
                if (ctx->ctrl_ext && ctx->ctrl_ext->fin)
                        serval_sal_send_ack(sk);
                goto drop;
        case SAL_CLOSEWAIT:
                err = serval_sal_closewait_state_process(sk, skb, ctx);
                break;
        case SAL_CLOSED:
                serval_sal_send_reset(sk, skb, ctx);
                goto drop;
        default:
		BUG();
        }
                
	/* Ignoring @err. */
        return 0;

drop:
	kfree_skb(skb);
	return 0;
}

static int linearize_and_parse_sal_header(struct sk_buff *skb,
	struct sal_context *sal_ctx)
{
	struct sal_hdr *shdr;
	int sal_length;

	skb_pull_xiphdr(skb);

	/* First see if we can pull the base header, because we know
	 * the packet should have at least that size SAL header. Note,
	 * we cannot simply look into the packet and check the real
	 * SAL header length (including extensions), because the skb
	 * migth be paged. This function call will also linearize the
	 * requested length.
	 */
        if (!pskb_may_pull(skb, sizeof(*shdr)))
		return -ENOMEM;

	/* Now we can actually look into the base header. */
	shdr = sal_hdr(skb);
	sal_length = shdr->shl << 2;
	if (sal_length > sizeof(*shdr)) {
		/* There are extensions, so we need to check that we
		 * can pull more than the base header.
		 */
		if (!pskb_may_pull(skb, sal_length))
			return -ENOMEM;
	}

	if (unlikely(serval_sal_csum(shdr, sal_length))) {
		/* SAL checksum error. */
		return -EINVAL;
	}

	/* Ok, we are ready to parse the full header. */
	if (serval_sal_parse_hdr(sal_ctx, shdr)) {
		/* Bad Serval header. */
		return -EINVAL;
	}

	return 0;
}

static int __serval_sal_rcv(struct sk_buff *skb,
	int (*do_rcv)(struct sock *sk, struct sk_buff *skb,
		const struct sal_context *ctx))
{
	struct sal_context sal_ctx;
	struct xip_dst *xdst;
	struct serval_sock *ssk;
	int rc;

	if (linearize_and_parse_sal_header(skb, &sal_ctx)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	/* We can safely use __skb_pull() here, because we have already
	 * linearized the SAL header part of the skb.
	 */
	__skb_pull(skb, sal_ctx.length);

	/* Repoint to the transport header pointer to the actual
	 * transport layer header.
	 */
	skb_reset_transport_header(skb);

	SAL_SKB_CB(skb)->flags = sal_ctx.flags;

	xdst = skb_xdst(skb);
	ssk = xdst->info;
	/* XXX Need a refcnt on @sk here and in XDP's local_input_input(). */
	skb_dst_drop(skb);

	bh_lock_sock_nested(&ssk->xia_sk.sk);
	/* One should not drop the packet @skb because do_rcv() consumes it. */
	rc = do_rcv(&ssk->xia_sk.sk, skb, &sal_ctx);
	bh_unlock_sock(&ssk->xia_sk.sk);

	return rc < 0 ? NET_RX_DROP : NET_RX_SUCCESS;
}

int serval_sal_rcv(struct sk_buff *skb)
{
	return __serval_sal_rcv(skb, serval_sal_state_process);
}

int serval_sal_rsk_rcv(struct sk_buff *skb)
{
	return __serval_sal_rcv(skb, do_rcv_for_srsk);
}

static int serval_sal_rexmit(struct sock *sk)
{        
        struct sk_buff *skb;

        skb = serval_sal_ctrl_queue_head(sk);
        if (!skb) {
		/* No packet to retransmit. */
                return -1;
        }

        SAL_SKB_CB(skb)->flags |= SVH_RETRANS;

        /* Always clone retransmitted packets */
        return serval_sal_transmit_skb(sk, skb, 1, GFP_ATOMIC);
}

static void serval_sal_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);
	serval_sal_done(sk);
}

void serval_sal_rexmit_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        struct serval_sock *ssk = sk_ssk(sk);

        bh_lock_sock(sk);

        if (ssk->retransmits >= net_serval.sysctl_sal_max_retransmits) {
		/* XXX: check error values here */
		/* Max retransmits attempts reached. NOT rescheduling timer! */
                serval_sal_write_err(sk);
        } else {
                /* Retransmitting and rescheduling timer. */
                serval_sal_rexmit(sk);

                ssk->backoff++;
                ssk->retransmits++; /* Increase number of attempts. */

                serval_sock_reset_xmit_timer(sk,
			min(ssk->rto << ssk->backoff, SAL_RTO_MAX),
			SAL_RTO_MAX);
        }
        bh_unlock_sock(sk);
        sock_put(sk);
}

/* This timeout is used for TIMEWAIT and FINWAIT2 */
void serval_sal_timewait_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        bh_lock_sock(sk);
        serval_sal_done(sk);
        bh_unlock_sock(sk);
        /* Release timer's reference. */
        sock_put(sk);
}

static inline int serval_sal_fin_time(const struct sock *sk)
{
	int fin_timeout = sysctl_sal_fin_timeout;
	const int rto = sk_ssk(sk)->rto;

	if (fin_timeout < (rto << 2) - (rto >> 1))
		fin_timeout = (rto << 2) - (rto >> 1);

	return fin_timeout;
}

/* XXX Review this function to support socket migration in XIA. */
#if 0
static int serval_sal_do_xmit(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        struct serval_sock *ssk = sk_ssk(sk);
      	uint32_t temp_daddr = 0;
        u8 skb_flags = SAL_SKB_CB(skb)->flags;
        struct net_device *mig_dev = NULL; 
        int rc;

        if (skb_flags & SVH_RSYN) {
                mig_dev = dev_get_by_index(sock_net(sk), ssk->mig_dev_if);

                if (mig_dev) {
			/* Sending on @mig_dev. */
			dev_get_ipv4_addr(mig_dev, &inet_sk(sk)->inet_saddr);
			skb->dev = mig_dev;
                }

                if (ssk->sal_state == SAL_RSYN_RECV) {
			/* Sending to migration address @ssk->mig_daddr. */ 
			memcpy(&temp_daddr, &inet_sk(sk)->inet_daddr, 4);
			memcpy(&inet_sk(sk)->inet_daddr, &ssk->mig_daddr, 4);
                }

                /* Must remove any cached route */
                sk_dst_reset(sk);
        }

        /*
          XXX we kind of hard code the outgoing device here based
          on what has been bound to the socket in the connection
          setup phase. Instead, the device should be resolved based
          on, e.g., dst IP (if it exists at this point).

          However, we currently do not implement an IP routing table
          for userlevel, which would otherwise be used for this
          resolution. Kernel space should work, because it routes
          packet according to the kernel's routing table, thus
          figuring out the device along the way.

          Packets that are sent using an advisory IP may fail in
          queue_xmit for userlevel unless the socket has had its
          interface set by a previous send event.
        */
        rc = xip_local_out(skb);
        
        if (skb_flags & SVH_RSYN) {
                /* Restore inet_sk(sk)->daddr */
                if (mig_dev) {
                        struct net_device *dev = 
                                dev_get_by_index(sock_net(sk), 
                                                 sk->sk_bound_dev_if);
                                
                        if (dev) {
				dev_get_ipv4_addr(dev,
					&inet_sk(sk)->inet_saddr);
                                dev_put(dev);
                        }
                }
                
                if (ssk->sal_state == SAL_RSYN_RECV) {
                        memcpy(&inet_sk(sk)->inet_daddr, &temp_daddr, 4);
                }
                /* Reset cached route again */
                sk_dst_reset(sk);
        }

        if (mig_dev)
                dev_put(mig_dev);

        return rc;
}
#else
static inline int serval_sal_do_xmit(struct sk_buff *skb)
{
	return xip_local_out(skb);
}
#endif

/* Check if the struct xip_dst associated to the destination address is fresh.
 * If not, refresh it; otherwise do nothing.
 */
int serval_sock_refresh_dest(struct sock *sk)
{
	struct xia_sock *xia;
	struct xip_dst *xdst;

	if (__sk_dst_check(sk, 0))
		return 0;	/* Route is fresh, do nothing. */

	xia = xia_sk(sk);
	unmark_xia_rows(xia->xia_daddr.s_row, xia->xia_dnum);
	xia->xia_dlast_node = XIA_ENTRY_NODE_INDEX;
	xdst = xip_mark_addr_and_get_dst(sock_net(sk), xia->xia_daddr.s_row,
		xia->xia_dnum, &xia->xia_dlast_node, 0);
	if (IS_ERR(xdst))
		return -EHOSTUNREACH;	/* Cannot route it. */

	sk_dst_set(sk, &xdst->dst);
	return 0;	/* Route is fresh again. */
}

/* This function is based on __sk_dst_check(). */
static struct xip_dst *__ssk_peer_srvc_check(struct serval_sock *ssk)
{
	struct xip_dst *xdst = ssk->peer_srvc_xdst;

	if (xdst && xdst->dst.obsolete &&
		!xdst->dst.ops->check(&xdst->dst, 0)) {
		sk_tx_queue_clear(&ssk->xia_sk.sk);
		ssk->peer_srvc_xdst = NULL;
		xdst_put(xdst);
		return NULL;
	}

	return xdst;
}

/* Check if the struct xip_dst associated to the peer's ServiceID address is
 * fresh. If not, refresh it; otherwise do nothing.
 */
static int refresh_peer_srvc(struct serval_sock *ssk)
{
	struct xip_dst *xdst;

	if (__ssk_peer_srvc_check(ssk))
		return 0;	/* Route is fresh, do nothing. */

	unmark_xia_rows(ssk->peer_srvc_addr.s_row, ssk->peer_srvc_num);
	ssk->peer_srvc_last_node = XIA_ENTRY_NODE_INDEX;
	xdst = xip_mark_addr_and_get_dst(sock_net(&ssk->xia_sk.sk),
		ssk->peer_srvc_addr.s_row, ssk->peer_srvc_num,
		&ssk->peer_srvc_last_node, 0);
	if (IS_ERR(xdst))
		return -EHOSTUNREACH;	/* Cannot route it. */

	set_peer_srvc_xdst(ssk, xdst);
	return 0;	/* Route is fresh again. */
}

static int add_xip_sal_headers_xdst(struct sock *sk, struct sk_buff *skb)
{
	struct serval_sock *ssk = sk_ssk(sk);
	struct xia_sock *xia = &ssk->xia_sk;
	int ext_len = 0;
	int flags, rc;
	const struct xia_row *src, *dest;
	xid_type_t src_sink_type;
	const __u8 *src_sink_id;
	int src_n, dest_n, dest_last_node;
	struct xip_dst *xdst;

	/* Unconnected datagram, add service extensions.
	 *
	 * XXX This code is UDP specific. If UDP is going to stay,
	 * this must be generalized since this code must be transport
	 * agnostic.
	 */
	if (unlikely(sk->sk_state == SAL_INIT && sk->sk_type == SOCK_DGRAM)) {
		/* Src: ServiceID. */
		struct xia_row *last_row = xia->xia_ssink;
		BUG_ON(!xia_sk_bound(xia));
		src = xia->xia_saddr.s_row;
		src_sink_type = last_row->s_xid.xid_type;
		src_sink_id = last_row->s_xid.xid_id;
		src_n = xia->xia_snum;

		/* Dest: ServiceID.
		 *
		 * This is a hack to have a ServiceID instead of
		 * a FlowID. See serval_udp.c:serval_udp_sendmsg() for
		 * details.
		 *
		 * We don't bother refreshing @xdst here because
		 * UDP just obtained it.
		 */
		BUG_ON(!xia->xia_daddr_set);
		dest = xia->xia_daddr.s_row;
		dest_n = xia->xia_dnum;
		dest_last_node = xia->xia_dlast_node;
		xdst = dst_xdst(sk_dst_get(&xia->sk));

		goto finish;
	}

	/* Choose source and destination addresses, and obtain @xdst. */
	flags = SAL_SKB_CB(skb)->flags;
	if (unlikely(flags & SVH_SYN)) {
		/* Src: ServiceID. */
		struct xia_row *last_row = xia->xia_ssink;
		BUG_ON(!xia_sk_bound(xia));
		src = xia->xia_saddr.s_row;
		src_sink_type = last_row->s_xid.xid_type;
		src_sink_id = last_row->s_xid.xid_id;
		src_n = xia->xia_snum;

		/* Dst: ServiceID. */
		BUG_ON(!ssk->peer_srvc_set);
		rc = refresh_peer_srvc(ssk);
		if (rc)
			return rc;
		dest = ssk->peer_srvc_addr.s_row;
		dest_n = ssk->peer_srvc_num;
		dest_last_node = ssk->peer_srvc_last_node;
		xdst = ssk->peer_srvc_xdst;
		xdst_hold(xdst);
        } else {
		/* Src: FlowID. */
		BUG_ON(!xia_sk_bound(xia));
		BUG_ON(!ssk->local_flowid_hashed);
		src = xia->xia_saddr.s_row;
		src_sink_type = XIDTYPE_FLOWID;
		src_sink_id = ssk->flow_fxid.fx_xid;
		src_n = xia->xia_snum;

		/* Dest: FlowID. */
		BUG_ON(!xia->xia_daddr_set);
		rc = serval_sock_refresh_dest(sk);
		if (rc)
			return rc;
		dest = xia->xia_daddr.s_row;
		dest_n = xia->xia_dnum;
		dest_last_node = xia->xia_dlast_node;
		xdst = dst_xdst(sk_dst_get(&xia->sk));
	}

	/* Add control extension header if needed. */
	if (flags & ~SVH_RETRANS) {
		struct sal_control_ext *ctrl_ext = push_ctrl_ext_hdr(skb);
		ctrl_ext->verno = htonl(SAL_SKB_CB(skb)->verno);
		ctrl_ext->ackno = htonl(ssk->rcv_seq.nxt);
		memcpy(ctrl_ext->nonce, ssk->local_nonce, SAL_NONCE_SIZE);
		ctrl_ext->syn = !!(flags & SVH_SYN);
		ctrl_ext->rsyn = !!(flags & SVH_RSYN);
		ctrl_ext->ack = !!(flags & SVH_ACK);
		ctrl_ext->nack = !!(flags & SVH_NACK);
		ctrl_ext->fin = !!(flags & SVH_FIN);
		ctrl_ext->rst = !!(flags & SVH_RST);
		ext_len += sizeof(*ctrl_ext);
        }

finish:
	/* Add SAL base header */
	push_sal_hdr(skb, sk->sk_protocol, ext_len);

	/* Add XIP header. */
	push_xip_hdr_bsrc(skb, xdst, src, src_sink_type, src_sink_id, src_n,
		dest, dest_n, dest_last_node);

	BUG_ON(xdst->input);
	skb_dst_set(skb, &xdst->dst);
	return 0;
}

static int serval_sal_transmit_skb(struct sock *sk, struct sk_buff *skb,
	int use_copy, gfp_t gfp_mask)
{
	int rc;

	if (likely(use_copy)) {
                /* pskb_copy will make a copy of header and
		 * non-fragmented data. Making a copy is necessary
		 * since we are changing the TCP header checksum for
		 * every copy we send (retransmission or copies for
		 * packets matching multiple rules).
		 */
                skb = pskb_copy(skb, gfp_mask);
		if (unlikely(!skb)) {
                        /* Shouldn't free the passed skb here, since
                         * we were asked to use a copy. That probably
                         * means the original skb sits in a queue
                         * somewhere, and freeing it would be bad.
			 */
                        return -ENOBUFS;
                }

                prepare_skb_to_send(skb, sk);
	}

	rc = add_xip_sal_headers_xdst(sk, skb);
	if (rc)
		return rc;

	return serval_sal_do_xmit(skb);
}

/* This function is typically called by transport to send data */
int serval_sal_xmit_skb(struct sk_buff *skb) 
{
	return serval_sal_transmit_skb(skb->sk, skb, 0, GFP_ATOMIC);
}

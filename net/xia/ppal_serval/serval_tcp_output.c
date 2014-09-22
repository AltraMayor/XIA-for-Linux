#include "serval_tcp.h"
#include "serval_tcp_request_sock.h"

/* People can turn this off for buggy TCP's found in printers etc. */
int sysctl_serval_tcp_retrans_collapse __read_mostly; /* Implicitly = 0. */
int sysctl_serval_tcp_mtu_probing __read_mostly; /* Implicitly = 0. */

/* This limits the percentage of the congestion window which we
 * will allow a single TSO frame to consume.  Building TSO frames
 * which are too large can cause TCP streams to be bursty.
 */
int sysctl_serval_tcp_base_mss __read_mostly = SERVAL_TCP_BASE_MSS;

/* From net/core/sock.c */
int sysctl_serval_wmem_max __read_mostly = 32767;
int sysctl_serval_rmem_max __read_mostly = 32767;
int sysctl_serval_tcp_window_scaling __read_mostly = 1;

int sysctl_serval_tcp_tso_win_divisor __read_mostly = 3;

/* People can turn this on to work with those rare, broken TCPs that
 * interpret the window field as a signed quantity.
 *
 * Implicitly = 0.
 */
int sysctl_serval_tcp_workaround_signed_windows __read_mostly;

/* By default, RFC2861 behavior.  */
int sysctl_serval_tcp_slow_start_after_idle __read_mostly = 1;

#define OPTION_SACK_ADVERTISE	(1 << 0)
#define OPTION_TS		(1 << 1)
#define OPTION_MD5		(1 << 2)
#define OPTION_WSCALE		(1 << 3)
#define OPTION_COOKIE_EXTENSION	(1 << 4)

struct tcp_out_options {
	u8 options;		/* bit field of OPTION_* */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u8 hash_size;		/* bytes in hash_location */
	u16 mss;		/* 0 to disable */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
	__u8 *hash_location;	/* temporary pointer, overloaded */
};


/* SND.NXT, if window was not shrunk.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 serval_tcp_acceptable_seq(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (!before(serval_tcp_wnd_end(tp), tp->snd_nxt))
		return tp->snd_nxt;
	else
		return serval_tcp_wnd_end(tp);
}


static inline int serval_tcp_urg_mode(const struct serval_tcp_sock *tp)
{
	return tp->snd_una != tp->snd_up;
}


/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
static __u16 serval_tcp_advertise_mss(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;

	if (dst) {
		unsigned int metric;

		metric = dst_metric_advmss(dst);
		if (metric < mss) {
			mss = metric;
			tp->advmss = mss;
		}
	}

	return (__u16)mss;
}

/* Write previously computed TCP options to the packet.
 *
 * Beware: Something in the Internet is very sensitive to the ordering of
 * TCP options, we learned this through the hard way, so be careful here.
 * Luckily we can at least blame others for their non-compliance but from
 * inter-operatibility perspective it seems that we're somewhat stuck with
 * the ordering which we have been using if we want to keep working with
 * those broken things (not that it currently hurts anybody as there isn't
 * particular reason why the ordering would need to be changed).
 *
 * At least SACK_PERM as the first option is known to lead to a disaster
 * (but it may well be that other scenarios fail similarly).
 */
static void serval_tcp_options_write(__be32 *ptr, struct serval_tcp_sock *tp,
				     struct tcp_out_options *opts)
{
	u8 options = opts->options;	/* mungable copy */

	if (unlikely(opts->mss)) {
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss);
	}
	/*
	if (likely(OPTION_TS & options)) {
		if (unlikely(OPTION_SACK_ADVERTISE & options)) {
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
			options &= ~OPTION_SACK_ADVERTISE;
		} else {
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		}
		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	}
	*/
	if (unlikely(OPTION_WSCALE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->ws);
	}
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
static unsigned serval_tcp_syn_options(struct sock *sk, struct sk_buff *skb,
				       struct tcp_out_options *opts,
				       struct tcp_md5sig_key **md5)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned remaining = MAX_SERVAL_TCP_OPTION_SPACE;

	*md5 = NULL;

	/* We always get an MSS option.  The option bytes which will be seen in
	 * normal data packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so that
	 * calculations in tcp_sendmsg are simpler etc.  So account for this
	 * fact here if necessary.  If we don't do this correctly, as a
	 * receiver we won't recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK rules correctly.
	 * SACKs don't matter, we never delay an ACK when we have any of those
	 * going out.  */
	opts->mss = serval_tcp_advertise_mss(sk);
	remaining -= TCPOLEN_MSS_ALIGNED;

	/*
	if (likely(sysctl_serval_tcp_timestamps && *md5 == NULL)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when;
		opts->tsecr = tp->rx_opt.ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	*/
	if (likely(sysctl_serval_tcp_window_scaling)) {
		opts->ws = tp->rx_opt.rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
		/* Added window scale option. */
	}
	return MAX_SERVAL_TCP_OPTION_SPACE - remaining;
}

/* Set up TCP options for SYN-ACKs. */
static unsigned serval_tcp_synack_options(struct sock *sk,
	struct serval_tcp_request_sock *trsk, unsigned mss, struct sk_buff *skb,
	struct tcp_out_options *opts, struct tcp_md5sig_key **md5)
{
	unsigned remaining = MAX_SERVAL_TCP_OPTION_SPACE;

	*md5 = NULL;

	/* We always send an MSS option. */
	opts->mss = mss;
	remaining -= TCPOLEN_MSS_ALIGNED;

	if (likely(trsk->wscale_ok)) {
		opts->ws = trsk->rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
/*
	if (likely(trsk->tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when;
		opts->tsecr = trsk->rsk.req.ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
*/
	return MAX_SERVAL_TCP_OPTION_SPACE - remaining;
}


/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
static unsigned serval_tcp_established_options(struct sock *sk,
					       struct sk_buff *skb,
					       struct tcp_out_options *opts,
					       struct tcp_md5sig_key **md5)
{
	/* struct tcp_skb_cb *tcb = skb ? TCP_SKB_CB(skb) : NULL;
	   struct serval_tcp_sock *tp = serval_tcp_sk(sk); */
	unsigned size = 0;

	*md5 = NULL;
	/*
	if (likely(tp->rx_opt.tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcb ? tcb->when : 0;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}
	*/
	return size;
}

/* Account for new data that has been sent to the network. */
static void serval_tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;

	serval_tcp_advance_send_head(sk, skb);
	tp->snd_nxt = TCP_SKB_CB(skb)->end_seq;

	/* Don't override Nagle indefinately with F-RTO */
	if (tp->frto_counter == 2)
		tp->frto_counter = 3;

	tp->packets_out += serval_tcp_skb_pcount(skb);

	if (!prior_packets)
		serval_tsk_reset_xmit_timer(sk, STSK_TIME_RETRANS,
					    tp->rto,
					    SERVAL_TCP_RTO_MAX);
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism. */
static void serval_tcp_cwnd_restart(struct sock *sk, struct dst_entry *dst)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	s32 delta = tcp_time_stamp - tp->lsndtime;
	u32 restart_cwnd = serval_tcp_init_cwnd(tp, dst);
	u32 cwnd = tp->snd_cwnd;

	serval_tcp_ca_event(sk, CA_EVENT_CWND_RESTART);

	tp->snd_ssthresh = serval_tcp_current_ssthresh(sk);
	restart_cwnd = min(restart_cwnd, cwnd);

	while ((delta -= tp->rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tp->snd_cwnd = max(cwnd, restart_cwnd);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_cwnd_used = 0;
}

/* Congestion state accounting after a packet has been sent. */
static void serval_tcp_event_data_sent(struct serval_tcp_sock *tp,
				       struct sk_buff *skb, struct sock *sk)
{
	const u32 now = tcp_time_stamp;

	if (sysctl_serval_tcp_slow_start_after_idle &&
	    (!tp->packets_out && (s32)(now - tp->lsndtime) > tp->rto))
		serval_tcp_cwnd_restart(sk, __sk_dst_get(sk));

	tp->lsndtime = now;

	/* If it is a reply for ato after last received
	 * packet, enter pingpong mode.
	 */
	if ((u32)(now - tp->tp_ack.lrcvtime) < tp->tp_ack.ato)
		tp->tp_ack.pingpong = 1;
}

/* Account for an ACK we sent. */
static inline void serval_tcp_event_ack_sent(struct sock *sk, unsigned int pkts)
{
	serval_tcp_dec_quickack_mode(sk, pkts);
	serval_tsk_clear_xmit_timer(sk, STSK_TIME_DACK);
}

/* Initialize TSO segments for a packet. */
static void serval_tcp_set_skb_tso_segs(struct sock *sk, struct sk_buff *skb,
					unsigned int mss_now)
{
	if (1 /* Disable GSO */ || skb->len <= mss_now ||
	    1 /* !sk_can_gso(sk) */ || skb->ip_summed == CHECKSUM_NONE) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		skb_shinfo(skb)->gso_segs = 1;
		skb_shinfo(skb)->gso_size = 0;
		skb_shinfo(skb)->gso_type = 0;
	} else {
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now);
		skb_shinfo(skb)->gso_size = mss_now;
		skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	}
}

/* Intialize TSO state of a skb.
 * This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
static int serval_tcp_init_tso_segs(struct sock *sk, struct sk_buff *skb,
				    unsigned int mss_now)
{
	int tso_segs = serval_tcp_skb_pcount(skb);

	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		serval_tcp_set_skb_tso_segs(sk, skb, mss_now);
		tso_segs = serval_tcp_skb_pcount(skb);
	}
	return tso_segs;
}


/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void serval_tcp_select_initial_window(int __space, __u32 mss,
				      __u32 *rcv_wnd, __u32 *window_clamp,
				      int wscale_ok, __u8 *rcv_wscale,
				      __u32 init_rcv_wnd)
{
	unsigned int space = (__space < 0 ? 0 : __space);

	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (65535 << 14);
	space = min(*window_clamp, space);

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = (space / mss) * mss;

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sysctl_serval_tcp_workaround_signed_windows)
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = space;

	(*rcv_wscale) = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window.
		 * See RFC1323 for an explanation of the limit to 14.
		 */
		space = max_t(u32, sysctl_serval_tcp_rmem[2],
			      sysctl_serval_rmem_max);
		space = min_t(u32, space, *window_clamp);

		while (space > 65535 && (*rcv_wscale) < 14) {
			space >>= 1;
			(*rcv_wscale)++;
		}
	}

	/* Set initial window to value enough for senders,
	 * following RFC2414. Senders, not following this RFC,
	 * will be satisfied with 2.
	 */
	if (mss > (1 << *rcv_wscale)) {
		int init_cwnd = 4;
		if (mss > 1460 * 3)
			init_cwnd = 2;
		else if (mss > 1460)
			init_cwnd = 3;
		/* when initializing use the value from init_rcv_wnd
		 * rather than the default from above
		 */
		if (init_rcv_wnd &&
		    (*rcv_wnd > init_rcv_wnd * mss))
			*rcv_wnd = init_rcv_wnd * mss;
		else if (*rcv_wnd > init_cwnd * mss)
			*rcv_wnd = init_cwnd * mss;
	}

	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min(65535U << (*rcv_wscale), *window_clamp);
}


/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static u16 serval_tcp_select_window(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 cur_win = serval_tcp_receive_window(tp);
	u32 new_win = __serval_tcp_select_window(sk);

	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale &&
	    sysctl_serval_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0)
		tp->pred_flags = 0;

	return new_win;
}


/* Congestion window validation. (RFC2861) */
static void serval_tcp_cwnd_validate(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->packets_out >= tp->snd_cwnd) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_time_stamp;
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out;

		if (sysctl_serval_tcp_slow_start_after_idle &&
		    (s32)(tcp_time_stamp - tp->snd_cwnd_stamp) >= tp->rto)
			serval_tcp_cwnd_application_limited(sk);
	}
}


/* Returns the portion of skb which can be sent right away without
 * introducing MSS oddities to segment boundaries. In rare cases where
 * mss_now != mss_cache, we will request caller to create a small skb
 * per input skb which could be mostly avoided here (if desired).
 *
 * We explicitly want to create a request for splitting write queue tail
 * to a small skb for Nagle purposes while avoiding unnecessary modulos,
 * thus all the complexity (cwnd_len is always MSS multiple which we
 * return whenever allowed by the other factors). Basically we need the
 * modulo only when the receiver window alone is the limiting factor or
 * when we would be allowed to send the split-due-to-Nagle skb fully.
 */
static unsigned int serval_tcp_mss_split_point(struct sock *sk,
					       struct sk_buff *skb,
					       unsigned int mss_now,
					       unsigned int cwnd)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 needed, window, cwnd_len;

	window = serval_tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
	cwnd_len = mss_now * cwnd;

	if (likely(cwnd_len <= window &&
		   skb != serval_tcp_write_queue_tail(sk)))
		return cwnd_len;

	needed = min(skb->len, window);

	if (cwnd_len <= needed)
		return cwnd_len;

	return needed - needed % mss_now;
}


/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int serval_tcp_cwnd_test(struct serval_tcp_sock *tp,
						struct sk_buff *skb)
{
	u32 in_flight, cwnd;

	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPH_FIN) &&
	    serval_tcp_skb_pcount(skb) == 1)
		return 1;

	in_flight = serval_tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd)
		return cwnd - in_flight;

	return 0;
}

/* Minshall's variant of the Nagle send check. */
static inline int serval_tcp_minshall_check(const struct serval_tcp_sock *tp)
{
	return after(tp->snd_sml, tp->snd_una) &&
		!after(tp->snd_sml, tp->snd_nxt);
}

/* Return 0, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized.
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_NODELAY was set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
static inline int serval_tcp_nagle_check(const struct serval_tcp_sock *tp,
					 const struct sk_buff *skb,
					 unsigned mss_now, int nonagle)
{
	return skb->len < mss_now &&
		((nonagle & TCP_NAGLE_CORK) ||
		 (!nonagle && tp->packets_out &&
		  serval_tcp_minshall_check(tp)));
}

/* Return non-zero if the Nagle test allows this packet to be
 * sent now.
 */
static inline int serval_tcp_nagle_test(struct serval_tcp_sock *tp,
					struct sk_buff *skb,
					unsigned int cur_mss,
					int nonagle)
{
	/* Nagle rule does not apply to frames, which sit in the middle of the
	 * write_queue (they have no chances to get new data).
	 *
	 * This is implemented in the callers, where they modify the 'nonagle'
	 * argument based upon the location of SKB in the send queue.
	 */
	if (nonagle & TCP_NAGLE_PUSH)
		return 1;

	/* Don't use the nagle rule for urgent data (or for the final FIN).
	 * Nagle can be ignored during F-RTO too (see RFC4138).
	 */
	if (serval_tcp_urg_mode(tp) || (tp->frto_counter == 2) ||
	    (TCP_SKB_CB(skb)->tcp_flags & TCPH_FIN))
		return 1;

	if (!serval_tcp_nagle_check(tp, skb, cur_mss, nonagle))
		return 1;

	return 0;
}

/* Does at least the first segment of SKB fit into the send window? */
static inline int serval_tcp_snd_wnd_test(struct serval_tcp_sock *tp,
					  struct sk_buff *skb,
					  unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;
	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;
	return !after(end_seq, serval_tcp_wnd_end(tp));
}

/* This checks if the data bearing packet SKB (usually tcp_send_head(sk))
 * should be put on the wire right now.  If so, it returns the number of
 * packets allowed by the congestion window.
 */
static unsigned int serval_tcp_snd_test(struct sock *sk, struct sk_buff *skb,
					unsigned int cur_mss, int nonagle)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned int cwnd_quota;

	serval_tcp_init_tso_segs(sk, skb, cur_mss);

	/*
	if (!serval_tcp_nagle_test(tp, skb, cur_mss, nonagle))
		return 0;
	*/

	cwnd_quota = serval_tcp_cwnd_test(tp, skb);
	if (cwnd_quota && !serval_tcp_snd_wnd_test(tp, skb, cur_mss))
		cwnd_quota = 0;

	return cwnd_quota;
}

/* This routine just queues the buffer for sending.
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void serval_tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	skb_header_release(skb);
	serval_tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
static void serval_tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	/* Tells hardware to compute checksum or not. */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;

	TCP_SKB_CB(skb)->tcp_flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;

	TCP_SKB_CB(skb)->seq = seq;

	if (flags & (TCPH_SYN | TCPH_FIN))
		seq++;

	TCP_SKB_CB(skb)->end_seq = seq;
}

/* Pcount in the middle of the write queue got changed, we need to do various
 * tweaks to fix counters
 */
static void serval_tcp_adjust_pcount(struct sock *sk,
				     struct sk_buff *skb, int decr)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	tp->packets_out -= decr;

	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		tp->sacked_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
		tp->retrans_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
		tp->lost_out -= decr;

	/* Reno case is special. Sigh... */
	if (serval_tcp_is_reno(tp) && decr > 0)
		tp->sacked_out -= min_t(u32, tp->sacked_out, decr);

	/* serval_tcp_adjust_fackets_out(sk, skb, decr); */

	/*
	if (tp->lost_skb_hint &&
		before(TCP_SKB_CB(skb)->seq,
			TCP_SKB_CB(tp->lost_skb_hint)->seq) &&
		(serval_tcp_is_fack(tp) ||
			(TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)))
		tp->lost_cnt_hint -= decr;
	*/
	serval_tcp_verify_left_out(tp);
}

/* This is similar to __pskb_pull_head() (it will go to core/skbuff.c
 * eventually). The difference is that pulled data not copied, but
 * immediately discarded.
 */
static void __pskb_trim_head(struct sk_buff *skb, int len)
{
	int i, k, eat;

	eat = len;
	k = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int size = skb_frag_size(&skb_shinfo(skb)->frags[i]);

		if (size <= eat) {
			skb_frag_unref(skb, i);
			eat -= size;
		} else {
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];
			if (eat) {
				skb_shinfo(skb)->frags[k].page_offset += eat;
				skb_frag_size_sub(&skb_shinfo(skb)->frags[k],
						  eat);
				eat = 0;
			}
			k++;
		}
	}
	skb_shinfo(skb)->nr_frags = k;
	skb_reset_tail_pointer(skb);
	skb->data_len -= len;
	skb->len = skb->data_len;
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
int serval_tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
			unsigned int mss_now)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	int nlen;
	u8 flags;

	BUG_ON(len > skb->len);

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	if (skb_cloned(skb) &&
	    skb_is_nonlinear(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = serval_sk_stream_alloc_skb(sk, nsize, GFP_ATOMIC);
	if (buff == NULL)
		return -ENOMEM; /* We'll just try again later. */

	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPH_FIN | TCPH_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;

	if (!skb_shinfo(skb)->nr_frags && skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Copy and checksum data tail into the new buffer. */
		buff->csum = csum_partial_copy_nocheck(skb->data + len,
						       skb_put(buff, nsize),
						       nsize, 0);

		skb_trim(skb, len);

		skb->csum = csum_block_sub(skb->csum, buff->csum, len);
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_split(skb, buff, len);
	}

	buff->ip_summed = skb->ip_summed;

	/* Looks stupid, but our code really uses when of
	 * skbs, which it never sent before. --ANK
	 */
	TCP_SKB_CB(buff)->when = TCP_SKB_CB(skb)->when;
	buff->tstamp = skb->tstamp;

	old_factor = serval_tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	serval_tcp_set_skb_tso_segs(sk, skb, mss_now);
	serval_tcp_set_skb_tso_segs(sk, buff, mss_now);

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - serval_tcp_skb_pcount(skb) -
			serval_tcp_skb_pcount(buff);

		if (diff)
			serval_tcp_adjust_pcount(sk, skb, diff);
	}

	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	serval_tcp_insert_write_queue_after(skb, buff, sk);

	return 0;
}

/* Test if sending is allowed right now. */
int serval_tcp_may_send_now(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb = serval_tcp_send_head(sk);

	return skb &&
		serval_tcp_snd_test(sk, skb, serval_tcp_current_mss(sk),
				    (serval_tcp_skb_is_last(sk, skb) ?
				     tp->nonagle : TCP_NAGLE_PUSH));
}


/* Remove acked data from a packet in the transmit queue. */
int serval_tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	if (skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* If len == headlen, we avoid __skb_pull to preserve alignment. */
	if (unlikely(len < skb_headlen(skb)))
		__skb_pull(skb, len);
	else
		__pskb_trim_head(skb, len - skb_headlen(skb));

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb->truesize	     -= len;
	sk->sk_wmem_queued   -= len;
	sk_mem_uncharge(sk, len);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);

	/* Any change of skb->len requires recalculation of tso
	 * factor and mss.
	 */
	if (serval_tcp_skb_pcount(skb) > 1)
		serval_tcp_set_skb_tso_segs(sk, skb,
					    serval_tcp_current_mss(sk));

	return 0;
}

/* Calculate MSS. Not accounting for SACKs here.  */
int serval_tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct serval_sock *ssk = sk_ssk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	mss_now = pmtu - ssk->af_ops->net_header_len - sizeof(struct tcphdr);

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	if (mss_now < 48)
		mss_now = 48;

	/* Now subtract TCP options size, not including SACKs */
	mss_now -= tp->tcp_header_len - sizeof(struct tcphdr);

	return mss_now;
}

/* Inverse of above */
int serval_tcp_mss_to_mtu(struct sock *sk, int mss)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct serval_sock *ssk = sk_ssk(sk);
	return mss + tp->tcp_header_len + ssk->af_ops->net_header_len;
}

/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * XIP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
static int serval_tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,
				   int clone_it, gfp_t gfp_mask)
{
	struct serval_sock *ssk = sk_ssk(sk);
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned tcp_options_size, tcp_header_size;
	struct tcp_md5sig_key *md5;
	struct tcphdr *th;
	int err;

	BUG_ON(!skb || !serval_tcp_skb_pcount(skb));

	if (likely(clone_it)) {
		if (unlikely(skb_cloned(skb)))
			skb = pskb_copy(skb, gfp_mask);
		else
			skb = skb_clone(skb, gfp_mask);
		if (unlikely(!skb))
			return -ENOBUFS;
	}

	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

	if (unlikely(tcb->tcp_flags & TCPH_SYN))
		tcp_options_size = serval_tcp_syn_options(sk, skb, &opts, &md5);
	else
		tcp_options_size = serval_tcp_established_options(sk, skb,
								  &opts,
								  &md5);

	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	if (serval_tcp_packets_in_flight(tp) == 0)
		serval_tcp_ca_event(sk, CA_EVENT_TX_START);

	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);
	skb_set_owner_w(skb, sk);

	/* Build TCP header and checksum it. */
	th = tcp_hdr(skb);
	th->source		= 0;
	th->dest		= 0;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(tp->rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->tcp_flags);

	if (unlikely(tcb->tcp_flags & TCPH_SYN)) {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	} else {
		th->window	= htons(serval_tcp_select_window(sk));
	}
	th->check		= 0;
	th->urg_ptr		= 0;

	/* The urg_mode check is necessary during a below snd_una win probe */
	if (unlikely(serval_tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			th->urg_ptr = htons(0xFFFF);
			th->urg = 1;
		}
	}

	serval_tcp_options_write((__be32 *)(th + 1), tp, &opts);

	/*
	if (likely((tcb->tcp_flags & TCPH_SYN) == 0))
		TCP_ECN_send(sk, skb, tcp_header_size);
	*/
#ifdef CONFIG_TCP_MD5SIG_DISABLED
	/* Calculate the MD5 hash, as we have all we need now */
	if (md5) {
		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		tp->af_specific->calc_md5_hash(opts.hash_location,
					       md5, sk, NULL, skb);
	}
#endif

	if (ssk->af_ops->send_check)
		ssk->af_ops->send_check(sk, skb);

	if (likely(tcb->tcp_flags & TCPH_ACK))
		serval_tcp_event_ack_sent(sk, serval_tcp_skb_pcount(skb));

	if (skb->len != tcp_header_size)
		serval_tcp_event_data_sent(tp, skb, sk);

	/*
	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq) {
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
			      serval_tcp_skb_pcount(skb));
	}
	*/

	err = serval_sal_xmit_skb(skb);

	if (likely(err <= 0))
		return err;

	serval_tcp_enter_cwr(sk, 1);

	return net_xmit_eval(err);
}


/* Collapses two adjacent SKB's during retransmission. */
static void serval_tcp_collapse_retrans(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *next_skb = serval_tcp_write_queue_next(sk, skb);
	int skb_size, next_skb_size;

	skb_size = skb->len;
	next_skb_size = next_skb->len;

	BUG_ON(serval_tcp_skb_pcount(skb) != 1 ||
	       serval_tcp_skb_pcount(next_skb) != 1);

	/* serval_tcp_highest_sack_combine(sk, next_skb, skb); */

	serval_tcp_unlink_write_queue(next_skb, sk);

	skb_copy_from_linear_data(next_skb, skb_put(skb, next_skb_size),
				  next_skb_size);

	if (next_skb->ip_summed == CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_PARTIAL;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->csum = csum_block_add(skb->csum, next_skb->csum, skb_size);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

	/* Merge over control information. This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->tcp_flags |= TCP_SKB_CB(next_skb)->tcp_flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked &
		TCPCB_EVER_RETRANS;

	/* changed transmit queue under us so clear hints */
	serval_tcp_clear_retrans_hints_partial(tp);
	if (next_skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = skb;

	serval_tcp_adjust_pcount(sk, next_skb, serval_tcp_skb_pcount(next_skb));

	sk_wmem_free_skb(sk, next_skb);
}

/* Check if coalescing SKBs is legal. */
static int serval_tcp_can_collapse(struct sock *sk, struct sk_buff *skb)
{
	if (serval_tcp_skb_pcount(skb) > 1)
		return 0;
	/* XXX SACK collapsing could be used to remove this condition. */
	if (skb_shinfo(skb)->nr_frags != 0)
		return 0;
	if (skb_cloned(skb))
		return 0;
	if (skb == serval_tcp_send_head(sk))
		return 0;
	/* XXX Some heuristics for collapsing over SACK'd could be invented. */
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		return 0;

	return 1;
}


/* Collapse packets in the retransmit queue to make to create
 * less packets on the wire. This is only done on retransmission.
 */
static void serval_tcp_retrans_try_collapse(struct sock *sk,
					    struct sk_buff *to,
					    int space)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb = to, *tmp;
	int first = 1;

	if (!sysctl_serval_tcp_retrans_collapse)
		return;

	if (TCP_SKB_CB(skb)->tcp_flags & TCPH_SYN)
		return;

	serval_tcp_for_write_queue_from_safe(skb, tmp, sk) {
		if (!serval_tcp_can_collapse(sk, skb))
			break;

		space -= skb->len;

		if (first) {
			first = 0;
			continue;
		}

		if (space < 0)
			break;
		/* Punt if not enough space exists in the first SKB for
		 * the data in the second
		 */
		if (skb->len > skb_tailroom(to))
			break;

		if (after(TCP_SKB_CB(skb)->end_seq, serval_tcp_wnd_end(tp)))
			break;

		serval_tcp_collapse_retrans(sk, to);
	}
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
int serval_tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned int cur_mss;
	int err;

	/* Inconslusive MTU probe */
	if (tp->tp_mtup.probe_size)
		tp->tp_mtup.probe_size = 0;

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 */
	if (atomic_read(&sk->sk_wmem_alloc) >
	    min(sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2), sk->sk_sndbuf))
		return -EAGAIN;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			BUG();
		if (serval_tcp_trim_head(sk, skb,
					 tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	if (serval_sock_refresh_dest(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = serval_tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, serval_tcp_wnd_end(tp)) &&
	    TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	if (skb->len > cur_mss) {
		if (serval_tcp_fragment(sk, skb, cur_mss, cur_mss))
			return -ENOMEM; /* We'll try again later. */
	} else {
		int oldpcount = serval_tcp_skb_pcount(skb);

		if (unlikely(oldpcount > 1)) {
			serval_tcp_init_tso_segs(sk, skb, cur_mss);
			serval_tcp_adjust_pcount(sk, skb, oldpcount -
						 serval_tcp_skb_pcount(skb));
		}
	}

	serval_tcp_retrans_try_collapse(sk, skb, cur_mss);

	/* Some Solaris stacks overoptimize and ignore the FIN on a
	 * retransmit when old data is attached.  So strip it off
	 * since it is cheap to do so and saves bytes on the network.
	 */
	if (skb->len > 0 &&
	    (TCP_SKB_CB(skb)->tcp_flags & TCPH_FIN) &&
	    tp->snd_una == (TCP_SKB_CB(skb)->end_seq - 1)) {
		if (!pskb_trim(skb, 0)) {
			/* Reuse, even though it does some unnecessary work */
			serval_tcp_init_nondata_skb(skb,
				TCP_SKB_CB(skb)->end_seq - 1,
				TCP_SKB_CB(skb)->tcp_flags);
			skb->ip_summed = CHECKSUM_NONE;
		}
	}

	/* Make a copy, if the first transmission SKB clone we made
	 * is still in somebody's hands, else make a clone.
	 */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;

	err = serval_tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);

	if (err == 0) {
		/* Update global TCP statistics. */
		/* TCP_INC_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS); */

		tp->total_retrans++;

		if (!tp->retrans_out)
			tp->lost_retrans_low = tp->snd_nxt;
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		tp->retrans_out += serval_tcp_skb_pcount(skb);

		/* Save stamp of the first retransmit. */
		if (!tp->retrans_stamp)
			tp->retrans_stamp = TCP_SKB_CB(skb)->when;

		tp->undo_retrans++;

		/* snd_nxt is stored to detect loss of retransmitted segment,
		 * see tcp_input.c tcp_sacktag_write_queue().
		 */
		TCP_SKB_CB(skb)->ack_seq = tp->snd_nxt;
	}
	return err;
}

/* Try to defer sending, if possible, in order to minimize the amount
 * of TSO splitting we do.  View it as a kind of TSO Nagle test.
 *
 * This algorithm is from John Heffner.
 */
static int serval_tcp_tso_should_defer(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 send_win, cong_win, limit, in_flight;
	int win_divisor;

	if (TCP_SKB_CB(skb)->tcp_flags & TCPH_FIN)
		goto send_now;

	if (tp->ca_state != TCP_CA_Open)
		goto send_now;

	/* Defer for less than two clock ticks. */
	if (tp->tso_deferred &&
	    (((u32)jiffies << 1) >> 1) - (tp->tso_deferred >> 1) > 1)
		goto send_now;

	in_flight = serval_tcp_packets_in_flight(tp);

	BUG_ON(serval_tcp_skb_pcount(skb) <= 1 || (tp->snd_cwnd <= in_flight));

	send_win = serval_tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

	/* From in_flight test above, we know that cwnd > in_flight.  */
	cong_win = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	limit = min(send_win, cong_win);

	/* If a full-sized TSO skb can be sent, do it. */
	if (limit >= sk->sk_gso_max_size)
		goto send_now;

	/* Middle in queue won't get any more data, full sendable already? */
	if ((skb != serval_tcp_write_queue_tail(sk)) && (limit >= skb->len))
		goto send_now;

	win_divisor = ACCESS_ONCE(sysctl_serval_tcp_tso_win_divisor);

	if (win_divisor) {
		u32 chunk = min(tp->snd_wnd, tp->snd_cwnd * tp->mss_cache);

		/* If at least some fraction of a window is available,
		 * just use it.
		 */
		chunk /= win_divisor;
		if (limit >= chunk)
			goto send_now;
	} else {
		/* Different approach, try not to defer past a single
		 * ACK.  Receiver should ACK every other full sized
		 * frame, so if we have space for more than 3 frames
		 * then send now.
		 */
		if (limit > serval_tcp_max_burst(tp) * tp->mss_cache)
			goto send_now;
	}

	/* Ok, it looks like it is advisable to defer.  */
	tp->tso_deferred = 1 | (jiffies << 1);

	return 1;

send_now:
	tp->tso_deferred = 0;
	return 0;
}

/* Create a new MTU probe if we are ready.
 * MTU probe is regularly attempting to increase the path MTU by
 * deliberately sending larger packets.  This discovers routing
 * changes resulting in larger path MTUs.
 *
 * Returns 0 if we should wait to probe (no cwnd available),
 *	 1 if a probe was sent,
 *	 -1 otherwise
 */
static int serval_tcp_mtu_probe(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb, *nskb, *next;
	int len;
	int probe_size;
	int size_needed;
	int copy;
	int mss_now;

	/* Not currently probing/verifying,
	 * not in recovery,
	 * have enough cwnd, and
	 * not SACKing (the variable headers throw things off) */
	if (!tp->tp_mtup.enabled ||
	    tp->tp_mtup.probe_size ||
	    tp->ca_state != TCP_CA_Open ||
	    tp->snd_cwnd < 11 ||
	    tp->rx_opt.num_sacks || tp->rx_opt.dsack)
		return -1;

	/* Very simple search strategy: just double the MSS. */
	mss_now = serval_tcp_current_mss(sk);
	probe_size = 2 * tp->mss_cache;
	size_needed = probe_size + (tp->reordering + 1) * tp->mss_cache;
	if (probe_size > serval_tcp_mtu_to_mss(sk, tp->tp_mtup.search_high)) {
		/* XXX Set timer for probe_converge_event. */
		return -1;
	}

	/* Have enough data in the send queue to probe? */
	if (tp->write_seq - tp->snd_nxt < size_needed)
		return -1;

	if (tp->snd_wnd < size_needed)
		return -1;
	if (after(tp->snd_nxt + size_needed, serval_tcp_wnd_end(tp)))
		return 0;

	/* Do we need to wait to drain cwnd? With none in flight,
	   don't stall */
	if (serval_tcp_packets_in_flight(tp) + 2 > tp->snd_cwnd) {
		if (!serval_tcp_packets_in_flight(tp))
			return -1;
		else
			return 0;
	}

	/* We're allowed to probe.  Build it now. */
	if ((nskb = serval_sk_stream_alloc_skb(sk, probe_size, GFP_ATOMIC)) ==
		NULL)
		return -1;
	sk->sk_wmem_queued += nskb->truesize;
	sk_mem_charge(sk, nskb->truesize);

	skb = serval_tcp_send_head(sk);

	TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(skb)->seq;
	TCP_SKB_CB(nskb)->end_seq = TCP_SKB_CB(skb)->seq + probe_size;
	TCP_SKB_CB(nskb)->tcp_flags = TCPH_ACK;
	TCP_SKB_CB(nskb)->sacked = 0;
	nskb->csum = 0;
	nskb->ip_summed = skb->ip_summed;

	serval_tcp_insert_write_queue_before(nskb, skb, sk);

	len = 0;
	serval_tcp_for_write_queue_from_safe(skb, next, sk) {
		copy = min_t(int, skb->len, probe_size - len);
		if (nskb->ip_summed)
			skb_copy_bits(skb, 0, skb_put(nskb, copy), copy);
		else
			nskb->csum = skb_copy_and_csum_bits(skb, 0,
							    skb_put(nskb, copy),
							    copy, nskb->csum);

		if (skb->len <= copy) {
			/* We've eaten all the data from this skb.
			 * Throw it away. */
			TCP_SKB_CB(nskb)->tcp_flags |=
				TCP_SKB_CB(skb)->tcp_flags;
			serval_tcp_unlink_write_queue(skb, sk);
			sk_wmem_free_skb(sk, skb);
		} else {
			TCP_SKB_CB(nskb)->tcp_flags |=
				TCP_SKB_CB(skb)->tcp_flags &
				 ~(TCPH_FIN|TCPH_PSH);
			if (!skb_shinfo(skb)->nr_frags) {
				skb_pull(skb, copy);
				if (skb->ip_summed != CHECKSUM_PARTIAL)
					skb->csum = csum_partial(skb->data,
								 skb->len, 0);
			} else {
				__pskb_trim_head(skb, copy);
				serval_tcp_set_skb_tso_segs(sk, skb, mss_now);
			}
			TCP_SKB_CB(skb)->seq += copy;
		}

		len += copy;

		if (len >= probe_size)
			break;
	}
	serval_tcp_init_tso_segs(sk, nskb, nskb->len);

	/* We're ready to send.  If this fails, the probe will
	 * be resegmented into mss-sized pieces by tcp_write_xmit(). */
	TCP_SKB_CB(nskb)->when = tcp_time_stamp;
	if (!serval_tcp_transmit_skb(sk, nskb, 1, GFP_ATOMIC)) {
		/* Decrement cwnd here because we are sending
		 * effectively two packets. */
		tp->snd_cwnd--;
		serval_tcp_event_new_data_sent(sk, nskb);

		tp->tp_mtup.probe_size = serval_tcp_mss_to_mtu(sk, nskb->len);
		tp->mtu_probe.probe_seq_start = TCP_SKB_CB(nskb)->seq;
		tp->mtu_probe.probe_seq_end = TCP_SKB_CB(nskb)->end_seq;

		return 1;
	}

	return -1;
}

/* Trim TSO SKB to LEN bytes, put the remaining data into a new packet
 * which is put after SKB on the list.  It is very much like
 * tcp_fragment() except that it may make several kinds of assumptions
 * in order to speed up the splitting operation.  In particular, we
 * know that all the data is in scatter-gather pages, and that the
 * packet has never been sent out before (and thus is not cloned).
 */
static int serval_tso_fragment(struct sock *sk, struct sk_buff *skb,
			       unsigned int len, unsigned int mss_now,
			       gfp_t gfp)
{
	struct sk_buff *buff;
	int nlen = skb->len - len;
	u8 flags;

	/* All of a TSO frame must be composed of paged data.  */
	if (skb->len != skb->data_len)
		return serval_tcp_fragment(sk, skb, len, mss_now);

	buff = serval_sk_stream_alloc_skb(sk, 0, gfp);
	if (unlikely(buff == NULL))
		return -ENOMEM;

	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPH_FIN | TCPH_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;

	/* This packet was never sent out yet, so no SACK bits. */
	TCP_SKB_CB(buff)->sacked = 0;

	buff->ip_summed = skb->ip_summed = CHECKSUM_PARTIAL;
	skb_split(skb, buff, len);

	/* Fix up tso_factor for both original and new SKB.  */
	serval_tcp_set_skb_tso_segs(sk, skb, mss_now);
	serval_tcp_set_skb_tso_segs(sk, buff, mss_now);

	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	serval_tcp_insert_write_queue_after(skb, buff, sk);

	return 0;
}

static int serval_tcp_write_xmit(struct sock *sk, unsigned int mss_now,
				 int nonagle, int push_one, gfp_t gfp)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;

	sent_pkts = 0;

	if (!push_one) {
		/* Do MTU probing. */

		result = serval_tcp_mtu_probe(sk);

		if (!result) {
			return 0;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}

	while ((skb = serval_tcp_send_head(sk))) {
		unsigned int limit;

		tso_segs = serval_tcp_init_tso_segs(sk, skb, mss_now);
		BUG_ON(!tso_segs);

		cwnd_quota = serval_tcp_cwnd_test(tp, skb);

		if (!cwnd_quota)
			break;

		if (unlikely(!serval_tcp_snd_wnd_test(tp, skb, mss_now)))
			break;

		if (tso_segs == 1) {
			if (unlikely(!serval_tcp_nagle_test(tp, skb, mss_now,
				(serval_tcp_skb_is_last(sk, skb)
					? nonagle
					: TCP_NAGLE_PUSH))))
				break;
		} else {
			if (!push_one && serval_tcp_tso_should_defer(sk, skb))
				break;
		}

		limit = mss_now;
		if (tso_segs > 1 && !serval_tcp_urg_mode(tp))
			limit = serval_tcp_mss_split_point(sk, skb, mss_now,
							   cwnd_quota);


		if (skb->len > limit &&
		    unlikely(serval_tso_fragment(sk, skb, limit, mss_now, gfp)))
			break;

		TCP_SKB_CB(skb)->when = tcp_time_stamp;

		if (unlikely(serval_tcp_transmit_skb(sk, skb, 1, gfp)))
			break;

		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		serval_tcp_event_new_data_sent(sk, skb);

		serval_tcp_minshall_update(tp, mss_now, skb);
		sent_pkts++;

		if (push_one)
			break;
	}

	if (likely(sent_pkts)) {
		serval_tcp_cwnd_validate(sk);
		return 0;
	}

	return !tp->packets_out && serval_tcp_send_head(sk);
}

/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
void __serval_tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
				      int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

	if (serval_tcp_write_xmit(sk, cur_mss, nonagle, 0, GFP_ATOMIC))
		serval_tcp_check_probe_timer(sk);
}

/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
void serval_tcp_push_one(struct sock *sk, unsigned int mss_now)
{
	struct sk_buff *skb = serval_tcp_send_head(sk);
	BUG_ON(!skb || skb->len < mss_now);
	serval_tcp_write_xmit(sk, mss_now, TCP_NAGLE_PUSH,
			      1, sk->sk_allocation);
}

/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 *
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 *
 * BSD seems to make the following compromise:
 *
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
u32 __serval_tcp_select_window(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = tp->tp_ack.rcv_mss;
	int free_space = serval_tcp_space(sk);
	int full_space = min_t(int, tp->window_clamp,
			       serval_tcp_full_space(sk));
	int window;

	if (mss > full_space)
		mss = full_space;

	if (free_space < (full_space >> 1)) {
		tp->tp_ack.quick = 0;

		if (serval_tcp_memory_pressure)
			tp->rcv_ssthresh = min(tp->rcv_ssthresh,
					       4U * tp->advmss);

		if (free_space < mss)
			return 0;
	}

	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	window = tp->rcv_wnd;
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		if (((window >> tp->rx_opt.rcv_wscale) <<
		     tp->rx_opt.rcv_wscale) != window)
			window = (((window >> tp->rx_opt.rcv_wscale) + 1)
				  << tp->rx_opt.rcv_wscale);
	} else {
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		if (window <= free_space - mss || window > free_space)
			window = (free_space / mss) * mss;
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
	}

	return window;
}

/* MTU probing init per socket */
void serval_tcp_mtup_init(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	tp->tp_mtup.enabled = sysctl_serval_tcp_mtu_probing > 1;
	tp->tp_mtup.search_high =
		tp->rx_opt.mss_clamp + sizeof(struct tcphdr) +
		sk_ssk(sk)->af_ops->net_header_len;
	tp->tp_mtup.search_low =
		serval_tcp_mss_to_mtu(sk, sysctl_serval_tcp_base_mss);
	tp->tp_mtup.probe_size = 0;
}

/* This function synchronizes snd mss to current pmtu/exthdr set.
 *
 * tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
 * for TCP options, but includes only bare TCP header.
 *
 * tp->rx_opt.mss_clamp is mss negotiated at connection setup.
 * It is minimum of user_mss and mss received with SYN.
 * It also does not include TCP options.
 *
 * tp->mss_cache is current effective sending mss, including
 * all tcp options except for SACKs. It is evaluated,
 * taking into account current pmtu, but never exceeds
 * tp->rx_opt.mss_clamp.
 *
 * NOTE1. rfc1122 clearly states that advertised MSS
 * DOES NOT include either tcp or ip options.	--ANK (980731)
 */
unsigned int serval_tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int mss_now;

	if (tp->tp_mtup.search_high > pmtu)
		tp->tp_mtup.search_high = pmtu;

	mss_now = serval_tcp_mtu_to_mss(sk, pmtu);

	mss_now = serval_tcp_bound_to_half_wnd(tp, mss_now);

	/* And store cached results */
	tp->pmtu_cookie = pmtu;

	if (tp->tp_mtup.enabled) {
		mss_now = min(mss_now,
			      serval_tcp_mtu_to_mss(sk,
						    tp->tp_mtup.search_low));
	}

	tp->mss_cache = mss_now;

	return mss_now;
}

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 */
unsigned int serval_tcp_current_mss(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned header_len;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5;

	mss_now = tp->mss_cache;

	if (dst) {
		u32 mtu = dst_mtu(dst);
		if (mtu != tp->pmtu_cookie)
			mss_now = serval_tcp_sync_mss(sk, mtu);
	}

	header_len = serval_tcp_established_options(sk, NULL, &opts, &md5) +
		sizeof(struct tcphdr);
	/* The mss_cache is sized based on tp->tcp_header_len, which assumes
	 * some common options. If this is an odd packet (because we have SACK
	 * blocks etc) then our calculated header_len will be different, and
	 * we have to adjust mss_now correspondingly */
	if (header_len != tp->tcp_header_len) {
		int delta = (int) header_len - tp->tcp_header_len;
		mss_now -= delta;
	}

	return mss_now;
}

/* XXX Lots of hard coded stuff in this init function as the user
 * space version of the stack does not have dst cache
 * implemented. Therefore we cannot access the default dst_metrics.
 *
 * Further, __sk_dst_get(sk) will return NULL here, even in the
 * kernel. This is because the normal TCP/IP stack always routes a SYN
 * before transmission (i.e., it associates the socket with a route
 * that contains metrics). However, we cannot really route here, since
 * we do not know the destination --- it is resolved on the SYN.
 */
static void serval_tcp_connect_init(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	__u8 rcv_wscale;
	struct dst_entry *dst = __sk_dst_get(sk);
	unsigned int initrwnd = dst ? dst_metric(dst, RTAX_WINDOW) : 65535;
	tp->tcp_header_len = sizeof(struct tcphdr);

	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;

	serval_tcp_mtup_init(sk);

	if (dst)
		serval_tcp_sync_mss(sk, dst_mtu(dst));
	else
		serval_tcp_sync_mss(sk, 1500);

	if (!tp->window_clamp)
		tp->window_clamp = dst ? dst_metric(dst, RTAX_WINDOW) : 0;

	tp->advmss = dst ? dst_metric_advmss(dst) : SERVAL_TCP_MSS_INIT;

	if (tp->rx_opt.user_mss && tp->rx_opt.user_mss < tp->advmss)
		tp->advmss = tp->rx_opt.user_mss;

	serval_tcp_initialize_rcv_mss(sk);

	serval_tcp_select_initial_window(serval_tcp_full_space(sk),
		tp->advmss - (tp->rx_opt.ts_recent_stamp
			? tp->tcp_header_len - sizeof(struct tcphdr)
			: 0),
		&tp->rcv_wnd, &tp->window_clamp,
		sysctl_serval_tcp_window_scaling, &rcv_wscale, initrwnd);

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	serval_tcp_init_wl(tp, 0);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	tp->rcv_nxt = 0;
	tp->rcv_wup = 0;
	tp->copied_seq = 0;

	tp->rto = SERVAL_TCP_TIMEOUT_INIT;
	tp->retransmits = 0;
	serval_tcp_clear_retrans(tp);
}

int serval_tcp_connection_build_syn(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct tcp_out_options opts;
	unsigned int tcp_options_size, tcp_header_size;
	struct tcp_md5sig_key *md5;
	struct tcphdr *th;

	/* From tcp_ipv4.c */
	tp->rx_opt.mss_clamp = SERVAL_TCP_MSS_DEFAULT;

	if (!tp->write_seq)
		tp->write_seq = serval_tcp_random_sequence_number();

	serval_tcp_connect_init(sk);

	tcp_options_size = serval_tcp_syn_options(sk, skb, &opts, &md5);
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	th = (struct tcphdr *)skb_push(skb, tcp_header_size);
	if (!th)
		return -1;

	skb_reset_transport_header(skb);

	tp->snd_nxt = tp->write_seq;
	serval_tcp_init_nondata_skb(skb, tp->write_seq++, TCPH_SYN);

	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	tp->retrans_stamp = TCP_SKB_CB(skb)->when;

	memset(th, 0, tcp_header_size);
	th->seq			= htonl(TCP_SKB_CB(skb)->seq);
	th->ack_seq		= htonl(tp->rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					TCP_SKB_CB(skb)->tcp_flags);
	th->check = 0;
	/* tp->packets_out += serval_tcp_skb_pcount(skb); */

	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;

	serval_tcp_options_write((__be32 *)(th + 1), tp, &opts);

	__serval_tcp_v4_send_check(skb);
	return 0;
}

int serval_tcp_connection_build_synack(struct sock *sk, struct dst_entry *dst,
				       struct request_sock *req,
				       struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct serval_tcp_request_sock *trsk = serval_tcp_rsk(req);
	unsigned tcp_options_size, tcp_header_size;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5 = NULL;
	struct tcphdr *th;
	int mss;

	mss = dst_metric_advmss(dst);

	if (req->rcv_wnd == 0) { /* ignored for retransmitted syns */
		__u8 rcv_wscale;
		/* Set this up on the first call only */

		req->window_clamp = tp->window_clamp ? :
			dst_metric(dst, RTAX_WINDOW);
		/* tcp_full_space because it is guaranteed to be the
		 * first packet */
		serval_tcp_select_initial_window(serval_tcp_full_space(sk),
			mss - (trsk->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
			&req->rcv_wnd, &req->window_clamp, trsk->wscale_ok,
			&rcv_wscale, dst_metric(dst, RTAX_INITRWND));
		trsk->rcv_wscale = rcv_wscale;
	}

	serval_tcp_init_nondata_skb(skb, trsk->snt_isn, TCPH_SYN | TCPH_ACK);

	memset(&opts, 0, sizeof(opts));
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	tcp_options_size = serval_tcp_synack_options(sk, trsk, mss,
						     skb, &opts, &md5);
	tcp_header_size = tcp_options_size  + sizeof(struct tcphdr);

	th = (struct tcphdr *)skb_push(skb, tcp_header_size);

	if (!th)
		return -1;

	skb_reset_transport_header(skb);

	memset(th, 0, tcp_header_size);
	th->seq = htonl(trsk->snt_isn);
	th->ack_seq = htonl(trsk->rcv_isn + 1);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					TCP_SKB_CB(skb)->tcp_flags);
	th->check = 0;
	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	th->window = htons(min(req->rcv_wnd, 65535U));
	serval_tcp_options_write((__be32 *)(th + 1), tp, &opts);

	__serval_tcp_v4_send_check(skb);

	/* XXX Call serval_tcp_event_ack_sent? Not sure, since we
	 * haven't sent any data at this point.
	 */
	/*
	if (likely(tcb->tcp_flags & TCPH_ACK))
		serval_tcp_event_ack_sent(sk, serval_tcp_skb_pcount(skb));
	*/

	return 0;
}

int serval_tcp_connection_build_ack(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned int tcp_header_size = sizeof(struct tcphdr);
	struct tcphdr *th;

	th = (struct tcphdr *)skb_push(skb, tcp_header_size);

	if (!th)
		return -1;

	skb_reset_transport_header(skb);

	serval_tcp_init_nondata_skb(skb, serval_tcp_acceptable_seq(sk),
				    TCPH_ACK);
	memset(th, 0, tcp_header_size);
	th->seq = htonl(TCP_SKB_CB(skb)->seq);
	th->ack_seq = htonl(tp->rcv_nxt);
	th->window = htons(serval_tcp_select_window(sk));
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					TCP_SKB_CB(skb)->tcp_flags);
	th->check = 0;
	th->urg_ptr = 0;

	TCP_SKB_CB(skb)->when = tcp_time_stamp;

	if (sk_ssk(sk)->af_ops->send_check)
		sk_ssk(sk)->af_ops->send_check(sk, skb);

	/* XXX Call serval_tcp_event_ack_sent? Not sure, since we
	 * haven't sent any data at this point.
	 */
	/*
	if (likely(tcb->tcp_flags & TCPH_ACK))
		serval_tcp_event_ack_sent(sk, serval_tcp_skb_pcount(skb));
	*/

	return 0;
}

/* Send out a delayed ack, the caller does the policy checking
 * to see if we should even be here.  See tcp_input.c:tcp_ack_snd_check()
 * for details.
 */
void serval_tcp_send_delayed_ack(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int ato = tp->tp_ack.ato;
	unsigned long timeout;

	if (ato > TCP_DELACK_MIN) {
		int max_ato = HZ / 2;

		if (tp->tp_ack.pingpong ||
		    (tp->tp_ack.pending & STSK_ACK_PUSHED))
			max_ato = TCP_DELACK_MAX;

		/* Slow path, intersegment interval is "high". */

		/* If some rtt estimate is known, use it to bound delayed ack.*/
		if (tp->srtt) {
			int rtt = max(tp->srtt >> 3, TCP_DELACK_MIN);

			if (rtt < max_ato)
				max_ato = rtt;
		}

		ato = min(ato, max_ato);
	}

	/* Stay within the limit we were given */
	timeout = jiffies + ato;

	/* Use new timeout only if there wasn't a older one earlier. */
	if (tp->tp_ack.pending & STSK_ACK_TIMER) {
		/* If delack timer was blocked or is about to expire,
		 * send ACK now.
		 */
		if (tp->tp_ack.blocked ||
		    time_before_eq(tp->tp_ack.timeout, jiffies + (ato >> 2))) {
			serval_tcp_send_ack(sk);
			return;
		}

		if (!time_before(timeout, tp->tp_ack.timeout))
			timeout = tp->tp_ack.timeout;
	}
	tp->tp_ack.pending |= STSK_ACK_SCHED | STSK_ACK_TIMER;
	tp->tp_ack.timeout = timeout;
	sk_reset_timer(sk, &tp->delack_timer, timeout);
}

/* Check if we forward retransmits are possible in the current
 * window/congestion state.
 */
static int serval_tcp_can_forward_retransmit(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* Forward retransmissions are possible only during Recovery. */
	if (tp->ca_state != TCP_CA_Recovery)
		return 0;

	/* No forward retransmissions in Reno are possible. */
	if (serval_tcp_is_reno(tp))
		return 0;

	/* Yeah, we have to make difficult choice between forward transmission
	 * and retransmission... Both ways have their merits...
	 *
	 * For now we do not retransmit anything, while we have some new
	 * segments to send. In the other cases, follow rule 3 for
	 * NextSeg() specified in RFC3517.
	 */

	if (serval_tcp_may_send_now(sk))
		return 0;

	return 1;
}

/* This gets called after a retransmit timeout, and the initially
 * retransmitted data is acknowledged.  It tries to continue
 * resending the rest of the retransmit queue, until either
 * we've sent it all or the congestion window limit is reached.
 * If doing SACK, the first ACK which comes back for a timeout
 * based retransmit packet might feed us FACK information again.
 * If so, we use it to avoid unnecessarily retransmissions.
 */
void serval_tcp_xmit_retransmit_queue(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	struct sk_buff *hole = NULL;
	u32 last_lost;
	int fwd_rexmitting = 0;

	if (!tp->packets_out)
		return;

	if (!tp->lost_out)
		tp->retransmit_high = tp->snd_una;

	if (tp->retransmit_skb_hint) {
		skb = tp->retransmit_skb_hint;
		last_lost = TCP_SKB_CB(skb)->end_seq;
		if (after(last_lost, tp->retransmit_high))
			last_lost = tp->retransmit_high;
	} else {
		skb = serval_tcp_write_queue_head(sk);
		last_lost = tp->snd_una;
	}

	serval_tcp_for_write_queue_from(skb, sk) {
		__u8 sacked = TCP_SKB_CB(skb)->sacked;

		if (skb == serval_tcp_send_head(sk))
			break;
		/* we could do better than to assign each time */
		if (hole == NULL)
			tp->retransmit_skb_hint = skb;

		/* Assume this retransmit will generate
		 * only one packet for congestion window
		 * calculation purposes.  This works because
		 * tcp_retransmit_skb() will chop up the
		 * packet to be MSS sized and all the
		 * packet counting works out.
		 */
		if (serval_tcp_packets_in_flight(tp) >= tp->snd_cwnd)
			return;

		if (fwd_rexmitting) {
begin_fwd:
			if (!before(TCP_SKB_CB(skb)->seq,
				    serval_tcp_highest_sack_seq(tp)))
				break;
			/* mib_idx = LINUX_MIB_TCPFORWARDRETRANS; */

		} else if (!before(TCP_SKB_CB(skb)->seq, tp->retransmit_high)) {
			tp->retransmit_high = last_lost;
			if (!serval_tcp_can_forward_retransmit(sk))
				break;
			/* Backtrack if necessary to non-L'ed skb */
			if (hole != NULL) {
				skb = hole;
				hole = NULL;
			}
			fwd_rexmitting = 1;
			goto begin_fwd;

		} else if (!(sacked & TCPCB_LOST)) {
			if (hole == NULL && !(sacked &
				(TCPCB_SACKED_RETRANS | TCPCB_SACKED_ACKED)))
				hole = skb;
			continue;

		} else {
			last_lost = TCP_SKB_CB(skb)->end_seq;
		}

		if (sacked & (TCPCB_SACKED_ACKED|TCPCB_SACKED_RETRANS))
			continue;

		if (serval_tcp_retransmit_skb(sk, skb))
			return;

		if (skb == serval_tcp_write_queue_head(sk))
			serval_tsk_reset_xmit_timer(sk, STSK_TIME_RETRANS,
						    tp->rto,
						    SERVAL_TCP_RTO_MAX);
	}
}

/* Send a fin.  The caller locks the socket for us.  This cannot be
 * allowed to fail queueing a FIN frame under any circumstances.
 */
void serval_tcp_send_fin(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb = serval_tcp_write_queue_tail(sk);
	int mss_now;

	/* Optimization, tack on the FIN if we have a queue of
	 * unsent frames.  But be careful about outgoing SACKS
	 * and IP options.
	 */
	mss_now = serval_tcp_current_mss(sk);

	if (serval_tcp_send_head(sk) != NULL) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPH_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		tp->write_seq++;
	} else {
		/* Socket is locked, keep trying until memory is available. */
		for (;;) {
			skb = alloc_skb_fclone(MAX_SERVAL_TCP_HEADER,
					       sk->sk_allocation);
			if (skb)
				break;
			yield();
		}

		/* Reserve space for headers and prepare control bits. */
		skb_reserve(skb, MAX_SERVAL_TCP_HEADER);
		/* FIN eats a sequence byte, write_seq advanced by
		 * tcp_queue_skb().
		 */
		serval_tcp_init_nondata_skb(skb, tp->write_seq,
					    TCPH_ACK | TCPH_FIN);
		serval_tcp_queue_skb(sk, skb);
	}
	__serval_tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF);
}

/* This routine sends an ack and also updates the window. */
void serval_tcp_send_ack(struct sock *sk)
{
	struct sk_buff *buff;

	/* If we have been reset, we may not send again. */
	if (sk->sk_state == TCP_CLOSE)
		return;

	/* We are not putting this on the write queue, so
	 * tcp_transmit_skb() will set the ownership to this
	 * sock.
	 */
	buff = alloc_skb(MAX_SERVAL_TCP_HEADER, GFP_ATOMIC);

	if (buff == NULL) {
		serval_tsk_schedule_ack(sk);
		serval_tcp_sk(sk)->tp_ack.ato = TCP_ATO_MIN;
		serval_tsk_reset_xmit_timer(sk, STSK_TIME_DACK,
					    TCP_DELACK_MAX, SERVAL_TCP_RTO_MAX);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(buff, MAX_SERVAL_TCP_HEADER);
	serval_tcp_init_nondata_skb(buff,
				    serval_tcp_acceptable_seq(sk),
				    TCPH_ACK);

	/* Send it off, this clears delayed acks for us. */
	TCP_SKB_CB(buff)->when = tcp_time_stamp;
	serval_tcp_transmit_skb(sk, buff, 0, GFP_ATOMIC);
}

/* This routine sends a packet with an out of date sequence
 * number. It assumes the other end will try to ack it.
 *
 * Question: what should we make while urgent mode?
 * 4.4BSD forces sending single byte of data. We cannot send
 * out of window data, because we have SND.NXT==SND.MAX...
 *
 * Current solution: to send TWO zero-length segments in urgent mode:
 * one is with SEG.SEQ=SND.UNA to deliver urgent pointer, another is
 * out-of-date with SND.UNA-1 to probe window.
 */
static int serval_tcp_xmit_probe_skb(struct sock *sk, int urgent)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_SERVAL_TCP_HEADER, GFP_ATOMIC);
	if (skb == NULL)
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_SERVAL_TCP_HEADER);
	/* Use a previous sequence.  This should cause the other
	 * end to send an ack.  Don't queue or clone SKB, just
	 * send it.
	 */
	serval_tcp_init_nondata_skb(skb, tp->snd_una - !urgent, TCPH_ACK);
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	return serval_tcp_transmit_skb(sk, skb, 0, GFP_ATOMIC);
}

/* Initiate keepalive or window probe from timer. */
int serval_tcp_write_wakeup(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE)
		return -1;

	if ((skb = serval_tcp_send_head(sk)) != NULL &&
	    before(TCP_SKB_CB(skb)->seq, serval_tcp_wnd_end(tp))) {
		int err;
		unsigned int mss = serval_tcp_current_mss(sk);
		unsigned int seg_size =
			serval_tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

		if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

		/* We are probing the opening of a window
		 * but the window size is != 0
		 * must have been a result SWS avoidance ( sender )
		 */
		if (seg_size <
			TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||
			skb->len > mss) {
			seg_size = min(seg_size, mss);
			TCP_SKB_CB(skb)->tcp_flags |= TCPH_PSH;
			if (serval_tcp_fragment(sk, skb, seg_size, mss))
				return -1;
		} else if (!serval_tcp_skb_pcount(skb))
			serval_tcp_set_skb_tso_segs(sk, skb, mss);

		TCP_SKB_CB(skb)->tcp_flags |= TCPH_PSH;
		TCP_SKB_CB(skb)->when = tcp_time_stamp;
		err = serval_tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
		if (!err)
			serval_tcp_event_new_data_sent(sk, skb);
		return err;
	} else {
		if (between(tp->snd_up, tp->snd_una + 1, tp->snd_una + 0xFFFF))
			serval_tcp_xmit_probe_skb(sk, 1);
		return serval_tcp_xmit_probe_skb(sk, 0);
	}
}

/* A window probe timeout has occurred.  If window is not closed send
 * a partial packet else a zero probe.
 */
void serval_tcp_send_probe0(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int err;

	err = serval_tcp_write_wakeup(sk);

	if (tp->packets_out || !serval_tcp_send_head(sk)) {
		/* Cancel probe timer, if it is not required. */
		tp->probes_out = 0;
		tp->backoff = 0;
		return;
	}

	if (err <= 0) {
		if (tp->backoff < sysctl_serval_tcp_retries2)
			tp->backoff++;
		tp->probes_out++;
		serval_tsk_reset_xmit_timer(sk, STSK_TIME_PROBE0,
					    min(tp->rto << tp->backoff,
						SERVAL_TCP_RTO_MAX),
					    SERVAL_TCP_RTO_MAX);
	} else {
		/* If packet was not sent due to local congestion,
		 * do not backoff and do not remember icsk_probes_out.
		 * Let local senders to fight for local resources.
		 *
		 * Use accumulated backoff yet.
		 */
		if (!tp->probes_out)
			tp->probes_out = 1;
		serval_tsk_reset_xmit_timer(sk, STSK_TIME_PROBE0,
			min(tp->rto << tp->backoff,
				SERVAL_TCP_RESOURCE_PROBE_INTERVAL),
			SERVAL_TCP_RTO_MAX);
	}
}

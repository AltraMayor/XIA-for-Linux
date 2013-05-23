/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <platform.h>
#include <debug.h>
#include <netdevice.h>
#include <netinet_serval.h>
#include <serval_tcp_sock.h>
#include <serval_tcp.h>
#if defined(OS_LINUX_KERNEL)
#include <asm/unaligned.h>
#include <net/netdma.h>
#endif
#if defined(OS_USER)
#define NR_FILE 1 /* TODO: set appropriate value */
#endif

int sysctl_serval_tcp_timestamps __read_mostly = 0;
int sysctl_serval_tcp_reordering __read_mostly = SERVAL_TCP_FASTRETRANS_THRESH;
int sysctl_serval_tcp_moderate_rcvbuf __read_mostly = 1;
int sysctl_serval_tcp_abc __read_mostly;
int sysctl_serval_tcp_adv_win_scale __read_mostly = 2;
int sysctl_serval_tcp_app_win __read_mostly = 31;
int sysctl_serval_tcp_max_orphans __read_mostly = NR_FILE;
int sysctl_serval_tcp_thin_dupack __read_mostly;


#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
#define FLAG_DATA_LOST		0x80 /* SACK detected data lossage.		*/
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_ONLY_ORIG_SACKED	0x200 /* SACKs only non-rexmit sent before RTO */
#define FLAG_SND_UNA_ADVANCED	0x400 /* Snd_una was changed (!= FLAG_DATA_ACKED) */
#define FLAG_DSACKING_ACK	0x800 /* SACK blocks contained D-SACK info */
#define FLAG_NONHEAD_RETRANS_ACKED	0x1000 /* Non-head rexmitted data was ACKed */
#define FLAG_SACK_RENEGING	0x2000 /* snd_una advanced to a sacked seq */
#define FLAG_FIN_ACKED          0x4000

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)
#define FLAG_ANY_PROGRESS	(FLAG_FORWARD_PROGRESS|FLAG_SND_UNA_ADVANCED)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))


/* Adapt the MSS value used to make delayed ack decision to the
 * real world.
 */
static void serval_tcp_measure_rcv_mss(struct sock *sk, 
                                       const struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	const unsigned int lss = tp->tp_ack.last_seg_size;
	unsigned int len;

	tp->tp_ack.last_seg_size = 0;

	/* skb->len may jitter because of SACKs, even if peer
	 * sends good full-sized frames.
	 */
	len = skb_shinfo(skb)->gso_size ? : skb->len;
	if (len >= tp->tp_ack.rcv_mss) {
		tp->tp_ack.rcv_mss = len;
	} else {
		/* Otherwise, we make more careful check taking into account,
		 * that SACKs block is variable.
		 *
		 * "len" is invariant segment length, including TCP header.
		 */
		len += skb->data - skb_transport_header(skb);
		if (len >= SERVAL_TCP_MSS_DEFAULT + sizeof(struct tcphdr) ||
		    /* If PSH is not set, packet should be
		     * full sized, provided peer TCP is not badly broken.
		     * This observation (if it is correct 8)) allows
		     * to handle super-low mtu links fairly.
		     */
		    (len >= SERVAL_TCP_MIN_MSS + sizeof(struct tcphdr) &&
		     !(serval_tcp_flag_word(tcp_hdr(skb)) & TCP_REMNANT))) {
			/* Subtract also invariant (if peer is RFC compliant),
			 * tcp header plus fixed timestamp option length.
			 * Resulting "len" is MSS free of SACK jitter.
			 */
			len -= tp->tcp_header_len;
			tp->tp_ack.last_seg_size = len;
			if (len == lss) {
				tp->tp_ack.rcv_mss = len;
				return;
			}
		}
		if (tp->tp_ack.pending & STSK_ACK_PUSHED)
			tp->tp_ack.pending |= STSK_ACK_PUSHED2;
		tp->tp_ack.pending |= STSK_ACK_PUSHED;
	}
}


/* Buffer size and advertised window tuning.
 *
 * 1. Tuning sk->sk_sndbuf, when connection enters established state.
 */

static void serval_tcp_fixup_sndbuf(struct sock *sk)
{
	int sndmem = serval_tcp_sk(sk)->rx_opt.mss_clamp + 
                MAX_SERVAL_TCP_HEADER + 16 + sizeof(struct sk_buff);

	if (sk->sk_sndbuf < 3 * sndmem)
		sk->sk_sndbuf = min(3 * sndmem, sysctl_serval_tcp_wmem[2]);
}

/* 2. Tuning advertised window (window_clamp, rcv_ssthresh)
 *
 * All tcp_full_space() is split to two parts: "network" buffer, allocated
 * forward and advertised in receiver window (tp->rcv_wnd) and
 * "application buffer", required to isolate scheduling/application
 * latencies from network.
 * window_clamp is maximal advertised window. It can be less than
 * tcp_full_space(), in this case tcp_full_space() - window_clamp
 * is reserved for "application" buffer. The less window_clamp is
 * the smoother our behaviour from viewpoint of network, but the lower
 * throughput and the higher sensitivity of the connection to losses. 8)
 *
 * rcv_ssthresh is more strict window_clamp used at "slow start"
 * phase to predict further behaviour of this connection.
 * It is used for two goals:
 * - to enforce header prediction at sender, even when application
 *   requires some significant "application buffer". It is check #1.
 * - to prevent pruning of receive queue because of misprediction
 *   of receiver window. Check #2.
 *
 * The scheme does not work when sender sends good segments opening
 * window and then starts to feed us spaghetti. But it should work
 * in common situations. Otherwise, we have to rely on queue collapsing.
 */

/* Slow part of check#2. */
static int __serval_tcp_grow_window(const struct sock *sk, 
                                    const struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	/* Optimize this! */
	int truesize = serval_tcp_win_from_space(skb->truesize) >> 1;
	int window = serval_tcp_win_from_space(sysctl_serval_tcp_rmem[2]) >> 1;

	while (tp->rcv_ssthresh <= window) {
		if (truesize <= skb->len)
			return 2 * tp->tp_ack.rcv_mss;

		truesize >>= 1;
		window >>= 1;
	}
	return 0;
}

static void serval_tcp_grow_window(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        
	/* Check #1 */
	if (tp->rcv_ssthresh < tp->window_clamp &&
	    (int)tp->rcv_ssthresh < serval_tcp_space(sk) &&
	    !serval_tcp_memory_pressure) {
		int incr;

		/* Check #2. Increase window, if skb with such overhead
		 * will fit to rcvbuf in future.
		 */
		if (serval_tcp_win_from_space(skb->truesize) <= skb->len)
			incr = 2 * tp->advmss;
		else
			incr = __serval_tcp_grow_window(sk, skb);

		if (incr) {
			tp->rcv_ssthresh = min(tp->rcv_ssthresh + incr,
					       tp->window_clamp);
			tp->tp_ack.quick |= 1;
		}
	}
}



/* 3. Tuning rcvbuf, when connection enters established state. */

static void serval_tcp_fixup_rcvbuf(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int rcvmem = tp->advmss + MAX_SERVAL_TCP_HEADER + 
                16 + sizeof(struct sk_buff);

	/* Try to select rcvbuf so that 4 mss-sized segments
	 * will fit to window and corresponding skbs will fit to our rcvbuf.
	 * (was 3; 4 is minimum to allow fast retransmit to work.)
	 */
	while (serval_tcp_win_from_space(rcvmem) < tp->advmss)
		rcvmem += 128;
	if (sk->sk_rcvbuf < 4 * rcvmem)
		sk->sk_rcvbuf = min(4 * rcvmem, sysctl_serval_tcp_rmem[2]);
}

/* 4. Try to fixup all. It is made immediately after connection enters
 *    established state.
 */
static void serval_tcp_init_buffer_space(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int maxwin;

	if (!(sk->sk_userlocks & SOCK_RCVBUF_LOCK))
		serval_tcp_fixup_rcvbuf(sk);
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK))
		serval_tcp_fixup_sndbuf(sk);
        
	tp->rcvq_space.space = tp->rcv_wnd;

	maxwin = serval_tcp_full_space(sk);

	if (tp->window_clamp >= maxwin) {
		tp->window_clamp = maxwin;

		if (sysctl_serval_tcp_app_win && maxwin > 4 * tp->advmss)
			tp->window_clamp = max(maxwin -
					       (maxwin >> sysctl_serval_tcp_app_win),
					       4 * tp->advmss);
	}

	/* Force reservation of one segment. */
	if (sysctl_serval_tcp_app_win &&
	    tp->window_clamp > 2 * tp->advmss &&
	    tp->window_clamp + tp->advmss > maxwin)
		tp->window_clamp = max(2 * tp->advmss, maxwin - tp->advmss);

	tp->rcv_ssthresh = min(tp->rcv_ssthresh, tp->window_clamp);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}


/* 5. Recalculate window clamp after socket hit its memory bounds. */
static void serval_tcp_clamp_window(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	tp->tp_ack.quick = 0;

	if (sk->sk_rcvbuf < sysctl_serval_tcp_rmem[2] &&
	    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK) &&
	    !serval_tcp_memory_pressure &&
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
	    atomic_read(&serval_tcp_memory_allocated) < sysctl_serval_tcp_mem[0]
#else
	    atomic_long_read(&serval_tcp_memory_allocated) < sysctl_serval_tcp_mem[0]
#endif
) {
		sk->sk_rcvbuf = min(atomic_read(&sk->sk_rmem_alloc),
				    sysctl_serval_tcp_rmem[2]);
	}
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf)
		tp->rcv_ssthresh = min(tp->window_clamp, 2U * tp->advmss);
}

static void serval_tcp_incr_quickack(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned quickacks = tp->rcv_wnd / (2 * tp->tp_ack.rcv_mss);

	if (quickacks == 0)
		quickacks = 2;
	if (quickacks > tp->tp_ack.quick)
		tp->tp_ack.quick = min(quickacks, TCP_MAX_QUICKACKS);
}


void serval_tcp_enter_quickack_mode(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	serval_tcp_incr_quickack(sk);
	tp->tp_ack.pingpong = 0;
	tp->tp_ack.ato = TCP_ATO_MIN;
}

/* Send ACKs quickly, if "quick" count is not exhausted
 * and the session is not interactive.
 */

static inline int serval_tcp_in_quickack_mode(const struct sock *sk)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	return tp->tp_ack.quick && !tp->tp_ack.pingpong;
}


static void serval_tcp_clear_retrans_partial(struct serval_tcp_sock *tp)
{
	tp->retrans_out = 0;
	tp->lost_out = 0;

	tp->undo_marker = 0;
	tp->undo_retrans = 0;
}

void serval_tcp_clear_retrans(struct serval_tcp_sock *tp)
{
	serval_tcp_clear_retrans_partial(tp);

	tp->fackets_out = 0;
	tp->sacked_out = 0;
}

/* Initialize RCV_MSS value.
 * RCV_MSS is an our guess about MSS used by the peer.
 * We haven't any direct information about the MSS.
 * It's better to underestimate the RCV_MSS rather than overestimate.
 * Overestimations make us ACKing less frequently than needed.
 * Underestimations are more easy to detect and fix by tcp_measure_rcv_mss().
 */
void serval_tcp_initialize_rcv_mss(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	unsigned int hint = min_t(unsigned int, tp->advmss, tp->mss_cache);

        LOG_SSK(sk, "tp->advmss=%u tp->mss_cache=%u tp->rcv_wnd/2=%u hint=%u\n",
                tp->advmss, tp->mss_cache, tp->rcv_wnd/2, hint);

	hint = min(hint, tp->rcv_wnd / 2);
	hint = min(hint, SERVAL_TCP_MSS_DEFAULT);
	hint = max(hint, SERVAL_TCP_MIN_MSS);

	tp->tp_ack.rcv_mss = hint;

        LOG_SSK(sk, "rcv_mss=%u\n", hint);
}


/* Receiver "autotuning" code.
 *
 * The algorithm for RTT estimation w/o timestamps is based on
 * Dynamic Right-Sizing (DRS) by Wu Feng and Mike Fisk of LANL.
 * <http://www.lanl.gov/radiant/website/pubs/drs/lacsi2001.ps>
 *
 * More detail on this code can be found at
 * <http://www.psc.edu/~jheffner/senior_thesis.ps>,
 * though this reference is out of date.  A new paper
 * is pending.
 */
static void serval_tcp_rcv_rtt_update(struct serval_tcp_sock *tp, 
                                      u32 sample, int win_dep)
{
	u32 new_sample = tp->rcv_rtt_est.rtt;
	long m = sample;

	if (m == 0)
		m = 1;

	if (new_sample != 0) {
		/* If we sample in larger samples in the non-timestamp
		 * case, we could grossly overestimate the RTT especially
		 * with chatty applications or bulk transfer apps which
		 * are stalled on filesystem I/O.
		 *
		 * Also, since we are only going for a minimum in the
		 * non-timestamp case, we do not smooth things out
		 * else with timestamps disabled convergence takes too
		 * long.
		 */
		if (!win_dep) {
			m -= (new_sample >> 3);
			new_sample += m;
		} else if (m < new_sample)
			new_sample = m << 3;
	} else {
		/* No previous measure. */
		new_sample = m << 3;
	}

	if (tp->rcv_rtt_est.rtt != new_sample)
		tp->rcv_rtt_est.rtt = new_sample;
}

static inline void serval_tcp_rcv_rtt_measure(struct serval_tcp_sock *tp)
{
	if (tp->rcv_rtt_est.time == 0)
		goto new_measure;
	if (before(tp->rcv_nxt, tp->rcv_rtt_est.seq))
		return;
	serval_tcp_rcv_rtt_update(tp, jiffies - tp->rcv_rtt_est.time, 1);

new_measure:
	tp->rcv_rtt_est.seq = tp->rcv_nxt + tp->rcv_wnd;
	tp->rcv_rtt_est.time = tcp_time_stamp;
}

static inline void serval_tcp_rcv_rtt_measure_ts(struct sock *sk,
                                                 struct sk_buff *skb)
{
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	if (tp->rx_opt.rcv_tsecr &&
	    (TCP_SKB_CB(skb)->end_seq -
	     TCP_SKB_CB(skb)->seq >= tp->tp_ack.rcv_mss))
		serval_tcp_rcv_rtt_update(tp, tcp_time_stamp - tp->rx_opt.rcv_tsecr, 0);
}

/*

 * This function should be called every time data is copied to user space.
 * It calculates the appropriate TCP receive buffer space.
 */
void serval_tcp_rcv_space_adjust(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int time;
	int space;
        
	if (tp->rcvq_space.time == 0)
		goto new_measure;

	time = tcp_time_stamp - tp->rcvq_space.time;
	if (time < (tp->rcv_rtt_est.rtt >> 3) || tp->rcv_rtt_est.rtt == 0)
		return;

	space = 2 * (tp->copied_seq - tp->rcvq_space.seq);

	space = max(tp->rcvq_space.space, space);

	if (tp->rcvq_space.space != space) {
		int rcvmem;

		tp->rcvq_space.space = space;

		if (sysctl_serval_tcp_moderate_rcvbuf &&
		    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK)) {
			int new_clamp = space;

			/* Receive space grows, normalize in order to
			 * take into account packet headers and sk_buff
			 * structure overhead.
			 */
			space /= tp->advmss;
			if (!space)
				space = 1;
			rcvmem = (tp->advmss + MAX_SERVAL_TCP_HEADER +
				  16 + sizeof(struct sk_buff));
			while (serval_tcp_win_from_space(rcvmem) < tp->advmss)
				rcvmem += 128;
			space *= rcvmem;
			space = min(space, sysctl_serval_tcp_rmem[2]);
			if (space > sk->sk_rcvbuf) {
				sk->sk_rcvbuf = space;

				/* Make the window clamp follow along.  */
				tp->window_clamp = new_clamp;
			}
		}
	}

new_measure:
	tp->rcvq_space.seq = tp->copied_seq;
	tp->rcvq_space.time = tcp_time_stamp;
}


/* There is something which you must keep in mind when you analyze the
 * behavior of the tp->ato delayed ack timeout interval.  When a
 * connection starts up, we want to ack as quickly as possible.  The
 * problem is that "good" TCP's do slow start at the beginning of data
 * transmission.  The means that until we send the first few ACK's the
 * sender will sit on his end and only queue most of his data, because
 * he can only send snd_cwnd unacked packets at any given time.  For
 * each ACK we send, he increments snd_cwnd and transmits more of his
 * queue.  -DaveM
 */
static void serval_tcp_event_data_recv(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 now;

	serval_tsk_schedule_ack(sk);

	serval_tcp_measure_rcv_mss(sk, skb);

	serval_tcp_rcv_rtt_measure(tp);
        
	now = tcp_time_stamp;

	if (!tp->tp_ack.ato) {
		/* The _first_ data packet received, initialize
		 * delayed ACK engine.
		 */
		serval_tcp_incr_quickack(sk);
		tp->tp_ack.ato = TCP_ATO_MIN;
	} else {
		int m = now - tp->tp_ack.lrcvtime;

		if (m <= TCP_ATO_MIN / 2) {
			/* The fastest case is the first. */
			tp->tp_ack.ato = (tp->tp_ack.ato >> 1) + TCP_ATO_MIN / 2;
		} else if (m < tp->tp_ack.ato) {
			tp->tp_ack.ato = (tp->tp_ack.ato >> 1) + m;
			if (tp->tp_ack.ato > tp->rto)
				tp->tp_ack.ato = tp->rto;
		} else if (m > tp->rto) {
			/* Too long gap. Apparently sender failed to
			 * restart window, so that we send ACKs quickly.
			 */
			serval_tcp_incr_quickack(sk);
			sk_mem_reclaim(sk);
		}
	}
	tp->tp_ack.lrcvtime = now;

	//TCP_ECN_check_ce(tp, skb);

	if (skb->len >= 128)
		serval_tcp_grow_window(sk, skb);
}

/* Numbers are taken from RFC3390.
 *
 * John Heffner states:
 *
 *	The RFC specifies a window of no more than 4380 bytes
 *	unless 2*MSS > 4380.  Reading the pseudocode in the RFC
 *	is a bit misleading because they use a clamp at 4380 bytes
 *	rather than use a multiplier in the relevant range.
 */
__u32 serval_tcp_init_cwnd(struct serval_tcp_sock *tp, struct dst_entry *dst)
{
	__u32 cwnd = (dst ? dst_metric(dst, RTAX_INITCWND) : 0);

	if (!cwnd) {
		if (tp->mss_cache > 1460)
			cwnd = 2;
		else
			cwnd = (tp->mss_cache > 1095) ? 3 : 4;
	}
	return min_t(__u32, cwnd, tp->snd_cwnd_clamp);
}


/* Set slow start threshold and cwnd not falling to slow start */
void serval_tcp_enter_cwr(struct sock *sk, const int set_ssthresh)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	tp->prior_ssthresh = 0;
	tp->bytes_acked = 0;
	if (tp->ca_state < TCP_CA_CWR) {
		tp->undo_marker = 0;
		if (set_ssthresh)
			tp->snd_ssthresh = tp->ca_ops->ssthresh(sk);
		tp->snd_cwnd = min(tp->snd_cwnd,
				   serval_tcp_packets_in_flight(tp) + 1U);
		tp->snd_cwnd_cnt = 0;
		tp->high_seq = tp->snd_nxt;
		tp->snd_cwnd_stamp = tcp_time_stamp;
		//TCP_ECN_queue_cwr(tp);

		serval_tcp_set_ca_state(sk, TCP_CA_CWR);
                LOG_SSK(sk, "snd_ssthresh=%u snd_cwnd_clamp=%u snd_cwnd=%u\n",
                        tp->snd_ssthresh, tp->snd_cwnd_clamp, tp->snd_cwnd);

	}
}

/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
void serval_tcp_cwnd_application_limited(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->ca_state == TCP_CA_Open &&
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		/* Limited by application or receiver window. */
		u32 init_win = serval_tcp_init_cwnd(tp, __sk_dst_get(sk));
		u32 win_used = max(tp->snd_cwnd_used, init_win);
		if (win_used < tp->snd_cwnd) {        
			tp->snd_ssthresh = serval_tcp_current_ssthresh(sk);
			tp->snd_cwnd = (tp->snd_cwnd + win_used) >> 1;
                        LOG_SSK(sk, "snd_ssthresh=%u snd_cwnd_clamp=%u snd_cwnd=%u\n",
                                tp->snd_ssthresh, tp->snd_cwnd_clamp, tp->snd_cwnd);                        
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
static void serval_tcp_rtt_estimator(struct sock *sk, const __u32 mrtt)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
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
	if (tp->srtt != 0) {
		m -= (tp->srtt >> 3);	/* m is now error in rtt est */
		tp->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
		if (m < 0) {
			m = -m;		/* m is now abs(error) */
			m -= (tp->mdev >> 2);   /* similar update on mdev */
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
			m -= (tp->mdev >> 2);   /* similar update on mdev */
		}
		tp->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
		if (tp->mdev > tp->mdev_max) {
			tp->mdev_max = tp->mdev;
			if (tp->mdev_max > tp->rttvar)
				tp->rttvar = tp->mdev_max;
		}
		if (after(tp->snd_una, tp->rtt_seq)) {
			if (tp->mdev_max < tp->rttvar)
				tp->rttvar -= (tp->rttvar - tp->mdev_max) >> 2;
			tp->rtt_seq = tp->snd_nxt;
			tp->mdev_max = serval_tcp_rto_min(sk);
		}
	} else {
		/* no previous measure. */
		tp->srtt = m << 3;	/* take the measured time to be rtt */
		tp->mdev = m << 1;	/* make sure rto = 3*rtt */
		tp->mdev_max = tp->rttvar = max(tp->mdev, 
                                                serval_tcp_rto_min(sk));
		tp->rtt_seq = tp->snd_nxt;
	}
}
/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
void serval_tcp_set_rto(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
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
	tp->rto = __serval_tcp_set_rto(tp);

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exactly, which we pretend to do.
	 */

	/* NOTE: clamping at TCP_RTO_MIN is not required, current algo
	 * guarantees that rto is higher.
	 */
	serval_tcp_bound_rto(sk);
}

static inline int serval_tcp_fackets_out(struct serval_tcp_sock *tp)
{
	return serval_tcp_is_reno(tp) ? 
                tp->sacked_out + 1 : tp->fackets_out;
}

/* We can clear retrans_stamp when there are no retransmissions in the
 * window. It would seem that it is trivially available for us in
 * tp->retrans_out, however, that kind of assumptions doesn't consider
 * what will happen if errors occur when sending retransmission for the
 * second time. ...It could the that such segment has only
 * TCPCB_EVER_RETRANS set at the present time. It seems that checking
 * the head skb is enough except for some reneging corner cases that
 * are not worth the effort.
 *
 * Main reason for all this complexity is the fact that connection dying
 * time now depends on the validity of the retrans_stamp, in particular,
 * that successive retransmissions of a segment must not advance
 * retrans_stamp under any conditions.
 */
static int serval_tcp_any_retrans_done(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;

	if (tp->retrans_out)
		return 1;

	skb = serval_tcp_write_queue_head(sk);

	if (unlikely(skb && TCP_SKB_CB(skb)->sacked & 
                     TCPCB_EVER_RETRANS))
		return 1;

	return 0;
}

/* Lower bound on congestion window is slow start threshold
 * unless congestion avoidance choice decides to overide it.
 */
static inline u32 serval_tcp_cwnd_min(const struct sock *sk)
{
	const struct tcp_congestion_ops *ca_ops = 
                serval_tcp_sk(sk)->ca_ops;

	return ca_ops->min_cwnd ? ca_ops->min_cwnd(sk) : 
                serval_tcp_sk(sk)->snd_ssthresh;
}

/* Decrease cwnd each second ack. */
static void serval_tcp_cwnd_down(struct sock *sk, int flag)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int decr = tp->snd_cwnd_cnt + 1;

	if ((flag & (FLAG_ANY_PROGRESS | FLAG_DSACKING_ACK)) ||
	    (serval_tcp_is_reno(tp) && !(flag & FLAG_NOT_DUP))) {
		tp->snd_cwnd_cnt = decr & 1;
		decr >>= 1;

		if (decr && tp->snd_cwnd > serval_tcp_cwnd_min(sk))
			tp->snd_cwnd -= decr;

		tp->snd_cwnd = min(tp->snd_cwnd, serval_tcp_packets_in_flight(tp) + 1);
		tp->snd_cwnd_stamp = tcp_time_stamp;
	}
}


/*
 * Packet counting of FACK is based on in-order assumptions, therefore
 * TCP disables it when reordering is detected
 */
void serval_tcp_disable_fack(struct serval_tcp_sock *tp)
{
	/* RFC3517 uses different metric in lost marker => reset on
           change */

	if (serval_tcp_is_fack(tp))
		tp->lost_skb_hint = NULL;

	tp->rx_opt.sack_ok &= ~2;
}

/* Limits sacked_out so that sum with lost_out isn't ever larger than
 * packets_out. Returns zero if sacked_out adjustement wasn't necessary.
 */
static int serval_tcp_limit_reno_sacked(struct serval_tcp_sock *tp)
{
	u32 holes;

	holes = max(tp->lost_out, 1U);
	holes = min(holes, tp->packets_out);

	if ((tp->sacked_out + holes) > tp->packets_out) {
		tp->sacked_out = tp->packets_out - holes;
		return 1;
	}
	return 0;
}

static void serval_tcp_update_reordering(struct sock *sk, 
                                         const int metric,
                                         const int ts)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	if (metric > tp->reordering) {
		//int mib_idx;

		tp->reordering = min(TCP_MAX_REORDERING, metric);

		/* This exciting event is worth to be remembered. 8) */
                /*
		if (ts)
			mib_idx = LINUX_MIB_TCPTSREORDER;
		else if (tcp_is_reno(tp))
			mib_idx = LINUX_MIB_TCPRENOREORDER;
		else if (tcp_is_fack(tp))
			mib_idx = LINUX_MIB_TCPFACKREORDER;
		else
			mib_idx = LINUX_MIB_TCPSACKREORDER;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);
                */

#if FASTRETRANS_DEBUG > 1
		printk(KERN_DEBUG "Disorder%d %d %u f%u s%u rr%d\n",
		       tp->rx_opt.sack_ok, inet_csk(sk)->icsk_ca_state,
		       tp->reordering,
		       tp->fackets_out,
		       tp->sacked_out,
		       tp->undo_marker ? tp->undo_retrans : 0);
#endif
		serval_tcp_disable_fack(tp);
	}
}


/* If we receive more dupacks than we expected counting segments
 * in assumption of absent reordering, interpret this as reordering.
 * The only another reason could be bug in receiver TCP.
 */
static void serval_tcp_check_reno_reordering(struct sock *sk, 
                                             const int addend)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	if (serval_tcp_limit_reno_sacked(tp))
		serval_tcp_update_reordering(sk, tp->packets_out + addend, 0);
}

/* Emulate SACKs for SACKless connection: account for a new dupack. */

static void serval_tcp_add_reno_sack(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	tp->sacked_out++;
	serval_tcp_check_reno_reordering(sk, 0);
	serval_tcp_verify_left_out(tp);
}


/* Account for ACK, ACKing some data in Reno Recovery phase. */
static void serval_tcp_remove_reno_sacks(struct sock *sk, int acked)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (acked > 0) {
		/* One ACK acked hole. The rest eat duplicate ACKs. */
		if (acked - 1 >= tp->sacked_out)
			tp->sacked_out = 0;
		else
			tp->sacked_out -= acked - 1;
	}
	serval_tcp_check_reno_reordering(sk, acked);
	serval_tcp_verify_left_out(tp);
}

static inline void serval_tcp_reset_reno_sack(struct serval_tcp_sock *tp)
{
	tp->sacked_out = 0;
}



/* Enter Loss state. If "how" is not zero, forget all SACK information
 * and reset tags completely, otherwise preserve SACKs. If receiver
 * dropped its ofo queue, we will know this due to reneging detection.
 */
void serval_tcp_enter_loss(struct sock *sk, int how)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;

	/* Reduce ssthresh if it has not yet been made inside this window. */
	if (tp->ca_state <= TCP_CA_Disorder || tp->snd_una == tp->high_seq ||
	    (tp->ca_state == TCP_CA_Loss && !tp->retransmits)) {
		tp->prior_ssthresh = serval_tcp_current_ssthresh(sk);
		tp->snd_ssthresh = tp->ca_ops->ssthresh(sk);
		serval_tcp_ca_event(sk, CA_EVENT_LOSS);
                LOG_SSK(sk, "snd_ssthresh=%u snd_cwnd_clamp=%u snd_cwnd=%u\n",
                        tp->snd_ssthresh, tp->snd_cwnd_clamp, tp->snd_cwnd);
	}
	tp->snd_cwnd	   = 1;
	tp->snd_cwnd_cnt   = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;

	tp->bytes_acked = 0;
	serval_tcp_clear_retrans_partial(tp);
	
        if (serval_tcp_is_reno(tp))
                  serval_tcp_reset_reno_sack(tp);
        
	if (!how) {
		/* Push undo marker, if it was plain RTO and nothing
		 * was retransmitted. */
		tp->undo_marker = tp->snd_una;
	} else {
		tp->sacked_out = 0;
		tp->fackets_out = 0;
	}
	serval_tcp_clear_all_retrans_hints(tp);

	serval_tcp_for_write_queue(skb, sk) {
		if (skb == serval_tcp_send_head(sk))
			break;

		if (TCP_SKB_CB(skb)->sacked & TCPCB_RETRANS)
			tp->undo_marker = 0;
		TCP_SKB_CB(skb)->sacked &= (~TCPCB_TAGBITS)|TCPCB_SACKED_ACKED;
		if (!(TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_ACKED) || how) {
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_ACKED;
			TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
			tp->lost_out += serval_tcp_skb_pcount(skb);
			tp->retransmit_high = TCP_SKB_CB(skb)->end_seq;
		}
	}
	serval_tcp_verify_left_out(tp);

	tp->reordering = min_t(unsigned int, tp->reordering,
			       sysctl_serval_tcp_reordering);
	serval_tcp_set_ca_state(sk, TCP_CA_Loss);
	tp->high_seq = tp->snd_nxt;
	//TCP_ECN_queue_cwr(tp);
	/* Abort F-RTO algorithm if one is in progress */
	tp->frto_counter = 0;
}

/* Nothing was retransmitted or returned timestamp is less
 * than timestamp of the first retransmission.
 */
static inline int serval_tcp_packet_delayed(struct serval_tcp_sock *tp)
{
	return !tp->retrans_stamp ||
		(tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		 before(tp->rx_opt.rcv_tsecr, tp->retrans_stamp));
}

/* CWND moderation, preventing bursts due to too big ACKs
 * in dubious situations.
 */
static inline void serval_tcp_moderate_cwnd(struct serval_tcp_sock *tp)
{
	tp->snd_cwnd = min(tp->snd_cwnd,
			   serval_tcp_packets_in_flight(tp) + 
                           serval_tcp_max_burst(tp));
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

static void serval_tcp_undo_cwr(struct sock *sk, const int undo)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->prior_ssthresh) {

		if (tp->ca_ops->undo_cwnd)
			tp->snd_cwnd = tp->ca_ops->undo_cwnd(sk);
		else
			tp->snd_cwnd = max(tp->snd_cwnd, 
                                           tp->snd_ssthresh << 1);

		if (undo && tp->prior_ssthresh > tp->snd_ssthresh) {
			tp->snd_ssthresh = tp->prior_ssthresh;
			//TCP_ECN_withdraw_cwr(tp);
                        LOG_SSK(sk, "snd_ssthresh=%u snd_cwnd_clamp=%u snd_cwnd=%u\n",
                                tp->snd_ssthresh, tp->snd_cwnd_clamp, tp->snd_cwnd);
		}
	} else {
		tp->snd_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh);
	}
	serval_tcp_moderate_cwnd(tp);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

static inline int serval_tcp_may_undo(struct serval_tcp_sock *tp)
{
	return tp->undo_marker && 
                (!tp->undo_retrans || serval_tcp_packet_delayed(tp));
}

/* People celebrate: "We love our President!" */
static int serval_tcp_try_undo_recovery(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (serval_tcp_may_undo(tp)) {
		//int mib_idx;

		/* Happy end! We did not retransmit anything
		 * or our original transmission succeeded.
		 */
		//DBGUNDO(sk, tp->ca_state == TCP_CA_Loss ? "loss" : "retrans");
		serval_tcp_undo_cwr(sk, 1);
                /*
		if (tp->ca_state == TCP_CA_Loss)
			mib_idx = LINUX_MIB_TCPLOSSUNDO;
		else
			mib_idx = LINUX_MIB_TCPFULLUNDO;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);
                */
		tp->undo_marker = 0;
	}
	if (tp->snd_una == tp->high_seq && serval_tcp_is_reno(tp)) {
		/* Hold old state until something *above* high_seq
		 * is ACKed. For Reno it is MUST to prevent false
		 * fast retransmits (RFC2582). SACK TCP is safe. */
		serval_tcp_moderate_cwnd(tp);
		return 1;
	}
	serval_tcp_set_ca_state(sk, TCP_CA_Open);
	return 0;
}

/* Undo during fast recovery after partial ACK. */
static int serval_tcp_try_undo_partial(struct sock *sk, int acked)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	/* Partial ACK arrived. Force Hoe's retransmit. */
	int failed = serval_tcp_is_reno(tp) || 
                (serval_tcp_fackets_out(tp) > tp->reordering);

	if (serval_tcp_may_undo(tp)) {
		/* Plain luck! Hole if filled with delayed
		 * packet, rather than with a retransmit.
		 */
		if (!serval_tcp_any_retrans_done(sk))
			tp->retrans_stamp = 0;

		serval_tcp_update_reordering(sk, serval_tcp_fackets_out(tp) + acked, 1);

		//DBGUNDO(sk, "Hoe");
		serval_tcp_undo_cwr(sk, 0);
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPPARTIALUNDO);

		/* So... Do not make Hoe's retransmit yet.
		 * If the first packet was delayed, the rest
		 * ones are most probably delayed as well.
		 */
		failed = 0;
	}
	return failed;
}

/* Undo during loss recovery after partial ACK. */
static int serval_tcp_try_undo_loss(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (serval_tcp_may_undo(tp)) {
		struct sk_buff *skb;
		serval_tcp_for_write_queue(skb, sk) {
			if (skb == serval_tcp_send_head(sk))
				break;
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;
		}

		serval_tcp_clear_all_retrans_hints(tp);

		//DBGUNDO(sk, "partial loss");
		tp->lost_out = 0;
		serval_tcp_undo_cwr(sk, 1);
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPLOSSUNDO);
		tp->retransmits = 0;
		tp->undo_marker = 0;
		if (serval_tcp_is_sack(tp))
			serval_tcp_set_ca_state(sk, TCP_CA_Open);
		return 1;
	}
	return 0;
}

static inline void serval_tcp_complete_cwr(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	serval_tcp_ca_event(sk, CA_EVENT_COMPLETE_CWR);
}


/* Try to undo cwnd reduction, because D-SACKs acked all retransmitted
   data */
static void serval_tcp_try_undo_dsack(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->undo_marker && !tp->undo_retrans) {
		//DBGUNDO(sk, "D-SACK");
		serval_tcp_undo_cwr(sk, 1);
		tp->undo_marker = 0;
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPDSACKUNDO);
	}
}

static void serval_tcp_try_keep_open(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int state = TCP_CA_Open;
        
	if (serval_tcp_left_out(tp) || 
            serval_tcp_any_retrans_done(sk) || tp->undo_marker)
		state = TCP_CA_Disorder;

	if (tp->ca_state != state) {
		serval_tcp_set_ca_state(sk, state);
		tp->high_seq = tp->snd_nxt;
	}
}

static void serval_tcp_try_to_open(struct sock *sk, int flag)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	serval_tcp_verify_left_out(tp);

	if (!tp->frto_counter && !serval_tcp_any_retrans_done(sk))
		tp->retrans_stamp = 0;

	if (flag & FLAG_ECE)
		serval_tcp_enter_cwr(sk, 1);

	if (tp->ca_state != TCP_CA_CWR) {
		serval_tcp_try_keep_open(sk);
		serval_tcp_moderate_cwnd(tp);
	} else {
		serval_tcp_cwnd_down(sk, flag);
	}
}

static void serval_tcp_mtup_probe_failed(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	tp->tp_mtup.search_high = tp->tp_mtup.probe_size - 1;
	tp->tp_mtup.probe_size = 0;
        LOG_SSK(sk, "TCP MTU probe failed!\n");
}

static void serval_tcp_mtup_probe_success(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* FIXME: breaks with very large cwnd */
	tp->prior_ssthresh = serval_tcp_current_ssthresh(sk);
	tp->snd_cwnd = tp->snd_cwnd *
                serval_tcp_mss_to_mtu(sk, tp->mss_cache) /
                tp->tp_mtup.probe_size;
	tp->snd_cwnd_cnt = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_ssthresh = serval_tcp_current_ssthresh(sk);

        LOG_SSK(sk, "snd_ssthresh=%u snd_cwnd_clamp=%u snd_cwnd=%u\n",
                tp->snd_ssthresh, tp->snd_cwnd_clamp, tp->snd_cwnd);

	tp->tp_mtup.search_low = tp->tp_mtup.probe_size;
	tp->tp_mtup.probe_size = 0;
	serval_tcp_sync_mss(sk, tp->pmtu_cookie);

        LOG_SSK(sk, "TCP MTU probe success!\n");
}

/* If ACK arrived pointing to a remembered SACK, it means that our
 * remembered SACKs do not reflect real state of receiver i.e.
 * receiver _host_ is heavily congested (or buggy).
 *
 * Do processing similar to RTO timeout.
 */
static int serval_tcp_check_sack_reneging(struct sock *sk, int flag)
{
	if (flag & FLAG_SACK_RENEGING) {
		struct serval_tcp_sock *tp = serval_tcp_sk(sk);
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSACKRENEGING);

		serval_tcp_enter_loss(sk, 1);
		tp->retransmits++;
		serval_tcp_retransmit_skb(sk, serval_tcp_write_queue_head(sk));
                serval_tsk_reset_xmit_timer(sk, STSK_TIME_RETRANS,
                                            tp->rto, SERVAL_TCP_RTO_MAX);
		return 1;
	}
	return 0;
}

/* This must be called before lost_out is incremented */
static void serval_tcp_verify_retransmit_hint(struct serval_tcp_sock *tp, struct sk_buff *skb)
{
	if ((tp->retransmit_skb_hint == NULL) ||
	    before(TCP_SKB_CB(skb)->seq,
		   TCP_SKB_CB(tp->retransmit_skb_hint)->seq))
		tp->retransmit_skb_hint = skb;

	if (!tp->lost_out ||
	    after(TCP_SKB_CB(skb)->end_seq, tp->retransmit_high))
		tp->retransmit_high = TCP_SKB_CB(skb)->end_seq;
}

static void serval_tcp_skb_mark_lost(struct serval_tcp_sock *tp, 
                                     struct sk_buff *skb)
{
	if (!(TCP_SKB_CB(skb)->sacked & 
              (TCPCB_LOST|TCPCB_SACKED_ACKED))) {
		serval_tcp_verify_retransmit_hint(tp, skb);

		tp->lost_out += serval_tcp_skb_pcount(skb);
		TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
	}
}

static void serval_tcp_skb_mark_lost_uncond_verify(struct serval_tcp_sock *tp,
                                                   struct sk_buff *skb)
{
	serval_tcp_verify_retransmit_hint(tp, skb);

	if (!(TCP_SKB_CB(skb)->sacked & (TCPCB_LOST|TCPCB_SACKED_ACKED))) {
		tp->lost_out += serval_tcp_skb_pcount(skb);
		TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
	}
}

/* Heurestics to calculate number of duplicate ACKs. There's no dupACKs
 * counter when SACK is enabled (without SACK, sacked_out is used for
 * that purpose).
 *
 * Instead, with FACK TCP uses fackets_out that includes both SACKed
 * segments up to the highest received SACK block so far and holes in
 * between them.
 *
 * With reordering, holes may still be in flight, so RFC3517 recovery
 * uses pure sacked_out (total number of SACKed segments) even though
 * it violates the RFC that uses duplicate ACKs, often these are equal
 * but when e.g. out-of-window ACKs or packet duplication occurs,
 * they differ. Since neither occurs due to loss, TCP should really
 * ignore them.
 */
static inline int serval_tcp_dupack_heuristics(struct serval_tcp_sock *tp)
{
	return serval_tcp_is_fack(tp) ? 
                tp->fackets_out : tp->sacked_out + 1;
}

static inline int serval_tcp_skb_timedout(struct sock *sk, 
                                          struct sk_buff *skb)
{
	return tcp_time_stamp - TCP_SKB_CB(skb)->when > 
                serval_tcp_sk(sk)->rto;
}

static inline int serval_tcp_head_timedout(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	return tp->packets_out &&
                serval_tcp_skb_timedout(sk, serval_tcp_write_queue_head(sk));
}


/* New heuristics: it is possible only after we switched to restart
 * timer each time when something is ACKed. Hence, we can detect timed
 * out packets during fast retransmit without falling to slow start.
 *
 * Usefulness of this as is very questionable, since we should know
 * which of the segments is the next to timeout which is relatively
 * expensive to find in general case unless we add some data structure
 * just for that. The current approach certainly won't find the right
 * one too often and when it finally does find _something_ it usually
 * marks large part of the window right away (because a retransmission
 * with a larger timestamp blocks the loop from advancing). -ij
 */
static void serval_tcp_timeout_skbs(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;

	if (!serval_tcp_is_fack(tp) || !serval_tcp_head_timedout(sk))
		return;

	skb = tp->scoreboard_skb_hint;
	if (tp->scoreboard_skb_hint == NULL)
		skb = serval_tcp_write_queue_head(sk);

	serval_tcp_for_write_queue_from(skb, sk) {
		if (skb == serval_tcp_send_head(sk))
			break;
		if (!serval_tcp_skb_timedout(sk, skb))
			break;

		serval_tcp_skb_mark_lost(tp, skb);
	}

	tp->scoreboard_skb_hint = skb;

	serval_tcp_verify_left_out(tp);
}


/* Mark head of queue up as lost. With RFC3517 SACK, the packets is
 * is against sacked "cnt", otherwise it's against facked "cnt"
 */
static void serval_tcp_mark_head_lost(struct sock *sk, 
                                      int packets, int mark_head)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	int cnt, oldcnt;
	int err;
	unsigned int mss;

	WARN_ON(packets > tp->packets_out);

	if (tp->lost_skb_hint) {
		skb = tp->lost_skb_hint;
		cnt = tp->lost_cnt_hint;
		/* Head already handled? */
		if (mark_head && skb != serval_tcp_write_queue_head(sk))
			return;
	} else {
		skb = serval_tcp_write_queue_head(sk);
		cnt = 0;
	}

	serval_tcp_for_write_queue_from(skb, sk) {
		if (skb == serval_tcp_send_head(sk))
			break;
		/* TODO: do this better */
		/* this is not the most efficient way to do this... */
		tp->lost_skb_hint = skb;
		tp->lost_cnt_hint = cnt;

		if (after(TCP_SKB_CB(skb)->end_seq, tp->high_seq))
			break;

		oldcnt = cnt;
		if (serval_tcp_is_fack(tp) || serval_tcp_is_reno(tp) ||
		    (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
			cnt += serval_tcp_skb_pcount(skb);

		if (cnt > packets) {
			if ((serval_tcp_is_sack(tp) && !serval_tcp_is_fack(tp)) ||
			    (oldcnt >= packets))
				break;

			mss = skb_shinfo(skb)->gso_size;
			err = serval_tcp_fragment(sk, skb, (packets - oldcnt) * mss, mss);
			if (err < 0)
				break;
			cnt = packets;
		}

		serval_tcp_skb_mark_lost(tp, skb);

		if (mark_head)
			break;
	}
	serval_tcp_verify_left_out(tp);
}

/* Account newly detected lost packet(s) */
static void serval_tcp_update_scoreboard(struct sock *sk, 
                                         int fast_rexmit)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (serval_tcp_is_reno(tp)) {
		serval_tcp_mark_head_lost(sk, 1, 1);
	} else if (serval_tcp_is_fack(tp)) {
		int lost = tp->fackets_out - tp->reordering;
		if (lost <= 0)
			lost = 1;
		serval_tcp_mark_head_lost(sk, lost, 0);
	} else {
		int sacked_upto = tp->sacked_out - tp->reordering;
		if (sacked_upto >= 0)
			serval_tcp_mark_head_lost(sk, sacked_upto, 0);
		else if (fast_rexmit)
			serval_tcp_mark_head_lost(sk, 1, 1);
	}

	serval_tcp_timeout_skbs(sk);
}

/* This function decides, when we should leave Disordered state
 * and enter Recovery phase, reducing congestion window.
 *
 * Main question: may we further continue forward transmission
 * with the same cwnd?
 */
static int serval_tcp_time_to_recover(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	__u32 packets_out;

	/* Do not perform any recovery during F-RTO algorithm */
	if (tp->frto_counter)
		return 0;

	/* Trick#1: The loss is proven. */
	if (tp->lost_out)
		return 1;

	/* Not-A-Trick#2 : Classic rule... */
	if (serval_tcp_dupack_heuristics(tp) > tp->reordering)
		return 1;

	/* Trick#3 : when we use RFC2988 timer restart, fast
	 * retransmit can be triggered by timeout of queue head.
	 */
	if (serval_tcp_is_fack(tp) && serval_tcp_head_timedout(sk))
		return 1;

	/* Trick#4: It is still not OK... But will it be useful to delay
	 * recovery more?
	 */
	packets_out = tp->packets_out;
	if (packets_out <= tp->reordering &&
	    tp->sacked_out >= max_t(__u32, packets_out/2, 
                                    sysctl_serval_tcp_reordering) &&
	    !serval_tcp_may_send_now(sk)) {
		/* We have nothing to send. This connection is limited
		 * either by receiver window or by application.
		 */
		return 1;
	}

	/* If a thin stream is detected, retransmit after first
	 * received dupack. Employ only if SACK is supported in order
	 * to avoid possible corner-case series of spurious retransmissions
	 * Use only if there are no unsent data.
	 */
	if ((tp->thin_dupack || sysctl_serval_tcp_thin_dupack) &&
	    serval_tcp_stream_is_thin(tp) && serval_tcp_dupack_heuristics(tp) > 1 &&
	    serval_tcp_is_sack(tp) && !serval_tcp_send_head(sk))
		return 1;

	return 0;
}


/* I wish gso_size would have a bit more sane initialization than
 * something-or-zero which complicates things
 */
static int serval_tcp_skb_seglen(struct sk_buff *skb)
{
	return serval_tcp_skb_pcount(skb) == 1 ? 
                skb->len : serval_tcp_skb_mss(skb);
}

/* Do a simple retransmit without using the backoff mechanisms in
 * tcp_timer. This is used for path mtu discovery.
 * The socket is already locked here.
 */
void serval_tcp_simple_retransmit(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int mss = serval_tcp_current_mss(sk);
	u32 prior_lost = tp->lost_out;

	serval_tcp_for_write_queue(skb, sk) {
		if (skb == serval_tcp_send_head(sk))
			break;
		if (serval_tcp_skb_seglen(skb) > mss &&
		    !(TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)) {
			if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
				TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
				tp->retrans_out -= serval_tcp_skb_pcount(skb);
			}
			serval_tcp_skb_mark_lost_uncond_verify(tp, skb);
		}
	}

	serval_tcp_clear_retrans_hints_partial(tp);

	if (prior_lost == tp->lost_out)
		return;

	if (serval_tcp_is_reno(tp))
		serval_tcp_limit_reno_sacked(tp);

	serval_tcp_verify_left_out(tp);

	/* Don't muck with the congestion window here.
	 * Reason is that we do not increase amount of _data_
	 * in network, but units changed and effective
	 * cwnd/ssthresh really reduced now.
	 */
	if (tp->ca_state != TCP_CA_Loss) {
		tp->high_seq = tp->snd_nxt;
		tp->snd_ssthresh = serval_tcp_current_ssthresh(sk);
                LOG_SSK(sk, "snd_ssthresh=%u snd_cwnd_clamp=%u snd_cwnd=%u\n",
                        tp->snd_ssthresh, tp->snd_cwnd_clamp, tp->snd_cwnd);

		tp->prior_ssthresh = 0;
		tp->undo_marker = 0;
		serval_tcp_set_ca_state(sk, TCP_CA_Loss);
	}
	serval_tcp_xmit_retransmit_queue(sk);
}

/* Process an event, which can update packets-in-flight not trivially.
 * Main goal of this function is to calculate new estimate for left_out,
 * taking into account both packets sitting in receiver's buffer and
 * packets lost by network.
 *
 * Besides that it does CWND reduction, when packet loss is detected
 * and changes state of machine.
 *
 * It does _not_ decide what to send, it is made in function
 * tcp_xmit_retransmit_queue().
 */
static void serval_tcp_fastretrans_alert(struct sock *sk, 
                                         int pkts_acked, int flag, u32 ack)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int is_dupack = !(flag & (FLAG_SND_UNA_ADVANCED | FLAG_NOT_DUP));
	int do_lost = is_dupack || ((flag & FLAG_DATA_SACKED) &&
				    (serval_tcp_fackets_out(tp) > tp->reordering));
	int fast_rexmit = 0; //, mib_idx;

	if (WARN_ON(!tp->packets_out && tp->sacked_out))
		tp->sacked_out = 0;
	if (WARN_ON(!tp->sacked_out && tp->fackets_out))
		tp->fackets_out = 0;

	/* Now state machine starts.
	 * A. ECE, hence prohibit cwnd undoing, the reduction is required. */
	if (flag & FLAG_ECE)
		tp->prior_ssthresh = 0;

	/* B. In all the states check for reneging SACKs. */
	if (serval_tcp_check_sack_reneging(sk, flag))
		return;

	/* C. Process data loss notification, provided it is valid. */
	if (serval_tcp_is_fack(tp) && (flag & FLAG_DATA_LOST) &&
	    before(tp->snd_una, tp->high_seq) &&
	    tp->ca_state != TCP_CA_Open &&
	    tp->fackets_out > tp->reordering) {
		serval_tcp_mark_head_lost(sk, tp->fackets_out - tp->reordering, 0);
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPLOSS);
	}

	/* D. Check consistency of the current state. */
	serval_tcp_verify_left_out(tp);

	/* E. Check state exit conditions. State can be terminated
	 *    when high_seq is ACKed. */
	if (tp->ca_state == TCP_CA_Open) {
		WARN_ON(tp->retrans_out != 0);
		tp->retrans_stamp = 0;
	} else if (!before(tp->snd_una, tp->high_seq)) {
		switch (tp->ca_state) {
		case TCP_CA_Loss:
			tp->retransmits = 0;
			if (serval_tcp_try_undo_recovery(sk))
				return;
			break;

		case TCP_CA_CWR:
			/* CWR is to be held something *above* high_seq
			 * is ACKed for CWR bit to reach receiver. */
			if (tp->snd_una != tp->high_seq) {
				serval_tcp_complete_cwr(sk);
				serval_tcp_set_ca_state(sk, TCP_CA_Open);
			}
			break;
                        
		case TCP_CA_Disorder:
			serval_tcp_try_undo_dsack(sk);
			if (!tp->undo_marker ||
			    /* For SACK case do not Open to allow to undo
			     * catching for all duplicate ACKs. */
			    serval_tcp_is_reno(tp) || 
                            tp->snd_una != tp->high_seq) {
				tp->undo_marker = 0;
				serval_tcp_set_ca_state(sk, TCP_CA_Open);
			}
			break;

		case TCP_CA_Recovery:
			if (serval_tcp_is_reno(tp))
				serval_tcp_reset_reno_sack(tp);
			if (serval_tcp_try_undo_recovery(sk))
				return;
			serval_tcp_complete_cwr(sk);
			break;
		}
	}

	/* F. Process state. */
	switch (tp->ca_state) {
	case TCP_CA_Recovery:
		if (!(flag & FLAG_SND_UNA_ADVANCED)) {
			if (serval_tcp_is_reno(tp) && is_dupack)
				serval_tcp_add_reno_sack(sk);
		} else
			do_lost = serval_tcp_try_undo_partial(sk, pkts_acked);
		break;
	case TCP_CA_Loss:
		if (flag & FLAG_DATA_ACKED)
			tp->retransmits = 0;
		if (serval_tcp_is_reno(tp) && flag & FLAG_SND_UNA_ADVANCED)
			serval_tcp_reset_reno_sack(tp);
		if (!serval_tcp_try_undo_loss(sk)) {
			serval_tcp_moderate_cwnd(tp);
			serval_tcp_xmit_retransmit_queue(sk);
			return;
		}
		if (tp->ca_state != TCP_CA_Open)
			return;
		/* Loss is undone; fall through to processing in Open state. */
	default:
		if (serval_tcp_is_reno(tp)) {
			if (flag & FLAG_SND_UNA_ADVANCED)
				serval_tcp_reset_reno_sack(tp);
			if (is_dupack)
				serval_tcp_add_reno_sack(sk);
		}

		if (tp->ca_state == TCP_CA_Disorder)
			serval_tcp_try_undo_dsack(sk);

		if (!serval_tcp_time_to_recover(sk)) {
			serval_tcp_try_to_open(sk, flag);
			return;
		}

		/* MTU probe failure: don't reduce cwnd */
		if (tp->ca_state < TCP_CA_CWR &&
		    tp->tp_mtup.probe_size &&
		    tp->snd_una == tp->mtu_probe.probe_seq_start) {
			serval_tcp_mtup_probe_failed(sk);
			/* Restores the reduction we did in tcp_mtup_probe() */
			tp->snd_cwnd++;
			serval_tcp_simple_retransmit(sk);
			return;
		}

        /* If we've migrated, just retransmit, don't necessarily adjust cwnd */
        LOG_SSK(sk, "Fast retx ack=%lu snd_mig_last=%lu\n", ack, tp->snd_mig_last); 
        if (before(ack, tp->snd_mig_last)) {
            LOG_SSK(sk, "Out-of-order due to migration, potentially.\n", ack);
            serval_tcp_xmit_retransmit_queue(sk);
            return;
        }

		/* Otherwise enter Recovery state */
                /*
		if (serval_tcp_is_reno(tp))
			mib_idx = LINUX_MIB_TCPRENORECOVERY;
		else
			mib_idx = LINUX_MIB_TCPSACKRECOVERY;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);
                */
		tp->high_seq = tp->snd_nxt;
		tp->prior_ssthresh = 0;
		tp->undo_marker = tp->snd_una;
		tp->undo_retrans = tp->retrans_out;

		if (tp->ca_state < TCP_CA_CWR) {
			if (!(flag & FLAG_ECE))
				tp->prior_ssthresh = serval_tcp_current_ssthresh(sk);
			tp->snd_ssthresh = tp->ca_ops->ssthresh(sk);
                        LOG_SSK(sk, "snd_ssthresh=%u snd_cwnd_clamp=%u snd_cwnd=%u\n",
                                tp->snd_ssthresh, tp->snd_cwnd_clamp, tp->snd_cwnd);
			//TCP_ECN_queue_cwr(tp);
		}

		tp->bytes_acked = 0;
		tp->snd_cwnd_cnt = 0;
		serval_tcp_set_ca_state(sk, TCP_CA_Recovery);
		fast_rexmit = 1;
	}

	if (do_lost || (serval_tcp_is_fack(tp) && 
                        serval_tcp_head_timedout(sk)))
		serval_tcp_update_scoreboard(sk, fast_rexmit);
	serval_tcp_cwnd_down(sk, flag);
	serval_tcp_xmit_retransmit_queue(sk);
}

static void serval_tcp_valid_rtt_meas(struct sock *sk, u32 seq_rtt)
{
	serval_tcp_rtt_estimator(sk, seq_rtt);
	serval_tcp_set_rto(sk);
	serval_tcp_sk(sk)->backoff = 0;
        serval_sal_update_rtt(sk, seq_rtt);
}

/* If we get here, the whole TSO packet has not been acked. */
static u32 serval_tcp_tso_acked(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        struct tcphdr *th = tcp_hdr(skb);
	u32 packets_acked;
        u32 seq, end_seq;

        seq = ntohl(th->seq);
        end_seq = (seq + th->syn + th->fin +
                   skb->len - th->doff * 4);

	BUG_ON(!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una));

	packets_acked = serval_tcp_skb_pcount(skb);
	if (serval_tcp_trim_head(sk, skb, tp->snd_una - seq))
		return 0;
	packets_acked -= tcp_skb_pcount(skb);

	if (packets_acked) {
		BUG_ON(tcp_skb_pcount(skb) == 0);
		BUG_ON(!before(seq, end_seq));
	}

	return packets_acked;
}


/* Read draft-ietf-tcplw-high-performance before mucking
 * with this code. (Supersedes RFC1323)
 */
static void serval_tcp_ack_saw_tstamp(struct sock *sk, int flag)
{
	/* RTTM Rule: A TSecr value received in a segment is used to
	 * update the averaged RTT measurement only if the segment
	 * acknowledges some new data, i.e., only if it advances the
	 * left edge of the send window.
	 *
	 * See draft-ietf-tcplw-high-performance-00, section 3.3.
	 * 1998/04/10 Andrey V. Savochkin <saw@msu.ru>
	 *
	 * Changed: reset backoff as soon as we see the first valid sample.
	 * If we do not, we get strongly overestimated rto. With timestamps
	 * samples are accepted even from very old segments: f.e., when rtt=1
	 * increases to 8, we retransmit 5 times and after 8 seconds delayed
	 * answer arrives rto becomes 120 seconds! If at least one of segments
	 * in window is lost... Voila.	 			--ANK (010210)
	 */
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	serval_tcp_valid_rtt_meas(sk, tcp_time_stamp - tp->rx_opt.rcv_tsecr);
}

static void serval_tcp_ack_no_tstamp(struct sock *sk, u32 seq_rtt, int flag)
{
	/* We don't have a timestamp. Can only use
	 * packets that are not retransmitted to determine
	 * rtt estimates. Also, we must not reset the
	 * backoff for rto until we get a non-retransmitted
	 * packet. This allows us to deal with a situation
	 * where the network delay has increased suddenly.
	 * I.e. Karn's algorithm. (SIGCOMM '87, p5.)
	 */
        
	if (flag & FLAG_RETRANS_DATA_ACKED)
		return;

	serval_tcp_valid_rtt_meas(sk, seq_rtt);
}

static inline void serval_tcp_ack_update_rtt(struct sock *sk, const int flag,
                                             const s32 seq_rtt)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	/* Note that peer MAY send zero echo. In this case it is
         * ignored. (rfc1323) */
	if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr)
		serval_tcp_ack_saw_tstamp(sk, flag);
	else if (seq_rtt >= 0)
		serval_tcp_ack_no_tstamp(sk, seq_rtt, flag);
}


static void serval_tcp_ack_probe(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* Was it a usable window open? */

	if (!after(TCP_SKB_CB(serval_tcp_send_head(sk))->end_seq, 
                   serval_tcp_wnd_end(tp))) {
		tp->backoff = 0;
		serval_tsk_clear_xmit_timer(sk, STSK_TIME_PROBE0);
		/* Socket must be waked up by subsequent tcp_data_snd_check().
		 * This function is not for random using!
		 */
	} else {
		serval_tsk_reset_xmit_timer(sk, STSK_TIME_PROBE0,
                                            min(tp->rto << tp->backoff, 
                                                SERVAL_TCP_RTO_MAX),
                                            SERVAL_TCP_RTO_MAX);
        }
}

static inline int serval_tcp_ack_is_dubious(const struct sock *sk, 
                                            const int flag)
{
	return (!(flag & FLAG_NOT_DUP) || (flag & FLAG_CA_ALERT) ||
		serval_tcp_sk(sk)->ca_state != TCP_CA_Open);
}

static inline int serval_tcp_may_raise_cwnd(const struct sock *sk, 
                                            const int flag)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	return (!(flag & FLAG_ECE) || tp->snd_cwnd < tp->snd_ssthresh) &&
		!((1 << tp->ca_state) & (TCPF_CA_Recovery | TCPF_CA_CWR));
}

/* Check that window update is acceptable.
 * The function assumes that snd_una<=ack<=snd_next.
 */
static inline int serval_tcp_may_update_window(const struct serval_tcp_sock *tp,
                                               const u32 ack, const u32 ack_seq,
                                               const u32 nwin)
{
	return (after(ack, tp->snd_una) ||
		after(ack_seq, tp->snd_wl1) ||
		(ack_seq == tp->snd_wl1 && nwin > tp->snd_wnd));
}

/* Update our send window.
 *
 * Window update algorithm, described in RFC793/RFC1122 (used in linux-2.2
 * and in FreeBSD. NetBSD's one is even worse.) is wrong.
 */
static int serval_tcp_ack_update_window(struct sock *sk, struct sk_buff *skb, 
                                         u32 ack, u32 ack_seq)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int flag = 0;
	u32 nwin = ntohs(tcp_hdr(skb)->window);

	if (likely(!tcp_hdr(skb)->syn))
		nwin <<= tp->rx_opt.snd_wscale;

	if (serval_tcp_may_update_window(tp, ack, ack_seq, nwin)) {
		flag |= FLAG_WIN_UPDATE;
		serval_tcp_update_wl(tp, ack_seq);

		if (tp->snd_wnd != nwin) {
			tp->snd_wnd = nwin;

			/* Note, it is the only place, where
			 * fast path is recovered for sending TCP.
			 */
			tp->pred_flags = 0;
			serval_tcp_fast_path_check(sk);

			if (nwin > tp->max_window) {
				tp->max_window = nwin;
				serval_tcp_sync_mss(sk, tp->pmtu_cookie);
			}
		}
	}

	tp->snd_una = ack;

	return flag;
}

/* Restart timer after forward progress on connection.
 * RFC2988 recommends to restart timer to now+rto.
 */
static void serval_tcp_rearm_rto(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (!tp->packets_out) {
		serval_tsk_clear_xmit_timer(sk, STSK_TIME_RETRANS);
	} else {
		serval_tsk_reset_xmit_timer(sk, STSK_TIME_RETRANS,
                                            tp->rto, SERVAL_TCP_RTO_MAX);
	}
}

/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
static int serval_tcp_clean_rtx_queue(struct sock *sk, 
                                      int prior_fackets,
                                      u32 prior_snd_una)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	u32 now = tcp_time_stamp;
	int fully_acked = 1;
	int flag = 0;
	u32 pkts_acked = 0;
	u32 reord = tp->packets_out;
	//u32 prior_sacked = tp->sacked_out;
	s32 seq_rtt = -1;
	s32 ca_seq_rtt = -1;
	ktime_t last_ackt = net_invalid_timestamp();

	while ((skb = serval_tcp_write_queue_head(sk)) && 
               skb != serval_tcp_send_head(sk)) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		u32 acked_pcount;
		u8 sacked = scb->sacked;

		/* Determine how many packets and what bytes were
                 * acked, tso and else */
		if (after(scb->end_seq, tp->snd_una)) {
			if (serval_tcp_skb_pcount(skb) == 1 ||
			    !after(tp->snd_una, scb->seq))
				break;

			acked_pcount = serval_tcp_tso_acked(sk, skb);
			if (!acked_pcount)
				break;

			fully_acked = 0;
		} else {
			acked_pcount = serval_tcp_skb_pcount(skb);
		}

		if (sacked & TCPCB_RETRANS) {
			if (sacked & TCPCB_SACKED_RETRANS)
				tp->retrans_out -= acked_pcount;
			flag |= FLAG_RETRANS_DATA_ACKED;
			ca_seq_rtt = -1;
			seq_rtt = -1;
			if ((flag & FLAG_DATA_ACKED) || (acked_pcount > 1))
				flag |= FLAG_NONHEAD_RETRANS_ACKED;
		} else {
			ca_seq_rtt = now - scb->when;

#if defined(OS_LINUX_KERNEL)
			last_ackt = skb->tstamp;
#endif
			if (seq_rtt < 0) {
				seq_rtt = ca_seq_rtt;
			}
			if (!(sacked & TCPCB_SACKED_ACKED))
				reord = min(pkts_acked, reord);
		}

		if (sacked & TCPCB_SACKED_ACKED)
			tp->sacked_out -= acked_pcount;
		if (sacked & TCPCB_LOST)
			tp->lost_out -= acked_pcount;

		tp->packets_out -= acked_pcount;
		pkts_acked += acked_pcount;

		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		if (!(scb->tcp_flags & TCPH_SYN)) {
			flag |= FLAG_DATA_ACKED;
                        if (scb->tcp_flags & TCPH_FIN)
                                flag |= FLAG_FIN_ACKED;
		} else {
			flag |= FLAG_SYN_ACKED;
			tp->retrans_stamp = 0;
		}

		if (!fully_acked)
			break;

		serval_tcp_unlink_write_queue(skb, sk);
		sk_wmem_free_skb(sk, skb);

		tp->scoreboard_skb_hint = NULL;
		if (skb == tp->retransmit_skb_hint)
			tp->retransmit_skb_hint = NULL;
		if (skb == tp->lost_skb_hint)
			tp->lost_skb_hint = NULL;

	}

	if (likely(between(tp->snd_up, prior_snd_una, tp->snd_una)))
		tp->snd_up = tp->snd_una;

	if (skb && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
		flag |= FLAG_SACK_RENEGING;

	if (flag & FLAG_ACKED) {
		const struct tcp_congestion_ops *ca_ops
			= tp->ca_ops;

		if (unlikely(tp->tp_mtup.probe_size &&
			     !after(tp->mtu_probe.probe_seq_end, 
                                    tp->snd_una))) {
			serval_tcp_mtup_probe_success(sk);
		}

		serval_tcp_ack_update_rtt(sk, flag, seq_rtt);
		serval_tcp_rearm_rto(sk);

		if (serval_tcp_is_reno(tp)) {
			serval_tcp_remove_reno_sacks(sk, pkts_acked);
		} else {
                        LOG_WARN("Only TCP RENO supported!\n");
                        /*
			int delta;

			if (reord < prior_fackets)
				serval_tcp_update_reordering(sk, tp->fackets_out - reord, 0);

			delta = serval_tcp_is_fack(tp) ? pkts_acked :
						  prior_sacked - tp->sacked_out;
			tp->lost_cnt_hint -= min(tp->lost_cnt_hint, delta);
                        */
		}

		tp->fackets_out -= min(pkts_acked, tp->fackets_out);

		if (ca_ops->pkts_acked) {
			s32 rtt_us = -1;

			/* Is the ACK triggering packet unambiguous? */
			if (!(flag & FLAG_RETRANS_DATA_ACKED)) {
				/* High resolution needed and available? */

				if (ca_ops->flags & TCP_CONG_RTT_STAMP &&
				    !ktime_equal(last_ackt,
						 net_invalid_timestamp()))
					rtt_us = ktime_us_delta(ktime_get_real(),
								last_ackt);
				else if (ca_seq_rtt > 0)
                                        rtt_us = jiffies_to_usecs(ca_seq_rtt);
			}

			ca_ops->pkts_acked(sk, pkts_acked, rtt_us);
		}
	}

        if (flag & FLAG_FIN_ACKED) {
                LOG_SSK(sk, "End of stream ACK, sending SAL FIN\n");
                serval_sal_send_fin(sk);
        }
	return flag;
}

static void serval_tcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	tp->ca_ops->cong_avoid(sk, ack, in_flight);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* This routine deals with incoming acks, but not outgoing ones. */
static int serval_tcp_ack(struct sock *sk, struct sk_buff *skb, int flag)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 prior_snd_una = tp->snd_una;
	u32 ack_seq = TCP_SKB_CB(skb)->seq;
	u32 ack = TCP_SKB_CB(skb)->ack_seq;
	u32 prior_in_flight;
	u32 prior_fackets;
	int prior_packets;
	//int frto_cwnd = 0;

	/* If the ack is older than previous acks
	 * then we can probably ignore it.
	 */
	if (before(ack, prior_snd_una))
		goto old_ack;

	/* If the ack includes data we haven't sent yet, discard
	 * this segment (RFC793 Section 3.9).
	 */
	if (after(ack, tp->snd_nxt))
		goto invalid_ack;

	if (after(ack, prior_snd_una))
		flag |= FLAG_SND_UNA_ADVANCED;

	if (sysctl_serval_tcp_abc) {
		if (tp->ca_state < TCP_CA_CWR)
			tp->bytes_acked += ack - prior_snd_una;
		else if (tp->ca_state == TCP_CA_Loss)
			/* we assume just one segment left network */
			tp->bytes_acked += min(ack - prior_snd_una,
					       tp->mss_cache);
	}

	prior_fackets = tp->fackets_out;
	prior_in_flight = serval_tcp_packets_in_flight(tp);

	if (!(flag & FLAG_SLOWPATH) && after(ack, prior_snd_una)) {
		/* Window is constant, pure forward advance.
		 * No more checks are required.
		 * Note, we use the fact that SND.UNA>=SND.WL2.
		 */
		serval_tcp_update_wl(tp, ack_seq);
		tp->snd_una = ack;
		flag |= FLAG_WIN_UPDATE;

		serval_tcp_ca_event(sk, CA_EVENT_FAST_ACK);

		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPHPACKS);
	} else {
		if (ack_seq != TCP_SKB_CB(skb)->end_seq)
			flag |= FLAG_DATA;
                /*
		else
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPPUREACKS);
                */
		flag |= serval_tcp_ack_update_window(sk, skb, ack, ack_seq);

                /*
		if (TCP_SKB_CB(skb)->sacked)
			flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una);

		if (TCP_ECN_rcv_ecn_echo(tp, tcp_hdr(skb)))
			flag |= FLAG_ECE;
                */

		serval_tcp_ca_event(sk, CA_EVENT_SLOW_ACK);
	}

	/* We passed data and got it acked, remove any soft error
	 * log. Something worked...
	 */
	sk->sk_err_soft = 0;
	tp->probes_out = 0;
	tp->rcv_tstamp = tcp_time_stamp;
	prior_packets = tp->packets_out;
	if (!prior_packets)
		goto no_queue;

	/* See if we can take anything off of the retransmit queue. */
	flag |= serval_tcp_clean_rtx_queue(sk, prior_fackets, prior_snd_una);

#if defined(FRTO)        
	if (tp->frto_counter)
		frto_cwnd = serval_tcp_process_frto(sk, flag);

	/* Guarantee sacktag reordering detection against wrap-arounds */
	if (before(tp->frto_highmark, tp->snd_una))
		tp->frto_highmark = 0;
#endif
	if (serval_tcp_ack_is_dubious(sk, flag)) {
		/* Advance CWND, if state allows this. */
		if ((flag & FLAG_DATA_ACKED) /* && !frto_cwnd */ &&
		    serval_tcp_may_raise_cwnd(sk, flag))
			serval_tcp_cong_avoid(sk, ack, prior_in_flight);
		
                serval_tcp_fastretrans_alert(sk, prior_packets - 
                                             tp->packets_out, flag, ack);
	} else {
		if ((flag & FLAG_DATA_ACKED) /* && !frto_cwnd */)
			serval_tcp_cong_avoid(sk, ack, prior_in_flight);
	}

#if defined(OS_LINUX_KERNEL)

	if ((flag & FLAG_FORWARD_PROGRESS) || !(flag & FLAG_NOT_DUP)) {
		struct dst_entry *dst = __sk_dst_get(sk);
		if (dst)
			dst_confirm(dst);
	}
#endif
	return 1;

no_queue:
	/* If this ack opens up a zero window, clear backoff.  It was
	 * being used to time the probes, and is probably far higher than
	 * it needs to be for normal retransmission.
	 */
	if (serval_tcp_send_head(sk))
		serval_tcp_ack_probe(sk);
	return 1;

invalid_ack:
        LOG_SSK(sk, "invalid ACK %u after %u:%u\n", 
                ack, tp->snd_una, tp->snd_nxt);
	//SOCK_DEBUG(sk, "Ack %u after %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
	return -1;

old_ack:
        /*
	if (TCP_SKB_CB(skb)->sacked) {
		tcp_sacktag_write_queue(sk, skb, prior_snd_una);
		if (tp->tp_ca_state == TCP_CA_Open)
			tcp_try_keep_open(sk);
	}
        */
        LOG_SSK(sk, "old ACK %u before %u:%u\n", 
                ack, tp->snd_una, tp->snd_nxt);

	//SOCK_DEBUG(sk, "Ack %u before %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
	return 0;
}

static int serval_tcp_parse_aligned_timestamp(struct serval_tcp_sock *tp, 
                                              struct tcphdr *th)
{
	__be32 *ptr = (__be32 *)(th + 1);

	if (*ptr == htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
			  | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP)) {
		tp->rx_opt.saw_tstamp = 1;
		++ptr;
		tp->rx_opt.rcv_tsval = ntohl(*ptr);
		++ptr;
		tp->rx_opt.rcv_tsecr = ntohl(*ptr);
		return 1;
	}
	return 0;
}


/* Look for tcp options. Normally only called on SYN and SYNACK packets.
 * But, this can also be called on packets in the established flow when
 * the fast version below fails.
 */
void serval_tcp_parse_options(struct sk_buff *skb, 
                              struct serval_tcp_options_received *opt_rx,
                              u8 **hvpp, int estab)
{
	unsigned char *ptr;
	struct tcphdr *th = tcp_hdr(skb);
	int length = (th->doff * 4) - sizeof(struct tcphdr);

	ptr = (unsigned char *)(th + 1);
	opt_rx->saw_tstamp = 0;

        LOG_DBG("Parsing TCP options\n");

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			switch (opcode) {
			case TCPOPT_MSS:
				if (opsize == TCPOLEN_MSS && 
                                    th->syn && !estab) {
					u16 in_mss = get_unaligned_be16(ptr);
					if (in_mss) {
						if (opt_rx->user_mss &&
						    opt_rx->user_mss < in_mss)
							in_mss = opt_rx->user_mss;
						opt_rx->mss_clamp = in_mss;
                                                LOG_DBG("TCPOPT_MSS mss_clamp=%u\n",
                                                        in_mss);
					}
				}
				break;
			case TCPOPT_WINDOW:
                                LOG_DBG("TCPOPT_WINDOW\n");
				if (opsize == TCPOLEN_WINDOW && th->syn &&
				    !estab && sysctl_serval_tcp_window_scaling) {
					__u8 snd_wscale = *(__u8 *)ptr;
					opt_rx->wscale_ok = 1;
					if (snd_wscale > 14) {
						if (net_ratelimit())
							LOG_INF("tcp_parse_options: Illegal window "                                                                "scaling value %d >14 received.\n", snd_wscale);
						snd_wscale = 14;
					}
					opt_rx->snd_wscale = snd_wscale;
                                        LOG_DBG("TCPOPT_WINDOW wscale=%u\n",
                                                snd_wscale);
				}
				break;
			case TCPOPT_TIMESTAMP:
				if ((opsize == TCPOLEN_TIMESTAMP) &&
				    ((estab && opt_rx->tstamp_ok) ||
				     (!estab && sysctl_serval_tcp_timestamps))) {
					opt_rx->saw_tstamp = 1;
					opt_rx->rcv_tsval = get_unaligned_be32(ptr);
					opt_rx->rcv_tsecr = get_unaligned_be32(ptr + 4);
				}
				break;
			case TCPOPT_SACK_PERM:
                                /*
				if (opsize == TCPOLEN_SACK_PERM && th->syn &&
				    !estab && sysctl_tcp_sack) {
					opt_rx->sack_ok = 1;
					tcp_sack_reset(opt_rx);
				}
                                */
                                LOG_WARN("TCPOPT_SACK_PERM not implemented!\n");
				break;

			case TCPOPT_SACK:
                                /*
				if ((opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK)) &&
				   !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK) &&
				   opt_rx->sack_ok) {
					TCP_SKB_CB(skb)->sacked = (ptr - 2) - (unsigned char *)th;
				}
                                */
                                LOG_WARN("TCPOPT_SACK not implemented!\n");
				break;
#ifdef CONFIG_TCP_MD5SIG
			case TCPOPT_MD5SIG:
				/*
				 * The MD5 Hash has already been
				 * checked (see tcp_v{4,6}_do_rcv()).
				 */
				break;
#endif
			case TCPOPT_COOKIE:
				/* This option is variable length.
				 */
				switch (opsize) {
				case TCPOLEN_COOKIE_BASE:
					/* not yet implemented */
					break;
				case TCPOLEN_COOKIE_PAIR:
					/* not yet implemented */
					break;
				case TCPOLEN_COOKIE_MIN+0:
				case TCPOLEN_COOKIE_MIN+2:
				case TCPOLEN_COOKIE_MIN+4:
				case TCPOLEN_COOKIE_MIN+6:
				case TCPOLEN_COOKIE_MAX:
					/* 16-bit multiple */
					opt_rx->cookie_plus = opsize;
					*hvpp = ptr;
					break;
				default:
					/* ignore option */
					break;
				}
				break;
			}

			ptr += opsize-2;
			length -= opsize;
		}
	}
}


static int serval_tcp_should_expand_sndbuf(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* If the user specified a specific send buffer setting, do
	 * not modify it.
	 */
	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return 0;

	/* If we are under global TCP memory pressure, do not expand.  */
	if (serval_tcp_memory_pressure)
		return 0;

	/* If we are under soft global TCP memory pressure, do not expand.  */
	if (           
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
            atomic_read(&serval_tcp_memory_allocated) >= sysctl_serval_tcp_mem[0]
#else
            atomic_long_read(&serval_tcp_memory_allocated) >= sysctl_serval_tcp_mem[0]
#endif
            )
		return 0;

	/* If we filled the congestion window, do not expand.  */
	if (tp->packets_out >= tp->snd_cwnd)
		return 0;

	return 1;
}

/* When incoming ACK allowed to free some skb from write_queue,
 * we remember this event in flag SOCK_QUEUE_SHRUNK and wake up socket
 * on the exit from tcp input handler.
 *
 * PROBLEM: sndbuf expansion does not work well with largesend.
 */
static void serval_tcp_new_space(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (serval_tcp_should_expand_sndbuf(sk)) {
		int sndmem = max_t(u32, tp->rx_opt.mss_clamp, tp->mss_cache) +
			MAX_SERVAL_TCP_HEADER + 16 + sizeof(struct sk_buff);
		int demanded = max_t(unsigned int, tp->snd_cwnd,
				     tp->reordering + 1);
		sndmem *= 2 * demanded;
		if (sndmem > sk->sk_sndbuf)
			sk->sk_sndbuf = min(sndmem, sysctl_serval_tcp_wmem[2]);
		tp->snd_cwnd_stamp = tcp_time_stamp;
	}

	sk->sk_write_space(sk);
}

static void serval_tcp_check_space(struct sock *sk)
{
	if (sock_flag(sk, SOCK_QUEUE_SHRUNK)) {
		sock_reset_flag(sk, SOCK_QUEUE_SHRUNK);
		if (sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
			serval_tcp_new_space(sk);
	}
}

static inline void serval_tcp_data_snd_check(struct sock *sk)
{
	serval_tcp_push_pending_frames(sk);
	serval_tcp_check_space(sk);
}

/*
 * Check if sending an ack is needed.
 */
static void __serval_tcp_ack_snd_check(struct sock *sk, int ofo_possible)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        int window = __serval_tcp_select_window(sk);

        LOG_SSK(sk, "rcv_nxt=%u rcv_wup=%u rcv_mss=%u window=%d rcv_wnd=%u quickack=%d ofo=%d\n", 
                tp->rcv_nxt, tp->rcv_wup, tp->tp_ack.rcv_mss, window, 
                tp->rcv_wnd, serval_tcp_in_quickack_mode(sk), 
                (ofo_possible && skb_peek(&tp->out_of_order_queue)));

        /* More than one full frame received... */
	if (((tp->rcv_nxt - tp->rcv_wup) > tp->tp_ack.rcv_mss &&
	     /* ... and right edge of window advances far enough.
	      * (tcp_recvmsg() will send ACK otherwise). Or...
	      */
	     window >= tp->rcv_wnd) ||
	    /* We ACK each frame or... */
	    serval_tcp_in_quickack_mode(sk) ||
	    /* We have out of order data. */
	    (ofo_possible && skb_peek(&tp->out_of_order_queue))) {
		/* Then ack it now */
		serval_tcp_send_ack(sk);

                LOG_SSK(sk, "sending normal ACK\n");
	} else {
		/* Else, send delayed ack. */
                LOG_SSK(sk, "sending delayed ACK\n");
		serval_tcp_send_delayed_ack(sk);
	}
}

static inline void serval_tcp_ack_snd_check(struct sock *sk)
{
	if (!serval_tsk_ack_scheduled(sk)) {
		/* We sent a data segment already. */
		return;
	}
	__serval_tcp_ack_snd_check(sk, 1);
}

/* Fast parse options. This hopes to only see timestamps.
 * If it is wrong it falls back on tcp_parse_options().
 */
static int serval_tcp_fast_parse_options(struct sk_buff *skb, 
                                         struct tcphdr *th,
                                         struct serval_tcp_sock *tp, 
                                         u8 **hvpp)
{
	/* In the spirit of fast parsing, compare doff directly to
	 * constant values.  Because equality is used, short doff can
	 * be ignored here.
	 */
	if (th->doff == (sizeof(*th) / 4)) {
		tp->rx_opt.saw_tstamp = 0;
		return 0;
	} else if (tp->rx_opt.tstamp_ok &&
		   th->doff == ((sizeof(*th) + TCPOLEN_TSTAMP_ALIGNED) / 4)) {
		if (serval_tcp_parse_aligned_timestamp(tp, th))
			return 1;
	}

	serval_tcp_parse_options(skb, &tp->rx_opt, hvpp, 1);
        return 1;
}


static inline void serval_tcp_store_ts_recent(struct serval_tcp_sock *tp)
{
	tp->rx_opt.ts_recent = tp->rx_opt.rcv_tsval;
	tp->rx_opt.ts_recent_stamp = get_seconds();
}

static inline void serval_tcp_replace_ts_recent(struct serval_tcp_sock *tp, 
                                                u32 seq)
{
	if (tp->rx_opt.saw_tstamp && !after(seq, tp->rcv_wup)) {
		/* PAWS bug workaround wrt. ACK frames, the PAWS discard
		 * extra check below makes sure this can only happen
		 * for pure ACK frames.  -DaveM
		 *
		 * Not only, also it occurs for expired timestamps.
		 */

		if (serval_tcp_paws_check(&tp->rx_opt, 0))
			serval_tcp_store_ts_recent(tp);
	}
}

#if defined(ENABLE_TCP_PAWS)

static inline int serval_tcp_paws_discard(const struct sock *sk,
                                          const struct sk_buff *skb)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        
	return !serval_tcp_paws_check(&tp->rx_opt, TCP_PAWS_WINDOW) &&
	       !serval_tcp_disordered_ack(sk, skb);
}

#endif /* ENABLE_TCP_PAWS */


static void serval_tcp_dsack_set(struct sock *sk, u32 seq, u32 end_seq)
{
#if defined(ENABLE_TCP_SACK)
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	if (serval_tcp_is_sack(tp) && sysctl_tcp_dsack) {
		/*
                int mib_idx;
                
		if (before(seq, tp->rcv_nxt))
			mib_idx = LINUX_MIB_TCPDSACKOLDSENT;
		else
			mib_idx = LINUX_MIB_TCPDSACKOFOSENT;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);
                */
		tp->rx_opt.dsack = 1;
		tp->duplicate_sack[0].start_seq = seq;
		tp->duplicate_sack[0].end_seq = end_seq;
	}
#endif
}

#if defined(ENABLE_TCP_SACK)
static inline int serval_tcp_sack_extend(struct tcp_sack_block *sp, u32 seq,
                                         u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return 1;
	}
	return 0;
}

static void serval_tcp_dsack_extend(struct sock *sk, u32 seq, u32 end_seq)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (!tp->rx_opt.dsack)
		serval_tcp_dsack_set(sk, seq, end_seq);
	else
		serval_tcp_sack_extend(tp->duplicate_sack, seq, end_seq);
}

#endif /* ENABLE_TCP_SACK */

/*
 * 	Process the FIN bit. This now behaves as it is supposed to work
 *	and the FIN takes effect when it is validly part of sequence
 *	space. Not before when we get holes.
 *
 *	If we are ESTABLISHED, a received fin moves us to CLOSE-WAIT
 *	(and thence onto LAST-ACK and finally, CLOSE, we never enter
 *	TIME-WAIT)
 *
 *	If we are in FINWAIT-1, a received FIN indicates simultaneous
 *	close and we go into CLOSING (and later onto TIME-WAIT)
 *
 *	If we are in FINWAIT-2, a received FIN moves us to TIME-WAIT.
 */
static void serval_tcp_fin(struct sk_buff *skb, 
                           struct sock *sk, struct tcphdr *th)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

        LOG_SSK(sk, "TCP FIN %s\n", tcphdr_to_str(th));

	serval_tsk_schedule_ack(sk);

	/* It _is_ possible, that we have something out-of-order _after_ FIN.
	 * Probably, we should reset in this case. For now drop them.
	 */
	__skb_queue_purge(&tp->out_of_order_queue);
#if defined(ENABLE_TCP_SACK)
	if (serval_tcp_is_sack(tp))
		serval_tcp_sack_reset(&tp->rx_opt);
#endif
	sk_mem_reclaim(sk);
}

/* This one checks to see if we can put data from the
 * out_of_order queue into the receive_queue.
 */
static void serval_tcp_ofo_queue(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
#if defined(ENABLE_TCP_SACK)
	__u32 dsack_high = tp->rcv_nxt;
#endif
	struct sk_buff *skb;

	while ((skb = skb_peek(&tp->out_of_order_queue)) != NULL) {
		if (after(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
			break;

                /*
		if (before(TCP_SKB_CB(skb)->seq, dsack_high)) {
			__u32 dsack = dsack_high;
			if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
				dsack_high = TCP_SKB_CB(skb)->end_seq;
			serval_tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
		}
                */
		if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {
			LOG_SSK(sk, "ofo packet was already received\n");
			__skb_unlink(skb, &tp->out_of_order_queue);
			__kfree_skb(skb);
			continue;
		}
		LOG_PKT("ofo requeuing : rcv_next=%u seq=%u end=%u\n",
                        tp->rcv_nxt, TCP_SKB_CB(skb)->seq,
                        TCP_SKB_CB(skb)->end_seq);

		__skb_unlink(skb, &tp->out_of_order_queue);
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (tcp_hdr(skb)->fin)
			serval_tcp_fin(skb, sk, tcp_hdr(skb));
	}
}

static int serval_tcp_prune_ofo_queue(struct sock *sk);
static int serval_tcp_prune_queue(struct sock *sk);

static inline int serval_tcp_try_rmem_schedule(struct sock *sk, 
                                               struct sk_buff *skb,
                                               unsigned int size)
{
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
	    !sk_rmem_schedule(sk,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0))
                              skb,
#endif
                              size)) {
                
		if (serval_tcp_prune_queue(sk) < 0)
			return -1;
                
		if (!sk_rmem_schedule(sk, 
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0))
                                      skb,
#endif
                                      size)) {
                        
                        if (!serval_tcp_prune_ofo_queue(sk))
                                return -1;
                        
                        if (!sk_rmem_schedule(sk, 
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0))
                                              skb,
#endif
                                              size))
				return -1;
		}
	}
	return 0;
}

static void serval_tcp_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int eaten = -1;

	if (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq) {
		//LOG_SSK(sk, "seq is end_seq, dropping\n");
                goto drop;
        }

	skb_dst_drop(skb);
	__skb_pull(skb, th->doff * 4);

	//TCP_ECN_accept_cwr(tp, skb);

	tp->rx_opt.dsack = 0;

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt) {
		if (serval_tcp_receive_window(tp) == 0)                        
			goto out_of_window;

		/* Ok. In sequence. In window. */
		if (tp->ucopy.task == current &&
		    tp->copied_seq == tp->rcv_nxt && tp->ucopy.len &&
		    sock_owned_by_user(sk) && !tp->urg_data) {
			int chunk = min_t(unsigned int, skb->len,
					  tp->ucopy.len);

			__set_current_state(TASK_RUNNING);

			local_bh_enable();
			if (!skb_copy_datagram_iovec(skb, 0, tp->ucopy.iov, chunk)) {
				tp->ucopy.len -= chunk;
				tp->copied_seq += chunk;
				eaten = (chunk == skb->len && !th->fin);
				serval_tcp_rcv_space_adjust(sk);
			}
			local_bh_disable();
		}

		if (eaten <= 0) {
queue_and_out:
			if (eaten < 0 &&
			    serval_tcp_try_rmem_schedule(sk, skb, skb->truesize))
				goto drop;
                        
			skb_set_owner_r(skb, sk);
			__skb_queue_tail(&sk->sk_receive_queue, skb);
		}
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (skb->len)
			serval_tcp_event_data_recv(sk, skb);
		if (th->fin)
			serval_tcp_fin(skb, sk, th);

		if (!skb_queue_empty(&tp->out_of_order_queue)) {
			serval_tcp_ofo_queue(sk);

			/* RFC2581. 4.2. SHOULD send immediate ACK, when
			 * gap in queue is filled.
			 */
			if (skb_queue_empty(&tp->out_of_order_queue))
				tp->tp_ack.pingpong = 0;
		}
#if defined(ENABLE_TCP_SACK)
		if (tp->rx_opt.num_sacks)
			serval_tcp_sack_remove(tp);
#endif
		serval_tcp_fast_path_check(sk);

		if (eaten > 0) {
			__kfree_skb(skb);
                } else if (!sock_flag(sk, SOCK_DEAD)) {

			sk->sk_data_ready(sk, 0);
                }
		return;
        }

	if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {
		/* A retransmit, 2nd most common case.  Force an immediate ack. */
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOST);

		serval_tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, 
                                     TCP_SKB_CB(skb)->end_seq);
        out_of_window:
		serval_tcp_enter_quickack_mode(sk);
		serval_tsk_schedule_ack(sk);
        drop:
		__kfree_skb(skb);
		return;
	}

	/* Out of window. F.e. zero window probe. */
	if (!before(TCP_SKB_CB(skb)->seq, 
                    tp->rcv_nxt + serval_tcp_receive_window(tp)))
		goto out_of_window;

	serval_tcp_enter_quickack_mode(sk);

	if (before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		/* Partial packet, seq < rcv_next < end_seq */
                
		serval_tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, tp->rcv_nxt);
		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		if (!serval_tcp_receive_window(tp))
			goto out_of_window;
		goto queue_and_out;
	}

	//TCP_ECN_check_ce(tp, skb);

	if (serval_tcp_try_rmem_schedule(sk, skb, skb->truesize)) {
                LOG_SSK(sk, "rmem schedule failed\n");
		goto drop;
        }

	/* Disable header prediction. */
	tp->pred_flags = 0;
	serval_tsk_schedule_ack(sk);
        
	skb_set_owner_r(skb, sk);

	if (!skb_peek(&tp->out_of_order_queue)) {
#if defined(ENABLE_TCP_SACK)
		/* Initial out of order segment, build 1 SACK. */
		if (serval_tcp_is_sack(tp)) {
			tp->rx_opt.num_sacks = 1;
			tp->selective_acks[0].start_seq = TCP_SKB_CB(skb)->seq;
			tp->selective_acks[0].end_seq =
						TCP_SKB_CB(skb)->end_seq;
		}
#endif
		__skb_queue_head(&tp->out_of_order_queue, skb);
	} else {
		struct sk_buff *skb1 = skb_peek_tail(&tp->out_of_order_queue);
		u32 seq = TCP_SKB_CB(skb)->seq;
		u32 end_seq = TCP_SKB_CB(skb)->end_seq;

		if (seq == TCP_SKB_CB(skb1)->end_seq) {
			__skb_queue_after(&tp->out_of_order_queue, skb1, skb);
#if defined(ENABLE_TCP_SACK)
			if (!tp->rx_opt.num_sacks ||
			    tp->selective_acks[0].end_seq != seq)
				goto add_sack;
			/* Common case: data arrive in order after hole. */
			tp->selective_acks[0].end_seq = end_seq;
#endif
			return;
		}

		/* Find place to insert this segment. */
		while (1) {
			if (!after(TCP_SKB_CB(skb1)->seq, seq))
				break;
			if (skb_queue_is_first(&tp->out_of_order_queue, skb1)) {
				skb1 = NULL;
				break;
			}
			skb1 = skb_queue_prev(&tp->out_of_order_queue, skb1);
		}

		/* Do skb overlap to previous one? */
		if (skb1 && before(seq, TCP_SKB_CB(skb1)->end_seq)) {
			if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
				/* All the bits are present. Drop. */
				__kfree_skb(skb);
				serval_tcp_dsack_set(sk, seq, end_seq);
				goto add_sack;
			}

			if (after(seq, TCP_SKB_CB(skb1)->seq)) {
				/* Partial overlap. */
				serval_tcp_dsack_set(sk, seq,
                                                     TCP_SKB_CB(skb1)->end_seq);
			} else {
				if (skb_queue_is_first(&tp->out_of_order_queue,
						       skb1))
					skb1 = NULL;
				else
					skb1 = skb_queue_prev(
						&tp->out_of_order_queue,
						skb1);
			}
		}
		if (!skb1)
			__skb_queue_head(&tp->out_of_order_queue, skb);
		else
			__skb_queue_after(&tp->out_of_order_queue, skb1, skb);

		/* And clean segments covered by new one as whole. */
		while (!skb_queue_is_last(&tp->out_of_order_queue, skb)) {
			skb1 = skb_queue_next(&tp->out_of_order_queue, skb);

			if (!after(end_seq, TCP_SKB_CB(skb1)->seq))
				break;
			if (before(end_seq, TCP_SKB_CB(skb1)->end_seq)) {

#if defined(ENABLE_TCP_SACK)
				serval_tcp_dsack_extend(sk, 
                                                        TCP_SKB_CB(skb1)->seq,
                                                        end_seq);
#endif
				break;
			}
			__skb_unlink(skb1, &tp->out_of_order_queue);

#if defined(ENABLE_TCP_SACK)
			serval_tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
                                                TCP_SKB_CB(skb1)->end_seq);
#endif
			__kfree_skb(skb1);
		}

        add_sack:;
#if defined(ENABLE_TCP_SACK)
		if (serval_tcp_is_sack(tp))
			serval_tcp_sack_new_ofo_skb(sk, seq, end_seq);
#endif
	}
}

static struct sk_buff *serval_tcp_collapse_one(struct sock *sk, 
                                               struct sk_buff *skb,
                                               struct sk_buff_head *list)
{
	struct sk_buff *next = NULL;

	if (!skb_queue_is_last(list, skb))
		next = skb_queue_next(list, skb);

	__skb_unlink(skb, list);
	__kfree_skb(skb);
	//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPRCVCOLLAPSED);

	return next;
}

/* Collapse contiguous sequence of skbs head..tail with
 * sequence numbers start..end.
 *
 * If tail is NULL, this means until the end of the list.
 *
 * Segments with FIN/SYN are not collapsed (only because this
 * simplifies code)
 */
static void serval_tcp_collapse(struct sock *sk, struct sk_buff_head *list,
                                struct sk_buff *head, struct sk_buff *tail,
                                u32 start, u32 end)
{
	struct sk_buff *skb, *n;
	int end_of_skbs;

	/* First, check that queue is collapsible and find
	 * the point where collapsing can be useful. */
	skb = head;
restart:
	end_of_skbs = 1;
	skb_queue_walk_from_safe(list, skb, n) {
		if (skb == tail)
			break;
		/* No new bits? It is possible on ofo queue. */
		if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
			skb = serval_tcp_collapse_one(sk, skb, list);
			if (!skb)
				break;
			goto restart;
		}

		/* The first skb to collapse is:
		 * - not SYN/FIN and
		 * - bloated or contains data before "start" or
		 *   overlaps to the next one.
		 */
		if (!tcp_hdr(skb)->syn && !tcp_hdr(skb)->fin &&
		    (serval_tcp_win_from_space(skb->truesize) > skb->len ||
		     before(TCP_SKB_CB(skb)->seq, start))) {
			end_of_skbs = 0;
			break;
		}

		if (!skb_queue_is_last(list, skb)) {
			struct sk_buff *next = skb_queue_next(list, skb);
			if (next != tail &&
			    TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(next)->seq) {
				end_of_skbs = 0;
				break;
			}
		}

		/* Decided to skip this, advance start seq. */
		start = TCP_SKB_CB(skb)->end_seq;
	}
	if (end_of_skbs || tcp_hdr(skb)->syn || tcp_hdr(skb)->fin)
		return;

	while (before(start, end)) {
		struct sk_buff *nskb;
		unsigned int header = skb_headroom(skb);
		int copy = SKB_MAX_ORDER(header, 0);

		/* Too big header? This can happen with IPv6. */
		if (copy < 0)
			return;
		if (end - start < copy)
			copy = end - start;
		nskb = alloc_skb(copy + header, GFP_ATOMIC);
		if (!nskb)
			return;

		skb_set_mac_header(nskb, skb_mac_header(skb) - skb->head);
		skb_set_network_header(nskb, (skb_network_header(skb) -
					      skb->head));
		skb_set_transport_header(nskb, (skb_transport_header(skb) -
						skb->head));
		skb_reserve(nskb, header);
		memcpy(nskb->head, skb->head, header);
		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
		TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(nskb)->end_seq = start;
		__skb_queue_before(list, skb, nskb);
		skb_set_owner_r(nskb, sk);

		/* Copy data, releasing collapsed skbs. */
		while (copy > 0) {
			int offset = start - TCP_SKB_CB(skb)->seq;
			int size = TCP_SKB_CB(skb)->end_seq - start;

			BUG_ON(offset < 0);
			if (size > 0) {
				size = min(copy, size);
				if (skb_copy_bits(skb, offset, skb_put(nskb, size), size))
					BUG();
				TCP_SKB_CB(nskb)->end_seq += size;
				copy -= size;
				start += size;
			}
			if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
				skb = serval_tcp_collapse_one(sk, skb, list);
				if (!skb ||
				    skb == tail ||
				    tcp_hdr(skb)->syn ||
				    tcp_hdr(skb)->fin)
					return;
			}
		}
	}
}

/* Collapse ofo queue. Algorithm: select contiguous sequence of skbs
 * and tcp_collapse() them until all the queue is collapsed.
 */
static void serval_tcp_collapse_ofo_queue(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb = skb_peek(&tp->out_of_order_queue);
	struct sk_buff *head;
	u32 start, end;

	if (skb == NULL)
		return;

	start = TCP_SKB_CB(skb)->seq;
	end = TCP_SKB_CB(skb)->end_seq;
	head = skb;

	for (;;) {
		struct sk_buff *next = NULL;

		if (!skb_queue_is_last(&tp->out_of_order_queue, skb))
			next = skb_queue_next(&tp->out_of_order_queue, skb);
		skb = next;

		/* Segment is terminated when we see gap or when
		 * we are at the end of all the queue. */
		if (!skb ||
		    after(TCP_SKB_CB(skb)->seq, end) ||
		    before(TCP_SKB_CB(skb)->end_seq, start)) {
			serval_tcp_collapse(sk, &tp->out_of_order_queue,
				     head, skb, start, end);
			head = skb;
			if (!skb)
				break;
			/* Start new segment */
			start = TCP_SKB_CB(skb)->seq;
			end = TCP_SKB_CB(skb)->end_seq;
		} else {
			if (before(TCP_SKB_CB(skb)->seq, start))
				start = TCP_SKB_CB(skb)->seq;
			if (after(TCP_SKB_CB(skb)->end_seq, end))
				end = TCP_SKB_CB(skb)->end_seq;
		}
	}
}

/*
 * Purge the out-of-order queue.
 * Return true if queue was pruned.
 */
static int serval_tcp_prune_ofo_queue(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int res = 0;

	if (!skb_queue_empty(&tp->out_of_order_queue)) {
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_OFOPRUNED);
		__skb_queue_purge(&tp->out_of_order_queue);

		/* Reset SACK state.  A conforming SACK implementation will
		 * do the same at a timeout based retransmit.  When a connection
		 * is in a sad state like this, we care only about integrity
		 * of the connection not performance.
		 */
#if defined(ENABLE_TCP_SACK)
		if (tp->rx_opt.sack_ok)
			serval_tcp_sack_reset(&tp->rx_opt);
#endif
		sk_mem_reclaim(sk);
		res = 1;
	}
	return res;
}

/* Reduce allocated memory if we can, trying to get
 * the socket within its memory limits again.
 *
 * Return less than zero if we should start dropping frames
 * until the socket owning process reads some of the data
 * to stabilize the situation.
 */
static int serval_tcp_prune_queue(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PRUNECALLED);

	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
		serval_tcp_clamp_window(sk);
	else if (serval_tcp_memory_pressure)
		tp->rcv_ssthresh = min(tp->rcv_ssthresh, 4U * tp->advmss);

	serval_tcp_collapse_ofo_queue(sk);

	if (!skb_queue_empty(&sk->sk_receive_queue))
		serval_tcp_collapse(sk, &sk->sk_receive_queue,
                                    skb_peek(&sk->sk_receive_queue),
                                    NULL,
                                    tp->copied_seq, tp->rcv_nxt);
	sk_mem_reclaim(sk);

	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* Collapsing did not help, destructive actions follow.
	 * This must not ever occur. */

	serval_tcp_prune_ofo_queue(sk);
        
	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* If we are really being abused, tell the caller to silently
	 * drop receive data on the floor.  It will get retransmitted
	 * and hopefully then we'll have sufficient space.
	 */
	//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_RCVPRUNED);

	/* Massive buffer overcommit. */
	tp->pred_flags = 0;
	return -1;
}

static void serval_tcp_send_dupack(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
	    before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOST);
		serval_tcp_enter_quickack_mode(sk);

                /*
		if (serval_tcp_is_sack(tp) && sysctl_serval_tcp_dsack) {
			u32 end_seq = TCP_SKB_CB(skb)->end_seq;

			if (after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt))
				end_seq = tp->rcv_nxt;
			serval_tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, end_seq);
		}
                */
	}

	serval_tcp_send_ack(sk);
}


/* Check segment sequence number for validity.
 *
 * Segment controls are considered valid, if the segment
 * fits to the window after truncation to the window. Acceptability
 * of data (and SYN, FIN, of course) is checked separately.
 * See tcp_data_queue(), for example.
 *
 * Also, controls (RST is main one) are accepted using RCV.WUP instead
 * of RCV.NXT. Peer still did not advance his SND.UNA when we
 * delayed ACK, so that hisSND.UNA<=ourRCV.WUP.
 * (borrowed from freebsd)
 */

static inline int serval_tcp_sequence(struct serval_tcp_sock *tp, 
                                      u32 seq, u32 end_seq)
{
	return !before(end_seq, tp->rcv_wup) &&
		!after(seq, tp->rcv_nxt + serval_tcp_receive_window(tp));
}

#ifdef CONFIG_NET_DMA
static int serval_tcp_dma_try_early_copy(struct sock *sk, struct sk_buff *skb,
                                         int hlen)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int chunk = skb->len - hlen;
	int dma_cookie;
	int copied_early = 0;

	if (tp->ucopy.wakeup)
		return 0;

	if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
		tp->ucopy.dma_chan = dma_find_channel(DMA_MEMCPY);

	if (tp->ucopy.dma_chan && skb_csum_unnecessary(skb)) {

		dma_cookie = dma_skb_copy_datagram_iovec(tp->ucopy.dma_chan,
							 skb, hlen,
							 tp->ucopy.iov, chunk,
							 tp->ucopy.pinned_list);

		if (dma_cookie < 0)
			goto out;

		tp->ucopy.dma_cookie = dma_cookie;
		copied_early = 1;

		tp->ucopy.len -= chunk;
		tp->copied_seq += chunk;
		serval_tcp_rcv_space_adjust(sk);

		if ((tp->ucopy.len == 0) ||
		    (tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_PSH) ||
		    (atomic_read(&sk->sk_rmem_alloc) > (sk->sk_rcvbuf >> 1))) {
			tp->ucopy.wakeup = 1;
			sk->sk_data_ready(sk, 0);
		}
	} else if (chunk > 0) {
		tp->ucopy.wakeup = 1;
		sk->sk_data_ready(sk, 0);
	}
out:
	return copied_early;
}
#endif /* CONFIG_NET_DMA */

/* Does PAWS and seqno based validation of an incoming segment, flags will
 * play significant role here.
 */
static int serval_tcp_validate_incoming(struct sock *sk, struct sk_buff *skb,
                                        struct tcphdr *th, int syn_inerr)
{
	u8 *hash_location;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

#if defined(ENABLE_TCP_PAWS)
	/* RFC1323: H1. Apply PAWS check first. */
	if (serval_tcp_fast_parse_options(skb, th, tp, &hash_location) && 
            tp->rx_opt.saw_tstamp &&
	    serval_tcp_paws_discard(sk, skb)) {
		if (!th->rst) {
			//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
			serval_tcp_send_dupack(sk, skb);
			goto discard;
		}
		/* Reset is accepted even if it did not pass PAWS. */
	}
#else
        serval_tcp_fast_parse_options(skb, th, tp, &hash_location);
#endif /* ENABLE_TCP_PAWS */

	/* Step 1: check sequence number */
	if (!serval_tcp_sequence(tp, TCP_SKB_CB(skb)->seq, 
                                 TCP_SKB_CB(skb)->end_seq)) {
		/* RFC793, page 37: "In all states except SYN-SENT, all reset
		 * (RST) segments are validated by checking their SEQ-fields."
		 * And page 69: "If an incoming segment is not acceptable,
		 * an acknowledgment should be sent in reply (unless the RST
		 * bit is set, if so drop the segment and return)".
		 */
		if (!th->rst)
			serval_tcp_send_dupack(sk, skb);

                LOG_SSK(sk, "Bad seqno seq=%u end_seq=%u rcv_nxt=%u rcv_wnd=%u\n", 
                        TCP_SKB_CB(skb)->seq, 
                        TCP_SKB_CB(skb)->end_seq, 
                        tp->rcv_nxt, 
                        tp->rcv_wnd);
                        
		goto discard;
	}

	/* Step 2: check RST bit */
	if (th->rst) {
		serval_sal_rcv_reset(sk);
                LOG_SSK(sk, "RST bit set!\n");
		goto discard;
	}

	/* ts_recent update must be made after we are sure that the packet
	 * is in window.
	 */
	serval_tcp_replace_ts_recent(tp, TCP_SKB_CB(skb)->seq);

	/* step 3: check security and precedence [ignored] */

	/* step 4: Check for a SYN in window. */
	if (th->syn && !before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		/* if (syn_inerr)
			TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONSYN);
                */
                LOG_SSK(sk, "SYN out of window. Handling as RESET\n");
		serval_sal_rcv_reset(sk);
		return -1;
	}

	return 1;

discard:
        LOG_SSK(sk, "Discarding packet\n");
        kfree_skb(skb);
	return 0;
}

static int serval_tcp_copy_to_iovec(struct sock *sk, 
                                    struct sk_buff *skb, int hlen)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int chunk = skb->len - hlen;
	int err;

	local_bh_enable();
	if (skb_csum_unnecessary(skb))
		err = skb_copy_datagram_iovec(skb, hlen, tp->ucopy.iov, chunk);
	else
		err = skb_copy_and_csum_datagram_iovec(skb, hlen,
						       tp->ucopy.iov);

	if (!err) {
		tp->ucopy.len -= chunk;
		tp->copied_seq += chunk;
		serval_tcp_rcv_space_adjust(sk);
	}

	local_bh_disable();
	return err;
}

static __sum16 __serval_tcp_checksum_complete_user(struct sock *sk,
                                                   struct sk_buff *skb)
{
	__sum16 result = 0;

	if (sock_owned_by_user(sk)) {
		local_bh_enable();
		result = __serval_tcp_checksum_complete(skb);
		local_bh_disable();
	} else {
		result = __serval_tcp_checksum_complete(skb);
	}

	return result;
}

static inline int serval_tcp_checksum_complete_user(struct sock *sk,
					     struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
                __serval_tcp_checksum_complete_user(sk, skb);
}

/*
 *	This function implements the receiving procedure of RFC 793 for
 *	all states except ESTABLISHED and TIME_WAIT.
 *	It's called from both tcp_v4_rcv and tcp_v6_rcv and should be
 *	address independent.
 */

int serval_tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb,
                                 struct tcphdr *th, unsigned len)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int queued = 0;
	int res;

	tp->rx_opt.saw_tstamp = 0;

	switch (sk->sk_state) {
	case TCP_CLOSE:
	case TCP_LISTEN:
        case TCP_SYN_SENT:
		goto discard;
        }

	res = serval_tcp_validate_incoming(sk, skb, th, 0);

	if (res <= 0) {
                LOG_ERR("Incoming packet could not be validated\n");
                return -res;
        }
	/* step 5: check the ACK field */
	if (th->ack) {
                serval_tcp_ack(sk, skb, FLAG_SLOWPATH);
                
		switch (sk->sk_state) {
		case TCP_FIN_WAIT1:
			if (tp->snd_una == tp->write_seq) {
#if defined(OS_LINUX_KERNEL)
				struct dst_entry *dst;
                                dst = __sk_dst_get(sk);
				if (dst)
					dst_confirm(dst);
#endif

				if (sock_flag(sk, SOCK_DEAD)) {
					int tmo;
#if 0
					if (tp->linger2 < 0 ||
					    (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
					     after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt))) {
                                                LOG_SSK(sk, "TCP Done!\n");
						serval_sal_done(sk);
                           
						return 1;
					}
#endif /* 0 */
					tmo = serval_tcp_fin_time(sk);

					if (tmo > TCP_TIMEWAIT_LEN) {
						serval_tsk_reset_keepalive_timer(sk, tmo - TCP_TIMEWAIT_LEN);
					} else if (th->fin || sock_owned_by_user(sk)) {
						/* Bad case. We could lose such FIN otherwise.
						 * It is not a big problem, but it looks confusing
						 * and not so rare event. We still can lose it now,
						 * if it spins in bh_lock_sock(), but it is really
						 * marginal case.
						 */
						serval_tsk_reset_keepalive_timer(sk, tmo);
					} else {
						goto discard;
					}
				}
			}
			break;
                case TCP_CLOSE_WAIT:
                        break;
                case TCP_CLOSING:
                        break;
		case TCP_LAST_ACK:
			if (tp->snd_una == tp->write_seq) {
				serval_tcp_update_metrics(sk);
				goto discard;
			}
			break;
		}
	} else {
                LOG_SSK(sk, "NO ACK in packet -> goto discard\n");
		goto discard;
        }
	/* step 6: check the URG bit */
	//serval_tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	switch (sk->sk_state) {
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
			break;
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		/* RFC 793 says to queue data in these states,
		 * RFC 1122 says we MUST send a reset.
		 * BSD 4.4 also does reset.
		 */
		if (sk->sk_shutdown & RCV_SHUTDOWN) {
			if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
			    after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt)) {
                                LOG_SSK(sk, "received seqno after rcv_nxt. Handling as RESET\n");
				serval_sal_rcv_reset(sk);
                                /* FIXME: free_skb here, or handle in
                                   calling func? */
				return 1;
			}
		}
		/* Fall through */
	case TCP_ESTABLISHED:
		serval_tcp_data_queue(sk, skb);
		queued = 1;
		break;
	}

	/* tcp_data could move socket to TIME-WAIT */
	if (sk->sk_state != TCP_CLOSE) {
		serval_tcp_data_snd_check(sk);
		serval_tcp_ack_snd_check(sk);
	}

	if (!queued) {
discard:
                kfree_skb(skb);
	}

	return 0;
}

/*
 *	TCP receive function for the ESTABLISHED state.
 *
 *	It is split into a fast path and a slow path. The fast path is
 * 	disabled when:
 *	- A zero window was announced from us - zero window probing
 *        is only handled properly in the slow path.
 *	- Out of order segments arrived.
 *	- Urgent data is expected.
 *	- There is no buffer space left
 *	- Unexpected TCP flags/window values/header lengths are received
 *	  (detected by checking the TCP header against pred_flags)
 *	- Data is sent in both directions. Fast path only supports pure senders
 *	  or pure receivers (this means either the sequence number or the ack
 *	  value must stay constant)
 *	- Unexpected TCP option.
 *
 *	When these conditions are not satisfied it drops into a standard
 *	receive procedure patterned after RFC793 to handle all cases.
 *	The first three cases are guaranteed by proper pred_flags setting,
 *	the rest is checked inline. Fast processing is turned on in
 *	tcp_data_queue when everything is OK.
 */
int serval_tcp_rcv_established(struct sock *sk, struct sk_buff *skb,
                               struct tcphdr *th, unsigned len)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int res;

	/*
	 *	Header prediction.
	 *	The code loosely follows the one in the famous
	 *	"30 instruction TCP receive" Van Jacobson mail.
	 *
	 *	Van's trick is to deposit buffers into socket queue
	 *	on a device interrupt, to call tcp_recv function
	 *	on the receive process context and checksum and copy
	 *	the buffer to user space. smart...
	 *
	 *	Our current scheme is not silly either but we take the
	 *	extra cost of the net_bh soft interrupt processing...
	 *	We do checksum and copy also but from device to kernel.
	 */

	tp->rx_opt.saw_tstamp = 0;

	/*	pred_flags is 0xS?10 << 16 + snd_wnd
	 *	if header_prediction is to be made
	 *	'S' will always be tp->tcp_header_len >> 2
	 *	'?' will be 0 for the fast path, otherwise pred_flags is 0 to
	 *  turn it off	(when there are holes in the receive
	 *	 space for instance)
	 *	PSH flag is ignored.
	 */

        tp->bytes_queued += len;

        LOG_PKT("Packet %s total_bytes=%u\n", 
                tcphdr_to_str(th), tp->bytes_queued);

	if ((serval_tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags &&
	    TCP_SKB_CB(skb)->seq == tp->rcv_nxt &&
	    !after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)) {
		int tcp_header_len = tp->tcp_header_len;
                
		/* Timestamp header prediction: tcp_header_len
		 * is automatically equal to th->doff*4 due to pred_flags
		 * match.
		 */

		/* Check timestamp */
		if (tcp_header_len == sizeof(struct tcphdr) + 
                    TCPOLEN_TSTAMP_ALIGNED) {
                        LOG_PKT("TCP has timestamp\n");

			/* No? Slow path! */
			if (!serval_tcp_parse_aligned_timestamp(tp, th))
				goto slow_path;

			/* If PAWS failed, check it more carefully in slow path */
			if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
				goto slow_path;

			/* DO NOT update ts_recent here, if checksum fails
			 * and timestamp was corrupted part, it will result
			 * in a hung connection since we will drop all
			 * future packets due to the PAWS test.
			 */
		}

		if (len <= tcp_header_len) {
			/* Bulk data transfer: sender */
			if (len == tcp_header_len) {
				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len ==
				    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
				    tp->rcv_nxt == tp->rcv_wup)
					serval_tcp_store_ts_recent(tp);

				/* We know that such packets are checksummed
				 * on entry.
				 */
                                serval_tcp_ack(sk, skb, 0);
				__kfree_skb(skb);
				serval_tcp_data_snd_check(sk);
				return 0;
			} else { /* Header too small */
				//TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
				goto discard;
			}
		} else {
			int eaten = 0;
			int copied_early = 0;

			if (tp->copied_seq == tp->rcv_nxt &&
			    len - tcp_header_len <= tp->ucopy.len) {
#ifdef CONFIG_NET_DMA
				if (serval_tcp_dma_try_early_copy(sk, skb, tcp_header_len)) {                                        
					copied_early = 1;
					eaten = 1;
				}
#endif
				if (tp->ucopy.task == current &&
				    sock_owned_by_user(sk) && !copied_early) {
					__set_current_state(TASK_RUNNING);

					if (!serval_tcp_copy_to_iovec(sk, skb, tcp_header_len))
						eaten = 1;
				}
				if (eaten) {
					/* Predicted packet is in window by definition.
					 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
					 * Hence, check seq<=rcv_wup reduces to:
					 */
					if (tcp_header_len ==
					    (sizeof(struct tcphdr) +
					     TCPOLEN_TSTAMP_ALIGNED) &&
					    tp->rcv_nxt == tp->rcv_wup)
						serval_tcp_store_ts_recent(tp);

					serval_tcp_rcv_rtt_measure_ts(sk, skb);

					__skb_pull(skb, tcp_header_len);
					tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
					//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPHPHITSTOUSER);
				}
				if (copied_early)
					serval_tcp_cleanup_rbuf(sk, skb->len);
			}
			if (!eaten) {
				if (serval_tcp_checksum_complete_user(sk, skb)) {
                                        LOG_ERR("Csum error!\n");
					goto csum_error;
                                }
				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len ==
				    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
				    tp->rcv_nxt == tp->rcv_wup)
					serval_tcp_store_ts_recent(tp);

				serval_tcp_rcv_rtt_measure_ts(sk, skb);

				if ((int)skb->truesize > sk->sk_forward_alloc)
					goto step5;

				//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPHPHITS);

				/* Bulk data transfer: receiver */
                                __skb_pull(skb, tcp_header_len);
				__skb_queue_tail(&sk->sk_receive_queue, skb);
				skb_set_owner_r(skb, sk);
				tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
			}

			serval_tcp_event_data_recv(sk, skb);

			if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una) {
				/* Well, only one small jumplet in fast path... */
				serval_tcp_ack(sk, skb, FLAG_DATA);
				serval_tcp_data_snd_check(sk);
				if (!serval_tsk_ack_scheduled(sk))
					goto no_ack;
			}
                        
			if (!copied_early || tp->rcv_nxt != tp->rcv_wup)
				__serval_tcp_ack_snd_check(sk, 0);
                no_ack:
#ifdef CONFIG_NET_DMA
			if (copied_early)
				__skb_queue_tail(&sk->sk_async_wait_queue, skb);
			else
#endif
                        {
                                if (eaten) {
                                        __kfree_skb(skb);
                                } else {
                                        sk->sk_data_ready(sk, 0);
                                }
                        }
			return 0;
		}
	}

slow_path:

	if (len < (th->doff << 2)) {
                LOG_PKT("doff error\n");
                goto csum_error;
        }
        if (serval_tcp_checksum_complete_user(sk, skb)) {
                LOG_PKT("checksum error\n");
                goto csum_error;
        }
	/*
	 *	Standard slow path.
	 */

	res = serval_tcp_validate_incoming(sk, skb, th, 1);

	if (res <= 0)
		return -res;

step5:
	if (th->ack && serval_tcp_ack(sk, skb, FLAG_SLOWPATH) < 0)
		goto discard;

	serval_tcp_rcv_rtt_measure_ts(sk, skb);

	/* Process urgent data. */
	//serval_tcp_urg(sk, skb, th);

	/* step 7: process the segment text */

        LOG_PKT("Queueing packet, skb->len=%u\n", 
                skb->len);

	serval_tcp_data_queue(sk, skb);

	serval_tcp_data_snd_check(sk);
	serval_tcp_ack_snd_check(sk);
	return 0;

csum_error:
	//TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
        LOG_ERR("Checksum error!\n");
discard:
	__kfree_skb(skb);
	return 0;
}

/* 
 */
int serval_tcp_syn_recv_state_process(struct sock *sk, struct sk_buff *skb)
{
        struct tcphdr *th;
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        int err = 0;

        if (serval_tcp_rcv_checks(sk, skb, 0)) {
                LOG_ERR("packet failed receive checks!\n");
                kfree_skb(skb);
                return -1;
        }

        th = tcp_hdr(skb);
	tp->rx_opt.saw_tstamp = 0;
     
        LOG_PKT("TCP %s\n", tcphdr_to_str(th));

	err = serval_tcp_validate_incoming(sk, skb, th, 0);

	if (err <= 0) {
                /* serval_tcp_validate_incoming has dropped the
                   packet */
                LOG_ERR("Bad ACK in SYN-RECV state\n");
		return -err;
        }

	if (th->ack) {
		int acceptable = serval_tcp_ack(sk, skb, FLAG_SLOWPATH) > 0;

                if (!acceptable) {
                        LOG_WARN("ACK is not acceptable.\n");
                        __kfree_skb(skb);
                        return 1;
                }

                LOG_SSK(sk, "ACK is acceptable!\n");

                tp->copied_seq = tp->rcv_nxt;
#if defined(OS_LINUX_KERNEL)
                smp_mb();
#endif
                tp->snd_una = TCP_SKB_CB(skb)->ack_seq;
                tp->snd_wnd = ntohs(th->window) <<
                                tp->rx_opt.snd_wscale;
                
                serval_tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
                
                /* tcp_ack considers this ACK as duplicate
                 * and does not calculate rtt.
                 * Force it here.
                 */
                serval_tcp_ack_update_rtt(sk, 0, 0);
                
                if (tp->rx_opt.tstamp_ok)
                          tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;

                /* Make sure socket is routed, for
                 * correct metrics.
                 */
                serval_sk(sk)->af_ops->rebuild_header(sk);
                
                serval_tcp_init_metrics(sk);
                
                serval_tcp_init_congestion_control(sk);
                
                /* Prevent spurious tcp_cwnd_restart() on
                 * first data packet.
                 */
                tp->lsndtime = tcp_time_stamp;
                
                serval_tcp_mtup_init(sk);
                serval_tcp_initialize_rcv_mss(sk);
                serval_tcp_init_buffer_space(sk);
                serval_tcp_fast_path_on(tp);
        } else {
                LOG_WARN("No ACK flag in packet!\n");
                kfree_skb(skb);
                return 1;
        }

        return 0;
}

int serval_tcp_syn_sent_state_process(struct sock *sk, struct sk_buff *skb)
{
        u8 *hash_location;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        struct tcphdr *th = tcp_hdr(skb);
	int saved_clamp = tp->rx_opt.mss_clamp;

        if (serval_tcp_rcv_checks(sk, skb, 0))
                goto drop;

	serval_tcp_parse_options(skb, &tp->rx_opt, &hash_location, 0);

        if (th->ack) {
                LOG_SSK(sk, "SYN-ACK %s\n", tcphdr_to_str(th));

		/* rfc793:
		 * "If the state is SYN-SENT then
		 *    first check the ACK bit
		 *      If the ACK bit is set
		 *	  If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send
		 *        a reset (unless the RST bit is set, if so drop
		 *        the segment and return)"
		 *
		 *  We do not send data with SYN, so that RFC-correct
		 *  test reduces to:
		 */
		if (TCP_SKB_CB(skb)->ack_seq != tp->snd_nxt) {
                        LOG_WARN("Unexpected ACK ack_seq=%u snd_next=%u\n",
                                 TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt);
                        goto reset_and_undo;
                }

		tp->snd_wl1 = TCP_SKB_CB(skb)->seq;
		serval_tcp_ack(sk, skb, FLAG_SLOWPATH);

		/* Ok.. it's good. Set up sequence numbers.
		 */
		tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		tp->snd_wnd = ntohs(th->window);
		serval_tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);

                LOG_SSK(sk, "rx_opt.wscale_ok=%u\n", tp->rx_opt.wscale_ok);

		if (!tp->rx_opt.wscale_ok) {
                        LOG_SSK(sk, "Window scaling is NOT OK!\n");
			tp->rx_opt.snd_wscale = tp->rx_opt.rcv_wscale = 0;
			tp->window_clamp = min(tp->window_clamp, 65535U);
                }

		if (tp->rx_opt.saw_tstamp) {
			tp->rx_opt.tstamp_ok = 1;
			tp->tcp_header_len =
				sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
			tp->advmss	    -= TCPOLEN_TSTAMP_ALIGNED;
			serval_tcp_store_ts_recent(tp);
		} else {
			tp->tcp_header_len = sizeof(struct tcphdr);
		}

#if defined(ENABLE_TCP_SACK)
		if (serval_tcp_is_sack(tp) && sysctl_serval_tcp_fack)
			serval_tcp_enable_fack(tp);
#endif

		serval_tcp_mtup_init(sk);
		serval_tcp_sync_mss(sk, tp->pmtu_cookie);
		serval_tcp_initialize_rcv_mss(sk);

		/* Remember, tcp_poll() does not lock socket!
		 * Change state from SYN-SENT only after copied_seq
		 * is initialized. */
		tp->copied_seq = tp->rcv_nxt;

#if defined(OS_LINUX_KERNEL)
		smp_mb();
#endif

		/* Make sure socket is routed, for correct metrics.  */
		serval_sk(sk)->af_ops->rebuild_header(sk);

		serval_tcp_init_metrics(sk);

		serval_tcp_init_congestion_control(sk);

		/* Prevent spurious tcp_cwnd_restart() on first data
		 * packet.
		 */
		tp->lsndtime = tcp_time_stamp;

		serval_tcp_init_buffer_space(sk);

		if (sock_flag(sk, SOCK_KEEPOPEN))
			serval_tsk_reset_keepalive_timer(sk, serval_keepalive_time_when(tp));

		if (!tp->rx_opt.snd_wscale)
			__serval_tcp_fast_path_on(tp, tp->snd_wnd);
		else
			tp->pred_flags = 0;

                /*
                  Waking should be handled in SAL
		if (!sock_flag(sk, SOCK_DEAD)) {
			sk->sk_state_change(sk);
			sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
		}
                */

		if (sk->sk_write_pending ||
		    //icsk->icsk_accept_queue.rskq_defer_accept ||
		    tp->tp_ack.pingpong) {
			/* Save one ACK. Data will be ready after
			 * several ticks, if write_pending is set.
			 *
			 * It may be deleted, but with this feature tcpdumps
			 * look so _wonderfully_ clever, that I was not able
			 * to stand against the temptation 8)     --ANK
			 */
			serval_tsk_schedule_ack(sk);
			tp->tp_ack.lrcvtime = tcp_time_stamp;
			tp->tp_ack.ato	 = TCP_ATO_MIN;
			serval_tcp_incr_quickack(sk);
			serval_tcp_enter_quickack_mode(sk);
			serval_tsk_reset_xmit_timer(sk, STSK_TIME_DACK,
                                                    TCP_DELACK_MAX, SERVAL_TCP_RTO_MAX);
		} 
        } else {
                LOG_INF("No ACK in TCP message received in SYN-SENT state\n");
                goto reset_and_undo;
        }
        
        return 0;
        
 reset_and_undo:
	tp->rx_opt.mss_clamp = saved_clamp;
 drop:
        kfree_skb(skb);
        return -1;
}

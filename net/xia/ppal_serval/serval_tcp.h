#ifndef _SERVAL_TCP_H_
#define _SERVAL_TCP_H_

#include <net/tcp.h>
#include "serval_tcp_sock.h"
#include "serval_sal.h"

struct serval_tcp_skb_cb {
	/* It must be the first field. */
	struct tcp_skb_cb	tcp_cb;
	/* Used in output path to compute rtt's. */
	__u32			when;
};

#define SERVAL_TCP_SKB_CB(__skb) ((struct serval_tcp_skb_cb *)&((__skb)->cb[0]))

/* TCP timestamps are only 32-bits, this causes a slight
 * complication on 64-bit systems since we store a snapshot
 * of jiffies in the buffer control blocks below.  We decided
 * to use only the low 32-bits of jiffies and hide the ugly
 * casts with the following macro.
 */
#define tcp_time_stamp		((__u32)(jiffies))


#define EXTRA_HDR (20)

/* payload + LL + IP + extra */
#define MAX_SERVAL_TCP_HEADER (MAX_SAL_HDR + 128)

#define MAX_SERVAL_TCP_OPTION_SPACE 40

/*
 * TCP general constants
 */
#if defined(OS_USER)
#define SERVAL_TCP_MSS_DEFAULT		1460U
#else
#define SERVAL_TCP_MSS_DEFAULT		 524U	/* IPv4 (RFC1122, RFC2581) */
#endif
/* IPv6 (tunneled), EDNS0 (RFC3226) */
#define SERVAL_TCP_MSS_DESIRED		1220U

#define SERVAL_TCP_MSS_INIT (1460 - sizeof(struct sal_hdr))

/*
 * Never offer a window over 32767 without using window scaling. Some
 * poor stacks do signed 16bit maths!
 */
#define MAX_TCP_WINDOW		32767U

/* Minimal accepted MSS. It is (60+60+8) - (20+20). */
#define SERVAL_TCP_MIN_MSS		88U

/* The least MTU to use for probing */
#define SERVAL_TCP_BASE_MSS		512

/* After receiving this amount of duplicate ACKs fast retransmit starts. */
#define SERVAL_TCP_FASTRETRANS_THRESH 3

/* Maximal reordering. */
#define TCP_MAX_REORDERING	127

/* Maximal number of ACKs sent quickly to accelerate slow-start. */
#define TCP_MAX_QUICKACKS	16U

/* urg_data states */
#define TCP_URG_VALID	0x0100
#define TCP_URG_NOTYET	0x0200
#define TCP_URG_READ	0x0400

#define TCP_RETR1	3	/*
				 * This is how many retries it does before it
				 * tries to figure out if the gateway is
				 * down. Minimal RFC value is 3; it corresponds
				 * to ~3sec-8min depending on RTO.
				 */

#define TCP_RETR2	15	/*
				 * This should take at least
				 * 90 minutes to time out.
				 * RFC1122 says that the limit is 100 sec.
				 * 15 is ~13-30min depending on RTO.
				 */

#define TCP_ORPHAN_RETRIES 7	/* number of times to retry on an orphaned
				 * socket. 7 is ~50sec-16min.
				 */


#define TCP_TIMEWAIT_LEN (60*HZ) /* how long to wait to destroy TIME-WAIT
				  * state, about 60 seconds	*/
#define TCP_FIN_TIMEOUT	TCP_TIMEWAIT_LEN
				 /* BSD style FIN_WAIT2 deadlock breaker.
				  * It used to be 3min, new value is 60sec,
				  * to combine FIN-WAIT-2 timeout with
				  * TIME-WAIT timer.
				  */

/* maximal time to delay before sending an ACK */
#define TCP_DELACK_MAX	((unsigned)(HZ/5))
#if HZ >= 100
/* minimal time to delay before sending an ACK */
#define TCP_DELACK_MIN	((unsigned)(HZ/25))
#define TCP_ATO_MIN	((unsigned)(HZ/25))
#else
#define TCP_DELACK_MIN	4U
#define TCP_ATO_MIN	4U
#endif
#define SERVAL_TCP_RTO_MAX	((unsigned)(120*HZ))
#define SERVAL_TCP_RTO_MIN	((unsigned)(HZ/5))
/* RFC 1122 initial RTO value. */
#define SERVAL_TCP_TIMEOUT_INIT ((unsigned)(3*HZ))

/* Maximal interval between probes for local resources. */
#define SERVAL_TCP_RESOURCE_PROBE_INTERVAL ((unsigned)(HZ/2U))

#define TCP_KEEPALIVE_TIME	(120*60*HZ)	/* two hours */
/* Max of 9 keepalive probes. */
#define TCP_KEEPALIVE_PROBES	9
#define TCP_KEEPALIVE_INTVL	(75*HZ)

#define MAX_TCP_KEEPIDLE	32767
#define MAX_TCP_KEEPINTVL	32767
#define MAX_TCP_KEEPCNT		127
#define MAX_TCP_SYNCNT		127

#define TCP_SYNQ_INTERVAL	(HZ/5)	/* Period of SYNACK timer */

#define TCP_PAWS_24DAYS	(60 * 60 * 24 * 24)
#define TCP_PAWS_MSL	60		/* Per-host timestamps are invalidated
					 * after this time. It should be equal
					 * (or greater than) TCP_TIMEWAIT_LEN
					 * to provide reliability equal to one
					 * provided by timewait state.
					 */
#define TCP_PAWS_WINDOW	1		/* Replay window for per-host
					 * timestamps. It must be less than
					 * minimal timewait lifetime.
					 */

/*
 *	TCP option
 */

#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM	4       /* SACK Permitted */
#define TCPOPT_SACK	     5       /* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */
#define TCPOPT_COOKIE		253	/* Cookie extension (experimental) */

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS	    4
#define TCPOLEN_WINDOW	 3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG	 18
#define TCPOLEN_COOKIE_BASE    2	/* Cookie-less header extension */
#define TCPOLEN_COOKIE_PAIR    3	/* Cookie pair header extension */
#define TCPOLEN_COOKIE_MIN     (TCPOLEN_COOKIE_BASE+TCP_COOKIE_MIN)
#define TCPOLEN_COOKIE_MAX     (TCPOLEN_COOKIE_BASE+TCP_COOKIE_MAX)

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED		12
#define TCPOLEN_WSCALE_ALIGNED		4
#define TCPOLEN_SACKPERM_ALIGNED	4
#define TCPOLEN_SACK_BASE		2
#define TCPOLEN_SACK_BASE_ALIGNED	4
#define TCPOLEN_SACK_PERBLOCK		8
#define TCPOLEN_MD5SIG_ALIGNED		20
#define TCPOLEN_MSS_ALIGNED		4

/* TCP thin-stream limits */
/* After 6 linear retries, do exp. backoff */
#define TCP_THIN_LINEAR_RETRIES 6

#define serval_tcp_flag_byte(th) (((u_int8_t *)th)[13])

#define TCPH_FIN 0x01
#define TCPH_SYN 0x02
#define TCPH_RST 0x04
#define TCPH_PSH 0x08
#define TCPH_ACK 0x10
#define TCPH_URG 0x20
#define TCPH_ECE 0x40
#define TCPH_CWR 0x80

__u32 serval_tcp_random_sequence_number(void);

/* sysctl variables for tcp */
extern int sysctl_serval_tcp_timestamps;
extern int sysctl_serval_tcp_window_scaling;
extern int sysctl_serval_tcp_sack;
extern int sysctl_serval_tcp_fin_timeout;
extern int sysctl_serval_tcp_keepalive_time;
extern int sysctl_serval_tcp_keepalive_probes;
extern int sysctl_serval_tcp_keepalive_intvl;
extern int sysctl_serval_tcp_syn_retries;
extern int sysctl_serval_tcp_synack_retries;
extern int sysctl_serval_tcp_retries1;
extern int sysctl_serval_tcp_retries2;
extern int sysctl_serval_tcp_orphan_retries;
extern int sysctl_serval_tcp_syncookies;
extern int sysctl_serval_tcp_retrans_collapse;
extern int sysctl_serval_tcp_stdurg;
extern int sysctl_serval_tcp_rfc1337;
extern int sysctl_serval_tcp_abort_on_overflow;
extern int sysctl_serval_tcp_max_orphans;
extern int sysctl_serval_tcp_fack;
extern int sysctl_serval_tcp_reordering;
extern int sysctl_serval_tcp_ecn;
extern int sysctl_serval_tcp_dsack;
extern int sysctl_serval_tcp_app_win;
extern int sysctl_serval_tcp_adv_win_scale;
extern int sysctl_serval_tcp_tw_reuse;
extern int sysctl_serval_tcp_frto;
extern int sysctl_serval_tcp_frto_response;
extern int sysctl_serval_tcp_low_latency;
/* extern int sysctl_serval_tcp_dma_copybreak; */
extern int sysctl_serval_tcp_nometrics_save;
extern int sysctl_serval_tcp_moderate_rcvbuf;
extern int sysctl_serval_tcp_tso_win_divisor;
extern int sysctl_serval_tcp_abc;
extern int sysctl_serval_tcp_mtu_probing;
extern int sysctl_serval_tcp_base_mss;
extern int sysctl_serval_tcp_workaround_signed_windows;
extern int sysctl_serval_tcp_slow_start_after_idle;
extern int sysctl_serval_tcp_max_ssthresh;
extern int sysctl_serval_tcp_cookie_size;
extern int sysctl_serval_tcp_thin_linear_timeouts;
extern int sysctl_serval_tcp_thin_dupack;
extern long sysctl_serval_tcp_mem[3];
extern int sysctl_serval_tcp_wmem[3];
extern int sysctl_serval_tcp_rmem[3];

extern atomic_long_t serval_tcp_memory_allocated;

extern int serval_tcp_memory_pressure;
extern void serval_tcp_enter_memory_pressure(struct sock *sk);

static inline int serval_keepalive_intvl_when(const struct serval_tcp_sock *tp)
{
	return tp->keepalive_intvl ? : sysctl_serval_tcp_keepalive_intvl;
}

static inline int serval_keepalive_time_when(const struct serval_tcp_sock *tp)
{
	return tp->keepalive_time ? : sysctl_serval_tcp_keepalive_time;
}

static inline int serval_keepalive_probes(const struct serval_tcp_sock *tp)
{
	return tp->keepalive_probes ? : sysctl_serval_tcp_keepalive_probes;
}

static inline u32 serval_keepalive_time_elapsed(
	const struct serval_tcp_sock *tp)
{
	return min_t(u32, tcp_time_stamp - tp->tp_ack.lrcvtime,
			  tcp_time_stamp - tp->rcv_tstamp);
}

static inline int serval_tcp_fin_time(const struct sock *sk)
{
	int fin_timeout = serval_tcp_sk(sk)->linger2
		? : sysctl_serval_tcp_fin_timeout;
	const int rto = serval_tcp_sk(sk)->rto;

	if (fin_timeout < (rto << 2) - (rto >> 1))
		fin_timeout = (rto << 2) - (rto >> 1);

	return fin_timeout;
}


static inline unsigned int serval_tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline unsigned int serval_tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}


static inline void serval_tcp_dec_quickack_mode(struct sock *sk,
						const unsigned int pkts)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->tp_ack.quick) {
		if (pkts >= tp->tp_ack.quick) {
			tp->tp_ack.quick = 0;
			/* Leaving quickack mode we deflate ATO. */
			tp->tp_ack.ato   = TCP_ATO_MIN;
		} else
			tp->tp_ack.quick -= pkts;
	}
}

static inline int serval_tcp_too_many_orphans(struct sock *sk, int shift)
{
	struct percpu_counter *ocp = sk->sk_prot->orphan_count;
	int orphans = percpu_counter_read_positive(ocp);

	if (orphans << shift > sysctl_serval_tcp_max_orphans) {
		orphans = percpu_counter_sum_positive(ocp);
		if (orphans << shift > sysctl_serval_tcp_max_orphans)
			return 1;
	}

	if (sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&
		atomic_long_read(&serval_tcp_memory_allocated) >
			sysctl_serval_tcp_mem[2])
		return 1;

	return 0;
}

/* Compute the actual rto_min value */
static inline u32 serval_tcp_rto_min(struct sock *sk)
{
	u32 rto_min = SERVAL_TCP_RTO_MIN;
	struct dst_entry *dst = __sk_dst_get(sk);
	if (dst && dst_metric_locked(dst, RTAX_RTO_MIN))
		rto_min = dst_metric_rtt(dst, RTAX_RTO_MIN);
	return rto_min;
}

/* Due to TSO, an SKB can be composed of multiple actual
 * packets.  To keep these tracked properly, we use this.
 */
static inline int serval_tcp_skb_pcount(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_segs;
}

/* This is valid iff tcp_skb_pcount() > 1. */
static inline int serval_tcp_skb_mss(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_size;
}

static inline int serval_tcp_paws_check(
	const struct serval_tcp_options_received *rx_opt, int paws_win)
{
	if ((s32)(rx_opt->ts_recent - rx_opt->rcv_tsval) <= paws_win)
		return 1;
	if (unlikely(get_seconds() >= rx_opt->ts_recent_stamp +
		TCP_PAWS_24DAYS))
		return 1;
	return 0;
}

static inline int
serval_tcp_paws_reject(const struct serval_tcp_options_received *rx_opt,
		       int rst)
{
	if (serval_tcp_paws_check(rx_opt, 0))
		return 0;

	/* RST segments are not recommended to carry timestamp,
	   and, if they do, it is recommended to ignore PAWS because
	   "their cleanup function should take precedence over timestamps."
	   Certainly, it is mistake. It is necessary to understand the reasons
	   of this constraint to relax it: if peer reboots, clock may go
	   out-of-sync and half-open connections will not be reset.
	   Actually, the problem would be not existing if all
	   the implementations followed draft about maintaining clock
	   via reboots. Linux-2.2 DOES NOT!

	   However, we can relax time bounds for RST segments to MSL.
	 */
	if (rst && get_seconds() >= rx_opt->ts_recent_stamp + TCP_PAWS_MSL)
		return 0;
	return 1;
}

void serval_tcp_parse_options(struct sk_buff *skb,
			      struct serval_tcp_options_received *opt_rx,
			      u8 **hvpp, int estab);

int serval_tcp_syn_recv_state_process(struct sock *sk, struct sk_buff *skb);
int serval_tcp_syn_sent_state_process(struct sock *sk, struct sk_buff *skb);

int serval_tcp_connection_build_syn(struct sock *sk, struct sk_buff *skb);
int serval_tcp_connection_build_synack(struct sock *sk,
				       struct dst_entry *dst,
				       struct request_sock *rsk,
				       struct sk_buff *skb);
int serval_tcp_connection_build_ack(struct sock *sk,
				    struct sk_buff *skb);

struct sk_buff *serval_sk_stream_alloc_skb(struct sock *sk, int size,
	gfp_t gfp);

#if defined(ENABLE_SPLICE)

#include <linux/seq_file.h>

int serval_tcp_read_sock(struct sock *sk, read_descriptor_t *desc,
			 sk_read_actor_t recv_actor);
#endif

void serval_tcp_initialize_rcv_mss(struct sock *sk);

int serval_tcp_mtu_to_mss(struct sock *sk, int pmtu);
int serval_tcp_mss_to_mtu(struct sock *sk, int mss);

unsigned int serval_tcp_sync_mss(struct sock *sk, u32 pmtu);
unsigned int serval_tcp_current_mss(struct sock *sk);


static inline int serval_tcp_use_frto(struct sock *sk)
{
	return 0;
}

static inline void serval_tcp_enter_frto(struct sock *sk)
{
}

void serval_tcp_enter_loss(struct sock *sk, int how);
void serval_tcp_clear_retrans(struct serval_tcp_sock *tp);

static inline void
serval_tcp_clear_options(struct serval_tcp_options_received *rx_opt)
{
	rx_opt->tstamp_ok = rx_opt->sack_ok = 0;
	rx_opt->wscale_ok = rx_opt->snd_wscale = 0;
	rx_opt->cookie_plus = 0;
}

/* Bound MSS / TSO packet size with the half of the window */
static inline int serval_tcp_bound_to_half_wnd(struct serval_tcp_sock *tp,
					       int pktsize)
{
	int cutoff;

	/* When peer uses tiny windows, there is no use in packetizing
	 * to sub-MSS pieces for the sake of SWS or making sure there
	 * are enough packets in the pipe for fast recovery.
	 *
	 * On the other hand, for extremely large MSS devices, handling
	 * smaller than MSS windows in this way does make sense.
	 */
	if (tp->max_window >= 512)
		cutoff = (tp->max_window >> 1);
	else
		cutoff = tp->max_window;

	if (cutoff && pktsize > cutoff)
		return max_t(int, cutoff, 68U - tp->tcp_header_len);
	else
		return pktsize;
}

void __serval_tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
				      int nonagle);

/* serval_tcp_input.c */
void serval_tcp_cwnd_application_limited(struct sock *sk);

/* from STCP */
static inline void
serval_tcp_clear_retrans_hints_partial(struct serval_tcp_sock *tp)
{
	tp->lost_skb_hint = NULL;
	tp->scoreboard_skb_hint = NULL;
}

static inline void
serval_tcp_clear_all_retrans_hints(struct serval_tcp_sock *tp)
{
	serval_tcp_clear_retrans_hints_partial(tp);
	tp->retransmit_skb_hint = NULL;
}

/* write queue abstraction */
static inline void serval_tcp_write_queue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL)
		sk_wmem_free_skb(sk, skb);
	sk_mem_reclaim(sk);
	serval_tcp_clear_all_retrans_hints(serval_tcp_sk(sk));
}

static inline struct sk_buff *serval_tcp_write_queue_head(struct sock *sk)
{
	return skb_peek(&sk->sk_write_queue);
}

static inline struct sk_buff *serval_tcp_write_queue_tail(struct sock *sk)
{
	return skb_peek_tail(&sk->sk_write_queue);
}

static inline struct sk_buff *serval_tcp_write_queue_next(struct sock *sk,
						   struct sk_buff *skb)
{
	return skb_queue_next(&sk->sk_write_queue, skb);
}

static inline struct sk_buff *serval_tcp_write_queue_prev(struct sock *sk,
						   struct sk_buff *skb)
{
	return skb_queue_prev(&sk->sk_write_queue, skb);
}

#define serval_tcp_for_write_queue(skb, sk) \
	skb_queue_walk(&(sk)->sk_write_queue, skb)

#define serval_tcp_for_write_queue_from(skb, sk) \
	skb_queue_walk_from(&(sk)->sk_write_queue, skb)

#define serval_tcp_for_write_queue_from_safe(skb, tmp, sk) \
	skb_queue_walk_from_safe(&(sk)->sk_write_queue, skb, tmp)

static inline struct sk_buff *serval_tcp_send_head(struct sock *sk)
{
	return sk->sk_send_head;
}

static inline int serval_tcp_skb_is_last(const struct sock *sk,
	const struct sk_buff *skb)
{
	return skb_queue_is_last(&sk->sk_write_queue, skb);
}

static inline void serval_tcp_advance_send_head(struct sock *sk,
	struct sk_buff *skb)
{
	if (serval_tcp_skb_is_last(sk, skb))
		sk->sk_send_head = NULL;
	else
		sk->sk_send_head = serval_tcp_write_queue_next(sk, skb);
}

static inline void serval_tcp_check_send_head(struct sock *sk,
	struct sk_buff *skb_unlinked)
{
	if (sk->sk_send_head == skb_unlinked)
		sk->sk_send_head = NULL;
}

static inline void serval_tcp_init_send_head(struct sock *sk)
{
	sk->sk_send_head = NULL;
}

static inline void __serval_tcp_add_write_queue_tail(struct sock *sk,
	struct sk_buff *skb)
{
	__skb_queue_tail(&sk->sk_write_queue, skb);
}

static inline void serval_tcp_add_write_queue_tail(struct sock *sk,
						   struct sk_buff *skb)
{
	__serval_tcp_add_write_queue_tail(sk, skb);

	/* Queue it, remembering where we must start sending. */
	if (sk->sk_send_head == NULL) {
		sk->sk_send_head = skb;

		if (serval_tcp_sk(sk)->highest_sack == NULL)
			serval_tcp_sk(sk)->highest_sack = skb;
	}
}

static inline void __serval_tcp_add_write_queue_head(struct sock *sk,
	struct sk_buff *skb)
{
	__skb_queue_head(&sk->sk_write_queue, skb);
}

/* Insert buff after skb on the write queue of sk.  */
static inline void serval_tcp_insert_write_queue_after(struct sk_buff *skb,
						struct sk_buff *buff,
						struct sock *sk)
{
	__skb_queue_after(&sk->sk_write_queue, skb, buff);
}

/* Insert new before skb on the write queue of sk.  */
static inline void serval_tcp_insert_write_queue_before(struct sk_buff *new,
						  struct sk_buff *skb,
						  struct sock *sk)
{
	__skb_queue_before(&sk->sk_write_queue, skb, new);

	if (sk->sk_send_head == skb)
		sk->sk_send_head = new;
}

static inline void serval_tcp_unlink_write_queue(struct sk_buff *skb,
						 struct sock *sk)
{
	__skb_unlink(skb, &sk->sk_write_queue);
}

static inline int serval_tcp_write_queue_empty(struct sock *sk)
{
	return skb_queue_empty(&sk->sk_write_queue);
}

static inline void serval_tcp_push_pending_frames(struct sock *sk)
{
	if (serval_tcp_send_head(sk)) {
		struct serval_tcp_sock *tp = serval_tcp_sk(sk);

		__serval_tcp_push_pending_frames(sk,
						 serval_tcp_current_mss(sk),
						 tp->nonagle);
	}
}

/* Start sequence of the highest skb with SACKed bit, valid only if
 * sacked > 0 or when the caller has ensured validity by itself.
 */
static inline u32 serval_tcp_highest_sack_seq(struct serval_tcp_sock *tp)
{
	if (!tp->sacked_out)
		return tp->snd_una;

	if (tp->highest_sack == NULL)
		return tp->snd_nxt;

	return TCP_SKB_CB(tp->highest_sack)->seq;
}

/* The length of constant payload data.  Note that s_data_desired is
 * overloaded, depending on s_data_constant: either the length of constant
 * data (returned here) or the limit on variable data.
 */
static inline int serval_tcp_s_data_size(const struct serval_tcp_sock *tp)
{
	return (tp->cookie_values != NULL && tp->cookie_values->s_data_constant)
		? tp->cookie_values->s_data_desired
		: 0;
}

void serval_tcp_rcv_space_adjust(struct sock *sk);


/* Compute the actual receive window we are currently advertising.
 * Rcv_nxt can be after the window if our peer push more data
 * than the offered window.
 */
static inline u32 serval_tcp_receive_window(const struct serval_tcp_sock *tp)
{
	s32 win = tp->rcv_wup + tp->rcv_wnd - tp->rcv_nxt;

	if (win < 0)
		win = 0;
	return (u32) win;
}

/* Determine a window scaling and initial window to offer. */
void serval_tcp_select_initial_window(int __space, __u32 mss,
				      __u32 *rcv_wnd, __u32 *window_clamp,
				      int wscale_ok, __u8 *rcv_wscale,
				      __u32 init_rcv_wnd);

/* Choose a new window, without checks for shrinking, and without
 * scaling applied to the result.  The caller does these things
 * if necessary.  This is a "raw" window selection.
 */
u32 __serval_tcp_select_window(struct sock *sk);

void __serval_tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
				      int nonagle);

extern int serval_tcp_retransmit_skb(struct sock *, struct sk_buff *);
extern void serval_tcp_retransmit_timer(struct sock *sk);
extern void serval_tcp_xmit_retransmit_queue(struct sock *);
extern void serval_tcp_simple_retransmit(struct sock *sk);

void serval_tcp_push_one(struct sock *sk, unsigned int mss_now);

static inline int serval_tcp_win_from_space(int space)
{
	return sysctl_serval_tcp_adv_win_scale <= 0 ?
		(space>>(-sysctl_serval_tcp_adv_win_scale)) :
		space - (space>>sysctl_serval_tcp_adv_win_scale);
}

/* Note: caller must be prepared to deal with negative returns */
static inline int serval_tcp_space(const struct sock *sk)
{
	return serval_tcp_win_from_space(sk->sk_rcvbuf -
					 atomic_read(&sk->sk_rmem_alloc));
}

static inline int serval_tcp_full_space(const struct sock *sk)
{
	return serval_tcp_win_from_space(sk->sk_rcvbuf);
}


/* If cwnd > ssthresh, we may raise ssthresh to be half-way to cwnd.
 * The exception is rate halving phase, when cwnd is decreasing towards
 * ssthresh.
 */
static inline __u32 serval_tcp_current_ssthresh(const struct sock *sk)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	if ((1 << tp->ca_state) & (TCPF_CA_CWR | TCPF_CA_Recovery))
		return tp->snd_ssthresh;
	else
		return max(tp->snd_ssthresh,
			   ((tp->snd_cwnd >> 1) +
			    (tp->snd_cwnd >> 2)));
}

void serval_tcp_mtup_init(struct sock *sk);


static inline void serval_tcp_bound_rto(const struct sock *sk)
{
	if (serval_tcp_sk(sk)->rto > SERVAL_TCP_RTO_MAX)
		serval_tcp_sk(sk)->rto = SERVAL_TCP_RTO_MAX;
}

static inline u32 __serval_tcp_set_rto(const struct serval_tcp_sock *tp)
{
	return (tp->srtt >> 3) + tp->rttvar;
}

void serval_tcp_set_rto(struct sock *sk);

static inline void __serval_tcp_fast_path_on(struct serval_tcp_sock *tp,
					     u32 snd_wnd)
{
	tp->pred_flags = htonl((tp->tcp_header_len << 26) |
			       ntohl(TCP_FLAG_ACK) |
			       snd_wnd);
}

static inline void serval_tcp_fast_path_on(struct serval_tcp_sock *tp)
{
	__serval_tcp_fast_path_on(tp, tp->snd_wnd >> tp->rx_opt.snd_wscale);
}

static inline void serval_tcp_fast_path_check(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (skb_queue_empty(&tp->out_of_order_queue) &&
	    tp->rcv_wnd &&
	    atomic_read(&sk->sk_rmem_alloc) < sk->sk_rcvbuf &&
	    !tp->urg_data)
		serval_tcp_fast_path_on(tp);
}


void serval_tcp_enter_cwr(struct sock *sk, const int set_ssthresh);
__u32 serval_tcp_init_cwnd(struct serval_tcp_sock *tp, struct dst_entry *dst);

/* Slow start with delack produces 3 packets of burst, so that
 * it is safe "de facto".  This will be the default - same as
 * the default reordering threshold - but if reordering increases,
 * we must be able to allow cwnd to burst at least this much in order
 * to not pull it back when holes are filled.
 */
static inline __u32 serval_tcp_max_burst(const struct serval_tcp_sock *tp)
{
	return tp->reordering;
}

/* Returns end sequence number of the receiver's advertised window */
static inline u32 serval_tcp_wnd_end(const struct serval_tcp_sock *tp)
{
	return tp->snd_una + tp->snd_wnd;
}

int serval_tcp_is_cwnd_limited(const struct sock *sk, u32 in_flight);

static inline void serval_tcp_minshall_update(struct serval_tcp_sock *tp,
					      unsigned int mss,
					      const struct sk_buff *skb)
{
	if (skb->len < mss)
		tp->snd_sml = TCP_SKB_CB((struct sk_buff *)skb)->end_seq;
}

static inline void serval_tcp_check_probe_timer(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (!tp->packets_out && !tp->pending)
		serval_tsk_reset_xmit_timer(sk, STSK_TIME_PROBE0,
					    tp->rto, SERVAL_TCP_RTO_MAX);

}

static inline void serval_tcp_init_wl(struct serval_tcp_sock *tp, u32 seq)
{
	tp->snd_wl1 = seq;
}

static inline void serval_tcp_update_wl(struct serval_tcp_sock *tp, u32 seq)
{
	tp->snd_wl1 = seq;
}

void __serval_tcp_v4_send_check(struct sk_buff *skb);

/*
 * Calculate(/check) TCP checksum
 */
static inline __sum16 serval_tcp_v4_check(int len, __wsum base)
{
	/* These addresses don't make sense in XIA. */
	const __be32 saddr = 0;
	const __be32 daddr = 0;

	return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_TCP, base);
}

static inline __sum16 __serval_tcp_checksum_complete(struct sk_buff *skb)
{
	return __skb_checksum_complete(skb);
}

static inline int serval_tcp_checksum_complete(struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
		__serval_tcp_checksum_complete(skb);
}
/* Prequeue for VJ style copy to user, combined with checksumming. */

static inline void serval_tcp_prequeue_init(struct serval_tcp_sock *tp)
{
	tp->ucopy.task = NULL;
	tp->ucopy.len = 0;
	tp->ucopy.memory = 0;
	skb_queue_head_init(&tp->ucopy.prequeue);
}

int serval_tcp_do_rcv(struct sock *sk, struct sk_buff *skb);

/* Packet is added to VJ-style prequeue for processing in process
 * context, if a reader task is waiting. Apparently, this exciting
 * idea (VJ's mail "Re: query about TCP header on tcp-ip" of 07 Sep 93)
 * failed somewhere. Latency? Burstiness? Well, at least now we will
 * see, why it failed. 8)8)				  --ANK
 *
 * NOTE: is this not too big to inline?
 */
static inline int serval_tcp_prequeue(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (sysctl_serval_tcp_low_latency || !tp->ucopy.task)
		return 0;

	__skb_queue_tail(&tp->ucopy.prequeue, skb);
	tp->ucopy.memory += skb->truesize;
	if (tp->ucopy.memory > sk->sk_rcvbuf) {
		struct sk_buff *skb1;

		BUG_ON(sock_owned_by_user(sk));

		while ((skb1 = __skb_dequeue(&tp->ucopy.prequeue)) != NULL) {
			/* We handle backlog elsewhere */
			/* sk_backlog_rcv(sk, skb1); */

			serval_tcp_do_rcv(sk, skb1);
			/* NET_INC_STATS_BH(sock_net(sk),
					 LINUX_MIB_TCPPREQUEUEDROPPED); */
		}

		tp->ucopy.memory = 0;
	} else if (skb_queue_len(&tp->ucopy.prequeue) == 1) {
		wake_up_interruptible_sync_poll(sk_sleep(sk),
					   POLLIN | POLLRDNORM | POLLRDBAND);
		if (!serval_tsk_ack_scheduled(sk))
			serval_tsk_reset_xmit_timer(sk, STSK_TIME_DACK,
				(3 * serval_tcp_rto_min(sk)) / 4,
				SERVAL_TCP_RTO_MAX);
	}
	return 1;
}


extern void serval_tcp_init_congestion_control(struct sock *sk);
void serval_tcp_cleanup_congestion_control(struct sock *sk);
extern struct tcp_congestion_ops serval_tcp_init_congestion_ops;

/* From serval_tcp_metrics.c. */
int serval_tcp_net_metrics_init(struct xip_serval_ctx *ctx);
void serval_tcp_net_metrics_exit(struct xip_serval_ctx *ctx);
void serval_tcp_update_metrics(struct sock *sk);
void serval_tcp_init_metrics(struct sock *sk);

int serval_tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len);
int serval_tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
			unsigned int mss_now);
int serval_tcp_may_send_now(struct sock *sk);

static inline void serval_tcp_set_ca_state(struct sock *sk, const u8 ca_state)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->ca_ops->set_state)
		tp->ca_ops->set_state(sk, ca_state);
	tp->ca_state = ca_state;
}

static inline void serval_tcp_ca_event(struct sock *sk,
				       const enum tcp_ca_event event)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->ca_ops->cwnd_event)
		tp->ca_ops->cwnd_event(sk, event);
}

int serval_tcp_rcv_checks(struct sock *sk, struct sk_buff *skb, int is_syn);

void serval_tcp_send_delayed_ack(struct sock *sk);
void serval_tcp_send_ack(struct sock *sk);
void serval_tcp_send_fin(struct sock *sk);

void serval_tcp_init_xmit_timers(struct sock *);
static inline void serval_tcp_clear_xmit_timers(struct sock *sk)
{
	serval_tsk_clear_xmit_timers(sk);
}

void serval_tcp_disable_fack(struct serval_tcp_sock *tp);

/* These functions determine how the current flow behaves in respect of SACK
 * handling. SACK is negotiated with the peer, and therefore it can vary
 * between different flows.
 *
 * tcp_is_sack - SACK enabled
 * tcp_is_reno - No SACK
 * tcp_is_fack - FACK enabled, implies SACK enabled
 */
static inline int serval_tcp_is_sack(const struct serval_tcp_sock *tp)
{
	return tp->rx_opt.sack_ok;
}

static inline int serval_tcp_is_reno(const struct serval_tcp_sock *tp)
{
	return !serval_tcp_is_sack(tp);
}

static inline int serval_tcp_is_fack(const struct serval_tcp_sock *tp)
{
	return tp->rx_opt.sack_ok & 2;
}


static inline unsigned int serval_tcp_left_out(const struct serval_tcp_sock *tp)
{
	return tp->sacked_out + tp->lost_out;
}


/* Use define here intentionally to get WARN_ON location shown at the
 * caller */
#define serval_tcp_verify_left_out(tp) \
	WARN_ON(serval_tcp_left_out(tp) > tp->packets_out)


/* This determines how many packets are "in the network" to the best
 * of our knowledge.  In many cases it is conservative, but where
 * detailed information is available from the receiver (via SACK
 * blocks etc.) we can make more aggressive calculations.
 *
 * Use this for decisions involving congestion control, use just
 * tp->packets_out to determine if the send queue is empty or not.
 *
 * Read this equation as:
 *
 *	"Packets sent once on transmission queue" MINUS
 *	"Packets left network, but not honestly ACKed yet" PLUS
 *	"Packets fast retransmitted"
 */
static inline
unsigned int serval_tcp_packets_in_flight(const struct serval_tcp_sock *tp)
{
	return tp->packets_out - serval_tcp_left_out(tp) + tp->retrans_out;
}

#define SERVAL_TCP_INFINITE_SSTHRESH	0x7fffffff

static inline
int serval_tcp_in_initial_slowstart(const struct serval_tcp_sock *tp)
{
	return tp->snd_ssthresh >= SERVAL_TCP_INFINITE_SSTHRESH;
}


/* Determines whether this is a thin stream (which may suffer from
 * increased latency). Used to trigger latency-reducing mechanisms.
 */
static inline unsigned int serval_tcp_stream_is_thin(struct serval_tcp_sock *tp)
{
	return tp->packets_out < 4 && !serval_tcp_in_initial_slowstart(tp);
}

void serval_tcp_cleanup_rbuf(struct sock *sk, int copied);

int serval_tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb,
				 struct tcphdr *th, unsigned len);

int serval_tcp_rcv_established(struct sock *sk,
			       struct sk_buff *skb,
			       struct tcphdr *th,
			       unsigned len);

void serval_tcp_send_probe0(struct sock *sk);

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union serval_tcp_word_hdr {
	struct tcphdr hdr;
	__be32 words[5];
};

#define serval_tcp_flag_word(tp) \
	(((union serval_tcp_word_hdr *)(tp))->words[3])

#endif /* _SERVAL_TCP_H_ */

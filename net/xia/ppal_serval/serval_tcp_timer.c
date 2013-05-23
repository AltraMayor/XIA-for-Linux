/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <platform.h>
#include <debug.h>
#include <serval_tcp.h>
#include <serval_tcp_sock.h>

int sysctl_serval_tcp_keepalive_time __read_mostly = TCP_KEEPALIVE_TIME;
int sysctl_serval_tcp_keepalive_probes __read_mostly = TCP_KEEPALIVE_PROBES;
int sysctl_serval_tcp_keepalive_intvl __read_mostly = TCP_KEEPALIVE_INTVL;
int sysctl_serval_tcp_retries1 __read_mostly = TCP_RETR1;
int sysctl_serval_tcp_retries2 __read_mostly = TCP_RETR2;
int sysctl_serval_tcp_orphan_retries __read_mostly;
int sysctl_serval_tcp_thin_linear_timeouts __read_mostly;

static void serval_tcp_write_timer(unsigned long);
static void serval_tcp_delack_timer(unsigned long);
static void serval_tcp_keepalive_timer (unsigned long data);

void serval_tcp_init_xmit_timers(struct sock *sk)
{
	serval_tsk_init_xmit_timers(sk, &serval_tcp_write_timer, 
				    &serval_tcp_delack_timer,
				    &serval_tcp_keepalive_timer);
}

static void serval_tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

        LOG_SSK(sk, "Write ERROR, socket DONE\n");
	serval_sal_done(sk);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criteria is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
static int serval_tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int shift = 0;

	/* If peer does not open window for long time, or did not transmit
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*SERVAL_TCP_RTO_MAX || !do_reset)
		shift++;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		shift++;

	if (serval_tcp_too_many_orphans(sk, shift)) {
		/*
		if (net_ratelimit())
			printk(KERN_INFO "Out of socket memory\n");
		*/
		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;
		if (do_reset)
			serval_sal_send_active_reset(sk, GFP_ATOMIC);

                LOG_SSK(sk, "Too many orphans, TCP done!\n");
		serval_sal_done(sk);
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket. */
static int serval_tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_serval_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}


static void serval_tcp_mtu_probing(struct serval_tcp_sock *tp, 
				   struct sock *sk)
{
	/* Black hole detection */
	if (sysctl_serval_tcp_mtu_probing) {
		if (!tp->tp_mtup.enabled) {
			tp->tp_mtup.enabled = 1;
			serval_tcp_sync_mss(sk, tp->pmtu_cookie);
		} else {
			int mss;

			mss = serval_tcp_mtu_to_mss(sk, tp->tp_mtup.search_low) >> 1;
			mss = min(sysctl_serval_tcp_base_mss, mss);
			mss = max(mss, 68 - tp->tcp_header_len);
			tp->tp_mtup.search_low = serval_tcp_mss_to_mtu(sk, mss);
			serval_tcp_sync_mss(sk, tp->pmtu_cookie);
		}
	}
}

/* This function calculates a "timeout" which is equivalent to the timeout of a
 * TCP connection after "boundary" unsuccessful, exponentially backed-off
 * retransmissions with an initial RTO of TCP_RTO_MIN or TCP_TIMEOUT_INIT if
 * syn_set flag is set.
 */
static int retransmits_timed_out(struct sock *sk,
				 unsigned int boundary,
				 int syn_set)
{
	unsigned int timeout, linear_backoff_thresh;
	unsigned int start_ts;
	unsigned int rto_base = syn_set ? 
                SERVAL_TCP_TIMEOUT_INIT : 
                SERVAL_TCP_RTO_MIN;
	
	if (!serval_tcp_sk(sk)->retransmits)
		return 0;

        if (unlikely(!serval_tcp_sk(sk)->retrans_stamp)) {
                struct sk_buff *skb = serval_tcp_write_queue_head(sk);
                
                if (!skb) {
                        LOG_ERR("BUG! transmit queue empty!\n");
                        return 0;
                }
                start_ts = TCP_SKB_CB(skb)->when;
        } else {
		start_ts = serval_tcp_sk(sk)->retrans_stamp;
        }

	linear_backoff_thresh = ilog2(SERVAL_TCP_RTO_MAX/rto_base);

	if (boundary <= linear_backoff_thresh)
		timeout = ((2 << boundary) - 1) * rto_base;
	else
		timeout = ((2 << linear_backoff_thresh) - 1) * rto_base +
			  (boundary - linear_backoff_thresh) * SERVAL_TCP_RTO_MAX;

	return (tcp_time_stamp - start_ts) >= timeout;
}

/* A write timeout has occurred. Process the after effects. */
static int serval_tcp_write_timeout(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int retry_until = 0;
	int do_reset, syn_set = 0;

        LOG_SSK(sk, "write timeout\n");

	if (!((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		if (retransmits_timed_out(sk, sysctl_serval_tcp_retries1, 0)) {
			/* Black hole detection */
			serval_tcp_mtu_probing(tp, sk);

			dst_negative_advice(sk);
		}

		retry_until = sysctl_serval_tcp_retries2;

		if (sock_flag(sk, SOCK_DEAD)) {
			const int alive = (tp->rto < SERVAL_TCP_RTO_MAX);

			retry_until = serval_tcp_orphan_retries(sk, alive);
			do_reset = alive ||
				   !retransmits_timed_out(sk, retry_until, 0);
                        
                        LOG_SSK(sk, "do_reset=%d\n", do_reset);

			if (serval_tcp_out_of_resources(sk, do_reset))
				return 1;
		}
	}

	if (retransmits_timed_out(sk, retry_until, syn_set)) {
		/* Has it gone just too far? */
		serval_tcp_write_err(sk);
		return 1;
	}
	return 0;
}

static void serval_tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

        LOG_SSK(sk, "timeout\n");

	bh_lock_sock(sk);

	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		tp->tp_ack.blocked = 1;
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
		sk_reset_timer(sk, &tp->delack_timer, jiffies + TCP_DELACK_MIN);
		goto out_unlock;
	}

	sk_mem_reclaim_partial(sk);

	if (sk->sk_state == TCP_CLOSE || !(tp->tp_ack.pending & STSK_ACK_TIMER))
		goto out;

	if (time_after(tp->tp_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &tp->delack_timer, tp->tp_ack.timeout);
		goto out;
	}
	tp->tp_ack.pending &= ~STSK_ACK_TIMER;

	if (!skb_queue_empty(&tp->ucopy.prequeue)) {
		struct sk_buff *skb;

		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSCHEDULERFAILED);

		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk_backlog_rcv(sk, skb);

		tp->ucopy.memory = 0;
	}

	if (serval_tsk_ack_scheduled(sk)) {
		if (!tp->tp_ack.pingpong) {
			/* Delayed ACK missed: inflate ATO. */
			tp->tp_ack.ato = min(tp->tp_ack.ato << 1, tp->rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			tp->tp_ack.pingpong = 0;
			tp->tp_ack.ato      = TCP_ATO_MIN;
		}
		serval_tcp_send_ack(sk);
		//NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKS);
	}
out:
	if (serval_tcp_memory_pressure)
		sk_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void serval_tcp_probe_timer(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int max_probes;

	if (tp->packets_out || !serval_tcp_send_head(sk)) {
		tp->probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. icsk_probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
	max_probes = sysctl_serval_tcp_retries2;

	if (sock_flag(sk, SOCK_DEAD)) {
		const int alive = ((tp->rto << tp->backoff) < SERVAL_TCP_RTO_MAX);

		max_probes = serval_tcp_orphan_retries(sk, alive);

		if (serval_tcp_out_of_resources(sk, alive || 
                                                tp->probes_out <= max_probes))
			return;
	}

	if (tp->probes_out > max_probes) {
		serval_tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
		serval_tcp_send_probe0(sk);
	}
}

/*
 *	The TCP retransmit timer.
 */

void serval_tcp_retransmit_timer(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

        LOG_SSK(sk, "timeout, packets_out=%u\n", tp->packets_out);

	if (!tp->packets_out)
		goto out;

	WARN_ON(serval_tcp_write_queue_empty(sk));

	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */

		if (tcp_time_stamp - tp->rcv_tstamp > SERVAL_TCP_RTO_MAX) {
			serval_tcp_write_err(sk);
			goto out;
		}
		serval_tcp_enter_loss(sk, 0);
		serval_tcp_retransmit_skb(sk, serval_tcp_write_queue_head(sk));
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

	if (serval_tcp_write_timeout(sk))
		goto out;

	if (tp->retransmits == 0) {
#if 0
		int mib_idx;

		if (tp->ca_state == TCP_CA_Disorder) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		} else if (tp->ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (tp->ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else {
			mib_idx = LINUX_MIB_TCPTIMEOUTS;
		}
		NET_INC_STATS_BH(sock_net(sk), mib_idx);
#endif
	}
	
	if (serval_tcp_use_frto(sk)) {
		serval_tcp_enter_frto(sk);
	} else {
		serval_tcp_enter_loss(sk, 0);
	}

	if (serval_tcp_retransmit_skb(sk, 
				      serval_tcp_write_queue_head(sk)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!tp->retransmits)
			tp->retransmits = 1;
		serval_tsk_reset_xmit_timer(sk, STSK_TIME_RETRANS,
					    min(tp->rto, SERVAL_TCP_RESOURCE_PROBE_INTERVAL),
					    SERVAL_TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	tp->backoff++;
	tp->retransmits++;

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || sysctl_serval_tcp_thin_linear_timeouts) &&
	    serval_tcp_stream_is_thin(tp) &&
	    tp->retransmits <= TCP_THIN_LINEAR_RETRIES) {
		tp->backoff = 0;
		tp->rto = min(__serval_tcp_set_rto(tp), SERVAL_TCP_RTO_MAX);
	} else {
		/* Use normal (exponential) backoff */
		tp->rto = min(tp->rto << 1, SERVAL_TCP_RTO_MAX);
	}
	serval_tsk_reset_xmit_timer(sk, STSK_TIME_RETRANS, 
				    tp->rto, SERVAL_TCP_RTO_MAX);
	if (retransmits_timed_out(sk, sysctl_serval_tcp_retries1 + 1, 0))
		__sk_dst_reset(sk);

out:;
}

static void serval_tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int event;

        LOG_SSK(sk, "timeout\n");

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later */
		sk_reset_timer(sk, &tp->retransmit_timer, jiffies + (HZ / 20));
		goto out_unlock;
	}

	if (sk->sk_state == TCP_CLOSE || !tp->pending)
		goto out;

	if (time_after(tp->timeout, jiffies)) {
		sk_reset_timer(sk, &tp->retransmit_timer, tp->timeout);
		goto out;
	}

	event = tp->pending;
	tp->pending = 0;

	switch (event) {
	case STSK_TIME_RETRANS:
		serval_tcp_retransmit_timer(sk);
		break;
	case STSK_TIME_PROBE0:
		serval_tcp_probe_timer(sk);
		break;
	}
out:
	sk_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void serval_tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	//struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		serval_tsk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}

	LOG_SSK(sk, "Keepalive timer not implemented!\n");

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

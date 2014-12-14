#include <linux/export.h>
#include "serval_tcp_sock.h"
#include "serval_tcp.h"

int sysctl_serval_tcp_max_ssthresh; /* Implicitly = 0. */

/* Assign choice of congestion control. */
void serval_tcp_init_congestion_control(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* if no choice made yet assign the current value set as default */
	tp->ca_ops = &serval_tcp_init_congestion_ops;

	if (tp->ca_ops->init)
		tp->ca_ops->init(sk);
}

/* Manage refcounts on socket close. */
void serval_tcp_cleanup_congestion_control(struct sock *sk)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (tp->ca_ops->release)
		tp->ca_ops->release(sk);

	/* module_put(tp->ca_ops->owner); */
}

/* RFC2861 Check whether we are limited by application or congestion window
 * This is the inverse of cwnd check in tcp_tso_should_defer
 */
int serval_tcp_is_cwnd_limited(const struct sock *sk, u32 in_flight)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 left;

	if (in_flight >= tp->snd_cwnd)
		return 1;

	left = tp->snd_cwnd - in_flight;
	if (sk_can_gso(sk) &&
	    left * sysctl_serval_tcp_tso_win_divisor < tp->snd_cwnd &&
	    left * tp->mss_cache < sk->sk_gso_max_size)
		return 1;
	return left <= serval_tcp_max_burst(tp);
}

/* Slow start is used when congestion window is less than slow start
 * threshold. This version implements the basic RFC2581 version
 * and optionally supports:
 *	RFC3742 Limited Slow Start	  - growth limited to max_ssthresh
 *	RFC3465 Appropriate Byte Counting - growth limited by bytes acknowledged
 */
void serval_tcp_slow_start(struct serval_tcp_sock *tp)
{
	int cnt; /* increase in packets */

	/* RFC3465: ABC Slow start
	 * Increase only after a full MSS of bytes is acked
	 *
	 * TCP sender SHOULD increase cwnd by the number of
	 * previously unacknowledged bytes ACKed by each incoming
	 * acknowledgment, provided the increase is not more than L
	 */
	if (sysctl_serval_tcp_abc && tp->bytes_acked < tp->mss_cache)
		return;

	if (sysctl_serval_tcp_max_ssthresh > 0 &&
	    tp->snd_cwnd > sysctl_serval_tcp_max_ssthresh) {
		/* Limited slow start. */
		cnt = sysctl_serval_tcp_max_ssthresh >> 1;
	} else {
		/* Exponential increase. */
		cnt = tp->snd_cwnd;
	}

	/* RFC3465: ABC
	 * We MAY increase by 2 if discovered delayed ack
	 */
	if (sysctl_serval_tcp_abc > 1 && tp->bytes_acked >= 2*tp->mss_cache)
		cnt <<= 1;
	tp->bytes_acked = 0;

	tp->snd_cwnd_cnt += cnt;
	while (tp->snd_cwnd_cnt >= tp->snd_cwnd) {
		tp->snd_cwnd_cnt -= tp->snd_cwnd;
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
	}
}

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w) */
void serval_tcp_cong_avoid_ai(struct serval_tcp_sock *tp, u32 w)
{
	if (tp->snd_cwnd_cnt >= w) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}

/* TCP Reno congestion control
 *
 * This is special case used for fallback as well.
 * This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void serval_tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (!serval_tcp_is_cwnd_limited(sk, in_flight))
		return;

	/* In "safe" area, increase. */
	if (tp->snd_cwnd <= tp->snd_ssthresh)
		serval_tcp_slow_start(tp);

	/* In dangerous area, increase slowly. */
	else if (sysctl_serval_tcp_abc) {
		/* RFC3465: Appropriate Byte Count
		 * increase once for each full cwnd acked
		 */
		if (tp->bytes_acked >= tp->snd_cwnd*tp->mss_cache) {
			tp->bytes_acked -= tp->snd_cwnd*tp->mss_cache;
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;
		}
	} else {
		serval_tcp_cong_avoid_ai(tp, tp->snd_cwnd);
	}
}

/* Slow start threshold is half the congestion window (min 2). */
u32 serval_tcp_reno_ssthresh(struct sock *sk)
{
	const struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	return max(tp->snd_cwnd >> 1U, 2U);
}

struct tcp_congestion_ops serval_tcp_init_congestion_ops  = {
	.name		= "",
	.owner		= THIS_MODULE,
	.ssthresh	= serval_tcp_reno_ssthresh,
	.cong_avoid	= serval_tcp_reno_cong_avoid,
};

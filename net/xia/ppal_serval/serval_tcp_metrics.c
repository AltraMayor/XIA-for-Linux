#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/bootmem.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/tcp.h>
#include <linux/hash.h>
#include <linux/tcp_metrics.h>
#include <net/sock.h>
#include <net/dst.h>
#include <net/tcp.h>
#include "serval_tcp.h"
#include "serval_tcp_sock.h"

int sysctl_serval_tcp_nometrics_save __read_mostly;

struct tcp_metrics_block {
	struct tcp_metrics_block __rcu	*tcpm_next;
	__u8				tcpm_id[XIA_XID_MAX];
	unsigned long			tcpm_stamp;
	u32				tcpm_ts;
	u32				tcpm_ts_stamp;
	u32				tcpm_lock;
	u32				tcpm_vals[TCP_METRIC_MAX];
};

static bool tcp_metric_locked(struct tcp_metrics_block *tm,
			      enum tcp_metric_index idx)
{
	return tm->tcpm_lock & (1 << idx);
}

static u32 tcp_metric_get(struct tcp_metrics_block *tm,
			  enum tcp_metric_index idx)
{
	return tm->tcpm_vals[idx];
}

static u32 tcp_metric_get_jiffies(struct tcp_metrics_block *tm,
				  enum tcp_metric_index idx)
{
	return msecs_to_jiffies(tm->tcpm_vals[idx]);
}

static void tcp_metric_set(struct tcp_metrics_block *tm,
	enum tcp_metric_index idx, u32 val)
{
	tm->tcpm_vals[idx] = val;
}

static void tcp_metric_set_msecs(struct tcp_metrics_block *tm,
	enum tcp_metric_index idx, u32 val)
{
	tm->tcpm_vals[idx] = jiffies_to_msecs(val);
}

struct serval_tcpm_hash_bucket {
	struct tcp_metrics_block __rcu	*chain;
};

static DEFINE_SPINLOCK(tcp_metrics_lock);

static void tcpm_suck_dst(struct tcp_metrics_block *tm, struct dst_entry *dst)
{
	u32 val;

	tm->tcpm_stamp = jiffies;

	val = 0;
	if (dst_metric_locked(dst, RTAX_RTT))
		val |= 1 << TCP_METRIC_RTT;
	if (dst_metric_locked(dst, RTAX_RTTVAR))
		val |= 1 << TCP_METRIC_RTTVAR;
	if (dst_metric_locked(dst, RTAX_SSTHRESH))
		val |= 1 << TCP_METRIC_SSTHRESH;
	if (dst_metric_locked(dst, RTAX_CWND))
		val |= 1 << TCP_METRIC_CWND;
	if (dst_metric_locked(dst, RTAX_REORDERING))
		val |= 1 << TCP_METRIC_REORDERING;
	tm->tcpm_lock = val;

	tm->tcpm_vals[TCP_METRIC_RTT] = dst_metric_raw(dst, RTAX_RTT);
	tm->tcpm_vals[TCP_METRIC_RTTVAR] = dst_metric_raw(dst, RTAX_RTTVAR);
	tm->tcpm_vals[TCP_METRIC_SSTHRESH] = dst_metric_raw(dst, RTAX_SSTHRESH);
	tm->tcpm_vals[TCP_METRIC_CWND] = dst_metric_raw(dst, RTAX_CWND);
	tm->tcpm_vals[TCP_METRIC_REORDERING] =
		dst_metric_raw(dst, RTAX_REORDERING);
	tm->tcpm_ts = 0;
	tm->tcpm_ts_stamp = 0;
}

static struct tcp_metrics_block *tcpm_new(struct xip_serval_ctx *serval_ctx,
	struct dst_entry *dst, const __u8 *id, unsigned int hash, bool reclaim)
{
	struct tcp_metrics_block *tm;

	spin_lock_bh(&tcp_metrics_lock);
	if (unlikely(reclaim)) {
		struct tcp_metrics_block *oldest = rcu_dereference(
			serval_ctx->tcp_metrics_hash[hash].chain);
		for (tm = rcu_dereference(oldest->tcpm_next); tm;
		     tm = rcu_dereference(tm->tcpm_next)) {
			if (time_before(tm->tcpm_stamp, oldest->tcpm_stamp))
				oldest = tm;
		}
		tm = oldest;
	} else {
		tm = kmalloc(sizeof(*tm), GFP_ATOMIC);
		if (!tm)
			goto out_unlock;
	}

	/* XXX Updating @tm in place can mess an RCU reader
	 * when @reclaim is true.
	 * The following invalidation of the key is a workaround for that,
	 * a final solution should properly redesign the whole solution.
	 */
	memset(tm->tcpm_id, 0, sizeof(tm->tcpm_id));
	smp_wmb();

	tcpm_suck_dst(tm, dst);
	smp_wmb();

	memmove(tm->tcpm_id, id, sizeof(tm->tcpm_id));

	if (likely(!reclaim)) {
		tm->tcpm_next = serval_ctx->tcp_metrics_hash[hash].chain;
		rcu_assign_pointer(serval_ctx->tcp_metrics_hash[hash].chain,
			tm);
	}

out_unlock:
	spin_unlock_bh(&tcp_metrics_lock);
	return tm;
}

#define TCP_METRICS_TIMEOUT		(60 * 60 * HZ)

static void tcpm_check_stamp(struct tcp_metrics_block *tm,
	struct dst_entry *dst)
{
	if (tm && unlikely(time_after(jiffies,
		tm->tcpm_stamp + TCP_METRICS_TIMEOUT)))
		tcpm_suck_dst(tm, dst);
}

#define TCP_METRICS_RECLAIM_DEPTH	5
#define TCP_METRICS_RECLAIM_PTR		((struct tcp_metrics_block *)0x1UL)

static struct tcp_metrics_block *tcp_get_encode(struct tcp_metrics_block *tm,
	int depth)
{
	if (tm)
		return tm;
	if (depth > TCP_METRICS_RECLAIM_DEPTH)
		return TCP_METRICS_RECLAIM_PTR;
	return NULL;
}

static struct tcp_metrics_block *__tcp_get_metrics(const __u8 *id,
	struct xip_serval_ctx *serval_ctx, unsigned int hash)
{
	struct tcp_metrics_block *tm;
	int depth = 0;

	for (tm = rcu_dereference(serval_ctx->tcp_metrics_hash[hash].chain); tm;
	     tm = rcu_dereference(tm->tcpm_next)) {
		if (!memcmp(tm->tcpm_id, id, sizeof(tm->tcpm_id)))
			break;
		depth++;
	}
	return tcp_get_encode(tm, depth);
}

static struct tcp_metrics_block *tcp_get_metrics(struct sock *sk,
	struct dst_entry *dst, bool create)
{
	struct serval_sock *ssk = sk_ssk(sk);
	const u8 *id;
	struct net *net;
	struct xip_serval_ctx *serval_ctx;
	unsigned int hash;
	struct tcp_metrics_block *tm;
	bool reclaim;

	BUG_ON(!ssk->peer_srvc_set);
	id = ssk->peer_srvc_addr.s_row[ssk->peer_srvc_num - 1].s_xid.xid_id;

	net = dev_net(dst->dev);
	serval_ctx = srvc_serval(xip_find_ppal_ctx_vxt_rcu(net, srvc_vxt));

	BUILD_BUG_ON(XIA_XID_MAX != sizeof(u32) * 5);
	hash = jhash2((const u32 *)id, 5, 0) &
		((1 << serval_ctx->tcp_metrics_hash_log) - 1);

	tm = __tcp_get_metrics(id, serval_ctx, hash);
	reclaim = false;
	if (tm == TCP_METRICS_RECLAIM_PTR) {
		reclaim = true;
		tm = NULL;
	}
	if (!tm && create)
		tm = tcpm_new(serval_ctx, dst, id, hash, reclaim);
	else
		tcpm_check_stamp(tm, dst);

	return tm;
}

/* Save metrics learned by this TCP session.  This function is called
 * only, when TCP finishes successfully i.e. when it enters TIME-WAIT
 * or goes from LAST-ACK to CLOSE.
 */
void serval_tcp_update_metrics(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct tcp_metrics_block *tm;
	unsigned long rtt;
	u32 val;
	int m;

	if (sysctl_serval_tcp_nometrics_save || !dst)
		return;

	if (dst->flags & DST_HOST)
                dst_confirm(dst);

	rcu_read_lock();
	if (tp->backoff || !tp->srtt) {
		/* This session failed to estimate rtt. Why?
		 * Probably, no packets returned in time.  Reset our
		 * results.
		 */
		tm = tcp_get_metrics(sk, dst, false);
		if (tm && !tcp_metric_locked(tm, TCP_METRIC_RTT))
			tcp_metric_set(tm, TCP_METRIC_RTT, 0);
		goto out_unlock;
	} else
		tm = tcp_get_metrics(sk, dst, true);

	if (!tm)
		goto out_unlock;

	rtt = tcp_metric_get_jiffies(tm, TCP_METRIC_RTT);
	m = rtt - tp->srtt;

	/* If newly calculated rtt larger than stored one, store new
	 * one. Otherwise, use EWMA. Remember, rtt overestimation is
	 * always better than underestimation.
	 */
	if (!tcp_metric_locked(tm, TCP_METRIC_RTT)) {
		if (m <= 0)
			rtt = tp->srtt;
		else
			rtt -= (m >> 3);
		tcp_metric_set_msecs(tm, TCP_METRIC_RTT, rtt);
	}

	if (!tcp_metric_locked(tm, TCP_METRIC_RTTVAR)) {
		unsigned long var;

		if (m < 0)
			m = -m;

		/* Scale deviation to rttvar fixed point */
		m >>= 1;
		if (m < tp->mdev)
			m = tp->mdev;

		var = tcp_metric_get_jiffies(tm, TCP_METRIC_RTTVAR);
		if (m >= var)
			var = m;
		else
			var -= (var - m) >> 2;

		tcp_metric_set_msecs(tm, TCP_METRIC_RTTVAR, var);
	}

	if (serval_tcp_in_initial_slowstart(tp)) {
		/* Slow start still did not finish. */
		if (!tcp_metric_locked(tm, TCP_METRIC_SSTHRESH)) {
			val = tcp_metric_get(tm, TCP_METRIC_SSTHRESH);
			if (val && (tp->snd_cwnd >> 1) > val)
				tcp_metric_set(tm, TCP_METRIC_SSTHRESH,
					       tp->snd_cwnd >> 1);
		}
		if (!tcp_metric_locked(tm, TCP_METRIC_CWND)) {
			val = tcp_metric_get(tm, TCP_METRIC_CWND);
			if (tp->snd_cwnd > val)
				tcp_metric_set(tm, TCP_METRIC_CWND,
					       tp->snd_cwnd);
		}
	} else if (tp->snd_cwnd > tp->snd_ssthresh &&
		   tp->ca_state == TCP_CA_Open) {
		/* Cong. avoidance phase, cwnd is reliable. */
		if (!tcp_metric_locked(tm, TCP_METRIC_SSTHRESH))
			tcp_metric_set(tm, TCP_METRIC_SSTHRESH,
				       max(tp->snd_cwnd >> 1, tp->snd_ssthresh));
		if (!tcp_metric_locked(tm, TCP_METRIC_CWND)) {
			val = tcp_metric_get(tm, TCP_METRIC_CWND);
			tcp_metric_set(tm, TCP_METRIC_CWND, (val + tp->snd_cwnd) >> 1);
		}
	} else {
		/* Else slow start did not finish, cwnd is non-sense,
		 * ssthresh may be also invalid.
		 */
		if (!tcp_metric_locked(tm, TCP_METRIC_CWND)) {
			val = tcp_metric_get(tm, TCP_METRIC_CWND);
			tcp_metric_set(tm, TCP_METRIC_CWND,
				       (val + tp->snd_ssthresh) >> 1);
		}
		if (!tcp_metric_locked(tm, TCP_METRIC_SSTHRESH)) {
			val = tcp_metric_get(tm, TCP_METRIC_SSTHRESH);
			if (val && tp->snd_ssthresh > val)
				tcp_metric_set(tm, TCP_METRIC_SSTHRESH,
					       tp->snd_ssthresh);
		}
		if (!tcp_metric_locked(tm, TCP_METRIC_REORDERING)) {
			val = tcp_metric_get(tm, TCP_METRIC_REORDERING);
			if (val < tp->reordering &&
			    tp->reordering != sysctl_tcp_reordering)
				tcp_metric_set(tm, TCP_METRIC_REORDERING,
					       tp->reordering);
		}
	}
	tm->tcpm_stamp = jiffies;
out_unlock:
	rcu_read_unlock();
}

/* Initialize metrics on socket. */
void serval_tcp_init_metrics(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct tcp_metrics_block *tm;
	u32 val;

	if (dst == NULL)
		goto reset;

	dst_confirm(dst);

	rcu_read_lock();
	tm = tcp_get_metrics(sk, dst, true);
	if (!tm) {
		rcu_read_unlock();
		goto reset;
	}

	if (tcp_metric_locked(tm, TCP_METRIC_CWND))
		tp->snd_cwnd_clamp = tcp_metric_get(tm, TCP_METRIC_CWND);

	val = tcp_metric_get(tm, TCP_METRIC_SSTHRESH);
	if (val) {
		tp->snd_ssthresh = val;
		if (tp->snd_ssthresh > tp->snd_cwnd_clamp)
			tp->snd_ssthresh = tp->snd_cwnd_clamp;
	} else {
		/* ssthresh may have been reduced unnecessarily during.
		 * 3WHS. Restore it back to its initial default.
		 */
		tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	}
	val = tcp_metric_get(tm, TCP_METRIC_REORDERING);
	if (val && tp->reordering != val) {
		serval_tcp_disable_fack(tp);
		//serval_tcp_disable_early_retrans(tp);
		tp->reordering = val;
	}

	val = tcp_metric_get(tm, TCP_METRIC_RTT);
	if (val == 0 || tp->srtt == 0) {
		rcu_read_unlock();
		goto reset;
	}
	/* Initial rtt is determined from SYN,SYN-ACK.
	 * The segment is small and rtt may appear much
	 * less than real one. Use per-dst memory
	 * to make it more realistic.
	 *
	 * A bit of theory. RTT is time passed after "normal" sized packet
	 * is sent until it is ACKed. In normal circumstances sending small
	 * packets force peer to delay ACKs and calculation is correct too.
	 * The algorithm is adaptive and, provided we follow specs, it
	 * NEVER underestimate RTT. BUT! If peer tries to make some clever
	 * tricks sort of "quick acks" for time long enough to decrease RTT
	 * to low value, and then abruptly stops to do it and starts to delay
	 * ACKs, wait for troubles.
	 */
	val = msecs_to_jiffies(val);
	if (val > tp->srtt) {
		tp->srtt = val;
		tp->rtt_seq = tp->snd_nxt;
	}
	val = tcp_metric_get_jiffies(tm, TCP_METRIC_RTTVAR);
	if (val > tp->mdev) {
		tp->mdev = val;
		tp->mdev_max = tp->rttvar = max(tp->mdev, tcp_rto_min(sk));
	}
	rcu_read_unlock();

	serval_tcp_set_rto(sk);
reset:
	if (tp->srtt == 0) {
		/* RFC6298: 5.7 We've failed to get a valid RTT sample from
		 * 3WHS. This is most likely due to retransmission,
		 * including spurious one. Reset the RTO back to 3secs
		 * from the more aggressive 1sec to avoid more spurious
		 * retransmission.
		 */
		tp->mdev = tp->mdev_max = tp->rttvar = TCP_TIMEOUT_FALLBACK;
		tp->rto = TCP_TIMEOUT_FALLBACK;
	}
	/* Cut cwnd down to 1 per RFC5681 if SYN or SYN-ACK has been
	 * retransmitted. In light of RFC6298 more aggressive 1sec
	 * initRTO, we only reset cwnd when more than 1 SYN/SYN-ACK
	 * retransmission has occurred.
	 */
	if (tp->total_retrans > 1)
		tp->snd_cwnd = 1;
	else
		tp->snd_cwnd = serval_tcp_init_cwnd(tp, dst);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

int __net_init serval_tcp_net_metrics_init(struct xip_serval_ctx *serval_ctx)
{
	size_t size;
	unsigned int slots;

	slots = (totalram_pages >= 128 * 1024) ? 16 * 1024 : 8 * 1024;

	serval_ctx->tcp_metrics_hash_log = order_base_2(slots);
	size = sizeof(struct serval_tcpm_hash_bucket) <<
		serval_ctx->tcp_metrics_hash_log;

	serval_ctx->tcp_metrics_hash = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
	if (!serval_ctx->tcp_metrics_hash) {
		serval_ctx->tcp_metrics_hash = vzalloc(size);
		if (!serval_ctx->tcp_metrics_hash)
			return -ENOMEM;
	}
	return 0;
}

void __net_exit serval_tcp_net_metrics_exit(struct xip_serval_ctx *serval_ctx)
{
	unsigned int i;

	for (i = 0; i < (1U << serval_ctx->tcp_metrics_hash_log); i++) {
		struct tcp_metrics_block *tm = rcu_dereference_protected(
			serval_ctx->tcp_metrics_hash[i].chain, 1);
		while (tm) {
			struct tcp_metrics_block *next =
				rcu_dereference_protected(tm->tcpm_next, 1);
			kfree(tm);
			tm = next;
		}
	}
	if (is_vmalloc_addr(serval_ctx->tcp_metrics_hash))
		vfree(serval_ctx->tcp_metrics_hash);
	else
		kfree(serval_ctx->tcp_metrics_hash);
	serval_ctx->tcp_metrics_hash = NULL;
}

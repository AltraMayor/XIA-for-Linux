/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <platform.h>
#include <debug.h>
#include <netdevice.h>
#include <skbuff.h>
#include <sock.h>
#include <net.h>
#include <bitops.h>
#include <netinet_serval.h>
#include <serval_tcp_sock.h>
#include <serval_tcp_request_sock.h>
#include <serval_sal.h>
#include <serval_ipv4.h>
#include <serval_tcp.h>
#include <af_serval.h>

#if defined(OS_LINUX_KERNEL)
#include <asm/ioctls.h>
#include <linux/sockios.h>
#include <linux/swap.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
#include <linux/export.h>
#endif
#include <net/netdma.h>
#define ENABLE_PAGE 1
#endif

extern int serval_udp_encap_xmit(struct sk_buff *skb);

int sysctl_serval_tcp_fin_timeout __read_mostly = TCP_FIN_TIMEOUT;
int sysctl_serval_tcp_low_latency __read_mostly = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
int sysctl_serval_tcp_mem[3];
#else
long sysctl_serval_tcp_mem[3];
#endif
int sysctl_serval_tcp_wmem[3];
int sysctl_serval_tcp_rmem[3];

int serval_tcp_memory_pressure __read_mostly;

void serval_tcp_enter_memory_pressure(struct sock *sk)
{
        if (!serval_tcp_memory_pressure) {
                serval_tcp_memory_pressure = 1;
        }
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
atomic_t serval_tcp_memory_allocated __read_mostly;
#else
atomic_long_t serval_tcp_memory_allocated  __read_mostly;
#endif

static int serval_tcp_disconnect(struct sock *sk, int flags)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        int err = 0;

	serval_tcp_clear_xmit_timers(sk);
	__skb_queue_purge(&sk->sk_receive_queue);
	serval_tcp_write_queue_purge(sk);
	__skb_queue_purge(&tp->out_of_order_queue);
#ifdef CONFIG_NET_DMA
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif
        tp->srtt = 0;
	if ((tp->write_seq += tp->max_window + 2) == 0)
		tp->write_seq = 1;
	tp->backoff = 0;
	tp->snd_cwnd = 2;
	tp->probes_out = 0;
	tp->packets_out = 0;
	tp->snd_ssthresh = SERVAL_TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_cnt = 0;
	tp->bytes_acked = 0;
	tp->window_clamp = 0;
        tp->snd_mig_last = 0;
	serval_tcp_set_ca_state(sk, TCP_CA_Open);
	serval_tcp_clear_retrans(tp);
	serval_tsk_delack_init(sk);
	serval_tcp_init_send_head(sk);
	memset(&tp->rx_opt, 0, sizeof(tp->rx_opt));
	__sk_dst_reset(sk);

	sk->sk_error_report(sk);

        return err;
}

static void serval_tcp_shutdown(struct sock *sk, int how)
{
        LOG_SSK(sk, "\n");
}

__u32 serval_tcp_random_sequence_number(void)
{
   __u32 isn;

#if defined(OS_LINUX_KERNEL)
        get_random_bytes(&isn, sizeof(isn));
#else
        {
                unsigned int i;
                unsigned char *seqno = (unsigned char *)&isn;
              
                for (i = 0; i < sizeof(isn); i++) {
                        seqno[i] = random() & 0xff;
                }
        }       
#endif
        return isn;
}

static inline __u32 serval_tcp_init_sequence(struct sk_buff *skb)
{
        return serval_tcp_random_sequence_number();
}

static inline void serval_tcp_openreq_init(struct request_sock *req,
                                           struct serval_tcp_options_received *rx_opt,
                                           struct sk_buff *skb)
{
	struct inet_request_sock *ireq = inet_rsk(req);

	req->rcv_wnd = 0;		/* So that tcp_send_synack() knows! */
	req->cookie_ts = 0;
	serval_tcp_rsk(req)->rcv_isn = ntohl(tcp_hdr(skb)->seq);

	req->mss = rx_opt->mss_clamp;
	req->ts_recent = rx_opt->saw_tstamp ? rx_opt->rcv_tsval : 0;
	ireq->tstamp_ok = rx_opt->tstamp_ok;
	ireq->sack_ok = rx_opt->sack_ok;
	ireq->snd_wscale = rx_opt->snd_wscale;
	ireq->wscale_ok = rx_opt->wscale_ok;
      
	ireq->tstamp_ok = rx_opt->tstamp_ok;
	ireq->sack_ok = rx_opt->sack_ok;
	ireq->snd_wscale = rx_opt->snd_wscale;
	ireq->wscale_ok = rx_opt->wscale_ok;
	ireq->acked = 0;
	ireq->ecn_ok = 0;
	ireq->rmt_port = tcp_hdr(skb)->source;
	ireq->loc_port = tcp_hdr(skb)->dest;
}

static int serval_tcp_connection_request(struct sock *sk, 
                                         struct request_sock *req,
                                         struct sk_buff *skb)
{
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        /* struct inet_request_sock *ireq = inet_rsk(req); */
        struct serval_tcp_request_sock *trsk = serval_tcp_rsk(req);
	struct serval_tcp_options_received tmp_opt;
        u8 *hash_location;

        if (serval_tcp_rcv_checks(sk, skb, 1)) {                
                LOG_ERR("packet failed receive checks!\n");
                kfree_skb(skb);
                return -1;
        }

        memset(&tmp_opt, 0, sizeof(tmp_opt));
	serval_tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = SERVAL_TCP_MSS_DEFAULT;
	tmp_opt.user_mss  = tp->rx_opt.user_mss;
	serval_tcp_parse_options(skb, &tmp_opt, &hash_location, 0);

        serval_tcp_openreq_init(req, &tmp_opt, skb);

        trsk->snt_isn = serval_tcp_init_sequence(skb);

        return 0;
}

static int serval_tcp_syn_recv_sock(struct sock *sk, 
                                    struct sk_buff *skb,
                                    struct request_sock *rsk,
                                    struct sock *child,
                                    struct dst_entry *dst);

int serval_tcp_do_rcv(struct sock *sk, struct sk_buff *skb)
{
        if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		//sock_rps_save_rxhash(sk, skb->rxhash);
                LOG_SSK(sk, "Established state receive\n");
              
		if (serval_tcp_rcv_established(sk, skb, 
                                               tcp_hdr(skb), skb->len)) {
			goto reset;
		}
		return 0;
	} 

	if (skb->len < serval_tcp_hdrlen(skb) || 
            serval_tcp_checksum_complete(skb))
		goto csum_err;

	if (serval_tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len)) {
		goto reset;
	}

        return 0;
 reset:
        /* send reset? */
        LOG_SSK(sk, "TODO: send reset?\n");
 csum_err:
        //LOG_WARN("Should handle RESET in non-established state\n");
        kfree_skb(skb);
        return 0;
}

static __sum16 serval_tcp_v4_checksum_init(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);

	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!serval_tcp_v4_check(skb->len, iph->saddr,
                                         iph->daddr, skb->csum)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			return 0;
		}
	}

	skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
				       skb->len, IPPROTO_TCP, 0);

	if (skb->len <= 76) {
		return __skb_checksum_complete(skb);
	}
	return 0;
}

int serval_tcp_rcv_checks(struct sock *sk, struct sk_buff *skb, int is_syn)
{
        struct tcphdr *th;
        struct iphdr *iph;

#if defined(OS_LINUX_KERNEL)
	if (is_syn) {
                /* SYN packets can be broadcast and we should accept
                   those packets. */
                if (skb->pkt_type != PACKET_BROADCAST && 
                    skb->pkt_type != PACKET_HOST) {
                        LOG_ERR("TCP packet not for this host (broadcast)!\n");
                        goto bad_packet;
                }
        } else if (skb->pkt_type != PACKET_HOST) {
                LOG_ERR("TCP packet not for this host!\n");
                goto bad_packet;
        }
#endif

	if (!pskb_may_pull(skb, sizeof(struct tcphdr))) {
                LOG_SSK(sk, "No TCP header -- discarding\n");
                goto bad_packet;
        }

	th = tcp_hdr(skb);

	if (th->doff < sizeof(struct tcphdr) / 4) {
                LOG_SSK(sk, "TCP packet has bad data offset=%u!\n",
                        th->doff << 2);
		goto bad_packet;
        }

	if (!pskb_may_pull(skb, th->doff << 2)) {
                LOG_SSK(sk, "Cannot pull tcp header!\n");
		goto bad_packet;
        }

	iph = ip_hdr(skb);

#if defined(ENABLE_DEBUG)
        {
                char rmtstr[18], locstr[18], saddr[18], daddr[18];
                LOG_SSK(sk, "iph->saddr=%s iph->daddr=%s "
                        "inet_saddr=%s inet_daddr=%s\n",
                        inet_ntop(AF_INET, &iph->saddr, 
                                  rmtstr, 18),
                        inet_ntop(AF_INET, &iph->daddr, 
                                  locstr, 18),
                        inet_ntop(AF_INET, &inet_sk(sk)->inet_saddr, 
                                  saddr, 18),
                        inet_ntop(AF_INET, &inet_sk(sk)->inet_daddr, 
                                  daddr, 18));
        }
#endif

        /* An explanation is required here, I think. Packet length and
	 * doff are validated by header prediction, provided case of
	 * th->doff==0 is eliminated.  So, we defer the checks. */
	if (!skb_csum_unnecessary(skb) && 
            serval_tcp_v4_checksum_init(skb)) {
                LOG_ERR("Checksum error!\n");
                goto bad_packet;
        }

	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + 
                                    th->syn + th->fin +
				    skb->len - th->doff * 4);
	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->when	 = 0;
	TCP_SKB_CB(skb)->tcp_flags	 = iph->tos;
	TCP_SKB_CB(skb)->sacked	 = 0;        
        
        LOG_PKT("Received TCP %s rcv_nxt=%u snd_wnd=%u end_seq=%u datalen=%u\n",
                tcphdr_to_str(th),
                serval_tcp_sk(sk)->rcv_nxt,
                serval_tcp_sk(sk)->snd_wnd,
                TCP_SKB_CB(skb)->end_seq,
                skb->len - (th->doff << 2));

        return 0;
bad_packet:
        return -1;
}

/* 
   Receive from network.

   TODO/NOTE:

   Since we are adding packets to the backlog in the SAL, and not here
   in the transport receive function, we cannot drop packets with bad
   transport headers before adding to the backlog. Ideally, we would
   not bother queueing bad packets on the backlog, but this requires a
   way to check transport headers before backlogging.

   We could add an "early-packet-sanity-check" function in transport
   that the SAL calls before adding packets to the backlog just to
   make sure they are not bad. This function would basically have the
   checks in the beginning of the function below.

*/
static int serval_tcp_rcv(struct sock *sk, struct sk_buff *skb)
{
        int err = 0;
        
        if (serval_tcp_rcv_checks(sk, skb, 0))
                goto discard_it;

        if (!sock_owned_by_user(sk)) {
#ifdef CONFIG_NET_DMA        
                struct serval_tcp_sock *tp = serval_tcp_sk(sk);
                if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
                        tp->ucopy.dma_chan = dma_find_channel(DMA_MEMCPY);
                if (tp->ucopy.dma_chan)
                        err = serval_tcp_do_rcv(sk, skb);
                else
#endif
                        {                
                                if (!serval_tcp_prequeue(sk, skb))
                                        err = serval_tcp_do_rcv(sk, skb);
                        }
        } else {
                /* We are processing the backlog in user/process
                   context */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0))
                if (sk_add_backlog(sk, skb, 
                                   sk->sk_rcvbuf + sk->sk_sndbuf))
                        goto discard_it;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
                if (sk_add_backlog(sk, skb)) {
                        goto discard_it;
                }
#else
                sk_add_backlog(sk, skb);
#endif
        }
     
        return err;
discard_it:
        kfree_skb(skb);

        return 0;
}

void serval_tcp_done(struct sock *sk)
{
        LOG_SSK(sk, "TCP done!\n");
	serval_tcp_clear_xmit_timers(sk);
}

void serval_tcp_init(void)
{
        unsigned long limit;
        int max_rshare, max_wshare;
        
#if defined(OS_LINUX_KERNEL)
        limit = nr_free_buffer_pages() / 8;
        limit = max(limit, 128UL);
#else
        limit = 128UL;
#endif
        sysctl_serval_tcp_mem[0] = limit / 4 * 3;
        sysctl_serval_tcp_mem[1] = limit;
        sysctl_serval_tcp_mem[2] = sysctl_serval_tcp_mem[0] * 2;

        /* Set per-socket limits to no more than 1/128 the pressure
           threshold */
        limit = ((unsigned long)sysctl_serval_tcp_mem[1]) << (PAGE_SHIFT - 7);
        max_wshare = min(4UL*1024*1024, limit);
        max_rshare = min(6UL*1024*1024, limit);

        sysctl_serval_tcp_wmem[0] = SK_MEM_QUANTUM;
        sysctl_serval_tcp_wmem[1] = 16*1024;
        sysctl_serval_tcp_wmem[2] = max(64*1024, max_wshare);

        sysctl_serval_tcp_rmem[0] = SK_MEM_QUANTUM;
        sysctl_serval_tcp_rmem[1] = 87380;
        sysctl_serval_tcp_rmem[2] = max(87380, max_rshare);
}

static int serval_tcp_connection_close(struct sock *sk)
{
        struct sk_buff *skb;
	int data_was_unread = 0;
        
	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);
        
        serval_tcp_send_fin(sk);

        return data_was_unread;
}

static unsigned int serval_tcp_xmit_size_goal(struct sock *sk, u32 mss_now,
                                              int large_allowed)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 xmit_size_goal, old_size_goal;

	xmit_size_goal = mss_now;

	if (large_allowed && 0 /* sk_can_gso(sk) */) {
		xmit_size_goal = ((sk->sk_gso_max_size - 1) -
				  serval_sk(sk)->af_ops->net_header_len -
                                  serval_sk(sk)->ext_hdr_len -
				  tp->tcp_header_len);

		xmit_size_goal = 
                        serval_tcp_bound_to_half_wnd(tp, xmit_size_goal);

		/* We try hard to avoid divides here */
		old_size_goal = tp->xmit_size_goal_segs * mss_now;

		if (likely(old_size_goal <= xmit_size_goal &&
			   old_size_goal + mss_now > xmit_size_goal)) {
			xmit_size_goal = old_size_goal;
		} else {
			tp->xmit_size_goal_segs = xmit_size_goal / mss_now;
			xmit_size_goal = tp->xmit_size_goal_segs * mss_now;
		}
	}

	return max(xmit_size_goal, mss_now);
}

static int serval_tcp_send_mss(struct sock *sk, int *size_goal, int flags)
{
	int mss_now;

	mss_now = serval_tcp_current_mss(sk);
	*size_goal = serval_tcp_xmit_size_goal(sk, mss_now, !(flags & MSG_OOB));

	return mss_now;
}

static inline void serval_tcp_mark_push(struct serval_tcp_sock *tp, 
                                 struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->tcp_flags |= TCPH_PSH;
	tp->pushed_seq = tp->write_seq;
}

static inline int forced_push(struct serval_tcp_sock *tp)
{
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

static void serval_tcp_skb_free(struct sk_buff *skb)
{
        /* LOG_PKT("Freeing skb data packet, skb->len=%u\n", skb->len); */
}

static inline void skb_serval_tcp_set_owner(struct sk_buff *skb, 
                                            struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = serval_tcp_skb_free;
        /* Guarantees the socket is not free'd for in-flight packets */
        //sock_hold(sk);
}

/* From net/ipv4/tcp.c */
struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp)
{
	struct sk_buff *skb;

	/* The TCP header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);

	skb = alloc_skb(size + sk->sk_prot->max_header, gfp);

	if (skb) {
		if (sk_wmem_schedule(sk, skb->truesize)) {
			/*
			 * Make sure that we have exactly size bytes
			 * available to the caller, no more, no less.
			 */
			skb_reserve(skb, skb_tailroom(skb) - size);
			return skb;
		}
		__kfree_skb(skb);
	} else {
		sk->sk_prot->enter_memory_pressure(sk);
		sk_stream_moderate_sndbuf(sk);
	}
	return NULL;
}

static inline void skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	skb->csum    = 0;
	tcb->seq     = tcb->end_seq = tp->write_seq;
	tcb->tcp_flags   = TCPH_ACK;
	tcb->sacked  = 0;
	skb_header_release(skb);
	serval_tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
	if (tp->nonagle & TCP_NAGLE_PUSH)
		tp->nonagle &= ~TCP_NAGLE_PUSH;
}

#define TCP_PAGE(sk)	(sk->sk_frag.page)
#define TCP_OFF(sk)	(sk->sk_frag.offset)

static inline int select_size(struct sock *sk, int sg)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int tmp = tp->mss_cache;

	if (sg) {
		if (0 /* sk_can_gso(sk) */)
			tmp = 0;
		else {
			int pgbreak = SKB_MAX_HEAD(MAX_SERVAL_TCP_HEADER);

			if (tmp >= pgbreak &&
			    tmp <= pgbreak + (MAX_SKB_FRAGS - 1) * PAGE_SIZE)
				tmp = pgbreak;
		}
	}

	return tmp;
}

static inline void serval_tcp_mark_urg(struct serval_tcp_sock *tp, int flags)
{
	if (flags & MSG_OOB)
		tp->snd_up = tp->write_seq;        
}

static inline void serval_tcp_push(struct sock *sk, int flags, int mss_now,
                                   int nonagle)
{
	if (serval_tcp_send_head(sk)) {
		struct serval_tcp_sock *tp = serval_tcp_sk(sk);

		if (!(flags & MSG_MORE) || forced_push(tp))
			serval_tcp_mark_push(tp, serval_tcp_write_queue_tail(sk));

		serval_tcp_mark_urg(tp, flags);

		__serval_tcp_push_pending_frames(sk, mss_now,
                                                 (flags & MSG_MORE) ? 
                                                 TCP_NAGLE_CORK : nonagle);
	}
}

#ifdef CONFIG_NET_DMA
static void serval_tcp_service_net_dma(struct sock *sk, bool wait)
{
	dma_cookie_t done, used;
	dma_cookie_t last_issued;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	if (!tp->ucopy.dma_chan)
		return;

	last_issued = tp->ucopy.dma_cookie;
	dma_async_issue_pending(tp->ucopy.dma_chan);

	do {
		if (dma_async_is_tx_complete(tp->ucopy.dma_chan,
					      last_issued, &done,
					      &used) == DMA_SUCCESS) {
			/* Safe to free early-copied skbs now */
			__skb_queue_purge(&sk->sk_async_wait_queue);
			break;
		} else {
			struct sk_buff *skb;
			while ((skb = skb_peek(&sk->sk_async_wait_queue)) &&
			       (dma_async_is_complete(skb->dma_cookie, done,
						      used) == DMA_SUCCESS)) {
				__skb_dequeue(&sk->sk_async_wait_queue);
				kfree_skb(skb);
			}
		}
	} while (wait);
}
#endif

#if defined(OS_LINUX_KERNEL)
/*
 *	Wait for a TCP event.
 *
 *	Note that we don't need to lock the socket, as the upper poll layers
 *	take care of normal races (between the test and the event) and we don't
 *	go look at any of the socket buffers directly.
 */
unsigned int serval_tcp_poll(struct file *file, 
                             struct socket *sock, 
                             poll_table *wait)
{
	unsigned int mask;
	struct sock *sk = sock->sk;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	sock_poll_wait(file, sk_sleep(sk), wait);
        
        if (sk->sk_state == TCP_LISTEN) {
                struct serval_sock *ssk = serval_sk(sk);
                return list_empty(&ssk->accept_queue) ? 0 :
                        (POLLIN | POLLRDNORM);
        }

        /* Socket is not locked. We are protected from async events
	 * by poll logic and correct handling of state changes
	 * made by other threads is impossible in any case.
	 */

	mask = 0;

	/*
	 * POLLHUP is certainly not done right. But poll() doesn't
	 * have a notion of HUP in just one direction, and for a
	 * socket the read side is more interesting.
	 *
	 * Some poll() documentation says that POLLHUP is incompatible
	 * with the POLLOUT/POLLWR flags, so somebody should check this
	 * all. But careful, it tends to be safer to return too many
	 * bits than too few, and you can easily break real applications
	 * if you don't tell them that something has hung up!
	 *
	 * Check-me.
	 *
	 * Check number 1. POLLHUP is _UNMASKABLE_ event (see UNIX98 and
	 * our fs/select.c). It means that after we received EOF,
	 * poll always returns immediately, making impossible poll() on write()
	 * in state CLOSE_WAIT. One solution is evident --- to set POLLHUP
	 * if and only if shutdown has been made in both directions.
	 * Actually, it is interesting to look how Solaris and DUX
	 * solve this dilemma. I would prefer, if POLLHUP were maskable,
	 * then we could set it on SND_SHUTDOWN. BTW examples given
	 * in Stevens' books assume exactly this behaviour, it explains
	 * why POLLHUP is incompatible with POLLOUT.	--ANK
	 *
	 * NOTE. Check for TCP_CLOSE is added. The goal is to prevent
	 * blocking on fresh not-connected or disconnected socket. --ANK
	 */
	if (sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE) {
		mask |= POLLHUP;
                LOG_SSK(sk, "POLLHUP\n");
        }
	if (sk->sk_shutdown & RCV_SHUTDOWN) {
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;
        }

	/* Connected? */
	if ((1 << sk->sk_state) & ~(TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		int target = sock_rcvlowat(sk, 0, INT_MAX);

		if (tp->urg_seq == tp->copied_seq &&
		    !sock_flag(sk, SOCK_URGINLINE) &&
		    tp->urg_data)
			target++;

		/* Potential race condition. If read of tp below will
		 * escape above sk->sk_state, we can be illegally awaken
		 * in SYN_* states. */
		if (tp->rcv_nxt - tp->copied_seq >= target)
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		} else
			mask |= POLLOUT | POLLWRNORM;

		if (tp->urg_data & TCP_URG_VALID)
			mask |= POLLPRI;
	}
	/* This barrier is coupled with smp_wmb() in serval_sal_rcv_reset() */
	smp_rmb();
	if (sk->sk_err) {
                LOG_SSK(sk, "POLLERR returned\n");
		mask |= POLLERR;
        }
	return mask;
}

#if defined(ENABLE_SPLICE)
/*
 * TCP splice context
 */
struct tcp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

static inline struct sk_buff *serval_tcp_recv_skb(struct sock *sk, 
                                                  u32 seq, u32 *off)
{
	struct sk_buff *skb;
	u32 offset;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		offset = seq - TCP_SKB_CB(skb)->seq;
		if (tcp_hdr(skb)->syn)
			offset--;
		if (offset < skb->len || tcp_hdr(skb)->fin) {
			*off = offset;
			return skb;
		}
	}
	return NULL;
}

/*
 * This routine provides an alternative to tcp_recvmsg() for routines
 * that would like to handle copying from skbuffs directly in 'sendfile'
 * fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int serval_tcp_read_sock(struct sock *sk, read_descriptor_t *desc,
                         sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;

	if (sk->sk_state == TCP_LISTEN)
		return -ENOTCONN;

	while ((skb = serval_tcp_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			int used;
			size_t len;

			len = skb->len - offset;
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;
				if (!len)
					break;
			}

			used = recv_actor(desc, skb, offset, len);

			if (used < 0) {
				if (!copied)
					copied = used;
				break;
			} else if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			/*
			 * If recv_actor drops the lock (e.g. TCP splice
			 * receive) the skb pointer might be invalid when
			 * getting here: tcp_collapse might have deleted it
			 * while aggregating skbs from the socket queue.
			 */
			skb = serval_tcp_recv_skb(sk, seq-1, &offset);
			if (!skb || (offset+1 != skb->len))
				break;
		}

		if (tcp_hdr(skb)->fin) {
                        tp->fin_found = 1;
                        LOG_SSK(sk, "Read FIN\n");
			sk_eat_skb(sk, skb, 0);
			++seq;
			break;
		}

		sk_eat_skb(sk, skb, 0);
		if (!desc->count)
			break;
		tp->copied_seq = seq;
	}
	tp->copied_seq = seq;

	serval_tcp_rcv_space_adjust(sk);

	/* Clean up data we have read: This will do ACK frames. */
	if (copied > 0)
		serval_tcp_cleanup_rbuf(sk, copied);
	return copied;
}

static int serval_tcp_splice_data_recv(read_descriptor_t *rd_desc, 
                                       struct sk_buff *skb,
                                       unsigned int offset, size_t len)
{
	struct tcp_splice_state *tss = rd_desc->arg.data;
	int ret;

	ret = skb_splice_bits(skb, offset, tss->pipe, min(rd_desc->count, len),
			      tss->flags);
	if (ret > 0)
		rd_desc->count -= ret;
	return ret;
}

static int __serval_tcp_splice_read(struct sock *sk,
                                    struct tcp_splice_state *tss)
{
	/* Store TCP splice context information in read_descriptor_t. */
	read_descriptor_t rd_desc = {
		.arg.data = tss,
		.count	  = tss->len,
	};

	return serval_tcp_read_sock(sk, &rd_desc, serval_tcp_splice_data_recv);
}

/**
 *  tcp_splice_read - splice data from TCP socket to a pipe
 * @sock:	socket to splice from
 * @ppos:	position (not valid)
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given socket and fill them into a pipe.
 *
 **/
ssize_t serval_tcp_splice_read(struct socket *sock, loff_t *ppos,
                               struct pipe_inode_info *pipe, size_t len,
                               unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct tcp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	long timeo;
	ssize_t spliced;
	int ret;

	sock_rps_record_flow(sk);
	/*
	 * We can't seek on a socket input
	 */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, sock->file->f_flags & O_NONBLOCK);

	while (tss.len) {
                if (!serval_tcp_sk(sk)->fin_found)
                        ret = __serval_tcp_splice_read(sk, &tss);
		if (ret < 0)
			break;
		else if (!ret) {
			if (spliced)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				if (!sock_flag(sk, SOCK_DONE))
					ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;

		if (!timeo)
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);

	if (spliced)
		return spliced;

	return ret;
}

static ssize_t serval_do_tcp_sendpages(struct sock *sk, struct page **pages, 
                                       int poffset, size_t psize, int flags)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int mss_now, size_goal;
	int err;
	ssize_t copied;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = serval_tcp_send_mss(sk, &size_goal, flags);
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	while (psize > 0) {
		struct sk_buff *skb = serval_tcp_write_queue_tail(sk);
		struct page *page = pages[poffset / PAGE_SIZE];
		int copy, i, can_coalesce;
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

		if (!serval_tcp_send_head(sk) || 
                    (copy = size_goal - skb->len) <= 0) {
                new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;
                        
			skb = sk_stream_alloc_skb(sk, 0, sk->sk_allocation);
			
                        if (!skb)
				goto wait_for_memory;

			skb_entail(sk, skb);
			copy = size_goal;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		can_coalesce = skb_can_coalesce(skb, i, page, offset);
		if (!can_coalesce && i >= MAX_SKB_FRAGS) {
			serval_tcp_mark_push(tp, skb);
			goto new_segment;
		}
		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		if (can_coalesce) {
			skb_shinfo(skb)->frags[i - 1].size += copy;
		} else {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		}

		skb->len += copy;
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		sk_mem_charge(sk, copy);
		skb->ip_summed = CHECKSUM_PARTIAL;
		tp->write_seq += copy;
		TCP_SKB_CB(skb)->end_seq += copy;
		skb_shinfo(skb)->gso_segs = 0;

		if (!copied)
			TCP_SKB_CB(skb)->tcp_flags &= ~TCPH_PSH;

		copied += copy;
		poffset += copy;
		if (!(psize -= copy))
			goto out;

		if (skb->len < size_goal || (flags & MSG_OOB))
			continue;

		if (forced_push(tp)) {
			serval_tcp_mark_push(tp, skb);
			__serval_tcp_push_pending_frames(sk, mss_now, 
                                                         TCP_NAGLE_PUSH);
		} else if (skb == serval_tcp_send_head(sk))
			serval_tcp_push_one(sk, mss_now);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if (copied)
			serval_tcp_push(sk, flags & ~MSG_MORE, 
                                        mss_now, TCP_NAGLE_PUSH);

		if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
			goto do_error;

		mss_now = serval_tcp_send_mss(sk, &size_goal, flags);
	}

out:
	if (copied)
		serval_tcp_push(sk, flags, mss_now, tp->nonagle);

	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	return sk_stream_error(sk, flags, err);
}

int serval_tcp_sendpage(struct sock *sk, struct page *page, int offset,
                        size_t size, int flags)
{
	ssize_t res;

        /* Using do_tcp_sendpages requires functioning hardware
           checksum support, and that doesn't work for Serval
           headers. Therefore, we must force use of normal sendmsg
           (called by sock_no_sendpage. */
	if (1 || !(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & NETIF_F_ALL_CSUM)) {
                return sock_no_sendpage(sk->sk_socket, page, offset, size,
					flags);
        }

	lock_sock(sk);
	res = serval_do_tcp_sendpages(sk, &page, offset, size, flags);
	release_sock(sk);
	return res;
}

#endif /* ENABLE_SPLICE */
#endif /* OS_LINUX_KERNEL */


/* # if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) */
#if 1
int serval_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
                       size_t size)
{
	struct iovec *iov;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags, err, copied = 0;
	int mss_now = 0, size_goal, copied_syn = 0, offset = 0;
	bool sg;
	long timeo;

	lock_sock(sk);

	flags = msg->msg_flags;

#if defined(ENABLE_TCP_FASTOPEN)
	if (flags & MSG_FASTOPEN) {
		err = serval_tcp_sendmsg_fastopen(sk, msg, &copied_syn);
		if (err == -EINPROGRESS && copied_syn > 0)
			goto out;
		else if (err)
			goto out_err;
		offset = copied_syn;
	}
#endif

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) 
#if defined(ENABLE_TCP_FASTOPEN)
            && !serval_tcp_passive_fastopen(sk)
#endif
            ) {
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto do_error;
	}

#if defined(ENABLE_TCP_REPAIR)
	if (unlikely(tp->repair)) {
		if (tp->repair_queue == TCP_RECV_QUEUE) {
			copied = serval_tcp_send_rcvq(sk, msg, size);
			goto out;
		}

		err = -EINVAL;
		if (tp->repair_queue == TCP_NO_QUEUE)
			goto out_err;

		/* 'common' sending to sendq */
	}
#endif
	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = serval_tcp_send_mss(sk, &size_goal, flags);

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	sg = !!(sk->sk_route_caps & NETIF_F_SG);

	while (--iovlen >= 0) {
		size_t seglen = iov->iov_len;
		unsigned char __user *from = iov->iov_base;

		iov++;
		if (unlikely(offset > 0)) {  /* Skip bytes copied in SYN */
			if (offset >= seglen) {
				offset -= seglen;
				continue;
			}
			seglen -= offset;
			from += offset;
			offset = 0;
		}

		while (seglen > 0) {
			int copy = 0;
			int max = size_goal;

			skb = serval_tcp_write_queue_tail(sk);
			if (serval_tcp_send_head(sk)) {
				if (skb->ip_summed == CHECKSUM_NONE)
					max = mss_now;
				copy = max - skb->len;
			}

			if (copy <= 0) {
new_segment:
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				if (!sk_stream_memory_free(sk))
					goto wait_for_sndbuf;

				skb = sk_stream_alloc_skb(sk,
							  select_size(sk, sg),
							  sk->sk_allocation);
				if (!skb)
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
					skb->ip_summed = CHECKSUM_PARTIAL;

				skb_entail(sk, skb);
				copy = size_goal;
				max = size_goal;
			}

			/* Try to append data to the end of skb. */
			if (copy > seglen)
				copy = seglen;

			/* Where to copy to? */
			if (skb_availroom(skb) > 0) {
				/* We have some space in skb head. Superb! */
				copy = min_t(int, copy, skb_availroom(skb));
				err = skb_add_data_nocache(sk, skb, from, copy);
				if (err)
					goto do_fault;
			} else {
				bool merge = true;
				int i = skb_shinfo(skb)->nr_frags;
				struct page_frag *pfrag = sk_page_frag(sk);

				if (!sk_page_frag_refill(sk, pfrag))
					goto wait_for_memory;

				if (!skb_can_coalesce(skb, i, pfrag->page,
						      pfrag->offset)) {
					if (i == MAX_SKB_FRAGS || !sg) {
						serval_tcp_mark_push(tp, skb);
						goto new_segment;
					}
					merge = false;
				}

				copy = min_t(int, copy, pfrag->size - pfrag->offset);

				if (!sk_wmem_schedule(sk, copy))
					goto wait_for_memory;

				err = skb_copy_to_page_nocache(sk, from, skb,
							       pfrag->page,
							       pfrag->offset,
							       copy);
				if (err)
					goto do_error;

				/* Update the skb. */
				if (merge) {
					skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
				} else {
					skb_fill_page_desc(skb, i, pfrag->page,
							   pfrag->offset, copy);
					get_page(pfrag->page);
				}
				pfrag->offset += copy;
			}

			if (!copied)
				TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;

			tp->write_seq += copy;
			TCP_SKB_CB(skb)->end_seq += copy;
			skb_shinfo(skb)->gso_segs = 0;

			from += copy;
			copied += copy;
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			if (skb->len < max || (flags & MSG_OOB) 
#if defined(ENABLE_TCP_REPAIR)
                            || unlikely(tp->repair)
#endif
                            )
				continue;

			if (forced_push(tp)) {
				serval_tcp_mark_push(tp, skb);
				__serval_tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
			} else if (skb == tcp_send_head(sk))
				serval_tcp_push_one(sk, mss_now);
			continue;

wait_for_sndbuf:
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)
				serval_tcp_push(sk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

			if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
				goto do_error;

			mss_now = serval_tcp_send_mss(sk, &size_goal, flags);
		}
	}

out:
	if (copied)
		serval_tcp_push(sk, flags, mss_now, tp->nonagle);
	release_sock(sk);
	return copied + copied_syn;

do_fault:
	if (!skb->len) {
		serval_tcp_unlink_write_queue(skb, sk);
		/* It is the one place in all of TCP, except connection
		 * reset, where we can be unlinking the send_head.
		 */
		serval_tcp_check_send_head(sk, skb);
		sk_wmem_free_skb(sk, skb);
	}

do_error:
	if (copied + copied_syn)
		goto out;
out_err:
	err = sk_stream_error(sk, flags, err);
	release_sock(sk);
	return err;
}
#else

static int serval_tcp_sendmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg, size_t len)
{
	struct iovec *iov;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags;
	int mss_now, size_goal;
	int sg, err, copied;
	long timeo;

        LOG_SSK(sk, "Sending tcp message, len=%zu\n", len);

	lock_sock(sk);

	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = serval_tcp_send_mss(sk, &size_goal, flags);

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

        /* Check scatter/gather I/O capability */
	sg = sk->sk_route_caps & NETIF_F_SG;

	while (--iovlen >= 0) {
		int seglen = iov->iov_len;
		char *from = iov->iov_base;

		iov++;

		while (seglen > 0) {
			int copy = 0;
			int max = size_goal;

			skb = serval_tcp_write_queue_tail(sk);

			if (serval_tcp_send_head(sk)) {
				if (skb->ip_summed == CHECKSUM_NONE)
					max = mss_now;
				copy = max - skb->len;
			}

			if (copy <= 0) {
#if defined(OS_LINUX_KERNEL)
new_segment:
#endif
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				if (!sk_stream_memory_free(sk))
					goto wait_for_sndbuf;

				skb = sk_stream_alloc_skb(sk,
							  select_size(sk, sg),
							  sk->sk_allocation);
				if (!skb)
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
                                        skb->ip_summed = CHECKSUM_PARTIAL;

				skb_entail(sk, skb);
				copy = size_goal;
				max = size_goal;
			}

			/* Try to append data to the end of skb. */
			if (copy > seglen)
				copy = seglen;

			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) {
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))
					copy = skb_tailroom(skb);

				if ((err = skb_add_data(skb, from, copy)) != 0) {
					goto do_fault;
                                }
			} else {
#if defined(ENABLE_PAGE)
				int merge = 0;
				int i = skb_shinfo(skb)->nr_frags;
				struct page *page = TCP_PAGE(sk);
				int off = TCP_OFF(sk);

				if (skb_can_coalesce(skb, i, page, off) &&
				    off != PAGE_SIZE) {
					/* We can extend the last page
					 * fragment. */
					merge = 1;
				} else if (i == MAX_SKB_FRAGS || !sg) {
					/* Need to add new fragment and cannot
					 * do this because interface is non-SG,
					 * or because all the page slots are
					 * busy. */
					serval_tcp_mark_push(tp, skb);
					goto new_segment;
				} else if (page) {
					if (off == PAGE_SIZE) {
						put_page(page);
						TCP_PAGE(sk) = page = NULL;
						off = 0;
					}
				} else
					off = 0;

				if (copy > PAGE_SIZE - off)
					copy = PAGE_SIZE - off;

				if (!sk_wmem_schedule(sk, copy))
					goto wait_for_memory;

				if (!page) {
					/* Allocate new cache page. */
					if (!(page = sk_stream_alloc_page(sk)))
						goto wait_for_memory;
				}

				/* Time to copy data. We are close to
				 * the end! */
				err = skb_copy_to_page(sk, from, skb, page,
						       off, copy);
				if (err) {
					/* If this page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TCP_PAGE(sk)) {
						TCP_PAGE(sk) = page;
						TCP_OFF(sk) = 0;
					}
					goto do_error;
				}

				/* Update the skb. */
				if (merge) {
					skb_shinfo(skb)->frags[i - 1].size +=
									copy;
				} else {
					skb_fill_page_desc(skb, i, page, off, copy);
					if (TCP_PAGE(sk)) {
						get_page(page);
					} else if (off + copy < PAGE_SIZE) {
						get_page(page);
						TCP_PAGE(sk) = page;
					}
				}

				TCP_OFF(sk) = off + copy;
#endif /* ENABLE_PAGE */
			}

			if (!copied)
				TCP_SKB_CB(skb)->tcp_flags &= ~TCPH_PSH;

			tp->write_seq += copy;
			TCP_SKB_CB(skb)->end_seq += copy;
			skb_shinfo(skb)->gso_segs = 0;

			from += copy;
			copied += copy;
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			if (skb->len < max || (flags & MSG_OOB))
				continue;

			if (forced_push(tp)) {
				serval_tcp_mark_push(tp, skb);
				__serval_tcp_push_pending_frames(sk, 
                                                                 mss_now, 
                                                                 TCP_NAGLE_PUSH);
			} else if (skb == serval_tcp_send_head(sk))
				serval_tcp_push_one(sk, mss_now);
			continue;

wait_for_sndbuf:
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)
				serval_tcp_push(sk, flags & ~MSG_MORE, 
                                                mss_now, TCP_NAGLE_PUSH);
                        
                        if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
				goto do_error;

			mss_now = serval_tcp_send_mss(sk, &size_goal, flags);
		}
	}

out:
	if (copied)
		serval_tcp_push(sk, flags, mss_now, tp->nonagle);

	release_sock(sk);

	return copied;

do_fault:
	if (!skb->len) {
		serval_tcp_unlink_write_queue(skb, sk);
		/* It is the one place in all of TCP, except connection
		 * reset, where we can be unlinking the send_head.
		 */
		serval_tcp_check_send_head(sk, skb);
		sk_wmem_free_skb(sk, skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	err = sk_stream_error(sk, flags, err);

	release_sock(sk);
	return err;
}
#endif

/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int serval_tcp_recv_urg(struct sock *sk, struct msghdr *msg, 
                               int len, int flags)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data ||
	    tp->urg_data == TCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (tp->urg_data & TCP_URG_VALID) {
		int err = 0;
		unsigned char c = tp->urg_data;

		if (!(flags & MSG_PEEK))
			tp->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_toiovec(msg->msg_iov, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void serval_tcp_cleanup_rbuf(struct sock *sk, int copied)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int time_to_ack = 0;

#ifdef TCP_DEBUG
        /*
	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
	WARN(skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq),
	     KERN_INFO "cleanup rbuf bug: copied %X seq %X rcvnxt %X\n",
	     tp->copied_seq, TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt);
        */
#endif
	if (serval_tsk_ack_scheduled(sk)) {
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (tp->tp_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > tp->tp_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((tp->tp_ack.pending & STSK_ACK_PUSHED2) ||
		      ((tp->tp_ack.pending & STSK_ACK_PUSHED) &&
		       !tp->tp_ack.pingpong)) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}
	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = serval_tcp_receive_window(tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2*rcv_window_now <= tp->window_clamp) {
			__u32 new_window = __serval_tcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}

	if (time_to_ack)
		serval_tcp_send_ack(sk);
}

static void serval_tcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);

	//NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPPREQUEUED);

	/* RX process wants to run with disabled BHs, though it is not
	 * necessary */
	local_bh_disable();
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
		sk_backlog_rcv(sk, skb);
        
	local_bh_enable();

	/* Clear memory counter. */
	tp->ucopy.memory = 0;
}

static int serval_tcp_recvmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg,
                              size_t len, int nonblock, int flags, 
                              int *addr_len)
{
 	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct task_struct *user_recv = NULL;
	int copied_early = 0;
	struct sk_buff *skb;
	u32 urg_hole = 0;

	lock_sock(sk);

	err = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN)
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);

	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)
		goto recv_urg;

	seq = &tp->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

#ifdef CONFIG_NET_DMA
	tp->ucopy.dma_chan = NULL;
	preempt_disable();
	skb = skb_peek_tail(&sk->sk_receive_queue);
	{
		int available = 0;

		if (skb)
			available = TCP_SKB_CB(skb)->seq + skb->len - (*seq);
		if ((available < target) &&
		    (len > sysctl_tcp_dma_copybreak) && !(flags & MSG_PEEK) &&
		    !sysctl_serval_tcp_low_latency &&
		    dma_find_channel(DMA_MEMCPY)) {
			preempt_enable_no_resched();
			tp->ucopy.pinned_list =
					dma_pin_iovec_pages(msg->msg_iov, len);
		} else {
			preempt_enable_no_resched();
		}
	}
#endif

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read
                 * anything or have SIGURG pending. */
		if (tp->urg_data && tp->urg_seq == *seq) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : 
                                        -EAGAIN;
                                LOG_SSK(sk, "Signal is pending, copied=%d\n",
                                        copied);
				break;
			}
		}

                if (tp->fin_found)
                        goto wait_for_event;

		/* Next get a buffer. */

		skb_queue_walk(&sk->sk_receive_queue, skb) {
			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */

			if (before(*seq, TCP_SKB_CB(skb)->seq))
				break;
                        
			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (tcp_hdr(skb)->syn)
				offset--;
                        
			if (offset < skb->len)
				goto found_ok_skb;

                        if (tcp_hdr(skb)->fin)
                                goto found_fin_ok;

			         /*
			WARN(!(flags & MSG_PEEK), KERN_INFO "recvmsg bug 2: "
					"copied %X seq %X rcvnxt %X fl %X\n",
					*seq, TCP_SKB_CB(skb)->seq,
					tp->rcv_nxt, flags);
                                 */
		}
        wait_for_event:
		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !sk->sk_backlog.tail)
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
                                LOG_SSK(sk, "socket has error %d\n", 
                                        sock_error(sk));
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
                                LOG_SSK(sk, "sock_intr_errno=%d\n",
                                        copied);
				break;
			}
		}

                LOG_DBG("tp->copied_seq=%u tp->rcv_nxt=%u\n",
                        tp->copied_seq, tp->rcv_nxt);

		serval_tcp_cleanup_rbuf(sk, copied);

		if (!sysctl_serval_tcp_low_latency && 
                    tp->ucopy.task == user_recv) {
			/* Install new reader */
			if (!user_recv && !(flags & (MSG_TRUNC | MSG_PEEK))) {
				user_recv = current;
				tp->ucopy.task = user_recv;
				tp->ucopy.iov = msg->msg_iov;
			}

			tp->ucopy.len = len;

			WARN_ON(tp->copied_seq != tp->rcv_nxt &&
				!(flags & (MSG_PEEK | MSG_TRUNC)));

			/* Ugly... If prequeue is not empty, we have to
			 * process it before releasing socket, otherwise
			 * order will be broken at second iteration.
			 * More elegant solution is required!!!
			 *
			 * Look: we have the following (pseudo)queues:
			 *
			 * 1. packets in flight
			 * 2. backlog
			 * 3. prequeue
			 * 4. receive_queue
			 *
			 * Each queue can be processed only if the next ones
			 * are empty. At this point we have empty receive_queue.
			 * But prequeue _can_ be not empty after 2nd iteration,
			 * when we jumped to start of loop because backlog
			 * processing added something to receive_queue.
			 * We cannot release_sock(), because backlog contains
			 * packets arrived _after_ prequeued ones.
			 *
			 * Shortly, algorithm is clear --- to process all
			 * the queues in order. We could make it more directly,
			 * requeueing packets from backlog to prequeue, if
			 * is not empty. It is more elegant, but eats cycles,
			 * unfortunately.
			 */
			if (!skb_queue_empty(&tp->ucopy.prequeue))
				goto do_prequeue;

			/* __ Set realtime policy in scheduler __ */
		}

#ifdef CONFIG_NET_DMA
		if (tp->ucopy.dma_chan)
			dma_async_issue_pending(tp->ucopy.dma_chan);
#endif
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else {
			sk_wait_data(sk, &timeo);
                        LOG_SSK(sk, "woke up after waiting for data\n");
                }
#ifdef CONFIG_NET_DMA
		serval_tcp_service_net_dma(sk, false);  /* Don't block */
		tp->ucopy.wakeup = 0;
#endif

		if (user_recv) {
			int chunk;

			/* __ Restore normal policy in scheduler __ */

			if ((chunk = len - tp->ucopy.len) != 0) {
                                /*
				NET_ADD_STATS_USER(sock_net(sk), 
                                                   LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG, chunk);
                                */
				len -= chunk;
				copied += chunk;
			}

			if (tp->rcv_nxt == tp->copied_seq &&
			    !skb_queue_empty(&tp->ucopy.prequeue)) {
do_prequeue:
				serval_tcp_prequeue_process(sk);

				if ((chunk = len - tp->ucopy.len) != 0) {
                                        /*
					NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
                                        */
					len -= chunk;
					copied += chunk;
				}
			}
		}
		if ((flags & MSG_PEEK) &&
		    (peek_seq - copied - urg_hole != tp->copied_seq)) {
			if (net_ratelimit())
				/* 
                                   printk(KERN_DEBUG "TCP(%s:%d): Application bug, race in MSG_PEEK.\n",
				       current->comm, task_pid_nr(current));
                                */
			peek_seq = tp->copied_seq;
		}
		continue;

	found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;

		/* Do we have urgent data here? */
		if (tp->urg_data) {
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						urg_hole++;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}

		if (!(flags & MSG_TRUNC)) {
#ifdef CONFIG_NET_DMA
			if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
				tp->ucopy.dma_chan = 
                                        dma_find_channel(DMA_MEMCPY);

			if (tp->ucopy.dma_chan) {
				tp->ucopy.dma_cookie = 
                                        dma_skb_copy_datagram_iovec(
                                                tp->ucopy.dma_chan, skb, 
                                                offset,
                                                msg->msg_iov, used,
                                                tp->ucopy.pinned_list);
                                
				if (tp->ucopy.dma_cookie < 0) {

					printk(KERN_ALERT "dma_cookie < 0\n");

					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}

				dma_async_issue_pending(tp->ucopy.dma_chan);

				if ((offset + used) == skb->len)
					copied_early = 1;

			} else
#endif
			{
				err = skb_copy_datagram_iovec(skb, offset,
                                                              msg->msg_iov, 
                                                              used);
				if (err) {
					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}
			}
		}

		*seq += used;
		copied += used;
		len -= used;

		serval_tcp_rcv_space_adjust(sk);

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
			tp->urg_data = 0;
			serval_tcp_fast_path_check(sk);
		}
		if (used + offset < skb->len)
			continue;

		if (tcp_hdr(skb)->fin)
                        goto found_fin_ok;

   		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		continue;
        found_fin_ok:
                ++*seq;

                LOG_SSK(sk, "Received FIN (MSG_PEEK=%d)\n",
                        (flags & MSG_PEEK) > 0);
                /*
                  Serval-specific FIN processing:

                  Since Serval does not actually close a connection
                  upon receiving a TCP FIN (closing is handled in the
                  SAL), this FIN is simply treated as a end of stream
                  marker. Instead of returning to the user, we
                  continue to hang/wait in this function until the SAL
                  closes (SOCK_DONE), and only then return 0. 
                */

                if (!(flags & MSG_PEEK)) {
                        tp->fin_found = 1;
                        sk_eat_skb(sk, skb, copied_early);
                        copied_early = 0;
                        continue;
                }
                break;
	} while (len > 0);

	if (user_recv) {
		if (!skb_queue_empty(&tp->ucopy.prequeue)) {
			int chunk;

			tp->ucopy.len = copied > 0 ? len : 0;

			serval_tcp_prequeue_process(sk);

			if (copied > 0 && (chunk = len - tp->ucopy.len) != 0) {
				/*
                                  NET_ADD_STATS_USER(sock_net(sk), 
                                  LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
                                */
				len -= chunk;
				copied += chunk;
			}
		}

		tp->ucopy.task = NULL;
		tp->ucopy.len = 0;
	}

#ifdef CONFIG_NET_DMA
	serval_tcp_service_net_dma(sk, true);  /* Wait for queue to drain */
	tp->ucopy.dma_chan = NULL;

	if (tp->ucopy.pinned_list) {
		dma_unpin_iovec_pages(tp->ucopy.pinned_list);
		tp->ucopy.pinned_list = NULL;
	}
#endif

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
	serval_tcp_cleanup_rbuf(sk, copied);

	release_sock(sk);
        LOG_SSK(sk, "copied=%d\n", copied);
	return copied;

out:
	release_sock(sk);
        LOG_SSK(sk, "err=%d\n", err);
	return err;

recv_urg:
	err = serval_tcp_recv_urg(sk, msg, len, flags);
	goto out;
}

extern int checksum_mode;

void __serval_tcp_v4_send_check(struct sk_buff *skb,
                                __be32 saddr, __be32 daddr)
{
	struct tcphdr *th = tcp_hdr(skb);
        unsigned long len = skb_tail_pointer(skb) - skb_transport_header(skb);

        if (!checksum_mode) {
                /* Force checksum calculation by protocol */
                skb->ip_summed = CHECKSUM_NONE;
                th->check = serval_tcp_v4_check(len, saddr, daddr,
                                                csum_partial(th,
                                                             len,
                                                             0));
        } else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		th->check = ~serval_tcp_v4_check(len, saddr, daddr, 0);
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		th->check = serval_tcp_v4_check(len, saddr, daddr,
                                                csum_partial(th,
                                                             th->doff << 2,
                                                             skb->csum));
      	}
}

/* This routine computes an IPv4 TCP checksum. */
void serval_tcp_v4_send_check(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);

	__serval_tcp_v4_send_check(skb, inet->inet_saddr, inet->inet_daddr);
}

#if defined(OS_LINUX_KERNEL)

/*
 *	Socket option code for TCP.
 */
static int serval_do_tcp_setsockopt(struct sock *sk, int level,
                                    int optname, char __user *optval, 
                                    unsigned int optlen)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        //struct serval_sock *ssk = serval_sk(sk);
	int val;
	int err = 0;

        LOG_SSK(sk, "level=SOL_TCP optname=%d\n", optname);

	/* These are data/string values, all the others are ints */
	switch (optname) {
                /*
	case TCP_CONGESTION: {
		char name[TCP_CA_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;

		val = strncpy_from_user(name, optval,
					min_t(long, TCP_CA_NAME_MAX-1, optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;

		lock_sock(sk);
		err = serval_tcp_set_congestion_control(sk, name);
		release_sock(sk);
		return err;
	}
                */
#if 0
	case TCP_COOKIE_TRANSACTIONS: {
		struct tcp_cookie_transactions ctd;
		struct tcp_cookie_values *cvp = NULL;

		if (sizeof(ctd) > optlen)
			return -EINVAL;
		if (copy_from_user(&ctd, optval, sizeof(ctd)))
			return -EFAULT;

		if (ctd.tcpct_used > sizeof(ctd.tcpct_value) ||
		    ctd.tcpct_s_data_desired > TCP_MSS_DESIRED)
			return -EINVAL;

		if (ctd.tcpct_cookie_desired == 0) {
			/* default to global value */
		} else if ((0x1 & ctd.tcpct_cookie_desired) ||
			   ctd.tcpct_cookie_desired > TCP_COOKIE_MAX ||
			   ctd.tcpct_cookie_desired < TCP_COOKIE_MIN) {
			return -EINVAL;
		}

		if (TCP_COOKIE_OUT_NEVER & ctd.tcpct_flags) {
			/* Supercedes all other values */
			lock_sock(sk);
			if (tp->cookie_values != NULL) {
				kref_put(&tp->cookie_values->kref,
					 tcp_cookie_values_release);
				tp->cookie_values = NULL;
			}
			tp->rx_opt.cookie_in_always = 0; /* false */
			tp->rx_opt.cookie_out_never = 1; /* true */
			release_sock(sk);
			return err;
		}

		/* Allocate ancillary memory before locking.
		 */
		if (ctd.tcpct_used > 0 ||
		    (tp->cookie_values == NULL &&
		     (sysctl_tcp_cookie_size > 0 ||
		      ctd.tcpct_cookie_desired > 0 ||
		      ctd.tcpct_s_data_desired > 0))) {
			cvp = kzalloc(sizeof(*cvp) + ctd.tcpct_used,
				      GFP_KERNEL);
			if (cvp == NULL)
				return -ENOMEM;

			kref_init(&cvp->kref);
		}
		lock_sock(sk);
		tp->rx_opt.cookie_in_always =
			(TCP_COOKIE_IN_ALWAYS & ctd.tcpct_flags);
		tp->rx_opt.cookie_out_never = 0; /* false */

		if (tp->cookie_values != NULL) {
			if (cvp != NULL) {
				/* Changed values are recorded by a changed
				 * pointer, ensuring the cookie will differ,
				 * without separately hashing each value later.
				 */
				kref_put(&tp->cookie_values->kref,
					 tcp_cookie_values_release);
			} else {
				cvp = tp->cookie_values;
			}
		}

		if (cvp != NULL) {
			cvp->cookie_desired = ctd.tcpct_cookie_desired;

			if (ctd.tcpct_used > 0) {
				memcpy(cvp->s_data_payload, ctd.tcpct_value,
				       ctd.tcpct_used);
				cvp->s_data_desired = ctd.tcpct_used;
				cvp->s_data_constant = 1; /* true */
			} else {
				/* No constant payload data. */
				cvp->s_data_desired = ctd.tcpct_s_data_desired;
				cvp->s_data_constant = 0; /* false */
			}

			tp->cookie_values = cvp;
		}
		release_sock(sk);
		return err;
	}
#endif /* 0 */
	default:
		/* fallthru */
		break;
	}

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TCP_MAXSEG:
		/* Values greater than interface MTU won't take effect. However
		 * at the point when this call is done we typically don't yet
		 * know which interface is going to be used */
		if (val < SERVAL_TCP_MIN_MSS || val > MAX_TCP_WINDOW) {
			err = -EINVAL;
			break;
		}
		tp->rx_opt.user_mss = val;
		break;

	case TCP_NODELAY:
                LOG_SSK(sk, "Setting TCP_NODELAY\n");
		if (val) {
			/* TCP_NODELAY is weaker than TCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TCP_NODELAY is set we make
			 * an explicit push, which overrides even TCP_CORK
			 * for currently queued segments.
			 */
			tp->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;
			serval_tcp_push_pending_frames(sk);
		} else {
			tp->nonagle &= ~TCP_NAGLE_OFF;
		}
		break;

	case TCP_THIN_LINEAR_TIMEOUTS:
		if (val < 0 || val > 1)
			err = -EINVAL;
		else
			tp->thin_lto = val;
		break;

	case TCP_THIN_DUPACK:
		if (val < 0 || val > 1)
			err = -EINVAL;
		else
			tp->thin_dupack = val;
		break;

	case TCP_CORK:
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TCP_CORK can be set together with TCP_NODELAY and it is
		 * stronger than TCP_NODELAY.
		 */
		if (val) {
			tp->nonagle |= TCP_NAGLE_CORK;
		} else {
			tp->nonagle &= ~TCP_NAGLE_CORK;
			if (tp->nonagle&TCP_NAGLE_OFF)
				tp->nonagle |= TCP_NAGLE_PUSH;
			serval_tcp_push_pending_frames(sk);
		}
		break;

	case TCP_KEEPIDLE:
		if (val < 1 || val > MAX_TCP_KEEPIDLE)
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ;
			if (sock_flag(sk, SOCK_KEEPOPEN) &&
			    !((1 << sk->sk_state) &
			      (TCPF_CLOSE | TCPF_LISTEN))) {
				u32 elapsed = serval_keepalive_time_elapsed(tp);
				if (tp->keepalive_time > elapsed)
					elapsed = tp->keepalive_time - elapsed;
				else
					elapsed = 0;
				serval_tsk_reset_keepalive_timer(sk, elapsed);
			}
		}
		break;
	case TCP_KEEPINTVL:
		if (val < 1 || val > MAX_TCP_KEEPINTVL)
			err = -EINVAL;
		else
			tp->keepalive_intvl = val * HZ;
		break;
	case TCP_KEEPCNT:
		if (val < 1 || val > MAX_TCP_KEEPCNT)
			err = -EINVAL;
		else
			tp->keepalive_probes = val;
		break;
	case TCP_LINGER2:
		if (val < 0)
			tp->linger2 = -1;
		else if (val > sysctl_serval_tcp_fin_timeout / HZ)
			tp->linger2 = 0;
		else
			tp->linger2 = val * HZ;
		break;
#if 0
	case TCP_DEFER_ACCEPT:
		/* Translate value in seconds to number of retransmits */
		icsk->icsk_accept_queue.rskq_defer_accept =
			secs_to_retrans(val, TCP_TIMEOUT_INIT / HZ,
					TCP_RTO_MAX / HZ);
		break;
#endif
	case TCP_WINDOW_CLAMP:
		if (!val) {
			if (sk->sk_state != TCP_CLOSE) {
				err = -EINVAL;
				break;
			}
			tp->window_clamp = 0;
		} else
			tp->window_clamp = val < SOCK_MIN_RCVBUF / 2 ?
						SOCK_MIN_RCVBUF / 2 : val;
		break;

	case TCP_QUICKACK:
		if (!val) {
			tp->tp_ack.pingpong = 1;
		} else {
			tp->tp_ack.pingpong = 0;
			if ((1 << sk->sk_state) &
			    (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
			    serval_tsk_ack_scheduled(sk)) {
				tp->tp_ack.pending |= STSK_ACK_PUSHED;
				serval_tcp_cleanup_rbuf(sk, 1);
				if (!(val & 1))
					tp->tp_ack.pingpong = 1;
			}
		}
		break;

#if 0
#ifdef CONFIG_TCP_MD5SIG
	case TCP_MD5SIG:
		/* Read the IP->Key mappings from userspace */
		err = tp->af_specific->md5_parse(sk, optval, optlen);
		break;
#endif
	case TCP_USER_TIMEOUT:
		/* Cap the max timeout in ms TCP will retry/retrans
		 * before giving up and aborting (ETIMEDOUT) a connection.
		 */
		//icsk->icsk_user_timeout = msecs_to_jiffies(val);
		break;
#endif
	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

static int serval_do_tcp_getsockopt(struct sock *sk, int level,
                                    int optname, char __user *optval, 
                                    int __user *optlen)
{
	struct serval_tcp_sock *tp = serval_tcp_sk(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TCP_MAXSEG:
		val = tp->mss_cache;
		if (!val && ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
			val = tp->rx_opt.user_mss;
		break;
	case TCP_NODELAY:
		val = !!(tp->nonagle&TCP_NAGLE_OFF);
		break;
	case TCP_CORK:
		val = !!(tp->nonagle&TCP_NAGLE_CORK);
		break;
	case TCP_KEEPIDLE:
		val = serval_keepalive_time_when(tp) / HZ;
		break;
	case TCP_KEEPINTVL:
		val = serval_keepalive_intvl_when(tp) / HZ;
		break;
	case TCP_KEEPCNT:
		val = serval_keepalive_probes(tp);
		break;
	case TCP_LINGER2:
		val = tp->linger2;
		if (val >= 0)
			val = (val ? : sysctl_serval_tcp_fin_timeout) / HZ;
		break;
                /*
	case TCP_DEFER_ACCEPT:
		val = retrans_to_secs(icsk->icsk_accept_queue.rskq_defer_accept,
				      TCP_TIMEOUT_INIT / HZ, TCP_RTO_MAX / HZ);
		break;
                */
	case TCP_WINDOW_CLAMP:
		val = tp->window_clamp;
		break;
	case TCP_INFO: {
		struct tcp_info info;

		if (get_user(len, optlen))
			return -EFAULT;

		tcp_get_info(sk, &info);

		len = min_t(unsigned int, len, sizeof(info));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &info, len))
			return -EFAULT;
		return 0;
	}
	case TCP_QUICKACK:
		val = !tp->tp_ack.pingpong;
		break;
                /*
	case TCP_CONGESTION:
		if (get_user(len, optlen))
			return -EFAULT;
		len = min_t(unsigned int, len, TCP_CA_NAME_MAX);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, icsk->icsk_ca_ops->name, len))
			return -EFAULT;
		return 0;
                */
                /*
	case TCP_COOKIE_TRANSACTIONS: {
		struct tcp_cookie_transactions ctd;
		struct tcp_cookie_values *cvp = tp->cookie_values;

		if (get_user(len, optlen))
			return -EFAULT;
		if (len < sizeof(ctd))
			return -EINVAL;

		memset(&ctd, 0, sizeof(ctd));
		ctd.tcpct_flags = (tp->rx_opt.cookie_in_always ?
				   TCP_COOKIE_IN_ALWAYS : 0)
				| (tp->rx_opt.cookie_out_never ?
				   TCP_COOKIE_OUT_NEVER : 0);

		if (cvp != NULL) {
			ctd.tcpct_flags |= (cvp->s_data_in ?
					    TCP_S_DATA_IN : 0)
					 | (cvp->s_data_out ?
					    TCP_S_DATA_OUT : 0);

			ctd.tcpct_cookie_desired = cvp->cookie_desired;
			ctd.tcpct_s_data_desired = cvp->s_data_desired;

			memcpy(&ctd.tcpct_value[0], &cvp->cookie_pair[0],
			       cvp->cookie_pair_size);
			ctd.tcpct_used = cvp->cookie_pair_size;
		}

		if (put_user(sizeof(ctd), optlen))
			return -EFAULT;
		if (copy_to_user(optval, &ctd, sizeof(ctd)))
			return -EFAULT;
		return 0;
	}
                */
                /*
	case TCP_THIN_LINEAR_TIMEOUTS:
		val = tp->thin_lto;
		break;
	case TCP_THIN_DUPACK:
		val = tp->thin_dupack;
		break;

	case TCP_USER_TIMEOUT:
		val = jiffies_to_msecs(icsk->icsk_user_timeout);
		break;
                */
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

#endif /* OS_LINUX_KERNEL */

int serval_tcp_setsockopt(struct sock *sk, int level, int optname, 
                          char __user *optval, unsigned int optlen)
{
#if defined(OS_LINUX_KERNEL)
        struct serval_sock *ssk = serval_sk(sk);

	if (level != SOL_TCP)
		return ssk->af_ops->setsockopt(sk, level, optname,
                                               optval, optlen);

	return serval_do_tcp_setsockopt(sk, level, optname, optval, optlen);
#else
        return -EOPNOTSUPP;
#endif
}

int serval_tcp_getsockopt(struct sock *sk, int level, 
                          int optname, char __user *optval,
                          int __user *optlen)
{
#if defined(OS_LINUX_KERNEL)
        struct serval_sock *ssk = serval_sk(sk);

	if (level != SOL_TCP)
		return  ssk->af_ops->getsockopt(sk, level, optname,
						     optval, optlen);

	return serval_do_tcp_getsockopt(sk, level, optname, optval, optlen);
#else
        return -EOPNOTSUPP;
#endif
}

#if defined(OS_LINUX_KERNEL)
int serval_tcp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        int answ;
        
        switch (cmd) {
        case SIOCINQ:
                if (sk->sk_state == TCP_LISTEN)
                        return -EINVAL;
                
                lock_sock(sk);
                if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
                        answ = 0;
                else if (sock_flag(sk, SOCK_URGINLINE) ||
                         !tp->urg_data ||
                         before(tp->urg_seq, tp->copied_seq) ||
                         !before(tp->urg_seq, tp->rcv_nxt)) {
                        struct sk_buff *skb;
                        
                        answ = tp->rcv_nxt - tp->copied_seq;
                        
                        /* Subtract 1, if FIN is in queue. */
                        skb = skb_peek_tail(&sk->sk_receive_queue);
                        if (answ && skb)
                                answ -= tcp_hdr(skb)->fin;
                } else
                        answ = tp->urg_seq - tp->copied_seq;
                release_sock(sk);
                break;
        case SIOCATMARK:
                answ = tp->urg_data && tp->urg_seq == tp->copied_seq;
                break;
        case SIOCOUTQ:
                if (sk->sk_state == TCP_LISTEN)
                        return -EINVAL;
                if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
                        answ = 0;
                else
                        answ = tp->write_seq - tp->snd_una;
                break;
/*
        case SIOCOUTQNSD:
                if (sk->sk_state == TCP_LISTEN)
                        return -EINVAL;
                
                if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
                        answ = 0;
                else
                        answ = tp->write_seq - tp->snd_nxt;
                break;
*/
        default:
                return -ENOIOCTLCMD;
        }
        
        return put_user(answ, (int __user *)arg);
}
#endif /* OS_LINUX_KERNEL */

static int serval_tcp_freeze_flow(struct sock *sk)
{
        LOG_SSK(sk, "Freezing TCP flow %s\n", 
                flow_id_to_str(&serval_sk(sk)->local_flowid));
        serval_tsk_clear_xmit_timer(sk, STSK_TIME_RETRANS);
        
        return 0;
}

static int serval_tcp_migration_completed(struct sock *sk)
{
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
        unsigned long t = jiffies;

        LOG_SSK(sk, "Unfreezing TCP flow %s\n", 
                flow_id_to_str(&serval_sk(sk)->local_flowid));
        tp->snd_mig_last = tp->snd_nxt;
        LOG_SSK(sk, "Last sequence number on old link: %lu\n", 
                tp->snd_mig_last, tp->snd_nxt);

        /* Restart retransmission timer */
        if (tp->packets_out) {
                t = 1; //tp->rto;

                LOG_SSK(sk, "Resetting rexmit timer to %lu\n", t);
                
                serval_tsk_reset_xmit_timer(sk, STSK_TIME_RETRANS, t,
                                            SERVAL_TCP_RTO_MAX);
        }

        if (tp->snd_wnd == 0) {
                LOG_SSK(sk, "Zero snd_wnd, sending probe\n");
                serval_tcp_send_probe0(sk);
        } else {
                LOG_SSK(sk, "Non-zero snd_wnd, pushing frames\n");
                serval_tcp_push_pending_frames(sk);
        }

        return 0;
}

static struct serval_sock_af_ops serval_tcp_af_ops = {
        .queue_xmit = serval_ipv4_xmit,
        .receive = serval_tcp_rcv,
        .send_check = serval_tcp_v4_send_check,
        .rebuild_header = serval_sock_rebuild_header,
#if defined(OS_LINUX_KERNEL)
        .setsockopt = ip_setsockopt,
        .getsockopt = ip_getsockopt,
#endif
        .conn_build_syn = serval_tcp_connection_build_syn,
        .conn_build_synack = serval_tcp_connection_build_synack,
        .conn_build_ack = serval_tcp_connection_build_ack,
        .conn_request = serval_tcp_connection_request,
        .conn_close = serval_tcp_connection_close,
        .net_header_len = SAL_NET_HEADER_LEN,
        .request_state_process = serval_tcp_syn_sent_state_process,
        .respond_state_process = serval_tcp_syn_recv_state_process,
        .conn_child_sock = serval_tcp_syn_recv_sock,
        .freeze_flow = serval_tcp_freeze_flow, 
        .migration_completed = serval_tcp_migration_completed,
        .done = serval_tcp_done,
};

static struct serval_sock_af_ops serval_tcp_encap_af_ops = {
        .encap_queue_xmit = serval_ipv4_xmit,
        .queue_xmit = serval_udp_encap_xmit,
        .receive = serval_tcp_rcv,
        .send_check = serval_tcp_v4_send_check,
        .rebuild_header = serval_sock_rebuild_header,
#if defined(OS_LINUX_KERNEL)
        .setsockopt = ip_setsockopt,
        .getsockopt = ip_getsockopt,
#endif
        .conn_build_syn = serval_tcp_connection_build_syn,
        .conn_build_synack = serval_tcp_connection_build_synack,
        .conn_build_ack = serval_tcp_connection_build_ack,
        .conn_request = serval_tcp_connection_request,
        .conn_close = serval_tcp_connection_close,
        .net_header_len = SAL_NET_HEADER_LEN + 8 /* sizeof(struct udphdr) */,
        .request_state_process = serval_tcp_syn_sent_state_process,
        .respond_state_process = serval_tcp_syn_recv_state_process,
        .conn_child_sock = serval_tcp_syn_recv_sock,
        .migration_completed = serval_tcp_migration_completed,
        .freeze_flow = serval_tcp_freeze_flow,
        .done = serval_tcp_done,
};

/*
  Adapted from tcp_minisocks.c 
*/
static struct sock *serval_tcp_create_openreq_child(struct sock *sk, 
                                                    struct request_sock *req,
                                                    struct sock *newsk,
                                                    struct sk_buff *skb)
{
        const struct inet_request_sock *ireq = inet_rsk(req);
        struct serval_tcp_request_sock *treq = serval_tcp_rsk(req);
        struct serval_sock *newssk = serval_sk(newsk);
        struct serval_tcp_sock *newtp = serval_tcp_sk(newsk);
        struct serval_tcp_sock *oldtp = serval_tcp_sk(sk);

        if (serval_rsk(req)->udp_encap_dport)
                newssk->af_ops = &serval_tcp_encap_af_ops;
        else
                newssk->af_ops = &serval_tcp_af_ops;

        /* Now setup serval_tcp_sock */
        newtp->pred_flags = 0;
        
        newtp->rcv_wup = newtp->copied_seq =
		newtp->rcv_nxt = treq->rcv_isn + 1;
        
        newtp->snd_sml = newtp->snd_una =
		newtp->snd_nxt = newtp->snd_up =
                treq->snt_isn + 1 + serval_tcp_s_data_size(oldtp);
        
        serval_tcp_prequeue_init(newtp);
        
        serval_tcp_init_wl(newtp, treq->rcv_isn);
        
        newtp->srtt = 0;
        newtp->mdev = SERVAL_TCP_TIMEOUT_INIT;
        newtp->rto = SERVAL_TCP_TIMEOUT_INIT;
        
        newtp->packets_out = 0;
        newtp->retrans_out = 0;
        newtp->sacked_out = 0;
        newtp->fackets_out = 0;
        newtp->snd_mig_last = 0;
        newtp->snd_ssthresh = SERVAL_TCP_INFINITE_SSTHRESH;
        
        /* So many TCP implementations out there (incorrectly) count the
         * initial SYN frame in their delayed-ACK and congestion control
         * algorithms that we must have the following bandaid to talk
         * efficiently to them.  -DaveM
         */
        newtp->snd_cwnd = 2;
        newtp->snd_cwnd_cnt = 0;
        newtp->bytes_acked = 0;
        
        newtp->frto_counter = 0;
        newtp->frto_highmark = 0;
        
        newtp->ca_ops = &serval_tcp_init_congestion_ops;
        
        serval_tcp_set_ca_state(newsk, TCP_CA_Open);
        serval_tcp_init_xmit_timers(newsk);
        skb_queue_head_init(&newtp->out_of_order_queue);
        newtp->write_seq = newtp->pushed_seq =
                treq->snt_isn + 1 + serval_tcp_s_data_size(oldtp);
        
        newtp->rx_opt.saw_tstamp = 0;
        
        newtp->rx_opt.dsack = 0;
        newtp->rx_opt.num_sacks = 0;
        
        newtp->urg_data = 0;
        
        if (sock_flag(newsk, SOCK_KEEPOPEN))
                serval_tsk_reset_keepalive_timer(newsk,
                                                 serval_keepalive_time_when(newtp));
        
        newtp->rx_opt.tstamp_ok = ireq->tstamp_ok;

#if defined(ENABLE_TCP_SACK)
        if ((newtp->rx_opt.sack_ok = ireq->sack_ok) != 0) {
                if (sysctl_serval_tcp_fack)
                        serval_tcp_enable_fack(newtp);
        }
#endif
        newtp->window_clamp = req->window_clamp;
        newtp->rcv_ssthresh = req->rcv_wnd;
        newtp->rcv_wnd = req->rcv_wnd;
        newtp->rx_opt.wscale_ok = ireq->wscale_ok;
        if (newtp->rx_opt.wscale_ok) {
                LOG_SSK(sk, "TCP window scaling OK!\n");
                newtp->rx_opt.snd_wscale = ireq->snd_wscale;
                newtp->rx_opt.rcv_wscale = ireq->rcv_wscale;
        } else {
                LOG_SSK(sk, "No TCP window scaling!\n");
                newtp->rx_opt.snd_wscale = newtp->rx_opt.rcv_wscale = 0;
                newtp->window_clamp = min(newtp->window_clamp, 65535U);
        }
        newtp->snd_wnd = (ntohs(tcp_hdr(skb)->window) <<
                          newtp->rx_opt.snd_wscale);
        newtp->max_window = newtp->snd_wnd;
        
        if (newtp->rx_opt.tstamp_ok) {
                newtp->rx_opt.ts_recent = req->ts_recent;
                newtp->rx_opt.ts_recent_stamp = get_seconds();
                newtp->tcp_header_len = sizeof(struct tcphdr) + 
                        TCPOLEN_TSTAMP_ALIGNED;
        } else {
                newtp->rx_opt.ts_recent_stamp = 0;
                newtp->tcp_header_len = sizeof(struct tcphdr);
        }

        /*
#ifdef CONFIG_TCP_MD5SIG
        newtp->md5sig_info = NULL;
        if (newtp->af_specific->md5_lookup(sk, newsk))
                newtp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif
        */
        if (skb->len >= SERVAL_TCP_MSS_DEFAULT + newtp->tcp_header_len)
                newtp->tp_ack.last_seg_size = skb->len - newtp->tcp_header_len;
        newtp->rx_opt.mss_clamp = req->mss;

        return newsk;
}

/**
   Called when a child sock is created in response to a successful
   three-way handshake on the server side.
 */
int serval_tcp_syn_recv_sock(struct sock *sk, 
                             struct sk_buff *skb,
                             struct request_sock *req,
                             struct sock *newsk,
                             struct dst_entry *dst)
{
        struct inet_sock *newinet = inet_sk(newsk);
        struct serval_tcp_sock *newtp = serval_tcp_sk(newsk);

        LOG_SSK(sk, "New TCP sock based on pkt %s\n", 
                tcphdr_to_str(tcp_hdr(skb)));

#if defined(OS_LINUX_KERNEL)
        if (!dst) {
                struct inet_request_sock *ireq = inet_rsk(req);
                struct rtable *rt;
                
                rt = serval_ip_route_output(sock_net(sk),
                                            ireq->rmt_addr,
                                            ireq->loc_addr,
                                            0, sk->sk_bound_dev_if);
                
                if (!rt) {
                        LOG_ERR("SYN-ACK not routable\n");
                        goto exit;
                }
                
                dst = route_dst(rt);
        }
#endif

        newsk = serval_tcp_create_openreq_child(sk, req, newsk, skb);

        /* FIXME: can we support GSO with Serval? */
	newsk->sk_gso_type = 0 /* SKB_GSO_TCPV4 */;
	sk_setup_caps(newsk, dst);
	
	newinet->inet_id = newtp->write_seq ^ jiffies;

	serval_tcp_mtup_init(newsk);
#if defined(OS_LINUX_KERNEL)
        serval_tcp_sync_mss(newsk, dst_mtu(dst));
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
	newtp->advmss = dst_metric(dst, RTAX_ADVMSS);
#else
        newtp->advmss = dst_metric_advmss(dst);
#endif
#else
        serval_tcp_sync_mss(newsk, SERVAL_TCP_MSS_DEFAULT);
	newtp->advmss = SERVAL_TCP_MSS_DEFAULT;
#endif

	if (serval_tcp_sk(sk)->rx_opt.user_mss &&
	    serval_tcp_sk(sk)->rx_opt.user_mss < newtp->advmss)
		newtp->advmss = serval_tcp_sk(sk)->rx_opt.user_mss;

	serval_tcp_initialize_rcv_mss(newsk);

        newtp->bytes_queued = 0;

        LOG_PKT("snd_wnd=%u rcv_wnd=%u rcv_nxt=%u snd_nxt=%u\n", 
                newtp->snd_wnd, newtp->rcv_wnd, 
                newtp->rcv_nxt, newtp->snd_nxt);
        
        return 0;
#if defined(OS_LINUX_KERNEL)
exit:
        dst_release(dst);
        return -1;
#endif
}

static int serval_tcp_init_sock(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);

        LOG_SSK(sk, "Initializing new TCP sock\n");

        skb_queue_head_init(&tp->out_of_order_queue);
	serval_tcp_init_xmit_timers(sk);
	serval_tcp_prequeue_init(tp);

        tp->rto = SERVAL_TCP_TIMEOUT_INIT;
	tp->mdev = SERVAL_TCP_TIMEOUT_INIT;
        /* So many TCP implementations out there (incorrectly) count
	 * the initial SYN frame in their delayed-ACK and congestion
	 * control algorithms that we must have the following bandaid
	 * to talk efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = 2;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	tp->snd_ssthresh = SERVAL_TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_clamp = ~0;
        tp->snd_mig_last = 0;
	tp->mss_cache = SERVAL_TCP_MSS_DEFAULT;

	tp->reordering = sysctl_serval_tcp_reordering;

	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = 2;
	tp->ca_ops = &serval_tcp_init_congestion_ops;

	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

        if (net_serval.sysctl_udp_encap)
                ssk->af_ops = &serval_tcp_encap_af_ops;
        else
                ssk->af_ops = &serval_tcp_af_ops;

	sk->sk_sndbuf = sysctl_serval_tcp_wmem[1];
	sk->sk_rcvbuf = sysctl_serval_tcp_rmem[1];

        tp->bytes_queued = 0;
        
        LOG_SSK(sk, "sockinit: snd_ssthresh=%u snd_cwnd_clamp=%u snd_cwnd=%u\n",
                tp->snd_ssthresh, tp->snd_cwnd_clamp, tp->snd_cwnd);

#if defined(OS_LINUX_KERNEL)
	local_bh_disable();
	percpu_counter_inc(&tcp_sockets_allocated);
	local_bh_enable();
#endif
        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
static int serval_tcp_destroy_sock(struct sock *sk)
#else
static void serval_tcp_destroy_sock(struct sock *sk)
#endif
{
        struct serval_tcp_sock *tp = serval_tcp_sk(sk);
   
        LOG_SSK(sk, "destroying TCP sock\n");

	serval_tcp_clear_xmit_timers(sk);

	serval_tcp_cleanup_congestion_control(sk);

	/* Cleanup up the write buffer. */
	serval_tcp_write_queue_purge(sk);

	__skb_queue_purge(&tp->out_of_order_queue);

#ifdef CONFIG_NET_DMA
	/* Cleans up our sk_async_wait_queue */
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif
        
	/* Clean prequeue, it must be empty really */
	__skb_queue_purge(&tp->ucopy.prequeue);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,7,0)) && defined(OS_LINUX_KERNEL)
	if (sk->sk_sndmsg_page) {
		__free_page(sk->sk_sndmsg_page);
		sk->sk_sndmsg_page = NULL;
	}
#endif
        
	//percpu_counter_dec(&tcp_sockets_allocated);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
        return 0;
#endif
}

static void serval_tcp_request_sock_destructor(struct request_sock *req)
{
}

struct request_sock_ops serval_tcp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct serval_tcp_request_sock),
        .destructor     =       serval_tcp_request_sock_destructor,
};

struct proto serval_tcp_proto = {
	.name			= "SERVAL_TCP",
	.owner			= THIS_MODULE,
        .init                   = serval_tcp_init_sock,
        .destroy                = serval_tcp_destroy_sock,
	.close  		= serval_sal_close,   
        .connect                = serval_sal_connect,
	.disconnect		= serval_tcp_disconnect,
	.shutdown		= serval_tcp_shutdown,
        .sendmsg                = serval_tcp_sendmsg,
        .recvmsg                = serval_tcp_recvmsg,
        .setsockopt             = serval_tcp_setsockopt,
        .getsockopt             = serval_tcp_getsockopt,
#if defined(OS_LINUX_KERNEL) && defined(ENABLE_SPLICE)
        .sendpage               = serval_tcp_sendpage,
#endif
	.backlog_rcv		= serval_tcp_do_rcv,
        .hash                   = serval_sock_hash,
        .unhash                 = serval_sock_unhash,
	.enter_memory_pressure	= serval_tcp_enter_memory_pressure,
	.memory_pressure	= &serval_tcp_memory_pressure,
	.memory_allocated	= &serval_tcp_memory_allocated,
	.sysctl_mem		= sysctl_serval_tcp_mem,
	.sysctl_wmem		= sysctl_serval_tcp_wmem,
	.sysctl_rmem		= sysctl_serval_tcp_rmem,
#if defined(OS_LINUX_KERNEL)
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
        .ioctl                  = serval_tcp_ioctl,
#endif
	.max_header		= MAX_SERVAL_TCP_HEADER,
	.obj_size		= sizeof(struct serval_tcp_sock),
	.rsk_prot		= &serval_tcp_request_sock_ops,
};

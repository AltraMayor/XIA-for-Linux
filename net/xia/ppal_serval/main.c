#include <linux/module.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>
#include <net/xia_socket.h>
#include <net/xia_vxidty.h>
#include <net/xia_output.h> /* Needed for xip_trim_packet_if_needed(). */
#include <net/xia_serval.h>
#include "af_serval.h"
#include "serval_sal.h"
#include "serval_tcp.h"

/* XXX Move it to struct xip_serval_ctx. */
struct netns_serval net_serval = {
	.sysctl_sal_max_retransmits = SAL_RETRANSMITS_MAX,
};

int srvc_vxt __read_mostly = -1;
int flow_vxt __read_mostly = -1;

/*
 *	Local ServiceID
 */

static int local_dump_srvc(struct fib_xid *fxid, struct fib_xid_table *xtbl,
			   struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			   struct netlink_callback *cb)
{
	const struct serval_sock *ssk;
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	struct xia_xid dst;

	ssk = rtid_fxid_ssk(fxid);
	if (!ssk) {
		/* This can happen while @ssk->srvc_rtid is being released. */
		return 0;
	}

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			RTM_NEWROUTE, sizeof(*rtm), NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = XRTABLE_LOCAL_INDEX;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_LOCAL;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl_ppalty(xtbl);
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst) ||
		     nla_put_u8(skb, RTA_PROTOINFO, ssk->xia_sk.sk.sk_state)))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_srvc(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct serval_rt_id *rtid = fxid_rtid(fxid);

	xdst_free_anchor(&rtid->anchor);
	kfree(rtid);
}

/* XXX	Add support for local ServiceID migration.
 *	One could use method .newroute to trigger a migration.
 *	Code from Serval to do that:
 *	serval_sock_migrate_service(&struct service_id from, new_dev->ifindex);
 */

static const xia_ppal_all_rt_eops_t srvc_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = fib_no_newroute,
		.delroute = fib_no_delroute,
		.dump_fxid = local_dump_srvc,
		.free_fxid = local_free_srvc,
	},

	XIP_FIB_REDIRECT_MAIN,
};

/*
 *	Local FlowID
 */

static int local_dump_flow(struct fib_xid *fxid, struct fib_xid_table *xtbl,
			   struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			   struct netlink_callback *cb)
{
	const struct serval_sock *ssk;
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	struct xia_xid dst;

	if (fxid->fx_entry_type == SOCK_TYPE) {
		ssk = rtid_fxid_ssk(fxid);
		if (!ssk) {
			/* This can happen while @ssk->flow_rtid is being
			 * released.
			 */
			return 0;
		}
	} else {
		ssk = NULL;
	}

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			RTM_NEWROUTE, sizeof(*rtm), NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = XRTABLE_LOCAL_INDEX;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_LOCAL;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl_ppalty(xtbl);
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	switch (fxid->fx_entry_type) {
	case SOCK_TYPE: {
		/* Add the other side of a socket. */
		if (ssk->peer_srvc_set) {
			struct xia_addr src;
			/* XXX We only have an RCU read lock here,
			 * don't we need a lock over @ssk to avoid races over
			 * @ssk->peer_srvc_set, @ssk->peer_srvc_addr and
			 * @ssk->peer_srvc_num?
			 */
			copy_n_and_shade_xia_addr_from_addr(&src,
				&ssk->peer_srvc_addr, ssk->peer_srvc_num);
			if (unlikely(nla_put(skb, RTA_SRC, sizeof(src), &src)))
				goto nla_put_failure;
		}
		if (unlikely(nla_put_u8(skb, RTA_PROTOINFO,
					ssk->xia_sk.sk.sk_state)))
			goto nla_put_failure;
		break;
	}

	case REQUEST_SOCK_TYPE: {
		/* Add the other side of a socket. */
		const struct serval_request_sock *srsk = flow_fxid_srsk(fxid);
		struct xia_xid src;

		src.xid_type = XIDTYPE_SRVCID;
		memmove(src.xid_id, srsk->peer_srvcid.s_sid,
			sizeof(src.xid_id));
		if (unlikely(nla_put(skb, RTA_SRC, sizeof(src), &src) ||
			     nla_put_u8(skb, RTA_PROTOINFO, SAL_RESPOND)))
			goto nla_put_failure;
		break;
	}

	default:
		BUG();
	}

	/* XXX Check out serval_sock.c:serval_sock_stats_flow() to see
	 * what else could/should be added to this dump.
	 */

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_flow(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	switch (fxid->fx_entry_type) {
	case SOCK_TYPE: {
		struct serval_rt_id *rtid = fxid_rtid(fxid);

		xdst_free_anchor(&rtid->anchor);
		kfree(rtid);
		break;
	}

	case REQUEST_SOCK_TYPE: {
		struct serval_request_sock *srsk = flow_fxid_srsk(fxid);

		xdst_free_anchor(&srsk->flow_anchor);
		srsk_put(srsk);
		break;
	}

	default:
		BUG();
	}
}

/* XXX	Add support for local FlowID migration.
 *	One could use method .newroute to trigger a migration.
 *	Code from Serval to do that:
 *	serval_sock_migrate_flow(&struct flow_id from, new_dev->ifindex);
 *
 *	To migrate a whole interface:
 *	serval_sock_migrate_iface(0, dev->ifindex);
 *
 *	When an interface goes down, this is what can be done:
 *		** Freezing all flows through @dev. **
 *		serval_sock_freeze_flows(dev);
 *		service_del_dev_all(dev->name);
 *		if (net_serval.sysctl_auto_migrate)
 *			serval_sock_migrate_iface(dev->ifindex, 0);
 */

static const xia_ppal_all_rt_eops_t flow_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = fib_no_newroute,
		.delroute = fib_no_delroute,
		.dump_fxid = local_dump_flow,
		.free_fxid = local_free_flow,
	},

	XIP_FIB_REDIRECT_MAIN,
};

/*
 *	Network namespace
 */

static struct xip_serval_ctx *create_serval_ctx(void)
{
	struct xip_serval_ctx *serval_ctx =
		kmalloc(sizeof(*serval_ctx), GFP_KERNEL);
	if (!serval_ctx)
		return NULL;
	xip_init_ppal_ctx(&serval_ctx->srvc, XIDTYPE_SRVCID);
	xip_init_ppal_ctx(&serval_ctx->flow, XIDTYPE_FLOWID);
	return serval_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_serval_ctx(struct xip_serval_ctx *serval_ctx)
{
	xip_release_ppal_ctx(&serval_ctx->flow);
	xip_release_ppal_ctx(&serval_ctx->srvc);
	kfree(serval_ctx);
}

static int __net_init serval_net_init(struct net *net)
{
	struct xip_serval_ctx *serval_ctx;
	int rc;

	serval_ctx = create_serval_ctx();
	if (!serval_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = init_xid_table(&serval_ctx->srvc, net, &xia_main_lock_table,
			    srvc_all_rt_eops);
	if (rc)
		goto serval_ctx;
	rc = init_xid_table(&serval_ctx->flow, net, &xia_main_lock_table,
			    flow_all_rt_eops);
	if (rc)
		goto serval_ctx;

	rc = xip_add_ppal_ctx(net, &serval_ctx->srvc);
	if (rc)
		goto serval_ctx;
	rc = xip_add_ppal_ctx(net, &serval_ctx->flow);
	if (rc)
		goto srvc_ctx;

	rc = serval_tcp_net_metrics_init(serval_ctx);
	if (rc)
		goto flow_ctx;
	goto out;

flow_ctx:
	BUG_ON(flow_serval(xip_del_ppal_ctx(net, XIDTYPE_FLOWID)) !=
		serval_ctx);
srvc_ctx:
	BUG_ON(srvc_serval(xip_del_ppal_ctx(net, XIDTYPE_SRVCID)) !=
		serval_ctx);
serval_ctx:
	free_serval_ctx(serval_ctx);
out:
	return rc;
}

static void __net_exit serval_net_exit(struct net *net)
{
	struct xip_serval_ctx *serval_ctx, *serval_ctx2;

	serval_ctx = flow_serval(xip_del_ppal_ctx(net, XIDTYPE_FLOWID));
	serval_tcp_net_metrics_exit(serval_ctx);
	serval_ctx2 = srvc_serval(xip_del_ppal_ctx(net, XIDTYPE_SRVCID));
	BUG_ON(serval_ctx != serval_ctx2);
	free_serval_ctx(serval_ctx);
}

static struct pernet_operations serval_net_ops __read_mostly = {
	.init = serval_net_init,
	.exit = serval_net_exit,
};

/*
 *	Serval Routing
 */

/* XXX These local_* methods were copied from XDP, and probably should
 * be moved to XIA module to be shared between principals.
 */

#if 0
static int local_input_input(struct sk_buff *skb)
{
	struct xip_dst *xdst = skb_xdst(skb);
	struct sock *sk = xdst->info;

	if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf))
		goto drop;

	skb_pull_xiphdr(skb);
	skb_dst_drop(skb);

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		/* Queue received @skb. */

		/* XXX Review RPS, see Documentation/networking/scaling.txt */
		sock_rps_save_rxhash(sk, skb);

		if (sock_queue_rcv_skb(sk, skb) < 0)
			goto unlock_drop;
	} else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf)) {
		goto unlock_drop;
	}
	bh_unlock_sock(sk);
	return 0;

unlock_drop:
	bh_unlock_sock(sk);
drop:
	atomic_inc(&sk->sk_drops);
	kfree_skb(skb);
	return -1;
}
#else
#define local_input_input serval_sal_rcv
#endif

/* XXX Move this function to XIA core and replace and all principals. */
static int bug_dst_out_method(struct sock *sk, struct sk_buff *skb)
{
	BUG();
}

#define local_output_input local_input_input

static int local_output_output(struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	skb = xip_trim_packet_if_needed(skb, dev->mtu);
	if (!skb)
		return -1;

	skb->dev = dev;
	skb->protocol = __cpu_to_be16(ETH_P_XIP);

	/* Deliver @skb to its socket. */
	return dev_loopback_xmit(skb);
}

static int srvc_deliver(struct xip_route_proc *rproc, struct net *net,
			const u8 *xid, struct xia_xid *next_xid,
			int anchor_index, struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct fib_xid *fxid;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, srvc_vxt);

	fxid = xia_find_xid_rcu(ctx->xpc_xtbl, xid);
	if (!fxid) {
		xdst_attach_to_anchor(xdst, anchor_index, &ctx->negdep);
		rcu_read_unlock();
		return XRP_ACT_NEXT_EDGE;
	}

	switch (fxid->fx_table_id) {
	case XRTABLE_LOCAL_INDEX: {
		/* It's a local ServiceID. */
		struct serval_rt_id *rtid = fxid_rtid(fxid);
		struct serval_sock *ssk = rtid_ssk(rtid);

		/* A ServiceID cannot be a passthrough. */
		xdst->passthrough_action = XDA_ERROR;

		xdst->sink_action = XDA_METHOD_AND_SELECT_EDGE;
		xdst->info = &ssk->xia_sk.sk;
		BUG_ON(xdst->dst.dev);
		xdst->dst.dev = net->loopback_dev;
		dev_hold(xdst->dst.dev);
		if (xdst->input) {
			xdst->dst.input = local_input_input;
			xdst->dst.output = bug_dst_out_method;
		} else {
			xdst->dst.input = local_output_input;
			xdst->dst.output = local_output_output;
		}
		xdst_attach_to_anchor(xdst, anchor_index, &rtid->anchor);
		rcu_read_unlock();
		return XRP_ACT_FORWARD;
	}

	case XRTABLE_MAIN_INDEX:
		fib_mrd_redirect(fxid, next_xid);
		rcu_read_unlock();
		return XRP_ACT_REDIRECT;

	}
	rcu_read_unlock();
	BUG();
}

static struct xip_route_proc srvc_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_SRVCID,
	.deliver = srvc_deliver,
};

static int flow_deliver(struct xip_route_proc *rproc, struct net *net,
			const u8 *xid, struct xia_xid *next_xid,
			int anchor_index, struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct fib_xid *fxid;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, flow_vxt);

	fxid = xia_find_xid_rcu(ctx->xpc_xtbl, xid);
	if (!fxid) {
		xdst_attach_to_anchor(xdst, anchor_index, &ctx->negdep);
		rcu_read_unlock();
		return XRP_ACT_NEXT_EDGE;
	}

	switch (fxid->fx_table_id) {
	case XRTABLE_LOCAL_INDEX:
		/* It's a local FlowID. */

		/* A FlowID cannot be a passthrough. */
		xdst->passthrough_action = XDA_ERROR;

		xdst->sink_action = XDA_METHOD_AND_SELECT_EDGE;
		BUG_ON(xdst->dst.dev);
		xdst->dst.dev = net->loopback_dev;
		dev_hold(xdst->dst.dev);

		switch (fxid->fx_entry_type) {
		case SOCK_TYPE: {
			struct serval_rt_id *rtid = fxid_rtid(fxid);

			xdst->info = rtid_ssk(rtid);
			if (xdst->input) {
				xdst->dst.input = local_input_input;
				xdst->dst.output = bug_dst_out_method;
			} else {
				xdst->dst.input = local_output_input;
				xdst->dst.output = local_output_output;
			}
			xdst_attach_to_anchor(xdst, anchor_index,
					      &rtid->anchor);
			break;
		}

		case REQUEST_SOCK_TYPE: {
			struct serval_request_sock *srsk = flow_fxid_srsk(fxid);

			xdst->info = srsk->parent_ssk;
			if (xdst->input) {
				xdst->dst.input = serval_sal_rsk_rcv;
				xdst->dst.output = bug_dst_out_method;
			} else {
				xdst->dst.input = serval_sal_rsk_rcv;
				xdst->dst.output = local_output_output;
			}
			xdst_attach_to_anchor(xdst, anchor_index,
					      &srsk->flow_anchor);
			break;
		}

		default:
			BUG();
		}

		rcu_read_unlock();
		return XRP_ACT_FORWARD;

	case XRTABLE_MAIN_INDEX:
		fib_mrd_redirect(fxid, next_xid);
		rcu_read_unlock();
		return XRP_ACT_REDIRECT;

	}
	rcu_read_unlock();
	BUG();
}

static struct xip_route_proc flow_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_FLOWID,
	.deliver = flow_deliver,
};

/*
 *	Socket API
 */

void serval_sock_init(struct serval_sock *ssk)
{
	struct sock *sk = &ssk->xia_sk.sk;

	sk->sk_state = 0;
	ssk->sal_state = SAL_RSYN_INITIAL;
	ssk->srvc_rtid = NULL;
	ssk->flow_rtid = NULL;
	INIT_LIST_HEAD(&ssk->accept_queue);
	INIT_LIST_HEAD(&ssk->syn_queue);
	setup_timer(&ssk->retransmit_timer, serval_sal_rexmit_timeout,
		    (unsigned long)sk);
	setup_timer(&ssk->tw_timer, serval_sal_timewait_timeout,
		    (unsigned long)sk);

	serval_sal_init_ctrl_queue(sk);

	ssk->rcv_seq.nxt = 0;
	ssk->snd_seq.una = 0;
	ssk->snd_seq.nxt = 0;
	/* Default to stop-and-wait behavior (wnd = 1). */
	ssk->rcv_seq.wnd = 1;
	ssk->snd_seq.wnd = 1;
	ssk->retransmits = 0;
	ssk->backoff = 0;
	ssk->srtt = 0;
	ssk->mdev = ssk->mdev_max = ssk->rttvar = SAL_TIMEOUT_INIT;
	ssk->rto = SAL_TIMEOUT_INIT;
}

void serval_sock_init_seeds(struct serval_sock *ssk)
{
	get_random_bytes(ssk->local_nonce, SAL_NONCE_SIZE);
	get_random_bytes(&ssk->snd_seq.iss, sizeof(ssk->snd_seq.iss));
}

void serval_sock_destroy(struct sock *sk)
{
	struct serval_sock *ssk = sk_ssk(sk);
	struct xip_dst *xdst;

	WARN_ON(sk->sk_state != SAL_CLOSED);
	WARN_ON(ssk->peer_srvc_xdst && !ssk->peer_srvc_set);
	WARN_ON(ssk->srvc_rtid);
	WARN_ON(ssk->flow_rtid);

	if (!sock_flag(sk, SOCK_DEAD)) {
		LIMIT_NETDEBUG(KERN_WARNING
			pr_fmt("Attempt to release alive XIA/Serval socket %p\n"),
			sk);
		return;
	}

	/* Stop timers. */
	sk_stop_timer(sk, &ssk->retransmit_timer);
	sk_stop_timer(sk, &ssk->tw_timer);

	if (sk->sk_prot->destroy)
		sk->sk_prot->destroy(sk);

	xdst = ssk->peer_srvc_xdst;
	if (xdst) {
		ssk->peer_srvc_xdst = NULL;
		xdst_put(xdst);
	}
	ssk->peer_srvc_set = false;

	/* Clean queues. */
	serval_sal_ctrl_queue_purge(sk);
	sk_stream_kill_queues(sk);

	sock_put(sk);
}

void serval_sock_done(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	serval_sock_set_state(sk, SAL_CLOSED);
	serval_sock_clear_xmit_timer(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	/* If there is still a user around, notify it.
	 * Otherwise, destroy the socket now.
	 */
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);
	else
		serval_sock_destroy(sk);
}

int serval_listen_stop(struct sock *sk)
{
	struct serval_sock *ssk = sk_ssk(sk);
	struct fib_xid_table *xtbl =
		xip_find_my_ppal_ctx_vxt(sock_net(sk), flow_vxt)->xpc_xtbl;

	/* Destroy queue of sockets that haven't completed the three-way
	 * handshake.
	 */
	while (!list_empty(&ssk->syn_queue)) {
		struct serval_request_sock *srsk = list_first_entry(
			&ssk->syn_queue, struct serval_request_sock, lh);

		/* Deleting SYN queued request socket. */
		list_del(&srsk->lh);
		fib_rm_fxid(xtbl, &srsk->flow_fxid);
		free_fxid(xtbl, &srsk->flow_fxid);
		sk->sk_ack_backlog--;
		srsk_put(srsk);
	}

	/* Destroy queue of sockets that completed the three-way handshake. */
	while (!list_empty(&ssk->accept_queue)) {
		struct serval_request_sock *srsk = list_first_entry(
			&ssk->accept_queue, struct serval_request_sock, lh);
		struct sock *child = srsk->req.sk;

		list_del(&srsk->lh);
		srsk->req.sk = NULL;

		/* XXX Do we need to disable BH? */
		local_bh_disable();
		bh_lock_sock(child);
		WARN_ON(sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);
		sk->sk_prot->unhash(child);

		/* Orphaning will mark the sock with flag DEAD,
		 * allowing the sock to be destroyed.
		 */
		sock_orphan(child);
		/* XXX Does we need to call
		 * percpu_counter_inc(sk->sk_prot->orphan_count); ???
		 */

		sock_put(child);
		bh_unlock_sock(child);
		local_bh_enable();

		/* Drop reference that was at @srsk->req.sk. */
		sock_put(child);

		sk->sk_ack_backlog--;
		srsk_put(srsk);
	}

	return 0;
}

static inline struct serval_rt_id *rtid_alloc(gfp_t flags)
{
	return kmalloc(sizeof(struct serval_rt_id), flags);
}

/* Don't call this function, use rtid_init() or __rtid_init() instead. */
static inline void __rtid_init_common(struct serval_rt_id *rtid,
				      struct serval_sock *ssk)
{
	xdst_init_anchor(&rtid->anchor);
	RCU_INIT_POINTER(rtid->ssk, ssk);
}

static void __rtid_init(struct serval_rt_id *rtid, struct serval_sock *ssk,
			int table_id, int entry_type)
{
	__init_fxid(&rtid->fxid, table_id, entry_type);
	__rtid_init_common(rtid, ssk);
}

static void rtid_init(struct serval_rt_id *rtid, struct serval_sock *ssk,
		      const u8 *xid, int table_id, int entry_type)
{
	init_fxid(&rtid->fxid, xid, table_id, entry_type);
	__rtid_init_common(rtid, ssk);
}

/* Don't call this function, use rtid_free() or rtid_free_norcu() instead. */
static inline void __rtid_free_common(struct serval_rt_id *rtid)
{
	RCU_INIT_POINTER(rtid->ssk, NULL);
}

/* ATTENTION, only call this function after rtid_init() or __rtid_init()
 * has been called on @rtid.
 */
static void rtid_free_norcu(struct fib_xid_table *xtbl,
			    struct serval_rt_id *rtid)
{
	__rtid_free_common(rtid);
	free_fxid_norcu(xtbl, &rtid->fxid);
}

/* ATTENTION, only call this function after rtid_init() or __rtid_init()
 * has been called on @rtid.
 */
static void rtid_free(struct fib_xid_table *xtbl, struct serval_rt_id *rtid)
{
	__rtid_free_common(rtid);
	free_fxid(xtbl, &rtid->fxid);
}

int serval_sock_bind(struct sock *sk, struct sockaddr *uaddr, int node_n)
{
	DECLARE_SOCKADDR(struct sockaddr_xia *, addr, uaddr);
	struct xia_row *ssink = &addr->sxia_addr.s_row[node_n - 1];
	struct xip_deferred_negdep_flush *dnf;
	struct serval_rt_id *rtid;
	struct serval_sock *ssk;
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *xtbl;
	struct net *net;
	int rc;

	/* Make sure we are allowed to bind here. */
	if (ssink->s_xid.xid_type != XIDTYPE_SRVCID)
		return -EXTYNOSUPPORT;

	dnf = fib_alloc_dnf(GFP_KERNEL);
	if (!dnf)
		return -ENOMEM;

	rtid = rtid_alloc(GFP_KERNEL);
	if (!rtid) {
		rc = -ENOMEM;
		goto dnf;
	}
	ssk = sk_ssk(sk);
	rtid_init(rtid, ssk, ssink->s_xid.xid_id, XRTABLE_LOCAL_INDEX, 0);

	net = sock_net(sk);
	ctx = xip_find_my_ppal_ctx_vxt(net, srvc_vxt);
	xtbl = ctx->xpc_xtbl;

	rc = fib_add_fxid(xtbl, &rtid->fxid);
	if (rc) {
		rc = rc == -EEXIST ? -EADDRINUSE : rc;
		goto rtid;
	}

	fib_defer_dnf(dnf, net, XIDTYPE_SRVCID);

	ssk->srvc_rtid = rtid;
	sock_prot_inuse_add(net, sk->sk_prot, 1);
	return 0;

rtid:
	rtid_free_norcu(xtbl, rtid);
dnf:
	fib_free_dnf(dnf);
	return rc;
}

static void serval_sock_unhash_s_f(struct sock *sk,
				   int unhash_srvc, int unhash_flow);

static int serval_connect(struct socket *sock, struct sockaddr *uaddr,
			  int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct serval_sock *ssk;
	int rc;

	rc = check_sockaddr_xia(uaddr, addr_len);
	if (rc)
		return rc;

	lock_sock(sk);

	switch (sock->state) {

	case SS_CONNECTED:
		rc = -EISCONN;
		goto out;

	case SS_CONNECTING:
		rc = -EALREADY;
		break;

	case SS_UNCONNECTED: {
		struct serval_rt_id *rtid;
		struct fib_xid_table *xtbl;

		if (sk->sk_state == SAL_LISTEN) {
			rc = -EISCONN;
			goto out;
		}

		ssk = sk_ssk(sk);
		if (!xia_sk_bound(&ssk->xia_sk)) {
			/* It must be bound in order to produce a source
			 * address with a FlowID.
			 */
			rc = -ESNOTBOUND;
			goto out;
		}
		BUG_ON(!ssk->srvc_rtid);

		/* Allocate a FlowID. */
		rtid = rtid_alloc(GFP_KERNEL);
		if (!rtid) {
			rc = -ENOMEM;
			goto out;
		}
		__rtid_init(rtid, ssk, XRTABLE_LOCAL_INDEX, SOCK_TYPE);
		BUILD_BUG_ON(sizeof(struct flow_id) != XIA_XID_MAX);
		serval_sock_get_flowid(rtid->fxid.fx_xid);

		/* Hash new FlowID. */
		BUG_ON(ssk->flow_rtid);
		serval_sock_set_state(sk, SAL_REQUEST);
		xtbl = xip_find_my_ppal_ctx_vxt(sock_net(sk),
						flow_vxt)->xpc_xtbl;
		rc = fib_add_fxid(xtbl, &rtid->fxid);
		if (rc) {
			serval_sock_set_state(sk, SAL_CLOSED);
			rtid_free_norcu(xtbl, rtid);
			goto out;
		}
		ssk->flow_rtid = rtid;
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

		rc = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (rc < 0) {
			/* Only unhash the FlowID to allow applications to
			 * call connect() without having to call bind() again.
			 */
			serval_sock_unhash_s_f(sk, false, true);

			serval_sock_set_state(sk, SAL_CLOSED);
			goto out;
		}
		sock->state = SS_CONNECTING;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		rc = -EINPROGRESS;
		break;
	}

	default:
		rc = -EINVAL;
		goto out;
	}

	if ((1 << sk->sk_state) & (SALF_REQUEST | SALF_RESPOND)) {
		long timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

		if (!timeo) {
			/* Error code is set above */
			goto out;
		}

		rc = sk_stream_wait_connect(sk, &timeo);
		if (rc)
			goto out;

		rc = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	/* We must be in SERVAL_REQUEST or later state. All those
	 * states are valid "connected" states, except for CLOSED.
	 */
	if (sk->sk_state == SAL_CLOSED) {
		rc = sock_error(sk) ? : -ECONNABORTED;
		sock->state = SS_UNCONNECTED;
		if (sk->sk_prot->disconnect(sk, flags))
			sock->state = SS_DISCONNECTING;
		goto out;
	}

	sock->state = SS_CONNECTED;
	rc = 0;

out:
	release_sock(sk);
	return rc;
}

/* XXX This function should be rewritten to wait for an event, not a timer!
 * See sk_stream_wait_connect() for an example.
 */
static int serval_wait_for_connect(struct sock *sk, long timeo)
{
	struct serval_sock *ssk = sk_ssk(sk);
	DEFINE_WAIT(wait);
	int rc;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);

		if (list_empty(&ssk->accept_queue))
			timeo = schedule_timeout(timeo);

		lock_sock(sk);
		if (!list_empty(&ssk->accept_queue)) {
			rc = 0;
			break;
		}
		if (sk->sk_state != SAL_LISTEN) {
			rc = -EINVAL;
			break;
		}
		if (signal_pending(current)) {
			rc = sock_intr_errno(timeo);
			break;
		}
		if (!timeo) {
			rc = -EAGAIN;
			break;
		}
	}
	finish_wait(sk_sleep(sk), &wait);
	return rc;
}

/* Caller must have the lock of @parent. */
static struct sock *serval_accept_dequeue(struct sock *parent,
					  struct socket *newsock)
{
	struct serval_sock *pssk = sk_ssk(parent);
	struct serval_request_sock *srsk;

	/* Parent sock is already locked. */
	list_for_each_entry(srsk, &pssk->accept_queue, lh) {
		struct sock *sk = srsk->req.sk;

		lock_sock(sk);
		sock_graft(sk, newsock);
		newsock->state = SS_CONNECTED;
		release_sock(sk);

		list_del(&srsk->lh);
		parent->sk_ack_backlog--;
		srsk_put(srsk);
		return sk;
	}
	return NULL;
}

static int serval_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk = sock->sk;
	struct serval_sock *ssk = sk_ssk(sk);
	int rc;

	lock_sock(sk);

	if (sk->sk_state != SAL_LISTEN) {
		rc = -EBADFD;
		goto out;
	}

	if (list_empty(&ssk->accept_queue)) {
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		if (!timeo) {
			/* If this is a non blocking socket don't sleep */
			rc = -EAGAIN;
			goto out;
		}

		rc = serval_wait_for_connect(sk, timeo);
		if (rc)
			goto out;
	}
	rc = serval_accept_dequeue(sk, newsock) ? 0 : -EAGAIN;

out:
	release_sock(sk);
	return rc;
}

static unsigned int serval_poll(struct file *file, struct socket *sock,
				poll_table *wait)
{
	struct sock *sk = sock->sk;
	unsigned int mask;

	sock_poll_wait(file, sk_sleep(sk), wait);
	if (sk->sk_state == SAL_LISTEN) {
		struct serval_sock *ssk = sk_ssk(sk);

		return list_empty(&ssk->accept_queue) ? 0 :
			(POLLIN | POLLRDNORM);
	}

	mask = 0;

	if (sk->sk_err)
		mask = POLLERR;

	if (sk->sk_shutdown == SHUTDOWN_MASK ||
	    sk->sk_state == SAL_CLOSED)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	if ((1 << sk->sk_state) & ~(SALF_REQUEST | SALF_RESPOND)) {
		if (atomic_read(&sk->sk_rmem_alloc) > 0)
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >=
			    sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >=
				    sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		}
	}

	return mask;
}

/* Next FlowID. */
static atomic64_t serval_flow_id;

void serval_sock_get_flowid(u8 *flowid)
{
	/* This large counter guarantees that each FlowID is unique. */
	u64 *p_counter = (u64 *)flowid;

	BUILD_BUG_ON(sizeof(*p_counter) != sizeof(serval_flow_id));
	BUILD_BUG_ON(XIA_XID_MAX <= sizeof(*p_counter));

	*p_counter = atomic64_inc_return(&serval_flow_id);
	if (!*p_counter) {
		/* Avoid counter to be equal to zero; this ensures that
		 * the whose FlowID is not all zeros.
		 */
		*p_counter = atomic64_inc_return(&serval_flow_id);
		BUG_ON(!*p_counter);
	}
	get_random_bytes(p_counter + 1, XIA_XID_MAX - sizeof(*p_counter));
}

int serval_swap_srsk_ssk_flowid(struct fib_xid *cur_fxid,
				struct serval_sock *new_ssk)
{
	struct xip_deferred_negdep_flush *dnf;
	struct serval_rt_id *rtid;
	struct net *net;
	struct fib_xid_table *xtbl;
	struct fib_xid *found_fxid;
	u32 bucket;

	dnf = fib_alloc_dnf(GFP_ATOMIC);
	if (!dnf)
		return -ENOMEM;

	rtid = rtid_alloc(GFP_ATOMIC);
	if (!rtid) {
		fib_free_dnf(dnf);
		return -ENOMEM;
	}
	rtid_init(rtid, new_ssk, cur_fxid->fx_xid,
		  XRTABLE_LOCAL_INDEX, SOCK_TYPE);

	net = sock_net(&new_ssk->xia_sk.sk);
	xtbl = xip_find_my_ppal_ctx_vxt(net, flow_vxt)->xpc_xtbl;
	found_fxid = xia_find_xid_lock(&bucket, xtbl, cur_fxid->fx_xid);
	if (unlikely(!found_fxid)) {
		/* This case should only happen if another thread was faster
		 * than us and has already removed @cur_fxid.
		 */
		BUG_ON(fib_add_fxid_locked(bucket, xtbl, &rtid->fxid));
		fib_unlock_bucket(xtbl, bucket);
		fib_defer_dnf(dnf, net, xtbl_ppalty(xtbl));
		goto out;
	}

	BUG_ON(found_fxid != cur_fxid);
	fib_replace_fxid_locked(xtbl, cur_fxid, &rtid->fxid);
	fib_unlock_bucket(xtbl, bucket);
	free_fxid(xtbl, cur_fxid);
	fib_free_dnf(dnf);

out:
	new_ssk->flow_rtid = rtid;
	sock_prot_inuse_add(net, new_ssk->xia_sk.sk.sk_prot, 1);
	return 0;
}

int __serval_sock_hash_flowid(struct net *net, struct fib_xid *fxid)
{
	struct xip_ppal_ctx *ctx = xip_find_my_ppal_ctx_vxt(net, flow_vxt);
	return fib_add_fxid(ctx->xpc_xtbl, fxid);
}

static void serval_sock_unhash_s_f(struct sock *sk,
				   int unhash_srvc, int unhash_flow)
{
	struct serval_sock *ssk = sk_ssk(sk);
	struct net *net = sock_net(sk);
	struct serval_rt_id *rtid;

	if (unhash_srvc && ssk->srvc_rtid) {
		struct fib_xid_table *srvc_xtbl;

		rtid = ssk->srvc_rtid;
		ssk->srvc_rtid = NULL;
		xia_reset_src(&ssk->xia_sk);

		/* Removing socket @sk from the service table. */
		srvc_xtbl = xip_find_my_ppal_ctx_vxt(net, srvc_vxt)->xpc_xtbl;
		fib_rm_fxid(srvc_xtbl, &rtid->fxid);
		rtid_free(srvc_xtbl, rtid);
		sock_prot_inuse_add(net, sk->sk_prot, -1);
	}

	if (unhash_flow && ssk->flow_rtid) {
		struct fib_xid_table *flow_xtbl;

		rtid = ssk->flow_rtid;
		ssk->flow_rtid = NULL;

		/* Removing socket @sk from the flow table. */
		flow_xtbl = xip_find_my_ppal_ctx_vxt(net, flow_vxt)->xpc_xtbl;
		fib_rm_fxid(flow_xtbl, &rtid->fxid);
		rtid_free(flow_xtbl, rtid);
		sock_prot_inuse_add(net, sk->sk_prot, -1);
	}
}

void serval_sock_unhash(struct sock *sk)
{
	return serval_sock_unhash_s_f(sk, true, true);
}

static int serval_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct serval_sock *ssk = sk_ssk(sk);
	int rc;

	lock_sock(sk);

	if (sock->type != SOCK_DGRAM && sock->type != SOCK_STREAM) {
		/* Bad socket type. */
		rc = -EOPNOTSUPP;
		goto out;
	}

	if (sock->state != SS_UNCONNECTED) {
		/* Socket not unconnected. */
		rc = -EINVAL;
		goto out;
	}

	if (!xia_sk_bound(&ssk->xia_sk)) {
		rc = -ESNOTBOUND;
		goto out;
	}
	BUG_ON(!ssk->srvc_rtid);

	serval_sock_set_state(sk, SAL_LISTEN);
	sk->sk_ack_backlog = 0;
	sk->sk_max_ack_backlog = backlog;
	rc = 0;

out:
	release_sock(sk);
	return rc;
}

static int serval_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int rc = 0;

	/* For an explanation see xia_shutdown(). */
	how++;
	if ((how & ~SHUTDOWN_MASK) || !how)
		return -EINVAL;

	/* Unregister notification only if we previously registered and
	 * this is not a child socket.
	 */

	lock_sock(sk);

	if (sock->state == SS_CONNECTING)
		sock->state = SS_CONNECTED;

	switch (sk->sk_state) {
	case SAL_CLOSED:
		rc = -ENOTCONN;
		/* Hack to wake up other listeners, who can poll for
		 * POLLHUP, even on eg. unconnected UDP sockets -- RR
		 */
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown)
			sk->sk_prot->shutdown(sk, how);
		break;

	/* Remaining two branches are temporary solution for missing
	 * close() in multithreaded environment. It is _not_ a good idea,
	 * but we have no choice until close() is repaired at VFS level.
	 */
	case SAL_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	case SAL_REQUEST:
		rc = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = rc ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);

	release_sock(sk);

	return rc;
}

static int serval_sendmsg(struct kiocb *iocb, struct socket *sock,
			  struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	/* XXX Is this test really necessary? */
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		return -EPIPE;

	return xia_sendmsg(iocb, sock, msg, size);
}

extern unsigned int serval_tcp_poll(struct file *file, struct socket *sock,
				    poll_table *wait);

#if defined(ENABLE_SPLICE)
extern ssize_t serval_udp_splice_read(struct socket *sock, loff_t *ppos,
				      struct pipe_inode_info *pipe,
				      size_t len, unsigned int flags);

extern ssize_t serval_tcp_splice_read(struct socket *sock, loff_t *ppos,
				      struct pipe_inode_info *pipe,
				      size_t len, unsigned int flags);
#endif /* ENABLE_SPLICE */

static const struct proto_ops serval_stream_ops = {
	.family		= PF_XIA,
	.owner		= THIS_MODULE,
	.release	= xia_release,
	.bind		= xia_bind,
	.connect	= serval_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= serval_accept,
	.getname	= xia_getname,
	.poll		= serval_tcp_poll,
	.ioctl		= xia_ioctl,
	.listen		= serval_listen,
	.shutdown	= serval_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= serval_sendmsg,
	.recvmsg	= xia_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= xia_sendpage,
#if defined(ENABLE_SPLICE)
	.splice_read	= serval_tcp_splice_read,
#endif
};

static const struct proto_ops serval_dgram_ops = {
	.family		= PF_XIA,
	.owner		= THIS_MODULE,
	.release	= xia_release,
	.bind		= xia_bind,
	.connect	= serval_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= serval_accept,
	.getname	= xia_getname,
	.poll		= serval_poll,
	.ioctl		= xia_ioctl,
	.listen		= serval_listen,
	.shutdown	= serval_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= serval_sendmsg,
	.recvmsg	= xia_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= xia_sendpage,
#if defined(ENABLE_SPLICE)
	.splice_read	= serval_udp_splice_read,
#endif
};

extern struct proto serval_tcp_proto;
extern struct proto serval_udp_proto;

static const struct xia_socket_type_proc serval_stream = {
	.proto		= &serval_tcp_proto,
	.alloc_slab	= true,
	.ops		= &serval_stream_ops,
};

static const struct xia_socket_type_proc serval_dgram = {
	.proto		= &serval_udp_proto,
	.alloc_slab	= true,
	.ops		= &serval_dgram_ops,
};

static struct xia_socket_proc serval_sock_proc __read_mostly = {
	.name			= "Serval",
	.ppal_type		= XIDTYPE_SRVCID,
	.procs[SOCK_STREAM]	= &serval_stream,
	.procs[SOCK_DGRAM]	= &serval_dgram,
};

/*
 *	Main
 */

/*
 *	Module parameters
 *
 * Permissions (affect visibility in sysfs):
 * 0 = not visible in sysfs
 * S_IRUGO = world readable
 * S_IRUGO|S_IWUSR = root can change
 */

extern void serval_tcp_init(void);
extern int serval_sysctl_register(struct net *net);
extern void serval_sysctl_unregister(struct net *net);

static int __init xia_serval_init(void)
{
	int rc = 0;

	rc = vxt_register_xidty(XIDTYPE_SRVCID);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for SRVCID\n");
		goto out;
	}
	srvc_vxt = rc;

	rc = vxt_register_xidty(XIDTYPE_FLOWID);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for FlowID\n");
		goto srvc_vxt;
	}
	flow_vxt = rc;

	/* Seed FlowID counter. */
	get_random_bytes(&serval_flow_id, sizeof(serval_flow_id));

	rc = xia_register_pernet_subsys(&serval_net_ops);
	if (rc)
		goto flow_vxt;

	rc = ppal_add_map("serval", XIDTYPE_SRVCID);
	if (rc)
		goto net;

	rc = ppal_add_map("flowid", XIDTYPE_FLOWID);
	if (rc)
		goto srvc_map;

	rc = xip_add_router(&srvc_rt_proc);
	if (rc)
		goto flow_map;

	rc = xip_add_router(&flow_rt_proc);
	if (rc)
		goto srvc_rt;

	serval_tcp_init();

	rc = serval_sysctl_register(&init_net);
	if (rc < 0) {
		pr_err("ERROR: Cannot register Serval sysctl interface\n");
		goto flow_rt;
	}

	rc = xia_add_socket(&serval_sock_proc);
	if (rc)
		goto sysctl;

	pr_alert("XIA Principal Serval loaded\n");
	goto out;

sysctl:
	serval_sysctl_unregister(&init_net);
flow_rt:
	xip_del_router(&flow_rt_proc);
srvc_rt:
	xip_del_router(&srvc_rt_proc);
flow_map:
	ppal_del_map(XIDTYPE_FLOWID);
srvc_map:
	ppal_del_map(XIDTYPE_SRVCID);
net:
	xia_unregister_pernet_subsys(&serval_net_ops);
flow_vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_FLOWID));
srvc_vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_SRVCID));
out:
	return rc;
}

static void __exit xia_serval_exit(void)
{
	xia_del_socket_begin(&serval_sock_proc);
	serval_sysctl_unregister(&init_net);
	xip_del_router(&flow_rt_proc);
	xip_del_router(&srvc_rt_proc);
	ppal_del_map(XIDTYPE_FLOWID);
	ppal_del_map(XIDTYPE_SRVCID);
	xia_unregister_pernet_subsys(&serval_net_ops);
	xia_del_socket_end(&serval_sock_proc);
	BUG_ON(vxt_unregister_xidty(XIDTYPE_FLOWID));
	BUG_ON(vxt_unregister_xidty(XIDTYPE_SRVCID));

	rcu_barrier();

	pr_alert("XIA Principal Serval UNloaded\n");
}

module_init(xia_serval_init);
module_exit(xia_serval_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_AUTHOR("Erik Nordström");
MODULE_DESCRIPTION("XIA Serval Principal");

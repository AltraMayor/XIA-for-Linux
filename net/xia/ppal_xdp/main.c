#include <linux/module.h>
#include <linux/swap.h>
#include <asm/ioctls.h>
#include <net/tcp_states.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>
#include <net/xia_socket.h>
#include <net/xia_output.h>
#include <net/xia_xdp.h>

/*
 *	Local XDP table
 */

struct fib_xid_xdp_local {
	/* Socket related fields. */

	/* struct xia_sock must be the first member to work with sk_alloc(). */
	struct xia_sock		xia_sk;

	/* Is socket corked? */
	bool			corkflag;

	/* Any pending outbound frame? */
	bool			pending;

	/* Two free bytes. */

	/* FIB XID related fields. */
	struct fib_xid		fxid;
	struct xip_dst_anchor   anchor;
};

static inline struct fib_xid_xdp_local *fxid_lxdp(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_xdp_local, fxid)
		: NULL;
}

static inline struct fib_xid_xdp_local *xiask_lxdp(struct xia_sock *xia)
{
	return likely(xia)
		? container_of(xia, struct fib_xid_xdp_local, xia_sk)
		: NULL;
}

static inline struct fib_xid_xdp_local *sk_lxdp(struct sock *sk)
{
	return xiask_lxdp(xia_sk(sk));
}

static int local_newroute_delroute(struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	return -EOPNOTSUPP;
}

static int local_dump_xdp(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 pid = NETLINK_CB(cb->skb).pid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct xia_xid dst;
	const struct xia_sock *xia;

	nlh = nlmsg_put(skb, pid, seq, RTM_NEWROUTE, sizeof(*rtm), NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = rtbl->tbl_id;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = rtbl->tbl_id == XRTABLE_LOCAL_INDEX
		? RTN_LOCAL : RTN_UNICAST;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	/* @dst can also be seem as the source of a socket since
	 * we are listing the local routing table of XDP principal, but
	 * that inversion of roles here would make this dump unnecessarily
	 * different of other principals' dumps.
	 */
	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	/* Add the other side of a socket. */
	xia = &fxid_lxdp(fxid)->xia_sk;
	if (xia->xia_daddr_set) {
		struct xia_addr src;
		/* XXX We only have an RCU read lock here, don't we need
		 * a lock over @xia to avoid races over xia->xia_daddr_set,
		 * xia->xia_daddr and xia->xia_dnum?
		 */
		copy_n_and_shade_xia_addr_from_addr(&src, &xia->xia_daddr,
			xia->xia_dnum);
		if (unlikely(nla_put(skb, RTA_SRC, sizeof(src), &src)))
			goto nla_put_failure;
	}

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_xdp(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_xdp_local *lxdp = fxid_lxdp(fxid);
	xdst_free_anchor(&lxdp->anchor);
	/* We do not sock_put(&lxdp->xia_sk.sk) because @fxid is released
	 * before @lxdp, and we do not deallocate memory here because @fxid is
	 * part of @lxdp.
	 */
}

static const struct xia_ppal_rt_eops xdp_rt_eops_local = {
	.newroute = local_newroute_delroute,
	.delroute = local_newroute_delroute,
	.dump_fxid = local_dump_xdp,
	.free_fxid = local_free_xdp,
};

/*
 *	Main XDP table
 */

struct fib_xid_xdp_main {
	struct fib_xid		common;
	struct xia_xid		gw;
};

static inline struct fib_xid_xdp_main *fxid_mxdp(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_xdp_main, common)
		: NULL;
}

static int main_newroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid_xdp_main *mxdp;
	int rc;

	rc = -EINVAL;
	if (!cfg->xfc_gw || cfg->xfc_gw->xid_type == XIDTYPE_XDP)
		goto out;

	rc = -ENOMEM;
	mxdp = kzalloc(sizeof(*mxdp), GFP_KERNEL);
	if (!mxdp)
		goto out;

	init_fxid(&mxdp->common, cfg->xfc_dst->xid_id);
	mxdp->gw = *cfg->xfc_gw;

	rc = fib_add_fxid(xtbl, &mxdp->common);
	if (rc)
		goto mxdp;
	goto out;

mxdp:
	free_fxid(xtbl, &mxdp->common);
out:
	return rc;
}

static int main_dump_xdp(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 pid = NETLINK_CB(cb->skb).pid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_xdp_main *mxdp = fxid_mxdp(fxid);
	struct xia_xid dst;

	nlh = nlmsg_put(skb, pid, seq, RTM_NEWROUTE, sizeof(*rtm), NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = rtbl->tbl_id;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = rtbl->tbl_id == XRTABLE_LOCAL_INDEX
		? RTN_LOCAL : RTN_UNICAST;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);

	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst) ||
			nla_put(skb, RTA_GATEWAY, sizeof(mxdp->gw), &mxdp->gw)
		))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void main_free_xdp(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_xdp_main *mxdp = fxid_mxdp(fxid);
	xdst_invalidate_redirect(xtbl_net(xtbl), XIDTYPE_XDP,
		mxdp->common.fx_xid, &mxdp->gw);
	kfree(mxdp);
}

static const struct xia_ppal_rt_eops xdp_rt_eops_main = {
	.newroute = main_newroute,
	.delroute = fib_default_delroute,
	.dump_fxid = main_dump_xdp,
	.free_fxid = main_free_xdp,
};

/*
 *	Network namespace
 */

static int __net_init xdp_net_init(struct net *net)
{
	int rc;

	rc = init_xid_table(net->xia.local_rtbl, XIDTYPE_XDP,
		&xia_main_lock_table, &xdp_rt_eops_local);
	if (rc)
		goto out;
	rc = init_xid_table(net->xia.main_rtbl, XIDTYPE_XDP,
		&xia_main_lock_table, &xdp_rt_eops_main);
	if (rc)
		goto local_rtbl;
	goto out;

local_rtbl:
	end_xid_table(net->xia.local_rtbl, XIDTYPE_XDP);
out:
	return rc;
}

static void __net_exit xdp_net_exit(struct net *net)
{
	rtnl_lock();
	end_xid_table(net->xia.main_rtbl, XIDTYPE_XDP);
	end_xid_table(net->xia.local_rtbl, XIDTYPE_XDP);
	rtnl_unlock();
}

static struct pernet_operations xdp_net_ops __read_mostly = {
	.init = xdp_net_init,
	.exit = xdp_net_exit,
};

/*
 *	XDP Routing
 */

/* Deliver to socket. */

static int local_input_input(struct sk_buff *skb)
{
	struct xip_dst *xdst = skb_xdst(skb);
	struct sock *sk = xdst->info;

	if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf))
		goto drop;

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

static int local_input_output(struct sk_buff *skb)
{
	BUG();
}

#define local_output_input local_input_input

static int local_output_output(struct sk_buff *skb)
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

static int xdp_local_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, int anchor_index, struct xip_dst *xdst)
{
	struct fib_xid_table *local_xtbl;
	struct fib_xid_xdp_local *lxdp;

	rcu_read_lock();
	local_xtbl = xia_find_xtbl_rcu(net->xia.local_rtbl, XIDTYPE_XDP);
	BUG_ON(!local_xtbl);
	lxdp = fxid_lxdp(xia_find_xid_rcu(local_xtbl, xid));
	if (!lxdp) {
		rcu_read_unlock();
		return -ENOENT;
	}

	/* An XDP cannot be a passthrough. */
	xdst->passthrough_action = XDA_ERROR;

	xdst->sink_action = XDA_METHOD;
	xdst->info = &lxdp->xia_sk.sk;
	BUG_ON(xdst->dst.dev);
	xdst->dst.dev = net->loopback_dev;
	dev_hold(xdst->dst.dev);
	if (xdst->input) {
		xdst->dst.input = local_input_input;
		xdst->dst.output = local_input_output;
	} else {
		xdst->dst.input = local_output_input;
		xdst->dst.output = local_output_output;
	}

	xdst_attach_to_anchor(xdst, anchor_index, &lxdp->anchor);

	rcu_read_unlock();
	return 0;
}

/* Redirect. */
static int xdp_main_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, struct xia_xid *next_xid, int anchor_index,
	struct xip_dst *xdst)
{
	struct fib_xid_table *main_xtbl;
	struct fib_xid_xdp_main *mxdp;
	int rc;

	rcu_read_lock();
	main_xtbl = xia_find_xtbl_rcu(net->xia.main_rtbl, XIDTYPE_XDP);
	BUG_ON(!main_xtbl);
	mxdp = fxid_mxdp(xia_find_xid_rcu(main_xtbl, xid));

	rc = XRP_ACT_NEXT_EDGE;
	if (!mxdp)
		goto out;

	memmove(next_xid, &mxdp->gw, sizeof(*next_xid));
	rc = XRP_ACT_REDIRECT;

out:
	rcu_read_unlock();
	return rc;
}

static struct xip_route_proc xdp_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_XDP,
	.local_deliver = xdp_local_deliver,
	.main_deliver = xdp_main_deliver,
};

/*
 *	Socket API
 */

static void xdp_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

/* XDP isn't meant as a tool to poke other principals, thus
 * enforce that all sinks are XIDTYPE_XDP.
 */
static int check_type_of_all_sinks(struct sockaddr_xia *addr, xid_type_t ty)
{
	int i;
	int n = xia_test_addr(&addr->sxia_addr);

	if (n < 1) {
		/* Invalid address since it's empty. */
		return -EINVAL;
	}

	/* Verify the type of all sinks. */
	for (i = 0; i < n; i++) {
		struct xia_row *row = &addr->sxia_addr.s_row[i];
		if (is_it_a_sink(row, i, n) && row->s_xid.xid_type != ty)
			return -EINVAL;
	}

	return n;
}

static int xdp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	DECLARE_SOCKADDR(struct sockaddr_xia *, daddr, uaddr);
	int rc, n;

	rc = check_type_of_all_sinks(daddr, XIDTYPE_XDP);
	if (rc < 0)
		return rc;
	n = rc;

	lock_sock(sk);
	rc = xia_set_dest(xia_sk(sk), &daddr->sxia_addr, n);
	release_sock(sk);
	return rc;
}

static int xdp_disconnect(struct sock *sk, int flags)
{
	sock_rps_reset_rxhash(sk);	/* XXX Review RPS calls. */
	lock_sock(sk);
	xia_reset_dest(xia_sk(sk));
	sk->sk_state = TCP_CLOSE;
	release_sock(sk);
	return 0;
}

/**
 * first_packet_length	- return length of first packet in receive queue
 *	@sk: socket
 *
 *	Returns the length of found skb, or 0 if none is found.
 */
static unsigned int first_packet_length(struct sock *sk)
{
	struct sk_buff_head *rcvq = &sk->sk_receive_queue;
	struct sk_buff *skb;
	unsigned int res;

	spin_lock_bh(&rcvq->lock);
	skb = skb_peek(rcvq);
	res = skb ? skb->len : 0;
	spin_unlock_bh(&rcvq->lock);

	return res;
}

static int xdp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	{
		int amount = sk_wmem_alloc_get(sk);
		return put_user(amount, (int __user *)arg);
	}

	case SIOCINQ:
	{
		unsigned int amount = first_packet_length(sk);
		return put_user(amount, (int __user *)arg);
	}

	default:
		return -ENOIOCTLCMD;

	}
}

static void xdp_flush_pending_frames(struct sock *sk)
{
	struct fib_xid_xdp_local *lxdp = sk_lxdp(sk);
	if (!lxdp->pending)
		return;
	lxdp->pending = false;
	xip_flush_pending_frames(sk);
}

static void xdp_destroy_sock(struct sock *sk)
{
	bool slow = lock_sock_fast(sk);
	xdp_flush_pending_frames(sk);
	unlock_sock_fast(sk, slow);
}

/* Since XDP is headerless, this function is just a wrapper for
 * xip_send_skb().
 */
static inline int xdp_send_skb(struct sk_buff *skb)
{
	return xip_send_skb(skb);
}

/* Push out all pending data as a single XDP datagram. Socket must be locked. */
static int xdp_push_pending_frames(struct sock *sk)
{
	struct fib_xid_xdp_local *lxdp = sk_lxdp(sk);
	struct sk_buff *skb = xip_finish_skb(sk);
	int rc = !IS_ERR_OR_NULL(skb) ? xdp_send_skb(skb) : PTR_ERR(skb);
	lxdp->pending = false;
	return rc;
}

static int xdp_setsockopt(struct sock *sk, int level, int optname,
	char __user *optval, unsigned int optlen)
{
	struct fib_xid_xdp_local *lxdp;
	int val, rc;

	if (level != XIDTYPE_XDP)
		return xip_setsockopt(sk, level, optname, optval, optlen);
	if (optlen < sizeof(int))
		return -EINVAL;
	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lxdp = sk_lxdp(sk);
	rc = 0;

	switch (optname) {
	case XDP_CORK:
		lxdp->corkflag = !!val;
		if (val) {
			lock_sock(sk);
			xdp_push_pending_frames(sk);
			release_sock(sk);
		}
		break;

	default:
		rc = -ENOPROTOOPT;
		break;
	}

	return rc;
}

static int xdp_getsockopt(struct sock *sk, int level, int optname,
	char __user *optval, int __user *optlen)
{
	struct fib_xid_xdp_local *lxdp;
	int val, len;

	if (level != XIDTYPE_XDP)
		return xip_getsockopt(sk, level, optname, optval, optlen);
	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;
	len = min_t(int, len, sizeof(int));
	if (put_user(len, optlen))
		return -EFAULT;

	lxdp = sk_lxdp(sk);
	
	switch (optname) {
	case XDP_CORK:
		val = lxdp->corkflag;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

static int xdp_getfrag(void *from, char *to, int  offset, int len,
	int odd, struct sk_buff *skb)
{
	return memcpy_fromiovecend(to, (struct iovec *)from, offset, len);
}

static int xdp_sendmsg(struct kiocb *iocb, struct sock *sk,
	struct msghdr *msg, size_t len)
{
	struct fib_xid_xdp_local *lxdp = sk_lxdp(sk);
	struct xia_sock *xia = &lxdp->xia_sk;
	int corkreq = lxdp->corkflag || (msg->msg_flags & MSG_MORE);
	struct xia_addr *dest, dest_stack;
	struct xip_dst *xdst;
	int rc, dest_n;
	bool connected = false;
	u8 dest_last_node;

	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	if (lxdp->pending) {
		/* There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(lxdp->pending)) {
			xdst = NULL;
			goto append_data;
		}
		release_sock(sk);
	}

	/* Is source address available? */
	if (!xia_sk_bound(xia))
		return -ESNOTBOUND; /* Please bind first! */

	/* Obtain destination address. */
	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_xia *, addr, msg->msg_name);
		rc = check_sockaddr_xia((struct sockaddr *)addr,
			msg->msg_namelen);
		if (rc)
			return rc;
		rc = check_type_of_all_sinks(addr, XIDTYPE_XDP);
		if (rc < 0)
			return rc;
		dest_n = rc;
		dest = &addr->sxia_addr;
		dest_last_node = XIA_ENTRY_NODE_INDEX;
	} else {
		if (!xia->xia_daddr_set)
			return -EDESTADDRREQ;
		dest = &xia->xia_daddr;
		dest_n = xia->xia_dnum;
		dest_last_node = xia->xia_dlast_node;
		/* Open fast path for connected socket. */
		connected = true;
	}
	
	/* XXX Shouldn't one support sock_tx_timestamp and something similar
	 * to IP's control messages (see ip_cmsg_send())?
	 * See net/ipv4/udp.c:udp_sendmsg for an example.
	 */

	/* Routing. */
	xdst = connected ? dst_xdst(sk_dst_check(sk, 0)) : NULL;
	if (!xdst) {
		struct net *net = sock_net(sk);
		memmove(&dest_stack, dest, sizeof(dest_stack));
		dest = &dest_stack;
		if (connected) {
			unmark_xia_addr(dest);
			dest_last_node = XIA_ENTRY_NODE_INDEX;
		}
		xdst = xip_mark_addr_and_get_dst(net, dest->s_row,
			dest_n, &dest_last_node, 0);
		if (IS_ERR(xdst))
			return PTR_ERR(xdst);
		if (connected) {
			xdst_hold(xdst);
			lock_sock(sk);
			memmove(&xia->xia_daddr, dest, sizeof(xia->xia_daddr));
			xia->xia_dlast_node = dest_last_node;
			sk_dst_set(sk, &xdst->dst);
			release_sock(sk);
		}
	}

	/* From now on, don't just `return', but `goto out'! */

	if (msg->msg_flags & MSG_CONFIRM) {
		dst_confirm(&xdst->dst);
		if ((msg->msg_flags & MSG_PROBE) && !len) {
			rc = 0;
			goto out;
		}
	}

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		struct sk_buff *skb = xip_make_skb(sk, dest, dest_n,
			dest_last_node, xdp_getfrag, msg->msg_iov, len,
			0, xdst, msg->msg_flags);
		if (IS_ERR(skb))
			rc = PTR_ERR(skb);
		else if (!skb)
			rc = -SOCK_NOSPACE;
		else
			rc = xdp_send_skb(skb);
		goto out;
	}

	lock_sock(sk);
	if (unlikely(lxdp->pending)) {
		/* The socket is already corked while preparing it;
		 * this condition is an application bug.
		 *
		 * It can be triggered when two threads call,
		 * about the same time, send(2) on the same socket, and
		 * each call uses flag MSG_MORE.
		 */
		release_sock(sk);
		LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("XDP %s(): cork app bug\n"),
			__func__);
		rc = -EINVAL;
		goto out;
	}

	/* Now cork the socket to append data. */
	lxdp->pending = true;

append_data:
	/* Socket must be locked at this point. */

	rc = xip_append_data(sk, xdp_getfrag, msg->msg_iov, len, 0, xdst,
		corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (rc)
		xdp_flush_pending_frames(sk);
	else if (!corkreq)
		rc = xdp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		lxdp->pending = false;
	release_sock(sk);

out:
	/* @xdst is NULL when appending data. */
	if (xdst)
		xdst_put(xdst);

	return rc ? rc : len;
}

/* If there is a packet there, return it, otherwise block. */
static int xdp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
	size_t len, int noblock, int flags, int *addr_len)
{
	DECLARE_SOCKADDR(struct sockaddr_xia *, sxia, msg->msg_name);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int rc, peeked;
	int offset = 0;

	if (addr_len)
		*addr_len = sizeof(*sxia);

	if (flags & MSG_ERRQUEUE)
		return xip_recv_error(sk, msg, len);

	skb = __skb_recv_datagram(sk, flags | (noblock ? MSG_DONTWAIT : 0),
		&peeked, &offset, &rc);
	if (!skb)
		return rc;

	ulen = skb->len;	/* Bytes available to user.		*/
	copied = len;		/* Bytes that will be copied to user.	*/
	if (copied > ulen)
		copied = ulen;
	else if (copied < ulen)
		 msg->msg_flags |= MSG_TRUNC;

	rc = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (unlikely(rc))
		goto out_free;

	sock_recv_ts_and_drops(msg, sk, skb);

	/* Return source address. */
	if (sxia) {
		const struct xiphdr *xiph = xip_hdr(skb);
		copy_n_and_shade_sockaddr_xia(sxia,
			&xiph->dst_addr[xiph->num_dst], xiph->num_src);
	}

	/* XXX Add support to control messages that return extra information
	 * about the datagram.
	 * In net/ipv4/udp.c:udp_recvmsg this is done this way:
	 *	if (inet->cmsg_flags)
	 *		ip_cmsg_recv(msg, skb);
	 */

	rc = flags & MSG_TRUNC ? ulen : copied;

out_free:
	/* XXX Write a patch or not to replace to skb_free_datagram() here
	 * and IPv4's and IPv6's UDP implementation?
	 * See comment of net/core/datagram.c:__skb_recv_datagram
	 */
	skb_free_datagram_locked(sk, skb);
	return rc;
}

static int xdp_bind(struct sock *sk, struct sockaddr *uaddr, int node_n)
{
	DECLARE_SOCKADDR(struct sockaddr_xia *, addr, uaddr);
	struct xia_row *ssink = &addr->sxia_addr.s_row[node_n - 1];

	/* Make sure we are allowed to bind here. */
	if (ssink->s_xid.xid_type != XIDTYPE_XDP)
		return -EXTYNOSUPPORT;

	if (sk->sk_prot->get_port(sk, node_n))
		return -EADDRINUSE;

	return 0;
}

static int xdp_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct xia_sock *xia = xia_sk(sk);
	int rc;

	/* XXX Review RPS, see Documentation/networking/scaling.txt */
	if (xia->xia_daddr_set)
		sock_rps_save_rxhash(sk, skb);

	rc = sock_queue_rcv_skb(sk, skb);
	if (rc < 0) {
		kfree_skb(skb);
		return -1;
	}
	return 0;
}

static void xdp_hash_rehash(struct sock *sk)
{
	BUG();
}

static void xdp_unhash(struct sock *sk)
{
	struct xia_sock *xia = xia_sk(sk);
	struct net *net;
	struct fib_xid_xdp_local *lxdp;
	struct fib_xid_table *local_xtbl;

	if (!xia_sk_bound(xia))
		return;
	xia_reset_src(xia);

	net = sock_net(sk);
	sock_prot_inuse_add(net, sk->sk_prot, -1);

	/* Remove from routing table. */
	local_xtbl = xia_find_xtbl_hold(net->xia.local_rtbl, XIDTYPE_XDP);
	BUG_ON(!local_xtbl);
	lxdp = xiask_lxdp(xia);
	fib_rm_fxid(local_xtbl, &lxdp->fxid);

	/* Free DST entries. */

	/* We must wait here because, @lxdp may be reused before RCU synchs.*/
	synchronize_rcu();
	free_fxid_norcu(local_xtbl, &lxdp->fxid);
	xtbl_put(local_xtbl);
}

/* The second parameter of this method was repurposed to better fit XIA.
 * Originally it was `snum' for port numbers.
 */
static int xdp_get_port(struct sock *sk, unsigned short node_n)
{
	struct xia_sock	*xia = xia_sk(sk);
	struct xia_row	*ssink = &xia->xia_saddr.s_row[node_n - 1];
	struct net *net = sock_net(sk);
	struct fib_xid_xdp_local *lxdp;
	struct fib_xid_table *local_xtbl;
	int rc;

	lxdp = xiask_lxdp(xia);
	init_fxid(&lxdp->fxid, ssink->s_xid.xid_id);

	rcu_read_lock();
	local_xtbl = xia_find_xtbl_rcu(net->xia.local_rtbl, XIDTYPE_XDP);
	BUG_ON(!local_xtbl);
	rc = fib_add_fxid(local_xtbl, &lxdp->fxid);
	/* We don't sock_hold(sk) because @lxdp->fxid is always released
	 * before @lxdp is freed.
	 */
	rcu_read_unlock();

	if (!rc)
		sock_prot_inuse_add(net, sk->sk_prot, 1);
	return rc;
}

static long sysctl_xdp_mem[3] __read_mostly;
static int sysctl_xdp_rmem_min __read_mostly = SK_MEM_QUANTUM;
static int sysctl_xdp_wmem_min __read_mostly = SK_MEM_QUANTUM;
static atomic_long_t xdp_memory_allocated;

static struct proto xdp_prot __read_mostly = {
	.name			= "XDP/DGRAM",
	.owner			= THIS_MODULE,
	.close			= xdp_close,
	.connect		= xdp_connect,
	.disconnect		= xdp_disconnect,
	.ioctl			= xdp_ioctl,
	.destroy		= xdp_destroy_sock,
	.setsockopt		= xdp_setsockopt,
	.getsockopt		= xdp_getsockopt,
	.sendmsg		= xdp_sendmsg,
	.recvmsg		= xdp_recvmsg,
	/* XXX It'd be nice to have .sendpage */
	.bind			= xdp_bind,
	.backlog_rcv		= xdp_backlog_rcv,
	.hash			= xdp_hash_rehash,
	.unhash			= xdp_unhash,
	.rehash			= xdp_hash_rehash,
	.get_port		= xdp_get_port,
	.memory_allocated	= &xdp_memory_allocated,
	.sysctl_mem		= sysctl_xdp_mem,
	.sysctl_wmem		= &sysctl_xdp_wmem_min,
	.sysctl_rmem		= &sysctl_xdp_rmem_min,
	.obj_size		= sizeof(struct fib_xid_xdp_local),
	.slab_flags		= 0,
};

static const struct proto_ops xdp_dgram_ops = {
	.family		= PF_XIA,
	.owner		= THIS_MODULE,
	.release	= xia_release,
	.bind		= xia_bind,
	.connect	= xia_dgram_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= xia_getname,
	.poll		= datagram_poll,
	.ioctl		= xia_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= xia_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= xia_sendmsg,
	.recvmsg	= xia_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= xia_sendpage,
	/* XXX Does one need support to CONFIG_COMPAT? */
};

static const struct xia_socket_type_proc xdp_dgram = {
	.proto		= &xdp_prot,
	.alloc_slab	= true,
	.ops		= &xdp_dgram_ops,
};

static struct xia_socket_proc xdp_sock_proc __read_mostly = {
	.name			= "XDP",
	.ppal_type		= XIDTYPE_XDP,
	.procs[SOCK_DGRAM]	= &xdp_dgram,
};

/*
 *	Main
 */

static int __init xia_xdp_init(void)
{
	int rc;
	unsigned long limit;

	/* Follow net/ipv4/udp.c:udp_init(). */
	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_xdp_mem[0] = limit / 4 * 3;
	sysctl_xdp_mem[1] = limit;
	sysctl_xdp_mem[2] = sysctl_xdp_mem[0] * 2;

	rc = xia_register_pernet_subsys(&xdp_net_ops);
	if (rc)
		goto out;

	rc = xip_add_router(&xdp_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("xdp", XIDTYPE_XDP);
	if (rc)
		goto route;

	rc = xia_add_socket(&xdp_sock_proc);
	if (rc)
		goto map;

	pr_alert("XIA Principal XDP loaded\n");
	goto out;

map:
	ppal_del_map(XIDTYPE_XDP);
route:
	xip_del_router(&xdp_rt_proc);
net:
	xia_unregister_pernet_subsys(&xdp_net_ops);
out:
	return rc;
}

/*
 * xia_ad_exit - this function is called when the modlule is removed.
 */
static void __exit xia_xdp_exit(void)
{
	xia_del_socket_begin(&xdp_sock_proc);
	ppal_del_map(XIDTYPE_XDP);
	xip_del_router(&xdp_rt_proc);
	xia_unregister_pernet_subsys(&xdp_net_ops);
	xia_del_socket_end(&xdp_sock_proc);
	pr_alert("XIA Principal XDP UNloaded\n");
}

module_init(xia_xdp_init);
module_exit(xia_xdp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA XDP Principal");

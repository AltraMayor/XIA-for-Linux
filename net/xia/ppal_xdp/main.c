#include <linux/module.h>
#include <linux/swap.h>
#include <asm/ioctls.h>
#include <net/tcp_states.h>
#include <net/xia_list_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>
#include <net/xia_socket.h>
#include <net/xia_output.h>
#include <net/xia_vxidty.h>
#include <net/xia_xdp.h>

/* XDP context */

struct xip_xdp_ctx {
	struct xip_ppal_ctx	ctx;

	/* No extra field. */
};

static inline struct xip_xdp_ctx *ctx_xdp(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_xdp_ctx, ctx)
		: NULL;
}

static int my_vxt __read_mostly = -1;

/* Use a list FIB.
 *
 * NOTE
 *	To fully change the list FIB, you must change @xdp_all_rt_eops and
 *	member obj_size of @xdp_prot.
 */
static const struct xia_ppal_rt_iops *xdp_rt_iops = &xia_ppal_list_rt_iops;

/* Local XDPs */

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
	struct xip_dst_anchor   anchor;
	/* WARNING: @fxid is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		fxid;
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

static int local_dump_xdp(struct fib_xid *fxid, struct fib_xid_table *xtbl,
			  struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			  struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct xia_xid dst;
	const struct xia_sock *xia;

	nlh = nlmsg_put(skb, portid, seq, RTM_NEWROUTE, sizeof(*rtm),
			NLM_F_MULTI);
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

	nlmsg_end(skb, nlh);
	return 0;

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

static const xia_ppal_all_rt_eops_t xdp_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = fib_no_newroute,
		.delroute = fib_no_delroute,
		.dump_fxid = local_dump_xdp,
		.free_fxid = local_free_xdp,
	},

	XIP_LIST_FIB_REDIRECT_MAIN,
};

/* Network namespace */

static struct xip_xdp_ctx *create_xdp_ctx(void)
{
	struct xip_xdp_ctx *xdp_ctx = kmalloc(sizeof(*xdp_ctx), GFP_KERNEL);

	if (!xdp_ctx)
		return NULL;
	xip_init_ppal_ctx(&xdp_ctx->ctx, XIDTYPE_XDP);
	return xdp_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_xdp_ctx(struct xip_xdp_ctx *xdp_ctx)
{
	xip_release_ppal_ctx(&xdp_ctx->ctx);
	kfree(xdp_ctx);
}

static int __net_init xdp_net_init(struct net *net)
{
	struct xip_xdp_ctx *xdp_ctx;
	int rc;

	xdp_ctx = create_xdp_ctx();
	if (!xdp_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = xdp_rt_iops->xtbl_init(&xdp_ctx->ctx, net, &xia_main_lock_table,
				    xdp_all_rt_eops, xdp_rt_iops);
	if (rc)
		goto xdp_ctx;

	rc = xip_add_ppal_ctx(net, &xdp_ctx->ctx);
	if (rc)
		goto xdp_ctx;
	goto out;

xdp_ctx:
	free_xdp_ctx(xdp_ctx);
out:
	return rc;
}

static void __net_exit xdp_net_exit(struct net *net)
{
	struct xip_xdp_ctx *xdp_ctx =
		ctx_xdp(xip_del_ppal_ctx(net, XIDTYPE_XDP));
	free_xdp_ctx(xdp_ctx);
}

static struct pernet_operations xdp_net_ops __read_mostly = {
	.init = xdp_net_init,
	.exit = xdp_net_exit,
};

/* XDP Routing */

static int local_input_input(struct sk_buff *skb)
{
	struct xip_dst *xdst = skb_xdst(skb);
	struct sock *sk = xdst->info;

	if (sk_rcvqueues_full(sk, sk->sk_rcvbuf))
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

static int local_input_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	BUG();
}

#define local_output_input local_input_input

static int local_output_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	skb = xip_trim_packet_if_needed(skb, dev->mtu);
	if (!skb)
		return -1;

	skb->dev = dev;
	skb->protocol = __cpu_to_be16(ETH_P_XIP);

	/* Deliver @skb to its socket. */
	return dev_loopback_xmit(net, sk, skb);
}

static int xdp_deliver(struct xip_route_proc *rproc, struct net *net,
		       const u8 *xid, struct xia_xid *next_xid,
		       int anchor_index, struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct fib_xid *fxid;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, my_vxt);

	fxid = xdp_rt_iops->fxid_find_rcu(ctx->xpc_xtbl, xid);
	if (!fxid) {
		xdst_attach_to_anchor(xdst, anchor_index, &ctx->negdep);
		rcu_read_unlock();
		return XRP_ACT_NEXT_EDGE;
	}

	switch (fxid->fx_table_id) {
	case XRTABLE_LOCAL_INDEX: {
		/* It's a local XDP (i.e. a listening socket). */
		struct fib_xid_xdp_local *lxdp = fxid_lxdp(fxid);

		/* An XDP cannot be a passthrough. */
		xdst->passthrough_action = XDA_ERROR;

		xdst->sink_action = XDA_METHOD_AND_SELECT_EDGE;
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

static struct xip_route_proc xdp_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_XDP,
	.deliver = xdp_deliver,
};

/* Socket API */

static void xdp_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

/* Check that @addr holds a valid, nonempty address.
 *
 * NOTE
 *	Although XDP is not meant as a tool to poke other principals,
 *	one should not enforce that all sinks of a destination address
 *	are of type XIDTYPE_XDP; otherwise, a destination address with
 *	a non-XDP sink that routing redirects to a local XDP cannot
 *	be used.
 */
static int check_valid_nonempty_addr(struct sockaddr_xia *addr)
{
	int n = xia_test_addr(&addr->sxia_addr);

	if (n < 1) {
		/* Invalid address since it's empty. */
		return -EINVAL;
	}

	return n;
}

static int xdp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	DECLARE_SOCKADDR(struct sockaddr_xia *, daddr, uaddr);
	int rc, n;

	rc = check_valid_nonempty_addr(daddr);
	if (rc < 0)
		return rc;
	n = rc;

	lock_sock(sk);
	rc = xia_set_dest(xia_sk(sk), daddr->sxia_addr.s_row, n);
	release_sock(sk);
	return rc;
}

static int xdp_disconnect(struct sock *sk, int flags)
{
	sock_rps_reset_rxhash(sk);	/* XXX Review RPS calls. */
	lock_sock(sk);
	xia_reset_dest(xia_sk(sk));
	release_sock(sk);
	return 0;
}

/* first_packet_length - return length of first packet in receive queue
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

static int xdp_init(struct sock *sk)
{
	struct fib_xid_xdp_local *lxdp = sk_lxdp(sk);

	xdst_init_anchor(&lxdp->anchor);
	return 0;
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
static inline int xdp_send_skb(struct net *net, struct sk_buff *skb)
{
	return xip_send_skb(net, skb);
}

/* Push out all pending data as a single XDP datagram. Socket must be locked. */
static int xdp_push_pending_frames(struct sock *sk)
{
	struct fib_xid_xdp_local *lxdp = sk_lxdp(sk);
	struct sk_buff *skb = xip_finish_skb(sk);
	int rc = !IS_ERR_OR_NULL(skb) ? xdp_send_skb(sock_net(sk), skb) : PTR_ERR(skb);

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
		if (!val) {
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
	struct msghdr *msg = from;
	return copy_from_iter(to, len, &msg->msg_iter) != len ? -EFAULT : 0;
}

static int xdp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
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
			rc = xip_append_data(sk, xdp_getfrag, msg, len,
					     corkreq ?
					     msg->msg_flags|MSG_MORE :
					     msg->msg_flags);
			if (rc)
				xdp_flush_pending_frames(sk);
			else if (!corkreq)
				rc = xdp_push_pending_frames(sk);
			else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
				lxdp->pending = false;
			release_sock(sk);
			goto out;
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
		rc = check_valid_nonempty_addr(addr);
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

	/* From now on, don't just `return' or `goto out', but `goto xdst'! */

	if (msg->msg_flags & MSG_CONFIRM) {
		dst_confirm(&xdst->dst);
		if ((msg->msg_flags & MSG_PROBE) && !len) {
			rc = 0;
			goto xdst;
		}
	}

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		struct sk_buff *skb = xip_make_skb(sk, dest, dest_n,
			dest_last_node, xdp_getfrag, msg, len,
			0, xdst, msg->msg_flags);
		if (IS_ERR(skb))
			rc = PTR_ERR(skb);
		else if (!skb)
			rc = -SOCK_NOSPACE;
		else
			rc = xdp_send_skb(sock_net(sk), skb);
		goto xdst;
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
		net_dbg_ratelimited("XDP %s(): cork app bug\n", __func__);
		rc = -EINVAL;
		goto xdst;
	}

	rc = xip_start_skb(sk, xdst, dest, dest_n, dest_last_node, 0,
			   corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (rc) {
		release_sock(sk);
		goto xdst;
	}

	/* Now cork the socket to append data. */
	lxdp->pending = true;

	rc = xip_append_data(sk, xdp_getfrag, msg, len,
			     corkreq ?
			     msg->msg_flags|MSG_MORE :
			     msg->msg_flags);
	if (rc)
		xdp_flush_pending_frames(sk);
	release_sock(sk);

xdst:
	xdst_put(xdst);
out:
	return rc ? rc : len;
}

/* If there is a packet there, return it, otherwise block. */
static int xdp_recvmsg(struct sock *sk, struct msghdr *msg,
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

	rc = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (unlikely(rc))
		goto out_free;

	sock_recv_ts_and_drops(msg, sk, skb);

	/* Return source address. */
	if (sxia) {
		const struct xiphdr *xiph = xip_hdr(skb);
		copy_n_and_shade_sockaddr_xia(sxia,
					      &xiph->dst_addr[xiph->num_dst],
					      xiph->num_src);
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
	struct xip_deferred_negdep_flush *dnf;
	struct fib_xid_xdp_local *lxdp;
	const u8 *id;
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *xtbl;
	struct net *net;
	int rc;

	/* Make sure we are allowed to bind here. */
	if (ssink->s_xid.xid_type != XIDTYPE_XDP)
		return -EXTYNOSUPPORT;

	dnf = fib_alloc_dnf(GFP_KERNEL);
	if (!dnf)
		return -ENOMEM;

	lxdp = sk_lxdp(sk);
	id = ssink->s_xid.xid_id;
	net = sock_net(sk);
	ctx = xip_find_my_ppal_ctx_vxt(net, my_vxt);
	xtbl = ctx->xpc_xtbl;
	fxid_init(xtbl, &lxdp->fxid, id, XRTABLE_LOCAL_INDEX, 0);

	rc = xdp_rt_iops->fxid_add(xtbl, &lxdp->fxid);
	/* We don't sock_hold(sk) because @lxdp->fxid is always released
	 * before @lxdp is freed.
	 */
	if (rc) {
		fxid_free_norcu(xtbl, &lxdp->fxid);
		fib_free_dnf(dnf);
		return rc == -EEXIST ? -EADDRINUSE : rc;
	}

	fib_defer_dnf(dnf, net, XIDTYPE_XDP);
	sock_prot_inuse_add(net, sk->sk_prot, 1);
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
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *xtbl;
	struct fib_xid_xdp_local *lxdp;

	if (!xia_sk_bound(xia))
		return;
	xia_reset_src(xia);

	net = sock_net(sk);
	sock_prot_inuse_add(net, sk->sk_prot, -1);

	/* Remove from routing table. */
	ctx = xip_find_my_ppal_ctx_vxt(net, my_vxt);
	xtbl = ctx->xpc_xtbl;
	lxdp = xiask_lxdp(xia);
	xdp_rt_iops->fxid_rm(xtbl, &lxdp->fxid);

	/* Free DST entries. */

	/* We must wait here because, @lxdp may be reused before RCU synchs.*/
	synchronize_rcu();
	fxid_free_norcu(xtbl, &lxdp->fxid);
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
	.init			= xdp_init,
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
	.memory_allocated	= &xdp_memory_allocated,
	.sysctl_mem		= sysctl_xdp_mem,
	.sysctl_wmem		= &sysctl_xdp_wmem_min,
	.sysctl_rmem		= &sysctl_xdp_rmem_min,
	.obj_size		= sizeof(struct fib_xid_xdp_local) +
				  sizeof(struct list_fib_xid),
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

/* Main */

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

	rc = vxt_register_xidty(XIDTYPE_XDP);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for XDP\n");
		goto out;
	}
	my_vxt = rc;

	rc = xia_register_pernet_subsys(&xdp_net_ops);
	if (rc)
		goto vxt;

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
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_XDP));
out:
	return rc;
}

/* xia_xdp_exit - this function is called when the modlule is removed. */
static void __exit xia_xdp_exit(void)
{
	xia_del_socket_begin(&xdp_sock_proc);
	ppal_del_map(XIDTYPE_XDP);
	xip_del_router(&xdp_rt_proc);
	xia_unregister_pernet_subsys(&xdp_net_ops);
	xia_del_socket_end(&xdp_sock_proc);
	BUG_ON(vxt_unregister_xidty(XIDTYPE_XDP));

	rcu_barrier();

	pr_alert("XIA Principal XDP UNloaded\n");
}

module_init(xia_xdp_init);
module_exit(xia_xdp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA XDP Principal");

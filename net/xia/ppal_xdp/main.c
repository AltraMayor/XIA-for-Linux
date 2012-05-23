#include <linux/module.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>

/* XDP Principal */
#define XIDTYPE_XDP (__cpu_to_be32(0x12))

/*
 *	Local XDP table
 */

struct fib_xid_xdp_local {
	struct fib_xid		common;
	struct sock		sk;
	struct xip_dst_anchor   anchor;
};

static inline struct fib_xid_xdp_local *fxid_lxdp(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_xdp_local, common)
		: NULL;
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
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	/* TODO Add information about the socket. */

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_xdp(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	xdst_free_anchor(&fxid_lxdp(fxid)->anchor);
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
	struct xip_dst *xdst = skb_xdst(skb);
	struct net *net = xdst_net(xdst);
	struct net_device *dev = net->loopback_dev;

	skb->dev = dev;
	skb->protocol = __cpu_to_be16(ETH_P_XIP);

	/* XXX Add support to path MTU here. */
	if (unlikely(skb->len > dev->mtu)) {
		pr_err();
		kfree_skb(skb);
		return -1;
	}

	/* Deliver @skb to its socket.
	 * It's based on ipv4/ip_output.c:ip_dev_loopback_xmit.
	 * XXX Adopt dev_loopback_xmit.
	 */
	skb_reset_mac_header(skb);
	__skb_pull(skb, skb_network_offset(skb));
	skb->pkt_type = PACKET_LOOPBACK;
	WARN_ON(!xdst);
	skb_dst_force(skb);
	netif_rx_ni(skb);
	return 0;
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
	xdst->info = &lxdp->sk;
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

static int __init xia_xdp_init(void)
{
	int rc;

	rc = xia_register_pernet_subsys(&xdp_net_ops);
	if (rc)
		goto out;

	rc = xip_add_router(&xdp_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("xdp", XIDTYPE_XDP);
	if (rc)
		goto route;

	pr_alert("XIA Principal XDP loaded\n");
	goto out;

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
	ppal_del_map(XIDTYPE_XDP);
	xip_del_router(&xdp_rt_proc);
	xia_unregister_pernet_subsys(&xdp_net_ops);
	pr_alert("XIA Principal XDP UNloaded\n");
}

module_init(xia_xdp_init);
module_exit(xia_xdp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA XDP Principal");

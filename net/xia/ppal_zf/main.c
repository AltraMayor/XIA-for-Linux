#include <linux/module.h>
#include <net/xia_list_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>
#include <net/xia_vxidty.h>

/* zFilter principal */
#define XIDTYPE_ZF (__cpu_to_be32(0x20))

/* ZF context */

struct xip_zf_ctx {
	struct xip_ppal_ctx	ctx;

	/* Anchor any match in the FIB. */
	struct xip_dst_anchor	positive_anchor;
};

static inline struct xip_zf_ctx *ctx_zf(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_zf_ctx, ctx)
		: NULL;
}

static int my_vxt __read_mostly = -1;

/* Use a list FIB.
 *
 * NOTE
 *	To fully change the list FIB, you must change @zf_all_rt_eops.
 */
static const struct xia_ppal_rt_iops *zf_rt_iops = &xia_ppal_list_rt_iops;

/* Local ZFs */

struct fib_xid_zf_local {
	struct xip_dst_anchor   anchor;

	/* WARNING: @common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		common;
};

static inline struct fib_xid_zf_local *fxid_lzf(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_zf_local, common)
		: NULL;
}

static int local_newroute(struct xip_ppal_ctx *ctx,
			  struct fib_xid_table *xtbl,
			  struct xia_fib_config *cfg)
{
	struct fib_xid_zf_local *new_lzf;
	int rc;

	new_lzf = zf_rt_iops->fxid_ppal_alloc(sizeof(*new_lzf), GFP_KERNEL);
	if (!new_lzf)
		return -ENOMEM;
	fxid_init(xtbl, &new_lzf->common, cfg->xfc_dst->xid_id,
		  XRTABLE_LOCAL_INDEX, 0);
	xdst_init_anchor(&new_lzf->anchor);

	rc = zf_rt_iops->fib_newroute(&new_lzf->common, xtbl, cfg, NULL);
	if (rc)
		fxid_free_norcu(xtbl, &new_lzf->common);
	return rc;
}

static int local_dump_zf(struct fib_xid *fxid, struct fib_xid_table *xtbl,
			 struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			 struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct xia_xid dst;

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

	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_zf(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_zf_local *lzf = fxid_lzf(fxid);

	xdst_free_anchor(&lzf->anchor);
	kfree(lzf);
}

/* Main ZFs */

struct fib_xid_zf_main {
	struct xia_xid		gw;

	/* WARNING: @common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		common;
};

static inline struct fib_xid_zf_main *fxid_mzf(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_zf_main, common)
		: NULL;
}

static int main_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
			 struct xia_fib_config *cfg)
{
	struct fib_xid_zf_main *new_mzf;
	int rc;

	if (!cfg->xfc_gw || cfg->xfc_gw->xid_type == XIDTYPE_ZF)
		return -EINVAL;

	new_mzf = zf_rt_iops->fxid_ppal_alloc(sizeof(*new_mzf), GFP_KERNEL);
	if (!new_mzf)
		return -ENOMEM;
	fxid_init(xtbl, &new_mzf->common, cfg->xfc_dst->xid_id,
		  XRTABLE_MAIN_INDEX, 0);
	new_mzf->gw = *cfg->xfc_gw;

	rc = zf_rt_iops->fib_newroute(&new_mzf->common, xtbl, cfg, NULL);
	if (rc)
		fxid_free_norcu(xtbl, &new_mzf->common);
	return rc;
}

static int main_dump_zf(struct fib_xid *fxid, struct fib_xid_table *xtbl,
			struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_zf_main *mzf = fxid_mzf(fxid);
	struct xia_xid dst;

	nlh = nlmsg_put(skb, portid, seq, RTM_NEWROUTE, sizeof(*rtm),
			NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = XRTABLE_MAIN_INDEX;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	dst.xid_type = XIDTYPE_ZF;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);

	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst) ||
		     nla_put(skb, RTA_GATEWAY, sizeof(mzf->gw), &mzf->gw)))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void main_free_zf(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_zf_main *mzf = fxid_mzf(fxid);

	xdst_invalidate_redirect(xtbl_net(xtbl), XIDTYPE_ZF,
				 mzf->common.fx_xid, &mzf->gw);
	kfree(mzf);
}

static const xia_ppal_all_rt_eops_t zf_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = local_newroute,
		.delroute = list_fib_delroute,
		.dump_fxid = local_dump_zf,
		.free_fxid = local_free_zf,
	},

	[XRTABLE_MAIN_INDEX] = {
		.newroute = main_newroute,
		.delroute = list_fib_delroute,
		.dump_fxid = main_dump_zf,
		.free_fxid = main_free_zf,
	},
};

/* Network namespace */

static struct xip_zf_ctx *create_zf_ctx(void)
{
	struct xip_zf_ctx *zf_ctx = kmalloc(sizeof(*zf_ctx), GFP_KERNEL);

	if (!zf_ctx)
		return NULL;
	xip_init_ppal_ctx(&zf_ctx->ctx, XIDTYPE_ZF);
	xdst_init_anchor(&zf_ctx->positive_anchor);
	return zf_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_zf_ctx(struct xip_zf_ctx *zf_ctx)
{
	xdst_free_anchor(&zf_ctx->positive_anchor);
	xip_release_ppal_ctx(&zf_ctx->ctx);
	kfree(zf_ctx);
}

static int __net_init zf_net_init(struct net *net)
{
	struct xip_zf_ctx *zf_ctx;
	int rc;

	zf_ctx = create_zf_ctx();
	if (!zf_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = zf_rt_iops->xtbl_init(&zf_ctx->ctx, net, &xia_main_lock_table,
				   zf_all_rt_eops, zf_rt_iops);
	if (rc)
		goto zf_ctx;

	rc = xip_add_ppal_ctx(net, &zf_ctx->ctx);
	if (rc)
		goto zf_ctx;
	goto out;

zf_ctx:
	free_zf_ctx(zf_ctx);
out:
	return rc;
}

static void __net_exit zf_net_exit(struct net *net)
{
	struct xip_zf_ctx *zf_ctx =
		ctx_zf(xip_del_ppal_ctx(net, XIDTYPE_ZF));
	free_zf_ctx(zf_ctx);
}

static struct pernet_operations zf_net_ops __read_mostly = {
	.init = zf_net_init,
	.exit = zf_net_exit,
};

/* ZF Routing */

static int zf_match(const u8 *xid, const u8 *link_id)
{
	const u32 *xid32 = (const u32 *)xid;
	const u32 *link_id32 = (const u32 *)link_id;
	int i;

	BUILD_BUG_ON(XIA_XID_MAX % sizeof(u32));

	for (i = 0; i < (XIA_XID_MAX / sizeof(u32)); i++) {
		if ((*xid32 & *link_id32) != *link_id32)
			return 0;
		xid32++;
		link_id32++;
	}

	return 1;
}

/* Information added to DST entries. */
struct zf_dst_info {
	u8 xid[XIA_XID_MAX];
};

static struct zf_dst_info *create_zf_dst_info(const u8 *xid)
{
	struct zf_dst_info *info = kmalloc(sizeof(*info), GFP_ATOMIC);

	if (!info)
		return NULL;
	memmove(info->xid, xid, XIA_XID_MAX);
	return info;
}

struct iterate_arg {
	const u8 *xid;
	bool matched;
	bool forwarded_local;
	struct sk_buff *skb;
	struct xip_dst *xdst;
	struct net *net;
};

/* Return true if the packet is ill formed. */
static int dig_last_node(struct sk_buff *skb)
{
	struct xiphdr *xiph = xip_hdr(skb);
	int chosen_edge = skb_xdst(skb)->chosen_edge;
	struct xia_row *last_row = xip_last_row(xiph->dst_addr, xiph->num_dst,
		xiph->last_node);

	BUG_ON(chosen_edge < 0 || chosen_edge >= XIA_OUTDEGREE_MAX);
	xip_select_edge(&xiph->last_node, last_row, chosen_edge);

	/* One cannot use is_row_valid() instead of the test below
	 * because XIA_ENTRY_NODE_INDEX could wrongly show up as an edge.
	 */
	BUG_ON(xiph->last_node >= xiph->num_dst);

	/* A ZF XID followed by local LinkID cannot be a sink.
	 * Notice that the packet may not have a ZF XID since the ZF XID may
	 * have come from a routing redirect.
	 */
	last_row = xip_last_row(xiph->dst_addr, xiph->num_dst, xiph->last_node);
	return is_it_a_sink(last_row, xiph->last_node, xiph->num_dst);
}

static int forward_local(struct iterate_arg *iarg,
			 struct fib_xid_zf_local *lzf)
{
	struct sk_buff *cpy_skb;
	int rc;

	/* It doesn't make sense to foward multiple local matches,
	 * so we only forward the first successful one.
	 */
	if (iarg->forwarded_local)
		goto out;

	cpy_skb = pskb_copy(iarg->skb, GFP_ATOMIC);
	if (!cpy_skb) {
		net_warn_ratelimited("XIA/ZF: no atomic memory to forward a patcket with the chosen local ZF edge\n");
		goto out;
	}

	if (dig_last_node(cpy_skb)) {
		net_warn_ratelimited("XIA/ZF: can't forward ill-formed patcket with the chosen local ZF edge\n");
		/* If one cannot dig the last node once,
		 * one cannot dig it for all local entries.
		 * Thus, we mark the packet as forwarded.
		 */
		goto failed_to_forward;
	}

	/* Route and forward @cpy_skb. */
	skb_dst_drop(cpy_skb);
	rc = xip_route(iarg->net, cpy_skb, 0);
	if (rc) {
		net_warn_ratelimited("XIA/ZF: can't route a packet after digging the local ZF edge: %i\n",
				     rc);
		/* If one cannot forward this packet once,
		 * one cannot forward it for all local entries.
		 * Thus, we mark the packet as forwarded.
		 */
		goto failed_to_forward;
	}
	rc = dst_output(sock_net(cpy_skb->sk), cpy_skb->sk, cpy_skb);
	if (rc)
		net_warn_ratelimited("XIA/ZF: can't forward a packet after digging the local ZF edge: %i\n",
				     rc);
	goto forwarded;

failed_to_forward:
	kfree_skb(cpy_skb);
forwarded:
	iarg->forwarded_local = true;
out:
	return 0;
}

static int forward_main(struct iterate_arg *iarg, struct fib_xid_zf_main *mzf)
{
	struct sk_buff *cpy_skb;
	int rc;

	cpy_skb = pskb_copy(iarg->skb, GFP_ATOMIC);
	if (!cpy_skb) {
		net_warn_ratelimited("XIA/ZF: no atomic memory to forward a patcket with the chosen main ZF edge\n");
		return 0;
	}

	/* Route and forward @cpy_skb. */
	skb_dst_drop(cpy_skb);
	/* XXX This way of routing may lead to loops, which should be
	 * gracefully handled.
	 */
	rc = xip_route_with_a_redirect(iarg->net, cpy_skb, &mzf->gw,
				       iarg->xdst->chosen_edge, 0);
	if (rc) {
		net_warn_ratelimited("XIA/ZF: can't route a packet after redirecting the main ZF edge: %i\n",
				     rc);
		kfree_skb(cpy_skb);
		return 0;
	}
	rc = dst_output(sock_net(cpy_skb->sk), cpy_skb->sk, cpy_skb);
	if (rc)
		net_warn_ratelimited("XIA/ZF: can't forward a packet after routing the main ZF edge: %i\n",
				     rc);
	return 0;
}

static int match_xids_rcu(struct fib_xid_table *xtbl, struct fib_xid *fxid,
			  const void *arg)
{
	struct iterate_arg *iarg = (struct iterate_arg *)arg;

	if (!zf_match(iarg->xid, fxid->fx_xid))
		return 0;
	iarg->matched = true;

	switch (fxid->fx_table_id) {
	case XRTABLE_LOCAL_INDEX:
		return forward_local(iarg, fxid_lzf(fxid));

	case XRTABLE_MAIN_INDEX:
		return forward_main(iarg, fxid_mzf(fxid));
	}
	BUG();
}

static int zf_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct xip_dst *xdst = skb_xdst(skb);
	struct zf_dst_info *info = (struct zf_dst_info *)xdst->info;
	struct iterate_arg arg =
		{.xid = info->xid, .matched = false, .forwarded_local = false,
		.skb = skb, .xdst = xdst, .net = net};
	struct xip_ppal_ctx *ctx;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, my_vxt);
	BUG_ON(zf_rt_iops->iterate_xids_rcu(ctx->xpc_xtbl, match_xids_rcu,
					    &arg));
	rcu_read_unlock();

	if (!arg.matched) {
		/* Flush this DST entry. */
		if (del_xdst_and_hold(xdst))
			xdst_rcu_free(xdst);
	}

	kfree_skb(skb);
	return NET_RX_SUCCESS;
}

static int match_any_xid_rcu(struct fib_xid_table *xtbl, struct fib_xid *fxid,
			     const void *arg)
{
	return zf_match(arg, fxid->fx_xid);
}

static int zf_deliver(struct xip_route_proc *rproc, struct net *net,
		      const u8 *xid, struct xia_xid *next_xid,
		      int anchor_index, struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct xip_zf_ctx *zf_ctx;
	struct zf_dst_info *info;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, my_vxt);
	zf_ctx = ctx_zf(ctx);

	if (!zf_rt_iops->iterate_xids_rcu(ctx->xpc_xtbl, match_any_xid_rcu,
					  xid)) {
		/* There's no matches. */
		xdst_attach_to_anchor(xdst, anchor_index, &ctx->negdep);
		rcu_read_unlock();
		return XRP_ACT_NEXT_EDGE;
	}

	info = create_zf_dst_info(xid);
	if (unlikely(!info)) {
		rcu_read_unlock();
		/* Not enough memory to conclude this operation. */
		return XRP_ACT_ABRUPT_FAILURE;
	}
	xdst->info = info;
	xdst->ppal_destroy = def_ppal_destroy;

	xdst->passthrough_action = XDA_METHOD;
	xdst->sink_action = XDA_METHOD;
	BUG_ON(xdst->dst.dev);
	xdst->dst.dev = net->loopback_dev;
	dev_hold(xdst->dst.dev);
	xdst->dst.input = xdst_def_hop_limit_input_method;
	xdst->dst.output = zf_output;

	xdst_attach_to_anchor(xdst, anchor_index, &zf_ctx->positive_anchor);
	rcu_read_unlock();
	return XRP_ACT_FORWARD;
}

static struct xip_route_proc zf_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_ZF,
	.deliver = zf_deliver,
};

/* xia_zf_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_zf_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_ZF);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for ZF\n");
		goto out;
	}
	my_vxt = rc;

	rc = xia_register_pernet_subsys(&zf_net_ops);
	if (rc)
		goto vxt;

	rc = xip_add_router(&zf_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("zf", XIDTYPE_ZF);
	if (rc)
		goto route;

	pr_alert("XIA Principal ZF loaded\n");
	goto out;

route:
	xip_del_router(&zf_rt_proc);
net:
	xia_unregister_pernet_subsys(&zf_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_ZF));
out:
	return rc;
}

/* xia_zf_exit - this function is called when the modlule is removed. */
static void __exit xia_zf_exit(void)
{
	ppal_del_map(XIDTYPE_ZF);
	xip_del_router(&zf_rt_proc);
	xia_unregister_pernet_subsys(&zf_net_ops);
	BUG_ON(vxt_unregister_xidty(XIDTYPE_ZF));

	rcu_barrier();

	pr_alert("XIA Principal ZF UNloaded\n");
}

module_init(xia_zf_init);
module_exit(xia_zf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Autonomous Domain Principal");

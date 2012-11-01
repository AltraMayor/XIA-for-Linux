#include <linux/module.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>

/* Autonomous Domain Principal */
#define XIDTYPE_AD (__cpu_to_be32(0x10))

/*
 *	AD context
 */

struct xip_ad_ctx {
	struct xip_ppal_ctx	ctx;
};

static inline struct xip_ad_ctx *ctx_ad(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_ad_ctx, ctx)
		: NULL;
}

/*
 *	Local AD table
 */

struct fib_xid_ad_local {
	struct fib_xid		common;

	struct xip_dst_anchor   anchor;
};

static inline struct fib_xid_ad_local *fxid_lad(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ad_local, common)
		: NULL;
}

static int local_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	struct fib_xid_ad_local *lad;
	int rc;

	rc = -ENOMEM;
	lad = kzalloc(sizeof(*lad), GFP_KERNEL);
	if (!lad)
		goto out;

	init_fxid(&lad->common, cfg->xfc_dst->xid_id);

	rc = fib_add_fxid(xtbl, &lad->common);
	if (rc)
		goto lad;
	goto out;

lad:
	free_fxid(xtbl, &lad->common);
out:
	return rc;
}

/* Based on net/ipv4/fib_semantics.c:fib_dump_info and its call in
 * net/ipv4/fib_trie.c:fn_trie_dump_fa.
 */
static int local_dump_ad(struct fib_xid *fxid, struct fib_xid_table *xtbl,
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

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_ad(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_ad_local *lad = fxid_lad(fxid);
	xdst_free_anchor(&lad->anchor);
	kfree(lad);
}

static const struct xia_ppal_rt_eops ad_rt_eops_local = {
	.newroute = local_newroute,
	.delroute = fib_default_delroute,
	.dump_fxid = local_dump_ad,
	.free_fxid = local_free_ad,
};

/*
 *	Main AD table
 */

struct fib_xid_ad_main {
	struct fib_xid		common;
	struct xia_xid		gw;
};

static inline struct fib_xid_ad_main *fxid_mad(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ad_main, common)
		: NULL;
}

static int main_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	struct fib_xid_ad_main *mad;
	int rc;

	rc = -EINVAL;
	if (!cfg->xfc_gw || cfg->xfc_gw->xid_type == XIDTYPE_AD)
		goto out;

	rc = -ENOMEM;
	mad = kzalloc(sizeof(*mad), GFP_KERNEL);
	if (!mad)
		goto out;

	init_fxid(&mad->common, cfg->xfc_dst->xid_id);
	mad->gw = *cfg->xfc_gw;

	rc = fib_add_fxid(xtbl, &mad->common);
	if (rc)
		goto mad;
	goto out;

mad:
	free_fxid(xtbl, &mad->common);
out:
	return rc;
}

static int main_dump_ad(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct xip_ppal_ctx *ctx, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_ad_main *mad = fxid_mad(fxid);
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

	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);

	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst) ||
			nla_put(skb, RTA_GATEWAY, sizeof(mad->gw), &mad->gw)
		))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void main_free_ad(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_ad_main *mad = fxid_mad(fxid);
	xdst_invalidate_redirect(xtbl_net(xtbl), XIDTYPE_AD,
		mad->common.fx_xid, &mad->gw);
	kfree(mad);
}

static const struct xia_ppal_rt_eops ad_rt_eops_main = {
	.newroute = main_newroute,
	.delroute = fib_default_delroute,
	.dump_fxid = main_dump_ad,
	.free_fxid = main_free_ad,
};

/*
 *	Network namespace
 */

static struct xip_ad_ctx *create_ad_ctx(void)
{
	struct xip_ad_ctx *ad_ctx = kmalloc(sizeof(*ad_ctx), GFP_KERNEL);
	if (!ad_ctx)
		return NULL;
	xip_init_ppal_ctx(&ad_ctx->ctx, XIDTYPE_AD);
	return ad_ctx;
}

static void free_ad_ctx(struct xip_ad_ctx *ad_ctx)
{
	xip_release_ppal_ctx(&ad_ctx->ctx);
	kfree(ad_ctx);
}

static int __net_init ad_net_init(struct net *net)
{
	struct xip_ad_ctx *ad_ctx;
	int rc;

	ad_ctx = create_ad_ctx();
	if (!ad_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = init_xid_table(&ad_ctx->ctx, XRTABLE_LOCAL_INDEX, net,
		&xia_main_lock_table, &ad_rt_eops_local);
	if (rc)
		goto ad_ctx;
	rc = init_xid_table(&ad_ctx->ctx, XRTABLE_MAIN_INDEX, net,
		&xia_main_lock_table, &ad_rt_eops_main);
	if (rc)
		goto ad_ctx;

	rc = xip_add_ppal_ctx(&net->xia.fib_ctx, &ad_ctx->ctx);
	if (rc)
		goto ad_ctx;
	goto out;

ad_ctx:
	free_ad_ctx(ad_ctx);
out:
	return rc;
}

static void __net_exit ad_net_exit(struct net *net)
{
	struct xip_ad_ctx *ad_ctx =
		ctx_ad(xip_del_ppal_ctx(&net->xia.fib_ctx, XIDTYPE_AD));
	free_ad_ctx(ad_ctx);
}

static struct pernet_operations ad_net_ops __read_mostly = {
	.init = ad_net_init,
	.exit = ad_net_exit,
};

/*
 *	AD Routing
 */

static int ad_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, struct xia_xid *next_xid, int anchor_index,
	struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *local_xtbl;
	struct fib_xid_ad_local *lad;
	struct fib_xid_table *main_xtbl;
	struct fib_xid_ad_main *mad;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_rcu(&net->xia.fib_ctx, XIDTYPE_AD);
	BUG_ON(!ctx);

	/* Is it a local AD? */
	local_xtbl = ctx->xpc_xid_tables[XRTABLE_LOCAL_INDEX];
	BUG_ON(!local_xtbl);
	lad = fxid_lad(xia_find_xid_rcu(local_xtbl, xid));
	if (lad) {
		xdst->passthrough_action = XDA_DIG;
		xdst->sink_action = XDA_ERROR; /* An AD cannot be a sink. */
		xdst_attach_to_anchor(xdst, anchor_index, &lad->anchor);
		rcu_read_unlock();
		return XRP_ACT_FORWARD;
	}

	/* Is it a main AD? */
	main_xtbl = ctx->xpc_xid_tables[XRTABLE_MAIN_INDEX];
	BUG_ON(!main_xtbl);
	mad = fxid_mad(xia_find_xid_rcu(main_xtbl, xid));
	if (mad) {
		memmove(next_xid, &mad->gw, sizeof(*next_xid));
		rcu_read_unlock();
		return XRP_ACT_REDIRECT;
	}

	rcu_read_unlock();
	return XRP_ACT_NEXT_EDGE;
}

static struct xip_route_proc ad_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_AD,
	.deliver = ad_deliver,
};

/*
 * xia_ad_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_ad_init(void)
{
	int rc;

	rc = xia_register_pernet_subsys(&ad_net_ops);
	if (rc)
		goto out;

	rc = xip_add_router(&ad_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("ad", XIDTYPE_AD);
	if (rc)
		goto route;

	pr_alert("XIA Principal AD loaded\n");
	goto out;

route:
	xip_del_router(&ad_rt_proc);
net:
	xia_unregister_pernet_subsys(&ad_net_ops);
out:
	return rc;
}

/*
 * xia_ad_exit - this function is called when the modlule is removed.
 */
static void __exit xia_ad_exit(void)
{
	ppal_del_map(XIDTYPE_AD);
	xip_del_router(&ad_rt_proc);
	xia_unregister_pernet_subsys(&ad_net_ops);
	pr_alert("XIA Principal AD UNloaded\n");
}

module_init(xia_ad_init);
module_exit(xia_ad_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Autonomous Domain Principal");

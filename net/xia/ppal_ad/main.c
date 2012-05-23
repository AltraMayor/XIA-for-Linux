#include <linux/module.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>

/* Autonomous Domain Principal */
#define XIDTYPE_AD (__cpu_to_be32(0x10))

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

static int local_newroute(struct fib_xid_table *xtbl,
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

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_ad(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	xdst_free_anchor(&fxid_lad(fxid)->anchor);
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

static int main_newroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
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
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 pid = NETLINK_CB(cb->skb).pid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_ad_main *mad = fxid_mad(fxid);
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

static int __net_init ad_net_init(struct net *net)
{
	int rc;

	rc = init_xid_table(net->xia.local_rtbl, XIDTYPE_AD,
		&xia_main_lock_table, &ad_rt_eops_local);
	if (rc)
		goto out;
	rc = init_xid_table(net->xia.main_rtbl, XIDTYPE_AD,
		&xia_main_lock_table, &ad_rt_eops_main);
	if (rc)
		goto local_rtbl;
	goto out;

local_rtbl:
	end_xid_table(net->xia.local_rtbl, XIDTYPE_AD);
out:
	return rc;
}

static void __net_exit ad_net_exit(struct net *net)
{
	rtnl_lock();
	end_xid_table(net->xia.main_rtbl, XIDTYPE_AD);
	end_xid_table(net->xia.local_rtbl, XIDTYPE_AD);
	rtnl_unlock();
}

static struct pernet_operations ad_net_ops __read_mostly = {
	.init = ad_net_init,
	.exit = ad_net_exit,
};

/*
 *	AD Routing
 */

static int ad_local_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, int anchor_index, struct xip_dst *xdst)
{
	struct fib_xid_table *local_xtbl;
	struct fib_xid_ad_local *lad;

	rcu_read_lock();
	local_xtbl = xia_find_xtbl_rcu(net->xia.local_rtbl, XIDTYPE_AD);
	BUG_ON(!local_xtbl);
	lad = fxid_lad(xia_find_xid_rcu(local_xtbl, xid));
	if (!lad) {
		rcu_read_unlock();
		return -ENOENT;
	}

	xdst->passthrough_action = XDA_DIG;
	xdst->sink_action = XDA_ERROR; /* An AD cannot be a sink. */
	xdst_attach_to_anchor(xdst, anchor_index, &lad->anchor);

	rcu_read_unlock();
	return 0;
}

static int ad_main_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, struct xia_xid *next_xid, int anchor_index,
	struct xip_dst *xdst)
{
	struct fib_xid_table *main_xtbl;
	struct fib_xid_ad_main *mad;
	int rc;

	rcu_read_lock();
	main_xtbl = xia_find_xtbl_rcu(net->xia.main_rtbl, XIDTYPE_AD);
	BUG_ON(!main_xtbl);
	mad = fxid_mad(xia_find_xid_rcu(main_xtbl, xid));

	rc = XRP_ACT_NEXT_EDGE;
	if (!mad)
		goto out;

	memmove(next_xid, &mad->gw, sizeof(*next_xid));
	rc = XRP_ACT_REDIRECT;

out:
	rcu_read_unlock();
	return rc;
}

static struct xip_route_proc ad_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_AD,
	.local_deliver = ad_local_deliver,
	.main_deliver = ad_main_deliver,
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

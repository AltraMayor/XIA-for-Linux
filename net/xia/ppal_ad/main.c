#include <linux/module.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>
#include <net/xia_vxidty.h>

/* Autonomous Domain Principal */
#define XIDTYPE_AD (__cpu_to_be32(0x10))

/*
 *	AD context
 */

struct xip_ad_ctx {
	struct xip_ppal_ctx	ctx;
	struct xip_dst_anchor	negdep;
};

static inline struct xip_ad_ctx *ctx_ad(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_ad_ctx, ctx)
		: NULL;
}

static int my_vxt __read_mostly = -1;

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

static void local_deferred_negdep(struct net *net, struct xia_xid *xid);

static int local_newroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *local_xtbl, struct xia_fib_config *cfg)
{
	struct deferred_xip_update *def_upd;
	struct fib_xid_ad_local *new_lad, *cur_lad;
	const u8 *id;
	u32 local_bucket;
	int rc;

	/* Allocate memory before acquiring lock because we can sleep now. */

	def_upd = fib_alloc_xip_upd(GFP_KERNEL);
	if (!def_upd)
		return -ENOMEM;

	new_lad = kmalloc(sizeof(*new_lad), GFP_KERNEL);
	if (!new_lad) {
		rc = -ENOMEM;
		goto def_upd;
	}
	id = cfg->xfc_dst->xid_id;
	init_fxid(&new_lad->common, id);
	xdst_init_anchor(&new_lad->anchor);

	/* Acquire lock. */
	cur_lad = fxid_lad(xia_find_xid_lock(&local_bucket, local_xtbl, id));

	if (cur_lad) {
		if ((cfg->xfc_nlflags & NLM_F_EXCL) ||
			!(cfg->xfc_nlflags & NLM_F_REPLACE)) {
			rc = -EEXIST;
			goto unlock_local;
		}

		/* Replace entry.
		 * Since local entries are identical, there's nothing to
		 * do here.
		 */
		rc = 0;
		goto unlock_local;
	}

	if (!(cfg->xfc_nlflags & NLM_F_CREATE)) {
		rc = -ENOENT;
		goto unlock_local;
	}

	/* Add new entry. */

	BUG_ON(fib_add_fxid_locked(local_bucket, local_xtbl, &new_lad->common));
	fib_unlock_bucket(local_xtbl, local_bucket);

	/* Before invalidating old anchors to force dependencies to
	 * migrate to @new_lad, wait an RCU synchronization to make sure that
	 * every thread see @new_lad.
	 */
	fib_defer_xip_upd(def_upd, local_deferred_negdep,
		xtbl_net(local_xtbl), XIDTYPE_AD, id);
	return 0;

unlock_local:
	fib_unlock_bucket(local_xtbl, local_bucket);
	free_fxid(local_xtbl, &new_lad->common);
def_upd:
	fib_free_xip_upd(def_upd);
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

static void local_deferred_negdep(struct net *net, struct xia_xid *xid)
{
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *main_xtbl;
	struct fib_xid_ad_main *mad;

	BUG_ON(xid->xid_type != XIDTYPE_AD);

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, my_vxt);
	if (unlikely(!ctx)) {
		/* Principal is unloading. */
		goto out;
	}
	main_xtbl = ctx->xpc_xid_tables[XRTABLE_MAIN_INDEX];
	mad = fxid_mad(xia_find_xid_rcu(main_xtbl, xid->xid_id));
	if (mad) {
		xdst_invalidate_redirect(net, xid->xid_type, xid->xid_id,
			&mad->gw);
	} else {
		/* Flush all @negdep due to XID redirects. */
		xdst_free_anchor(&ctx_ad(ctx)->negdep);
	}
out:
	rcu_read_unlock();
}

static void main_deferred_negdep(struct net *net, struct xia_xid *xid)
{
	struct xip_ad_ctx *ad_ctx;

	BUG_ON(xid->xid_type != XIDTYPE_AD);

	rcu_read_lock();
	ad_ctx = ctx_ad(xip_find_ppal_ctx_vxt_rcu(net, my_vxt));
	if (likely(ad_ctx)) {
		/* Flush all @negdep due to XID redirects. */
		xdst_free_anchor(&ad_ctx->negdep);
	}
	rcu_read_unlock();
}

static int main_newroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *main_xtbl, struct xia_fib_config *cfg)
{
	struct deferred_xip_update *def_upd;
	struct fib_xid_ad_main *new_mad, *cur_mad;
	const u8 *id;
	u32 main_bucket;
	int rc;

	if (!cfg->xfc_gw || cfg->xfc_gw->xid_type == XIDTYPE_AD)
		return -EINVAL;

	/* Allocate memory before acquiring lock because we can sleep now. */

	def_upd = fib_alloc_xip_upd(GFP_KERNEL);
	if (!def_upd)
		return -ENOMEM;

	new_mad = kmalloc(sizeof(*new_mad), GFP_KERNEL);
	if (!new_mad) {
		rc = -ENOMEM;
		goto def_upd;
	}
	id = cfg->xfc_dst->xid_id;
	init_fxid(&new_mad->common, id);
	new_mad->gw = *cfg->xfc_gw;

	/* Acquire lock. */
	cur_mad = fxid_mad(xia_find_xid_lock(&main_bucket, main_xtbl, id));

	if (cur_mad) {
		if ((cfg->xfc_nlflags & NLM_F_EXCL) ||
			!(cfg->xfc_nlflags & NLM_F_REPLACE)) {
			rc = -EEXIST;
			goto unlock_main;
		}

		/* Replace entry. */

		rc = 0;
		if (!memcmp(&cur_mad->gw, &new_mad->gw, sizeof(cur_mad->gw))) {
			/* Since main entries are identical,
			 * there's nothing to do here.
			 */
			goto unlock_main;
		} else {
			fib_replace_fxid_locked(main_xtbl, &cur_mad->common,
				&new_mad->common);
			fib_unlock_bucket(main_xtbl, main_bucket);
			free_fxid(main_xtbl, &cur_mad->common);
			goto def_upd;
		}
	}

	if (!(cfg->xfc_nlflags & NLM_F_CREATE)) {
		rc = -ENOENT;
		goto unlock_main;
	}

	/* Add new entry. */

	BUG_ON(fib_add_fxid_locked(main_bucket, main_xtbl, &new_mad->common));
	fib_unlock_bucket(main_xtbl, main_bucket);

	/* Before invalidating old anchors to force dependencies to
	 * migrate to @new_mad, wait an RCU synchronization to make sure that
	 * every thread see @new_mad.
	 */
	fib_defer_xip_upd(def_upd, main_deferred_negdep,
		xtbl_net(main_xtbl), XIDTYPE_AD, id);
	return 0;

unlock_main:
	fib_unlock_bucket(main_xtbl, main_bucket);
	free_fxid(main_xtbl, &new_mad->common);
def_upd:
	fib_free_xip_upd(def_upd);
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
	xdst_init_anchor(&ad_ctx->negdep);
	return ad_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_ad_ctx(struct xip_ad_ctx *ad_ctx)
{
	/* It's assumed that synchronize_rcu() has been called before. */
	xdst_free_anchor(&ad_ctx->negdep);

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

	rc = xip_add_ppal_ctx(net, &ad_ctx->ctx);
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
		ctx_ad(xip_del_ppal_ctx(net, XIDTYPE_AD));
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
	ctx = xip_find_ppal_ctx_vxt_rcu(net, my_vxt);
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

	xdst_attach_to_anchor(xdst, anchor_index, &ctx_ad(ctx)->negdep);
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

	rc = vxt_register_xidty(XIDTYPE_AD);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for AD\n");
		goto out;
	}
	my_vxt = rc;

	rc = xia_register_pernet_subsys(&ad_net_ops);
	if (rc)
		goto vxt;

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
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_AD));
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
	BUG_ON(vxt_unregister_xidty(XIDTYPE_AD));

	rcu_barrier();

	pr_alert("XIA Principal AD UNloaded\n");
}

module_init(xia_ad_init);
module_exit(xia_ad_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Autonomous Domain Principal");

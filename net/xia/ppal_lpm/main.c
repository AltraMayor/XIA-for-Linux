#include <linux/init.h>
#include <linux/module.h>
#include <net/xia_vxidty.h>
#include <net/xia_dag.h>
#include <net/xia_lpm.h>

#define XIDTYPE_LPM            (__cpu_to_be32(0x21))
struct xip_lpm_ctx {
	struct xip_ppal_ctx	ctx;

	/* No extra fields. */
};

static inline struct xip_lpm_ctx *ctx_lpm(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_lpm_ctx, ctx)
		: NULL;
}

static int my_vxt __read_mostly = -1;

/* Local LPMs */

struct fib_xid_lpm_local {
	struct xip_dst_anchor	anchor;

	/* WARNING: @common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid 		common;
};

static inline struct fib_xid_lpm_local *fxid_llpm(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_lpm_local, common)
		: NULL;
}

/* Use a tree FIB.
 *
 * NOTE
 *      To fully change the tree FIB, you must change @lpm_all_rt_eops
 *	as well as the tree FIB calls in local_newroute().
 */
const struct xia_ppal_rt_iops *lpm_rt_iops = &xia_ppal_tree_rt_iops;

/* Assuming the FIB is locked, find the appropriate anchor,
 * flush it, and unlock the FIB.
 */
static void newroute_flush_anchor_locked(struct fib_xid_table *xtbl,
					 struct fib_xid *new_fxid,
					 struct xip_deferred_negdep_flush *dnf)
{
	struct fib_xid *pred_fxid = tree_fib_get_pred_locked(new_fxid);

	if (!pred_fxid) {
		lpm_rt_iops->fib_unlock(xtbl, NULL);
		fib_defer_dnf(dnf, xtbl_net(xtbl), xtbl_ppalty(xtbl));
		return;
	}

	fib_free_dnf(dnf);
	synchronize_rcu();
	switch (pred_fxid->fx_table_id) {
	case XRTABLE_LOCAL_INDEX:
		xdst_free_anchor(&fxid_llpm(pred_fxid)->anchor);
		break;
	case XRTABLE_MAIN_INDEX:
		xdst_invalidate_redirect(xtbl_net(xtbl), xtbl_ppalty(xtbl),
					 pred_fxid->fx_xid,
					 &fxid_mrd(pred_fxid)->gw);
		break;
	default:
		BUG();
	}
	lpm_rt_iops->fib_unlock(xtbl, NULL);
}

static int local_newroute(struct xip_ppal_ctx *ctx,
			  struct fib_xid_table *xtbl,
			  struct xia_fib_config *cfg)
{
	struct xip_deferred_negdep_flush *dnf;
	struct fib_xid_lpm_local *new_llpm;
	int rc;

	if (!valid_prefix(cfg))
		return -EINVAL;

	new_llpm = lpm_rt_iops->fxid_ppal_alloc(sizeof(*new_llpm), GFP_KERNEL);
	if (!new_llpm)
		return -ENOMEM;

	dnf = fib_alloc_dnf(GFP_KERNEL);
	if (!dnf) {
		kfree(new_llpm);
		return -ENOMEM;
	}

	/* Construct a new FIB entry, with the entry type being
	 * the prefix length (the third parameter).
	 */
	fxid_init(xtbl, &new_llpm->common, cfg->xfc_dst->xid_id,
		  XRTABLE_LOCAL_INDEX, *(u8 *)cfg->xfc_protoinfo);
	xdst_init_anchor(&new_llpm->anchor);

	/* Use special version of newroute that keeps lock so that
	 * we can add an entry and find the appropriate predecessor
	 * atomically to flush the appropriate anchor.
	 */
	rc = tree_fib_newroute_lock(&new_llpm->common, xtbl, cfg, NULL);
	if (rc) {
		fib_free_dnf(dnf);
		fxid_free_norcu(xtbl, &new_llpm->common);
		return rc;
	}

	/* Flush appropriate anchor and release lock. */
	newroute_flush_anchor_locked(xtbl, &new_llpm->common, dnf);
	return 0;
}

static int local_dump_lpm(struct fib_xid *fxid, struct fib_xid_table *xtbl,
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

	/* Add prefix length to packet. */
	if (unlikely(nla_put(skb, RTA_PROTOINFO, sizeof(fxid->fx_entry_type),
			     &(fxid->fx_entry_type))))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_lpm(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_lpm_local *llpm = fxid_llpm(fxid);

	xdst_free_anchor(&llpm->anchor);
	kfree(llpm);
}

static int main_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
			 struct xia_fib_config *cfg)
{
	struct xip_deferred_negdep_flush *dnf;
	struct fib_xid_redirect_main *new_mrd;
	int rc;

	if (!valid_prefix(cfg) || !cfg->xfc_gw ||
	    cfg->xfc_gw->xid_type == xtbl_ppalty(xtbl))
		return -EINVAL;

	new_mrd = lpm_rt_iops->fxid_ppal_alloc(sizeof(*new_mrd), GFP_KERNEL);
	if (!new_mrd)
		return -ENOMEM;

	dnf = fib_alloc_dnf(GFP_KERNEL);
	if (!dnf) {
		kfree(new_mrd);
		return -ENOMEM;
	}

	fxid_init(xtbl, &new_mrd->common, cfg->xfc_dst->xid_id,
		  XRTABLE_MAIN_INDEX, *(u8 *)cfg->xfc_protoinfo);
	new_mrd->gw = *cfg->xfc_gw;

	/* Use special version of newroute that keeps lock so that
	 * we can add an entry and find the appropriate predecessor
	 * atomically to flush the appropriate anchor.
	 */
	rc = tree_fib_newroute_lock(&new_mrd->common, xtbl, cfg, NULL);
	if (rc) {
		fib_free_dnf(dnf);
		fxid_free_norcu(xtbl, &new_mrd->common);
		return rc;
	}

	/* Flush appropriate anchor and release lock. */
	newroute_flush_anchor_locked(xtbl, &new_mrd->common, dnf);
	return 0;
}

static const xia_ppal_all_rt_eops_t lpm_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = local_newroute,
		.delroute = tree_fib_delroute,
		.dump_fxid = local_dump_lpm,
		.free_fxid = local_free_lpm,
	},

	[XRTABLE_MAIN_INDEX] = {
		.newroute = main_newroute,
		.delroute = tree_fib_delroute,
		.dump_fxid = tree_fib_mrd_dump,
		.free_fxid = fib_mrd_free,
	},
};

/* Network namespace */

static struct xip_lpm_ctx *create_lpm_ctx(void)
{
	struct xip_lpm_ctx *lpm_ctx = kmalloc(sizeof(*lpm_ctx), GFP_KERNEL);

	if (!lpm_ctx)
		return NULL;
	xip_init_ppal_ctx(&lpm_ctx->ctx, XIDTYPE_LPM);
	return lpm_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_lpm_ctx(struct xip_lpm_ctx *lpm_ctx)
{
	xip_release_ppal_ctx(&lpm_ctx->ctx);
	kfree(lpm_ctx);
}

static int __net_init lpm_net_init(struct net *net)
{
	struct xip_lpm_ctx *lpm_ctx;
	int rc;

	lpm_ctx = create_lpm_ctx();
	if (!lpm_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = lpm_rt_iops->xtbl_init(&lpm_ctx->ctx, net, &xia_main_lock_table,
				    lpm_all_rt_eops, lpm_rt_iops);
	if (rc)
		goto lpm_ctx;

	rc = xip_add_ppal_ctx(net, &lpm_ctx->ctx);
	if (rc)
		goto lpm_ctx;
	goto out;

lpm_ctx:
	free_lpm_ctx(lpm_ctx);
out:
	return rc;
}

static void __net_exit lpm_net_exit(struct net *net)
{
	struct xip_lpm_ctx *lpm_ctx =
		ctx_lpm(xip_del_ppal_ctx(net, XIDTYPE_LPM));
	free_lpm_ctx(lpm_ctx);
}

static struct pernet_operations lpm_net_ops __read_mostly = {
	.init = lpm_net_init,
	.exit = lpm_net_exit,
};

/* LPM Routing */

static int lpm_deliver(struct xip_route_proc *rproc, struct net *net,
		       const u8 *xid, struct xia_xid *next_xid,
		       int anchor_index, struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct fib_xid *fxid;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, my_vxt);

	/* Note that since LPM does not use RCU, we use the locking
	 * form of fxid_find_lock, and we must later unlock it.
	 */
	fxid = lpm_rt_iops->fxid_find_lock(NULL, ctx->xpc_xtbl, xid);
	if (!fxid) {
		xdst_attach_to_anchor(xdst, anchor_index, &ctx->negdep);
		lpm_rt_iops->fib_unlock(ctx->xpc_xtbl, NULL);
		rcu_read_unlock();
		return XRP_ACT_NEXT_EDGE;
	}

	switch (fxid->fx_table_id) {
	case XRTABLE_LOCAL_INDEX: {
		struct fib_xid_lpm_local *llpm = fxid_llpm(fxid);

		xdst->passthrough_action = XDA_DIG;
		xdst->sink_action = XDA_ERROR; /* An LPM cannot be a sink. */
		xdst_attach_to_anchor(xdst, anchor_index, &llpm->anchor);
		lpm_rt_iops->fib_unlock(ctx->xpc_xtbl, NULL);
		rcu_read_unlock();
		return XRP_ACT_FORWARD;
	}

	case XRTABLE_MAIN_INDEX:
		fib_mrd_redirect(fxid, next_xid);
		lpm_rt_iops->fib_unlock(ctx->xpc_xtbl, NULL);
		rcu_read_unlock();
		return XRP_ACT_REDIRECT;
	}
	lpm_rt_iops->fib_unlock(ctx->xpc_xtbl, NULL);
	rcu_read_unlock();
	BUG();
}

static struct xip_route_proc lpm_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_LPM,
	.deliver = lpm_deliver,
};

static int __init xia_lpm_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_LPM);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for LPM\n");
		goto out;
	}
	my_vxt = rc;

	rc = xia_register_pernet_subsys(&lpm_net_ops);
	if (rc)
		goto vxt;

	rc = xip_add_router(&lpm_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("lpm", XIDTYPE_LPM);
	if (rc)
		goto route;

	pr_alert("XIA Principal LPM loaded\n");
	goto out;

route:
	xip_del_router(&lpm_rt_proc);
net:
	xia_unregister_pernet_subsys(&lpm_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_LPM));
out:
	return rc;
}

/* xia_lpm_exit - this function is called when the modlule is removed. */
static void __exit xia_lpm_exit(void)
{
	ppal_del_map(XIDTYPE_LPM);
	xip_del_router(&lpm_rt_proc);
	xia_unregister_pernet_subsys(&lpm_net_ops);
	BUG_ON(vxt_unregister_xidty(XIDTYPE_LPM));

	rcu_barrier();

	pr_alert("XIA Principal LPM UNloaded\n");
}

module_init(xia_lpm_init);
module_exit(xia_lpm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("André Eleuterio <andreeleuterio23@gmail.com>");
MODULE_DESCRIPTION("XIA Longest Prefix Matching Principal");

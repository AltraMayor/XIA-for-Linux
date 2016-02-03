#include <linux/export.h>
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <net/xia_locktbl.h>
#include <net/xia_vxidty.h>
#include <net/xia_fib.h>

/* Principal context */

int init_fib_ppal_ctx(struct net *net)
{
	memset(net->xia.fib_ctx, 0, sizeof(net->xia.fib_ctx));
	return 0;
}

int xip_init_ppal_ctx(struct xip_ppal_ctx *ctx, xid_type_t ty)
{
	ctx->xpc_ppal_type = ty;
	ctx->xpc_xtbl = NULL;
	xdst_init_anchor(&ctx->negdep);
	return 0;
}
EXPORT_SYMBOL_GPL(xip_init_ppal_ctx);

void xip_release_ppal_ctx(struct xip_ppal_ctx *ctx)
{
	struct fib_xid_table *xtbl;

	/* It's assumed that synchronize_rcu() has been called before. */
	xdst_free_anchor(&ctx->negdep);

	xtbl = ctx->xpc_xtbl;
	if (xtbl) {
		ctx->xpc_xtbl = NULL;
		xtbl_put(xtbl);
	}
}
EXPORT_SYMBOL_GPL(xip_release_ppal_ctx);

int xip_add_ppal_ctx(struct net *net, struct xip_ppal_ctx *ctx)
{
	xid_type_t ty = ctx->xpc_ppal_type;
	int vxt = xt_to_vxt(ty);

	if (unlikely(vxt < 0))
		return -EINVAL;

	if (net->xia.fib_ctx[vxt]) {
		BUG_ON(net->xia.fib_ctx[vxt]->xpc_ppal_type != ty);
		return -EEXIST;
	}
	rcu_assign_pointer(net->xia.fib_ctx[vxt], ctx);

	return 0;
}
EXPORT_SYMBOL_GPL(xip_add_ppal_ctx);

struct xip_ppal_ctx *xip_del_ppal_ctx(struct net *net, xid_type_t ty)
{
	int vxt = xt_to_vxt(ty);
	struct xip_ppal_ctx *ctx;

	BUG_ON(vxt < 0);
	ctx = net->xia.fib_ctx[vxt];
	BUG_ON(!ctx);
	BUG_ON(ctx->xpc_ppal_type != ty);
	RCU_INIT_POINTER(net->xia.fib_ctx[vxt], NULL);
	synchronize_rcu();
	return ctx;
}
EXPORT_SYMBOL_GPL(xip_del_ppal_ctx);

struct xip_ppal_ctx *xip_find_ppal_ctx_rcu(struct net *net, xid_type_t ty)
{
	int vxt = xt_to_vxt_rcu(ty);

	return likely(vxt >= 0)
		? xip_find_ppal_ctx_vxt_rcu(net, vxt)
		: NULL;
}
EXPORT_SYMBOL_GPL(xip_find_ppal_ctx_rcu);

void xtbl_destroy(struct fib_xid_table *xtbl)
{
	xtbl->dead = 1;
	barrier(); /* Announce that @xtbl is dead as soon as possible. */

	if (in_interrupt())
		schedule_work(&xtbl->fxt_death_work);
	else
		xtbl->all_iops->xtbl_death_work(&xtbl->fxt_death_work);
}
EXPORT_SYMBOL_GPL(xtbl_destroy);

static void __fxid_free(struct rcu_head *head)
{
	struct fib_xid *fxid =
		container_of(head, struct fib_xid, dead.rcu_head);
	struct fib_xid_table *xtbl = fxid->dead.xtbl;

	fxid_free_norcu(xtbl, fxid);
	xtbl_put(xtbl);
}

void fxid_free(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	fxid->dead.xtbl = xtbl;
	xtbl_hold(xtbl);
	call_rcu(&fxid->dead.rcu_head, __fxid_free);
}
EXPORT_SYMBOL_GPL(fxid_free);

int all_fib_newroute(struct fib_xid *new_fxid, struct fib_xid_table *xtbl,
		     struct xia_fib_config *cfg, int *padded, void *plock)
{
	struct xip_deferred_negdep_flush *dnf;
	struct fib_xid *cur_fxid;
	const u8 *id;
	int rc;

	if (padded)
		*padded = 0;

	/* Allocate memory before acquiring lock because we can sleep now. */
	dnf = fib_alloc_dnf(GFP_KERNEL);
	if (!dnf)
		return -ENOMEM;

	/* Acquire lock. */
	id = cfg->xfc_dst->xid_id;
	cur_fxid = xtbl->all_iops->fxid_find_lock(plock, xtbl, id);

	if (cur_fxid) {
		if ((cfg->xfc_nlflags & NLM_F_EXCL) ||
		    !(cfg->xfc_nlflags & NLM_F_REPLACE)) {
			rc = -EEXIST;
			goto unlock;
		}

		if (cur_fxid->fx_table_id != new_fxid->fx_table_id) {
			rc = -EINVAL;
			goto unlock;
		}

		/* Replace entry.
		 * Notice that @cur_fxid and @new_fxid may be of different
		 * types
		 */
		rc = 0;
		xtbl->all_iops->fxid_replace_locked(xtbl, cur_fxid, new_fxid);
		xtbl->all_iops->fib_unlock(xtbl, plock);
		fxid_free(xtbl, cur_fxid);
		goto def_upd;
	}

	if (!(cfg->xfc_nlflags & NLM_F_CREATE)) {
		rc = -ENOENT;
		goto unlock;
	}

	/* Add new entry. */
	BUG_ON(xtbl->all_iops->fxid_add_locked(plock, xtbl, new_fxid));
	xtbl->all_iops->fib_unlock(xtbl, plock);

	/* Before invalidating old anchors to force dependencies to
	 * migrate to @new_fxid, wait an RCU synchronization to make sure that
	 * every thread see @new_fxid.
	 */
	fib_defer_dnf(dnf, xtbl_net(xtbl), xtbl_ppalty(xtbl));

	if (padded)
		*padded = 1;
	return 0;

unlock:
	xtbl->all_iops->fib_unlock(xtbl, plock);
def_upd:
	fib_free_dnf(dnf);
	return rc;
}
EXPORT_SYMBOL_GPL(all_fib_newroute);

int all_fib_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
		     struct xia_fib_config *cfg, void *plock)
{
	struct fib_xid *fxid;
	int rc;

	fxid = xtbl->all_iops->fxid_find_lock(plock, xtbl,
					      cfg->xfc_dst->xid_id);
	if (!fxid) {
		rc = -ENOENT;
		goto unlock;
	}
	if (fxid->fx_table_id != cfg->xfc_table) {
		rc = -EINVAL;
		goto unlock;
	}

	xtbl->all_iops->fxid_rm_locked(plock, xtbl, fxid);
	xtbl->all_iops->fib_unlock(xtbl, plock);
	fxid_free(xtbl, fxid);
	return 0;

unlock:
	xtbl->all_iops->fib_unlock(xtbl, plock);
	return rc;
}
EXPORT_SYMBOL_GPL(all_fib_delroute);

void release_fib_ppal_ctx(struct net *net)
{
	int i;

	for (i = 0; i < XIP_MAX_XID_TYPES; i++) {
		struct xip_ppal_ctx *ctx = net->xia.fib_ctx[i];

		if (!ctx)
			continue;

		pr_crit("BUG: Principal 0x%x did not release its context\n",
			__be32_to_cpu(ctx->xpc_ppal_type));
		break;
	}
}

int fib_no_newroute(struct xip_ppal_ctx *ctx,
		    struct fib_xid_table *xtbl,
		    struct xia_fib_config *cfg)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(fib_no_newroute);

struct xip_deferred_negdep_flush {
	struct rcu_head		rcu_head;
	struct net		*net;
	xid_type_t		ty;
};

struct xip_deferred_negdep_flush *fib_alloc_dnf(gfp_t flags)
{
	return kmalloc(sizeof(struct xip_deferred_negdep_flush), flags);
}
EXPORT_SYMBOL_GPL(fib_alloc_dnf);

static void __fib_defer_dnf(struct rcu_head *head)
{
	struct xip_deferred_negdep_flush *dnf =
		container_of(head, struct xip_deferred_negdep_flush, rcu_head);
	struct xip_ppal_ctx *ctx;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_rcu(dnf->net, dnf->ty);
	if (likely(ctx)) { /* Principal could be unloading. */
		/* Flush @negdep. */
		xdst_free_anchor(&ctx->negdep);
	}
	rcu_read_unlock();

	fib_free_dnf(dnf);
}

void fib_defer_dnf(struct xip_deferred_negdep_flush *dnf,
		   struct net *net, xid_type_t ty)
{
	dnf->net = net;
	dnf->ty = ty;
	call_rcu(&dnf->rcu_head, __fib_defer_dnf);
}
EXPORT_SYMBOL_GPL(fib_defer_dnf);

int fib_mrd_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
		     struct xia_fib_config *cfg)
{
	const struct xia_ppal_rt_iops *iops = xtbl->all_iops;
	struct fib_xid_redirect_main *new_mrd;
	int rc;

	if (!cfg->xfc_gw || cfg->xfc_gw->xid_type == xtbl_ppalty(xtbl))
		return -EINVAL;

	new_mrd = iops->fxid_ppal_alloc(sizeof(*new_mrd), GFP_KERNEL);
	if (!new_mrd)
		return -ENOMEM;
	fxid_init(xtbl, &new_mrd->common, cfg->xfc_dst->xid_id,
		  XRTABLE_MAIN_INDEX, 0);
	new_mrd->gw = *cfg->xfc_gw;

	rc = iops->fib_newroute(&new_mrd->common, xtbl, cfg, NULL);
	if (rc)
		fxid_free_norcu(xtbl, &new_mrd->common);
	return rc;
}
EXPORT_SYMBOL_GPL(fib_mrd_newroute);

int fib_mrd_dump(struct fib_xid *fxid, struct fib_xid_table *xtbl,
		 struct xip_ppal_ctx *ctx, struct sk_buff *skb,
		 struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_redirect_main *mrd = fxid_mrd(fxid);
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

	dst.xid_type = xtbl_ppalty(xtbl);
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);

	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst) ||
		     nla_put(skb, RTA_GATEWAY, sizeof(mrd->gw), &mrd->gw)))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}
EXPORT_SYMBOL_GPL(fib_mrd_dump);

/* Don't call this function! Use free_fxid instead. */
void fib_mrd_free(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_redirect_main *mrd = fxid_mrd(fxid);

	xdst_invalidate_redirect(xtbl_net(xtbl), xtbl_ppalty(xtbl),
				 mrd->common.fx_xid, &mrd->gw);
	kfree(mrd);
}
EXPORT_SYMBOL_GPL(fib_mrd_free);

void fib_mrd_redirect(struct fib_xid *fxid, struct xia_xid *next_xid)
{
	*next_xid = fxid_mrd(fxid)->gw;
}
EXPORT_SYMBOL_GPL(fib_mrd_redirect);

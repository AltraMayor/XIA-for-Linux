#include <linux/module.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>
#include <net/xia_vxidty.h>

/* zFilter principal */
#define XIDTYPE_ZF (__cpu_to_be32(0x20))

/*
 *	ZF context
 */

struct xip_zf_ctx {
	struct xip_ppal_ctx	ctx;

	/* No extra field. */
};

static inline struct xip_zf_ctx *ctx_zf(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_zf_ctx, ctx)
		: NULL;
}

static int my_vxt __read_mostly = -1;

/*
 *	Local ZFs
 */

struct fib_xid_zf_local {
	struct fib_xid		common;

	struct xip_dst_anchor   anchor;
};

static inline struct fib_xid_zf_local *fxid_lzf(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_zf_local, common)
		: NULL;
}

static int local_newroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid_zf_local *new_lzf;
	int rc;

	new_lzf = kmalloc(sizeof(*new_lzf), GFP_KERNEL);
	if (!new_lzf)
		return -ENOMEM;
	init_fxid(&new_lzf->common, cfg->xfc_dst->xid_id,
		XRTABLE_LOCAL_INDEX, 0);
	xdst_init_anchor(&new_lzf->anchor);

	rc = fib_build_newroute(&new_lzf->common, xtbl, cfg, NULL);
	if (rc)
		free_fxid_norcu(xtbl, &new_lzf->common);
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

	return nlmsg_end(skb, nlh);

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

static const xia_ppal_all_rt_eops_t zf_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = local_newroute,
		.delroute = fib_default_local_delroute,
		.dump_fxid = local_dump_zf,
		.free_fxid = local_free_zf,
	},

	[XRTABLE_MAIN_INDEX] = {
		.newroute = fib_no_newroute,
		.delroute = fib_no_delroute,
	},
};

/*
 *	Network namespace
 */

static struct xip_zf_ctx *create_zf_ctx(void)
{
	struct xip_zf_ctx *zf_ctx = kmalloc(sizeof(*zf_ctx), GFP_KERNEL);
	if (!zf_ctx)
		return NULL;
	xip_init_ppal_ctx(&zf_ctx->ctx, XIDTYPE_ZF);
	return zf_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_zf_ctx(struct xip_zf_ctx *zf_ctx)
{
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

	rc = init_xid_table(&zf_ctx->ctx, net, &xia_main_lock_table,
		zf_all_rt_eops);
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

/*
 *	ZF Routing
 */

static int zf_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, struct xia_xid *next_xid, int anchor_index,
	struct xip_dst *xdst)
{
	/* TODO */
	BUG();
}

static struct xip_route_proc zf_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_ZF,
	.deliver = zf_deliver,
};

/*
 * xia_zf_init - this function is called when the module is loaded.
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

/*
 * xia_zf_exit - this function is called when the modlule is removed.
 */
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

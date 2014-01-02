#include <linux/init.h>
#include <linux/module.h>
#include <net/xia_dag.h>
#include <net/xia_fib.h>
#include <net/xia_vxidty.h>

#define XIDTYPE_U4ID		(__cpu_to_be32(0x16))

/*
 *	U4ID context
 */

struct xip_u4id_ctx {
	struct xip_ppal_ctx	ctx;
};

static inline struct xip_u4id_ctx *ctx_u4id(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_u4id_ctx, ctx)
		: NULL;
}

static int my_vxt __read_mostly = -1;

static const xia_ppal_all_rt_eops_t u4id_all_rt_eops = {
};

/*
 *	Network namespace
 */

static struct xip_u4id_ctx *create_u4id_ctx(void)
{
	struct xip_u4id_ctx *u4id_ctx = kmalloc(sizeof(*u4id_ctx), GFP_KERNEL);
	if (!u4id_ctx)
		return NULL;
	xip_init_ppal_ctx(&u4id_ctx->ctx, XIDTYPE_U4ID);
	return u4id_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_u4id_ctx(struct xip_u4id_ctx *u4id_ctx)
{
	xip_release_ppal_ctx(&u4id_ctx->ctx);
	kfree(u4id_ctx);
}

static int __net_init u4id_net_init(struct net *net)
{
	struct xip_u4id_ctx *u4id_ctx;
	int rc;

	u4id_ctx = create_u4id_ctx();
	if (!u4id_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = init_xid_table(&u4id_ctx->ctx, net, &xia_main_lock_table,
		u4id_all_rt_eops);
	if (rc)
		goto u4id_ctx;

	rc = xip_add_ppal_ctx(net, &u4id_ctx->ctx);
	if (rc)
		goto u4id_ctx;
	goto out;

u4id_ctx:
	free_u4id_ctx(u4id_ctx);
out:
	return rc;
}

static void __net_exit u4id_net_exit(struct net *net)
{
	struct xip_u4id_ctx *u4id_ctx =
		ctx_u4id(xip_del_ppal_ctx(net, XIDTYPE_U4ID));
	free_u4id_ctx(u4id_ctx);
}

static struct pernet_operations u4id_net_ops __read_mostly = {
	.init = u4id_net_init,
	.exit = u4id_net_exit,
};

/*
 *	U4ID Routing
 */

static int u4id_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, struct xia_xid *next_xid, int anchor_index,
	struct xip_dst *xdst)
{
	return 0;
}

static struct xip_route_proc u4id_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_U4ID,
	.deliver = u4id_deliver,
};

static int __init xia_u4id_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_U4ID);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for U4ID\n");
		goto out;
	}
	my_vxt = rc;

	rc = xia_register_pernet_subsys(&u4id_net_ops);
	if (rc)
		goto vxt;

	rc = xip_add_router(&u4id_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("u4id", XIDTYPE_U4ID);
	if (rc)
		goto route;

	printk(KERN_ALERT "XIA Principal U4ID loaded\n");
	goto out;

route:
	xip_del_router(&u4id_rt_proc);
net:
	xia_unregister_pernet_subsys(&u4id_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_U4ID));
out:
	return rc;
}

static void __exit xia_u4id_exit(void)
{
	ppal_del_map(XIDTYPE_U4ID);
	xip_del_router(&u4id_rt_proc);
	xia_unregister_pernet_subsys(&u4id_net_ops);
	BUG_ON(vxt_unregister_xidty(XIDTYPE_U4ID));

	rcu_barrier();

	printk(KERN_ALERT "XIA Principal U4ID UNloaded\n");
}

module_init(xia_u4id_init);
module_exit(xia_u4id_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cody Doucette <doucette@bu.edu>");
MODULE_DESCRIPTION("XIA UDP/IPv4 Principal");

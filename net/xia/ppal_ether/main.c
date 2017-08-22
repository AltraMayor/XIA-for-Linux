#include <linux/module.h>
#include <linux/err.h>
#include <net/xia_vxidty.h>
#include <net/xia_dag.h>
#include <net/xia_list_fib.h>

/* Ethernet Principal. */
#define XIDTYPE_ETHER (__cpu_to_be32(0x1a))

/* ETHER context. */
struct xip_ether_ctx {
	struct net          *net;
	struct xip_ppal_ctx ctx;
};

static inline struct xip_ether_ctx *ctx_ether(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_ether_ctx, ctx)
		: NULL;
}

/* ETHER's virtual XID type. */
static int ether_vxt __read_mostly = -1;

/* ETHER_FIB table internal operations. */
static const struct xia_ppal_rt_iops *ether_rt_iops = &xia_ppal_list_rt_iops;

/* Network namespace subsystem registration. */
static struct xip_ether_ctx *create_ether_ctx(struct net *net)
{
	struct xip_ether_ctx *ether_ctx =
					kmalloc(sizeof(*ether_ctx), GFP_KERNEL);

	if (!ether_ctx)
		return NULL;
	xip_init_ppal_ctx(&ether_ctx->ctx, XIDTYPE_ETHER);
	ether_ctx->net = net;
	return ether_ctx;
}

/* Caller must RCU synch before calling this function. */
static void free_ether_ctx(struct xip_ether_ctx *ether_ctx)
{
	ether_ctx->net = NULL;
	xip_release_ppal_ctx(&ether_ctx->ctx);
	kfree(ether_ctx);
}

static int __net_init ether_net_init(struct net *net)
{
	struct xip_ether_ctx *ether_ctx;
	int rc;

	ether_ctx = create_ether_ctx(net);
	if (!ether_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	/* TODO:rc = ether_rt_iops->xtbl_init(&ether_ctx->ctx, net,
	 * &xia_main_lock_table, ether_all_rt_eops, ether_rt_iops);
	 *if (rc)
	 *	goto ether_ctx;
	 */

	rc = xip_add_ppal_ctx(net, &ether_ctx->ctx);
	if (rc)
		goto ether_ctx;
	goto out;

ether_ctx:
	free_ether_ctx(ether_ctx);
out:
	return rc;
}

static void __net_exit ether_net_exit(struct net *net)
{
	/* Synchronize_rcu() called inside xip_del_ppal_ctx. */
	struct xip_ether_ctx *ether_ctx =
		ctx_ether(xip_del_ppal_ctx(net, XIDTYPE_ETHER));
	free_ether_ctx(ether_ctx);
}

static struct pernet_operations ether_net_ops __read_mostly = {
	.init = ether_net_init,
	.exit = ether_net_exit,
};

/* xia_ether_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_ether_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_ETHER);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for ETHER\n");
		goto out;
	}
	ether_vxt = rc;

	rc = xia_register_pernet_subsys(&ether_net_ops);
	if (rc)
		goto vxt;

	rc = ppal_add_map("ether", XIDTYPE_ETHER);
	if (rc)
		goto net;

	pr_alert("XIA Principal ETHER loaded\n");
	goto out;

net:
	xia_unregister_pernet_subsys(&ether_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_ETHER));
out:
	return rc;
}

/* xia_ether_exit - this function is called when the module is removed. */
static void __exit xia_ether_exit(void)
{
	ppal_del_map(XIDTYPE_ETHER);
	xia_unregister_pernet_subsys(&ether_net_ops);

	rcu_barrier();
	flush_scheduled_work();

	BUG_ON(vxt_unregister_xidty(XIDTYPE_ETHER));
	pr_alert("XIA Principal ETHER UNloaded\n");
}

module_init(xia_ether_init);
module_exit(xia_ether_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("XIA Ethernet Principal");

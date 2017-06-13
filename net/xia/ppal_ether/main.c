#include <linux/module.h>
#include <net/xia_dag.h>
#include <net/xia_output.h>
#include <net/xia_vxidty.h>
#include <net/xia_ether.h>

/* ETHER local table operations */
static int local_newroute(struct xip_ppal_ctx *ctx,
			  struct fib_xid_table *xtbl,
			  struct xia_fib_config *cfg)
{
	struct fib_xid_ether_local *leid;
	int rc;

	/* Intialization of a new fib_xid */
	leid = hid_rt_iops->fxid_ppal_alloc(sizeof(*leid), GFP_KERNEL);
	if (!leid)
		return -ENOMEM;
	fxid_init(xtbl, &leid->xhl_common, cfg->xfc_dst->xid_id,
		  XRTABLE_LOCAL_INDEX, 0);
	xdst_init_anchor(&leid->xel_anchor);

	/* Call to form a new entry in the ppal table in the current ctx */
	rc = hid_rt_iops->fib_newroute(&leid->xel_common, xtbl, cfg, NULL);

	/* If not formed succesfully */
	if (rc) {
		fxid_free_norcu(xtbl, &leid->xel_common);
	}
	return rc;
}

/* ETHER_FIB table internal operations */
const struct xia_ppal_rt_iops *ether_rt_iops = &xia_ppal_list_rt_iops;

/* ETHER_FIB all table external operations */
const struct xia_ppal_all_rt_eops_t *ether_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = local_newroute,
		.delroute = local_delroute,
		.dump_fxid = local_dump_hid,
		.free_fxid = local_free_hid,
	},

	[XRTABLE_MAIN_INDEX] = {
		.newroute = main_newroute,
		.delroute = main_delroute,
		.dump_fxid = main_dump_hid,
		.free_fxid = main_free_hid,
	},
};

/* routing process per principal struct */

static struct xip_route_proc ether_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_ETHER,
	.deliver = ether_deliver,
};

/* Network namespace subsystem registration*/

static struct xip_ether_ctx *create_ether_ctx(void)
{
	struct xip_ether_ctx *ether_ctx = kmalloc(sizeof(*ether_ctx), GFP_KERNEL);

	if (!ether_ctx)
		return NULL;
	xip_init_ppal_ctx(&ether_ctx->ctx, XIDTYPE_ETHER);
	return ether_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function,i.e., wait till all readers before have finished */
static void free_ether_ctx(struct xip_ether_ctx *ether_ctx)
{
	xip_release_ppal_ctx(&ether_ctx->ctx);
	kfree(ether_ctx);
}

static int __net_init ether_net_init(struct net *net)
{
	struct xip_ether_ctx *ether_ctx;
	int rc;

	ether_ctx = create_ether_ctx();
	if (!ether_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = ether_rt_iops->xtbl_init(&ether_ctx->ctx, net, &xia_main_lock_table,
				    ether_all_rt_eops, ether_rt_iops);
	if (rc)
		goto ether_ctx;

	rc = xip_add_ppal_ctx(net, &ether_ctx->ctx);
	if (rc)
		goto ether_ctx;
	goto out;

ether_ctx:
	free_ether_ctx(ether_ctx);
out:
	return rc;
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

	rc = xip_add_router(&ether_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("ether", XIDTYPE_ETHER);
	if (rc)
		goto route;

	pr_alert("XIA Principal ETHER loaded\n");
	goto out;

route:
	xip_del_router(&ether_rt_proc);
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
	xip_del_router(&ether_rt_proc);
	xia_unregister_pernet_subsys(&ether_net_ops);

	rcu_barrier();
	/* flush_scheduled_work(); */

	BUG_ON(vxt_unregister_xidty(XIDTYPE_ETHER));
	pr_alert("XIA Principal ETHER UNloaded\n");
}


module_init(xia_ether_init);
module_exit(xia_ether_exit);
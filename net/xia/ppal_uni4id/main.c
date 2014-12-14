#include <linux/module.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>
#include <net/xia_dag.h>
#include <net/xia_u4id.h>
#include <net/xia_vxidty.h>

/* United 4ID Principal */
#define XIDTYPE_UNI4ID (__cpu_to_be32(0x14))

/* United 4ID context */

struct xip_uni4id_ctx {
	struct xip_ppal_ctx	ctx;

	/* No extra field. */
};

static inline struct xip_uni4id_ctx *ctx_uni4id(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_uni4id_ctx, ctx)
		: NULL;
}

static int my_vxt __read_mostly = -1;

/* Network namespace */

static struct xip_uni4id_ctx *create_uni4id_ctx(void)
{
	struct xip_uni4id_ctx *uni4id_ctx = kmalloc(
		sizeof(*uni4id_ctx), GFP_KERNEL);
	if (!uni4id_ctx)
		return NULL;
	xip_init_ppal_ctx(&uni4id_ctx->ctx, XIDTYPE_UNI4ID);
	return uni4id_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_uni4id_ctx(struct xip_uni4id_ctx *uni4id_ctx)
{
	xip_release_ppal_ctx(&uni4id_ctx->ctx);
	kfree(uni4id_ctx);
}

static int __net_init uni4id_net_init(struct net *net)
{
	struct xip_uni4id_ctx *uni4id_ctx;
	int rc;

	uni4id_ctx = create_uni4id_ctx();
	if (!uni4id_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = xip_add_ppal_ctx(net, &uni4id_ctx->ctx);
	if (rc)
		goto uni4id_ctx;
	goto out;

uni4id_ctx:
	free_uni4id_ctx(uni4id_ctx);
out:
	return rc;
}

static void __net_exit uni4id_net_exit(struct net *net)
{
	struct xip_uni4id_ctx *uni4id_ctx =
		ctx_uni4id(xip_del_ppal_ctx(net, XIDTYPE_UNI4ID));
	free_uni4id_ctx(uni4id_ctx);
}

static struct pernet_operations uni4id_net_ops __read_mostly = {
	.init = uni4id_net_init,
	.exit = uni4id_net_exit,
};

/* United 4ID Routing */

/* XXX The following XID type should come from its
 * principal's header file once it is available.
 */
/* IP 4ID: XIP over IP. */
#define XIDTYPE_I4ID (__cpu_to_be32(0x15))

static const u8 uni_xid_prefix[] = {
	/* 0     1     2     3     4     5     6     7 */
	0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	/* 8     9    10    11    12    13    14    15 */
	0xfa, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static int uni4id_deliver(struct xip_route_proc *rproc, struct net *net,
			  const u8 *xid, struct xia_xid *next_xid,
			  int anchor_index, struct xip_dst *xdst)
{
	BUILD_BUG_ON(sizeof(uni_xid_prefix) != 16);
	BUILD_BUG_ON(XIA_XID_MAX != 20);

	if (memcmp(xid, uni_xid_prefix, sizeof(uni_xid_prefix))) {
		struct xip_ppal_ctx *ctx;

		/* Get rid of misformed XIDs. */
		xdst->passthrough_action = XDA_ERROR;
		xdst->sink_action = XDA_ERROR;
		rcu_read_lock();
		ctx = xip_find_ppal_ctx_vxt_rcu(net, my_vxt);
		xdst_attach_to_anchor(xdst, anchor_index, &ctx->negdep);
		rcu_read_unlock();
		return XRP_ACT_FORWARD;
	}

	/* Calculate next XID. */
	next_xid->xid_type = XIDTYPE_U4ID;
	next_xid->xid_id[0]  = xid[16];
	next_xid->xid_id[1]  = xid[17];
	next_xid->xid_id[2]  = xid[18];
	next_xid->xid_id[3]  = xid[19];
	next_xid->xid_id[4]  = 0x35;
	next_xid->xid_id[5]  = 0xd5;
	next_xid->xid_id[6]  = 0x00;
	next_xid->xid_id[7]  = 0x00;
	next_xid->xid_id[8]  = 0x00;
	next_xid->xid_id[9]  = 0x00;
	next_xid->xid_id[10] = 0x00;
	next_xid->xid_id[11] = 0x00;
	next_xid->xid_id[12] = 0x00;
	next_xid->xid_id[13] = 0x00;
	next_xid->xid_id[14] = 0x00;
	next_xid->xid_id[15] = 0x00;
	next_xid->xid_id[16] = 0x00;
	next_xid->xid_id[17] = 0x00;
	next_xid->xid_id[18] = 0x00;
	next_xid->xid_id[19] = 0x00;
	return XRP_ACT_REDIRECT;
}

static struct xip_route_proc uni4id_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_UNI4ID,
	.deliver = uni4id_deliver,
};

/* xia_uni4id_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_uni4id_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_UNI4ID);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for United 4ID\n");
		goto out;
	}
	my_vxt = rc;

	rc = xia_register_pernet_subsys(&uni4id_net_ops);
	if (rc)
		goto vxt;

	rc = xip_add_router(&uni4id_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("uni4id", XIDTYPE_UNI4ID);
	if (rc)
		goto route;

	pr_alert("XIA Principal United 4ID loaded\n");
	goto out;

route:
	xip_del_router(&uni4id_rt_proc);
net:
	xia_unregister_pernet_subsys(&uni4id_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_UNI4ID));
out:
	return rc;
}

/* xia_uni4id_exit - this function is called when the modlule is removed.
 */
static void __exit xia_uni4id_exit(void)
{
	ppal_del_map(XIDTYPE_UNI4ID);
	xip_del_router(&uni4id_rt_proc);
	xia_unregister_pernet_subsys(&uni4id_net_ops);
	BUG_ON(vxt_unregister_xidty(XIDTYPE_UNI4ID));

	rcu_barrier();

	pr_alert("XIA Principal United 4ID UNloaded\n");
}

module_init(xia_uni4id_init);
module_exit(xia_uni4id_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA United 4ID Principal");

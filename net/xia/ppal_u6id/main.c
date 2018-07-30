#include <linux/init.h>
#include <linux/in6.h>
#include <linux/module.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/xia_dag.h>
#include <net/xia_list_fib.h>
#include <net/xia_u6id.h>
#include <net/xia_vxidty.h>
#include <uapi/linux/udp.h>

/* U6ID Principal */
#define IPV6_ADDR_LEN 16;

/* U6ID context */

struct xip_u6id_ctx {
	struct xip_ppal_ctx ctx;

	struct socket __rcu *tunnel_sock;

	/* Anchor for ill-formed U6ID XIDs. */
	struct xip_dst_anchor ill_anchor;

	/* Anchor for non-local, well-formed U6IDs,
	 * which represent tunnel destinations.
	 * When one of the local U6IDs is a tunnel
	 * source then the destination is assumed
	 * to be reachable, so this anchor is
	 * positive. When there is no tunnel source,
	 * this anchor is negative.
	 */
	struct xip_dst_anchor forward_anchor;
};

static inline struct xip_u6id_ctx *ctx_u6id(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_u6id_ctx, ctx)
		:NULL;
}

static int my_vxt __read_mostly = -1;


/* Use a list FIB. */
static const struct xia_ppal_rt_iops *u6id_rt_iops = &xia_ppal_list_rt_iops;


/* XXX This function should support updating local entries for:
 *       - changing the tunnel status of an entry.
 *       - changing the checksum status of a tunnel entry.
 */
static int local_newroute(struct xip_ppal_ctx *ctx,
            struct fib_xid_table *xtbl,
            struct xia_fib_config *cfg)
{

}

static int local_delroute(struct xip_ppal_ctx *ctx,
			struct fib_xid_table *xtbl,
			struct xia_fib_config *cfg)
{

}

static int local_dump_u6id(struct fib_xid *fxid, struct fib_xid_table *xtbl,
						   struct xip_ppal_ctx *ctx, struct sk_buff *skb,
						   struct netlink_callback *cb)
{

}

/* Don't call this function! Use free_fxid instead. */
static void local_free_u6id(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{

}

static const xia_ppal_all_rt_eops_t u6id_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = local_newroute,
		.delroute = local_delroute,
		.dump_fxid = local_dump_u6id,
		.free_fxid = local_free_u6id,
	},  
};

/* Network namespace */

static struct xip_u6id_ctx *create_u6id_ctx(void)
{
	struct xip_u6id_ctx *u6id_ctx = kmalloc(sizeof(*u6id_ctx), GFP_KERNEL);

	if (!u6id_ctx)
		return NULL;
	xip_init_ppal_ctx(&u6id_ctx->ctx, XIDTYPE_U6ID);
	xdst_init_anchor(&u6id_ctx->ill_anchor);
	xdst_init_anchor(&u6id_ctx->forward_anchor);
	RCU_INIT_POINTER(u6id_ctx->tunnel_sock, NULL);
	return u6id_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_u6id_ctx(struct xip_u6id_ctx *u6id_ctx)
{
	/* There are no other writers for the tunnel socket, since
	 * no local entries can be added or removed by the user
	 * since xip_del_ppal_ctx has already been called.
	 */
	RCU_INIT_POINTER(u6id_ctx->tunnel_sock, NULL);

	/* There is no need to find the struct fib_xid_u6id_local
	 * that held the tunnel socket in order to set its
	 * tunnel field to false. The only read of the tunnel
	 * field happens in local_delroute, which can no longer
	 * be invoked since xip_del_ppal_ctx has already been called.
	 *
	 * Therefore, a local entry can incorrectly yet harmlessly hold
	 * a tunnel field of true for a brief time until it is freed
	 * even though the tunnel is no longer active.
	 */

	xdst_free_anchor(&u6id_ctx->forward_anchor);
	xdst_free_anchor(&u6id_ctx->ill_anchor);
	xip_release_ppal_ctx(&u6id_ctx->ctx);
	kfree(u6id_ctx);
}

static int __net_init u6id_net_init(struct net *net)
{
	struct xip_u6id_ctx *u6id_ctx;
	int rc;

	u6id_ctx = create_u6id_ctx();
	if (!u6id_ctx) {
		rc = -ENOMEM;
		goto out;
	}
    
	rc = u6id_rt_iops->xtbl_init(&u6id_ctx->ctx, net,
				&xia_main_lock_table, u6id_all_rt_eops,
				u6id_rt_iops);
	if (rc)
		goto u6id_ctx;
    
	rc = xip_add_ppal_ctx(net, &u6id_ctx->ctx);
	if (rc)
		goto u6id_ctx;
	goto out;

u6id_ctx:
	free_u6id_ctx(u6id_ctx);
out:
	return rc;
}

static void __net_exit u6id_net_exit(struct net *net)
{
	struct xip_u6id_ctx *u6id_ctx =
		ctx_u6id(xip_del_ppal_ctx(net, XIDTYPE_U6ID));
	free_u6id_ctx(u6id_ctx);
}

static struct pernet_operations u6id_net_ops __read_mostly = {
	.init = u6id_net_init,
	.exit = u6id_net_exit,
};

/* U6ID Routing */

static int u6id_deliver(struct xip_route_proc *rproc,struct net *net,
			const u8*xid, struct xia_xid *next_xid,
			int anchor_index, struct xip_dst *xdst)
{

}

static struct xip_route_proc u6id_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_U6ID,
	.deliver = u6id_deliver,
};

static int  __init xia_u6id_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_U6ID);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for U6ID.\n");
		goto out;
	}

	my_vxt = rc;
    
	rc = xia_register_pernet_subsys(&u6id_net_ops);
	if (rc)
		goto vxt;
    
	rc = xip_add_router(&u6id_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("u6id", XIDTYPE_U6ID);
	if (rc)
		goto route;

	printk(KERN_ALERT "XIA Principal U6ID loaded\n");
	goto out;

route:
	xip_del_router(&u6id_rt_proc);
net:
	xia_unregister_pernet_subsys(&u6id_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_U6ID));
out:
	return rc;
}

static void __exit xia_u6id_exit(void)
{
	ppal_del_map(XIDTYPE_U6ID);
	xip_del_router(&u6id_rt_proc);
	xia_unregister_pernet_subsys(&u6id_net_ops);
	BUG_ON(vxt_unregister_xidty(XIDTYPE_U6ID));
    
	rcu_barrier();
	flush_scheduled_work();

	printk(KERN_ALERT "XIA Principal U6ID Unloaded\n");
}

module_init(xia_u6id_init);
module_exit(xia_u6id_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("XIA UDP/IPv6 Principal");

#include <linux/module.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/xia_vxidty.h>
#include <net/xia_dag.h>
#include <net/xia_list_fib.h>
#include <net/xia_output.h>

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

/* ETHER-INTERFACE. */
struct ether_interface {
	struct net_device  *dev;
	atomic_t           refcnt;
	struct rcu_head    rcu_head;

	/* Prevents racing conditions over list. */
	spinlock_t         interface_lock;
	struct list_head   list_interface_common_addr;
};

static inline void ether_interface_hold(struct ether_interface *eint)
{
	atomic_inc(&eint->refcnt);
}

static struct ether_interface *ether_interface_get(
		const struct net_device *dev)
{
	struct ether_interface *eint;

	rcu_read_lock();
	eint = rcu_dereference(dev->eth_ptr);
	if (eint)
		ether_interface_hold(eint);
	rcu_read_unlock();

	return eint;
}

static void ether_interface_rcu_put(struct rcu_head *head)
{
	struct ether_interface *eint =
			container_of(head, struct ether_interface, rcu_head);

	dev_put(eint->dev);
	eint->dev = NULL;
	WARN_ON(spin_is_locked(&eint->interface_lock));
	WARN_ON(!list_empty(&eint->list_interface_common_addr));
	kfree(eint);
}

static inline void ether_interface_put(struct ether_interface *eint)
{
	if (atomic_dec_and_test(&eint->refcnt))
		call_rcu(&eint->rcu_head, ether_interface_rcu_put);
}

/* ETHER's virtual XID type. */
static int ether_vxt __read_mostly = -1;

/* ETHER_FIB table internal operations. */
static const struct xia_ppal_rt_iops *ether_rt_iops = &xia_ppal_list_rt_iops;

/* Local-FXID. */
struct fib_xid_ether_local {
	struct xip_dst_anchor   xel_anchor;

	/* WARNING: @xel_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid          xel_common;
};

static inline struct fib_xid_ether_local *fxid_lether(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ether_local, xel_common)
		: NULL;
}

/* ETHER local table operations. */
static int local_newroute(struct xip_ppal_ctx *ctx,
			  struct fib_xid_table *xtbl,
			  struct xia_fib_config *cfg)
{
	struct fib_xid_ether_local *leid;
	int rc;

	leid = ether_rt_iops->fxid_ppal_alloc(sizeof(*leid), GFP_KERNEL);
	if (!leid)
		return -ENOMEM;
	fxid_init(xtbl, &leid->xel_common, cfg->xfc_dst->xid_id,
		  XRTABLE_LOCAL_INDEX, 0);
	xdst_init_anchor(&leid->xel_anchor);

	rc = ether_rt_iops->fib_newroute(&leid->xel_common, xtbl, cfg, NULL);
	if (rc)
		fxid_free_norcu(xtbl, &leid->xel_common);

	return rc;
}

static int local_dump_ether(struct fib_xid *fxid, struct fib_xid_table *xtbl,
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
	if (!nlh)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0;
	rtm->rtm_table = XRTABLE_LOCAL_INDEX;
	rtm->rtm_protocol = RTPROT_UNSPEC;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_LOCAL;
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	/* Add the netlink attribute "destination address" to
	 * the nl_msg contained inside the skb.
	 */
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_ether(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_ether_local *leid = fxid_lether(fxid);

	xdst_free_anchor(&leid->xel_anchor);
	kfree(leid);
}

/* Interface intialization and exit functions. */
static struct ether_interface *eint_init(struct net_device *dev)
{
	struct ether_interface *eint;

	ASSERT_RTNL();

	eint = kzalloc(sizeof(*eint), GFP_KERNEL);
	if (!eint)
		return NULL;

	eint->dev = dev;
	dev_hold(dev);
	atomic_set(&eint->refcnt, 0);

	spin_lock_init(&eint->interface_lock);
	INIT_LIST_HEAD(&eint->list_interface_common_addr);

	ether_interface_hold(eint);
	RCU_INIT_POINTER(dev->eth_ptr, eint);
	return eint;
}

static void eint_destroy(struct ether_interface *eint)
{
	ASSERT_RTNL();

	RCU_INIT_POINTER(eint->dev->eth_ptr, NULL);
	ether_interface_put(eint);
}

static int ether_interface_event(struct notifier_block *nb,
				 unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct ether_interface *eint;

	ASSERT_RTNL();
	eint = rtnl_dereference(dev->eth_ptr);

	switch (event) {
	case NETDEV_REGISTER:
		WARN_ON(eint);
		eint = eint_init(dev);
		if (!eint)
			return notifier_from_errno(-ENOMEM);
		break;
	case NETDEV_UNREGISTER:
		eint_destroy(eint);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block interface_notifier __read_mostly = {
	.notifier_call = ether_interface_event,
};

static int register_dev(void)
{
	return register_netdevice_notifier(&interface_notifier);
}

static void unregister_dev(void)
{
	unregister_netdevice_notifier(&interface_notifier);
}

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

	rc = register_dev();
	if (rc)
		goto net;

	rc = ppal_add_map("ether", XIDTYPE_ETHER);
	if (rc)
		goto devicereg;

	pr_alert("XIA Principal ETHER loaded\n");
	goto out;

devicereg:
	unregister_dev();
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
	unregister_dev();
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

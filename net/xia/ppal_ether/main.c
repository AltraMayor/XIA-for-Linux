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

/* Main-FXID. */
struct fib_xid_ether_main {
	struct xip_dst_anchor   xem_anchor;
	struct ether_interface  *host_interface;
	struct list_head        interface_common_addr;

	struct hh_cache		cached_hdr;

	/* WARNING: @xhm_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid          xem_common;
};

/* Main-FXID functions. */
static inline struct fib_xid_ether_main *fxid_mether(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_ether_main, xem_common)
		: NULL;
}

/* Main-FXID + INTERFACE. */
static void attach_neigh_to_interface(struct fib_xid_ether_main *mether)
{
	ether_interface_hold(mether->host_interface);
	/* When using list_add_tail_rcu the caller must take whatever
	 * precautions are necessary (such as holding appropriate locks) to
	 * avoid racing with another list-mutation primitive, such as
	 * list_add_tail_rcu() or list_del_rcu(), running on this same list.
	 */
	spin_lock(&mether->host_interface->interface_lock);
	list_add_tail_rcu(&mether->host_interface->list_interface_common_addr,
			  &mether->interface_common_addr);
	spin_unlock(&mether->host_interface->interface_lock);
	/* Don't call ether_interface_put(einterface) here because @mether
	 * is in its list.
	 */
}

/* Main-FXID - INTERFACE. */
static void detach_neigh_to_interface(struct fib_xid_ether_main *mether)
{
	/* mether->host_interface may be NULL here because
	 * when ether_interface_get() in main_newroute() returns NULL,
	 * fxid_free_norcu() is called.
	 */
	if (!mether->host_interface)
		return;
	/* When using list_del_rcu the caller must take whatever precautions
	 * are necessary (such as holding appropriate locks) to avoid racing
	 * with another list-mutation primitive, such as list_add_tail_rcu()
	 * or list_del_rcu(), running on this same list.
	 */
	spin_lock(&mether->host_interface->interface_lock);
	list_del_rcu(&mether->interface_common_addr);
	spin_unlock(&mether->host_interface->interface_lock);

	ether_interface_put(mether->host_interface);
	mether->host_interface = NULL;
}

/* Initialize the cached Ethernet header. */
static void xia_ether_header_cache(struct fib_xid_ether_main *mfxid,
				   u8 *addr)
{
	struct ethhdr *eth;
	const struct net_device *dev = mfxid->host_interface->dev;

	seqlock_init(&mfxid->cached_hdr.hh_lock);
	eth = (struct ethhdr *)
	    (((u8 *)mfxid->cached_hdr.hh_data) + (HH_DATA_OFF(sizeof(*eth))));

	eth->h_proto = htons(ETH_P_XIP);
	memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
	memcpy(eth->h_dest, addr, ETH_ALEN);
	mfxid->cached_hdr.hh_len = ETH_HLEN;
}

/* Update the cached header with new Ethernet address. */
static void xia_ether_header_cache_update(struct fib_xid_ether_main *mfxid)
{
	struct ethhdr *eth;
	const struct net_device *dev = mfxid->host_interface->dev;

	eth = (struct ethhdr *)
	    (((u8 *)mfxid->cached_hdr.hh_data) + (HH_DATA_OFF(sizeof(*eth))));

	write_seqlock_bh(&mfxid->cached_hdr.hh_lock);
	memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
	write_sequnlock_bh(&mfxid->cached_hdr.hh_lock);
}

/* ETHER main table operations. */
static int main_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
			 struct xia_fib_config *cfg)
{
	struct xip_deferred_negdep_flush *dnf;
	struct fib_xid_ether_main *mether;
	struct net_device *out_interface;
	struct fib_xid *cur_fxid;
	u32 nl_flags, bucket;
	u32 *p;
	const char *id;
	int rc, i;

	/* Check for errors in cfg. */
	if (!cfg->xfc_dst)
		return -EINVAL;

	p = (u32 *)cfg->xfc_dst->xid_id;

	ASSERT_RTNL();
	out_interface = __dev_get_by_index(ctx_ether(ctx)->net,
					   __be32_to_cpu(*p));
	if (!out_interface)
		return -ENODEV;

	BUG_ON((XIA_XID_MAX - sizeof(*p)) < out_interface->addr_len);
	for (i = sizeof(*p) + out_interface->addr_len; i < XIA_XID_MAX; i++)
		if (cfg->xfc_dst->xid_id[i])
			return -EINVAL;

	if (!(out_interface->flags & IFF_UP) ||
	    (out_interface->flags & IFF_LOOPBACK))
		return -EINVAL;

	nl_flags      = cfg->xfc_nlflags;
	id            = cfg->xfc_dst->xid_id;
	cur_fxid = ether_rt_iops->fxid_find_lock(&bucket, xtbl, id);
	if (cur_fxid) {
		/* Found a matching fxid. */
		if (cur_fxid->fx_table_id != XRTABLE_MAIN_INDEX) {
			rc = -EINVAL;
			goto unlock_bucket;
		}

		/* Exact duplicate entry request. */
		if ((nl_flags & NLM_F_EXCL) ||
		    !(nl_flags & NLM_F_REPLACE)) {
			rc = -EEXIST;
			goto unlock_bucket;
		}
		rc = 0;
		goto unlock_bucket;
	}

	if (!(nl_flags & NLM_F_CREATE)) {
		rc = -ENOENT;
		goto unlock_bucket;
	}

	dnf = fib_alloc_dnf(GFP_KERNEL);
	if (!dnf) {
		rc = -ENOMEM;
		goto unlock_bucket;
	}

	mether = ether_rt_iops->fxid_ppal_alloc(sizeof(*mether), GFP_KERNEL);
	if (!mether) {
		rc = -ENOMEM;
		goto def_upd;
	}
	fxid_init(xtbl, &mether->xem_common, id, XRTABLE_MAIN_INDEX, 0);
	xdst_init_anchor(&mether->xem_anchor);
	INIT_LIST_HEAD(&mether->interface_common_addr);

	mether->host_interface = ether_interface_get(out_interface);
	if (!mether->host_interface) {
		rc = -EINVAL;
		goto free_mem;
	}
	xia_ether_header_cache(mether, &id[sizeof(*p)]);
	attach_neigh_to_interface(mether);
	/* Releasing reference obtained with ether_interface_get() because
	 * attach_neigh_to_interface() secures a reference as well.
	 */
	ether_interface_put(mether->host_interface);

	WARN_ON(ether_rt_iops->fxid_add_locked(&bucket, xtbl,
					       &mether->xem_common));
	ether_rt_iops->fib_unlock(xtbl, &bucket);
	fib_defer_dnf(dnf, ctx_ether(ctx)->net, XIDTYPE_ETHER);
	return 0;

free_mem:
	fxid_free_norcu(xtbl, &mether->xem_common);
def_upd:
	fib_free_dnf(dnf);
unlock_bucket:
	ether_rt_iops->fib_unlock(xtbl, &bucket);
	return rc;
}

static int main_dump_ether(struct fib_xid *fxid, struct fib_xid_table *xtbl,
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
	rtm->rtm_table = XRTABLE_MAIN_INDEX;
	rtm->rtm_protocol = RTPROT_UNSPEC;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Call using fxid_free only. */
void main_free_ether(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_ether_main *mether = fxid_mether(fxid);

	detach_neigh_to_interface(mether);
	xdst_free_anchor(&mether->xem_anchor);
	kfree(mether);
}

/* ETHER_FIB all table external operations. */
static const xia_ppal_all_rt_eops_t ether_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = local_newroute,
		.delroute = list_fib_delroute,
		.dump_fxid = local_dump_ether,
		.free_fxid = local_free_ether,
	},

	[XRTABLE_MAIN_INDEX] = {
		.newroute = main_newroute,
		.delroute = list_fib_delroute,
		.dump_fxid = main_dump_ether,
		.free_fxid = main_free_ether,
	},
};

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

/* Caller must hold RTNL lock, and makes sure that nobody adds entries
 * in eint->list_interface_common_addr while it's running.
 */
static void free_neighs_by_interface(struct ether_interface *eint)
{
	struct net_device *dev;
	struct net *net;
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *xtbl;
	struct fib_xid_ether_main *mether, *temp;

	ASSERT_RTNL();

	dev = eint->dev;
	net = dev_net(dev);
	ctx = xip_find_my_ppal_ctx_vxt(net, ether_vxt);
	xtbl = ctx->xpc_xtbl;

	list_for_each_entry_safe(mether, temp,
				 &eint->list_interface_common_addr,
				 interface_common_addr){
		struct fib_xid *fxid;
		u32 bucket;

		/* We don't lock eint->interface_lock to avoid deadlock. */
		fxid = ether_rt_iops->fxid_find_lock(&bucket, xtbl, 
			mether->xem_common.fx_xid);
		if (fxid) {
			BUG_ON(fxid->fx_table_id != XRTABLE_MAIN_INDEX);
			BUG_ON(&mether->xem_common != fxid);
			ether_rt_iops->fxid_rm_locked(&bucket, xtbl, fxid);
			fxid_free(xtbl, fxid);
		}
		ether_rt_iops->fib_unlock(xtbl, &bucket);
	}
}

static void update_neighs_by_interface(struct ether_interface *eint)
{
	struct fib_xid_ether_main *mether;

	ASSERT_RTNL();
	list_for_each_entry(mether, &eint->list_interface_common_addr,
			    interface_common_addr) {
		xia_ether_header_cache_update(mether);
	}
}

static void eint_destroy(struct ether_interface *eint)
{
	ASSERT_RTNL();

	free_neighs_by_interface(eint);

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
	case NETDEV_DOWN:
		free_neighs_by_interface(eint);
		break;
	case NETDEV_CHANGEADDR:
		update_neighs_by_interface(eint);
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

	rc = ether_rt_iops->xtbl_init(&ether_ctx->ctx, net,
			&xia_main_lock_table, ether_all_rt_eops, ether_rt_iops);
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

#include <linux/module.h>
#include <net/xia_dag.h>
#include <net/xia_output.h>
#include <net/xia_vxidty.h>
#include <net/xia_hid.h>

/* HID's virtal XID type. */
int hid_vxt __read_mostly = -1;

/* Use a list FIB. */
const struct xia_ppal_rt_iops *hid_rt_iops = &xia_ppal_list_rt_iops;

/* Local HIDs */

struct fib_xid_hid_local {
	/* XXX Adding a list of devs in which the HID is valid, would allow
	 * a network administrator to enforce physical network isolations;
	 * support dev == NULL as a wildcard.
	 */

	struct xip_dst_anchor	xhl_anchor;

	/* WARNING: @xhl_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xhl_common;
};

static inline struct fib_xid_hid_local *fxid_lhid(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_hid_local, xhl_common)
		: NULL;
}

static int local_newroute(struct xip_ppal_ctx *ctx,
			  struct fib_xid_table *xtbl,
			  struct xia_fib_config *cfg)
{
	struct fib_xid_hid_local *lhid;
	int rc, added;

	lhid = hid_rt_iops->fxid_ppal_alloc(sizeof(*lhid), GFP_KERNEL);
	if (!lhid)
		return -ENOMEM;
	fxid_init(xtbl, &lhid->xhl_common, cfg->xfc_dst->xid_id,
		  XRTABLE_LOCAL_INDEX, 0);
	xdst_init_anchor(&lhid->xhl_anchor);

	rc = hid_rt_iops->fib_newroute(&lhid->xhl_common, xtbl, cfg, &added);
	if (!rc) {
		struct xip_hid_ctx *hid_ctx = ctx_hid(ctx);

		if (added)
			atomic_inc(&hid_ctx->me);
		atomic_inc(&hid_ctx->to_announce);
	} else {
		fxid_free_norcu(xtbl, &lhid->xhl_common);
	}
	return rc;
}

static int local_delroute(struct xip_ppal_ctx *ctx,
			  struct fib_xid_table *xtbl,
			  struct xia_fib_config *cfg)
{
	int rc = hid_rt_iops->fib_delroute(ctx, xtbl, cfg);

	if (!rc) {
		struct xip_hid_ctx *hid_ctx = ctx_hid(ctx);

		atomic_dec(&hid_ctx->me);
		/* XXX NWP should support negative announcements to speed up
		 * detection of leaving HIDs.
		 */
		atomic_inc(&hid_ctx->to_announce);
	}
	return rc;
}

static int local_dump_hid(struct fib_xid *fxid, struct fib_xid_table *xtbl,
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

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_hid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_hid_local *lhid = fxid_lhid(fxid);

	xdst_free_anchor(&lhid->xhl_anchor);
	kfree(lhid);
}

/* Main HIDs */

static int main_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
			 struct xia_fib_config *cfg)
{
	if (!cfg->xfc_odev)
		return -EINVAL;
	if (!cfg->xfc_lladdr)
		return -EINVAL;
	if (cfg->xfc_lladdr_len != cfg->xfc_odev->addr_len)
		return -EINVAL;

	return insert_neigh(ctx_hid(ctx), cfg->xfc_dst->xid_id, cfg->xfc_odev,
		cfg->xfc_lladdr, cfg->xfc_nlflags);
}

static int main_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
			 struct xia_fib_config *cfg)
{
	if (!cfg->xfc_odev)
		return -EINVAL;
	if (!cfg->xfc_lladdr)
		return -EINVAL;
	if (cfg->xfc_lladdr_len != cfg->xfc_odev->addr_len)
		return -EINVAL;

	return remove_neigh(xtbl, cfg->xfc_dst->xid_id, cfg->xfc_odev,
		cfg->xfc_lladdr);
}

static int main_dump_hid(struct fib_xid *fxid, struct fib_xid_table *xtbl,
			 struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			 struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_hid_main *mhid = fxid_mhid(fxid);
	struct xia_xid dst;
	struct nlattr *ha_attr;
	struct hrdw_addr *pos_ha;

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

	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	/* Hardware addresses. */
	ha_attr = nla_nest_start(skb, RTA_MULTIPATH);
	if (!ha_attr)
		goto nla_put_failure;
	list_for_each_entry(pos_ha, &mhid->xhm_haddrs, ha_list) {
		struct rtnl_xia_hid_hdw_addrs *rtha =
			nla_reserve_nohdr(skb, sizeof(*rtha));
		if (!rtha)
			goto nla_put_failure;

		rtha->hha_addr_len = pos_ha->dev->addr_len;
		memmove(rtha->hha_ha, pos_ha->ha, rtha->hha_addr_len);
		rtha->hha_ifindex = pos_ha->dev->ifindex;

		/* No attributes. */

		/* length of rtnetlink header + attributes */
		rtha->hha_len = nlmsg_get_pos(skb) - (void *)rtha;
	}
	nla_nest_end(skb, ha_attr);

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static const xia_ppal_all_rt_eops_t hid_all_rt_eops = {
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

/* Network namespace */

static struct xip_hid_ctx *create_hid_ctx(struct net *net)
{
	struct xip_hid_ctx *hid_ctx = kmalloc(sizeof(*hid_ctx), GFP_KERNEL);

	if (!hid_ctx)
		return NULL;
	xip_init_ppal_ctx(&hid_ctx->ctx, XIDTYPE_HID);
	hid_ctx->net = net;
	hold_net(net);
	return hid_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_hid_ctx(struct xip_hid_ctx *hid_ctx)
{
	release_net(hid_ctx->net);
	hid_ctx->net = NULL;
	xip_release_ppal_ctx(&hid_ctx->ctx);
	kfree(hid_ctx);
}

static int __net_init hid_net_init(struct net *net)
{
	struct xip_hid_ctx *hid_ctx;
	int rc;

	hid_ctx = create_hid_ctx(net);
	if (!hid_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = hid_rt_iops->xtbl_init(&hid_ctx->ctx, net, &xia_main_lock_table,
				    hid_all_rt_eops, hid_rt_iops);
	if (rc)
		goto hid_ctx;

	rc = hid_init_hid_state(hid_ctx);
	if (rc)
		goto hid_ctx;

	rc = xip_add_ppal_ctx(net, &hid_ctx->ctx);
	if (rc)
		goto release_state;
	goto out;

release_state:
	hid_release_hid_state(hid_ctx);
hid_ctx:
	free_hid_ctx(hid_ctx);
out:
	return rc;
}

static void __net_exit hid_net_exit(struct net *net)
{
	struct xip_hid_ctx *hid_ctx =
		ctx_hid(xip_del_ppal_ctx(net, XIDTYPE_HID));
	hid_release_hid_state(hid_ctx);
	free_hid_ctx(hid_ctx);
}

static struct pernet_operations hid_net_ops __read_mostly = {
	.init = hid_net_init,
	.exit = hid_net_exit,
};

/* HID Routing */

static inline struct hrdw_addr *xdst_ha(struct xip_dst *xdst)
{
	return xdst->info;
}

static int main_input_input(struct sk_buff *skb)
{
	struct xiphdr *xiph;
	struct xip_dst *xdst;
	struct hrdw_addr *ha;

	/* XXX We should test that forwarding is enable per struct net.
	 * See example in net/ipv6/ip6_output.c:ip6_forward.
	 */

	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	xiph = xip_hdr(skb);
	if (!xiph->hop_limit) {
		/* XXX Is this warning necessary? If so,
		 * shouldn't it report more?
		 */
		net_warn_ratelimited("%s: hop limit reached\n", __func__);
		goto drop;
	}

	xdst = skb_xdst(skb);

	skb = xip_trim_packet_if_needed(skb, dst_mtu(&xdst->dst));
	if (unlikely(!skb))
		return NET_RX_DROP;

	/* We are about to mangle packet. Copy it! */
	ha = xdst_ha(xdst);
	if (skb_cow(skb, LL_RESERVED_SPACE(ha->dev) + xdst->dst.header_len))
		goto drop;
	xiph = xip_hdr(skb);

	/* Decrease ttl after skb cow done. */
	xiph->hop_limit--;

	return dst_output(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static inline struct hrdw_addr *skb_ha(struct sk_buff *skb)
{
	return xdst_ha(skb_xdst(skb));
}

static inline int xip_skb_dst_mtu(struct sk_buff *skb)
{
	return dst_mtu(skb_dst(skb));
}

static int main_input_output(struct sock *sk, struct sk_buff *skb)
{
	struct hrdw_addr *ha = skb_ha(skb);
	struct net_device *dev;
	unsigned int hh_len;
	int rc;

	skb = xip_trim_packet_if_needed(skb, xip_skb_dst_mtu(skb));
	if (!skb)
		return NET_RX_DROP;

	dev = ha->dev;
	skb->dev = dev;
	skb->protocol = __cpu_to_be16(ETH_P_XIP);

	/* Be paranoid, rather than too clever. */
	hh_len = LL_RESERVED_SPACE(dev);
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, hh_len);
		if (!skb2) {
			rc = -ENOMEM;
			goto drop;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

	/* XXX Implement link-layer header cache here.
	 * See net/ipv4/ip_output.c:ip_finish_output2,
	 * include/net/neighbour.h:neigh_output, and
	 * include/net/neighbour.h:neigh_hh_output.
	 */
	/* Fill the device header. */
	rc = dev_hard_header(skb, skb->dev, ETH_P_XIP, ha->ha,
			     dev->dev_addr, skb->len);
	if (rc < 0)
		goto drop;

	return dev_queue_xmit(skb);

drop:
	kfree_skb(skb);
	return rc;
}

/* Send packets out. */

static int main_output_input(struct sk_buff *skb)
{
	BUG();
}

#define main_output_output main_input_output

static int hid_deliver(struct xip_route_proc *rproc, struct net *net,
		       const u8 *xid, struct xia_xid *next_xid,
		       int anchor_index, struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct fib_xid *fxid;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, hid_vxt);

	fxid = hid_rt_iops->fxid_find_rcu(ctx->xpc_xtbl, xid);
	if (!fxid)
		goto out;

	switch (fxid->fx_table_id) {
	case XRTABLE_LOCAL_INDEX: {
		struct fib_xid_hid_local *lhid = fxid_lhid(fxid);

		xdst->passthrough_action = XDA_DIG;
		xdst->sink_action = XDA_ERROR; /* An HID cannot be a sink. */
		xdst_attach_to_anchor(xdst, anchor_index, &lhid->xhl_anchor);
		rcu_read_unlock();
		return XRP_ACT_FORWARD;
	}

	case XRTABLE_MAIN_INDEX: {
		struct fib_xid_hid_main *mhid = fxid_mhid(fxid);
		struct hrdw_addr *ha =
			list_first_or_null_rcu(&mhid->xhm_haddrs,
					       struct hrdw_addr, ha_list);

		if (unlikely(!ha)) {
			/* @ha may be NULL because we don't have a lock over
			 * @mhid, we're just browsing under RCU protection.
			 */
			goto out;
		}

		xdst->passthrough_action = XDA_METHOD;
		xdst->sink_action = XDA_METHOD;
		xdst->info = ha;
		BUG_ON(xdst->dst.dev);
		xdst->dst.dev = ha->dev;
		dev_hold(xdst->dst.dev);
		if (xdst->input) {
			xdst->dst.input = main_input_input;
			xdst->dst.output = main_input_output;
		} else {
			xdst->dst.input = main_output_input;
			xdst->dst.output = main_output_output;
		}
		xdst_attach_to_anchor(xdst, anchor_index, &ha->anchor);
		rcu_read_unlock();
		return XRP_ACT_FORWARD;
	}
	}
	rcu_read_unlock();
	BUG();

out:
	xdst_attach_to_anchor(xdst, anchor_index, &ctx->negdep);
	rcu_read_unlock();
	return XRP_ACT_NEXT_EDGE;
}

static struct xip_route_proc hid_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_HID,
	.deliver = hid_deliver,
};

/* xia_hid_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_hid_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_HID);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for HID\n");
		goto out;
	}
	hid_vxt = rc;

	rc = xia_register_pernet_subsys(&hid_net_ops);
	if (rc)
		goto vxt;

	rc = hid_nwp_init();
	if (rc)
		goto net;

	rc = xip_add_router(&hid_rt_proc);
	if (rc)
		goto nwp;

	rc = ppal_add_map("hid", XIDTYPE_HID);
	if (rc)
		goto route;

	pr_alert("XIA Principal HID loaded\n");
	goto out;

route:
	xip_del_router(&hid_rt_proc);
nwp:
	hid_nwp_exit();
net:
	xia_unregister_pernet_subsys(&hid_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_HID));
out:
	return rc;
}

/* xia_hid_exit - this function is called when the modlule is removed. */
static void __exit xia_hid_exit(void)
{
	ppal_del_map(XIDTYPE_HID);
	xip_del_router(&hid_rt_proc);
	hid_nwp_exit();
	xia_unregister_pernet_subsys(&hid_net_ops);

	rcu_barrier();
	flush_scheduled_work();

	BUG_ON(vxt_unregister_xidty(XIDTYPE_HID));
	pr_alert("XIA Principal HID UNloaded\n");
}

module_init(xia_hid_init);
module_exit(xia_hid_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Host Principal");

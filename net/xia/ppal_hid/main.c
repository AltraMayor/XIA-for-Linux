#include <linux/module.h>
#include <net/xia_dag.h>
#include <net/xia_route.h>
#include <net/xia_hid.h>

/*
 *	Local HID table
 */

struct fib_xid_hid_local {
	struct fib_xid	xhl_common; /* It must be first field! */

	/* XXX Adding a list of devs in which the HID is valid, would allow
	 * a network administrator to enforce physical network isolations;
	 * support dev == NULL as a wildcard.
	 */

	/* Empty. */
};

static int local_newroute(struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	struct fib_xid_hid_local *lhid;
	u8 *xid;
	struct net *net;
	struct fib_xid_table *main_xtbl;
	u32 local_bucket, main_bucket;
	int rc;

	/*
	 * The sequence of locks in this function must be careful to avoid
	 * deadlock with nwp.c:insert_neigh.
	 *
	 * This code requires that @local_bucket and @main_bucket don't
	 * fall on the same lock table.
	 */

	/* Allocating @lhid before aquiring locks to be able to sleep if
	 * necessary.
	 */
	lhid = kzalloc(sizeof(*lhid), GFP_KERNEL);
	if (!lhid)
		return -ENOMEM;
	xid = cfg->xfc_dst->xid_id;
	init_fxid(&lhid->xhl_common, xid);

	rc = -ESRCH;
	if (xia_find_xid_lock(&local_bucket, xtbl, xid))
		goto out;

	rc = -EINVAL;
	net = xtbl_net(xtbl);
	main_xtbl = xia_find_xtbl_hold(net->xia.main_rtbl, XIDTYPE_HID);
	BUG_ON(!net_eq(net, xtbl_net(main_xtbl)));
	if (xia_find_xid_lock(&main_bucket, main_xtbl, xid))
		goto unlock_main;

	rc = fib_add_fxid_locked(local_bucket, xtbl, &lhid->xhl_common);
	if (rc)
		goto unlock_main;

	fib_unlock_bucket(main_xtbl, main_bucket);
	xtbl_put(main_xtbl);
	atomic_inc(&net->xia.hid_state->to_announce);
	goto out;

unlock_main:
	fib_unlock_bucket(main_xtbl, main_bucket);
	xtbl_put(main_xtbl);
	free_fxid(xtbl, &lhid->xhl_common);
out:
	fib_unlock_bucket(xtbl, local_bucket);
	return rc;
}

static int local_delroute(struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	struct fib_xid *fxid = fib_rm_xid(xtbl, cfg->xfc_dst->xid_id);
	if (!fxid)
		return -ESRCH;
	free_fxid(xtbl, fxid);
	return 0;
}

static int local_dump_hid(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 pid = NETLINK_CB(cb->skb).pid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct xia_xid dst;

	nlh = nlmsg_put(skb, pid, seq, RTM_NEWROUTE, sizeof(*rtm), NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = rtbl->tbl_id;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;

	BUG_ON(rtbl->tbl_id != XRTABLE_LOCAL_INDEX);
	rtm->rtm_type = RTN_LOCAL;

	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;
	
	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	NLA_PUT_TYPE(skb, struct xia_xid, RTA_DST, dst);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static const struct xia_ppal_rt_eops hid_rt_eops_local = {
	.newroute = local_newroute,
	.delroute = local_delroute,
	.dump_fxid = local_dump_hid,
};

/*
 *	Main HID table
 */

static int main_newroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	if (!cfg->xfc_odev)
		return -EINVAL;
	if (!cfg->xfc_lladdr)
		return -EINVAL;
	if (cfg->xfc_lladdr_len != cfg->xfc_odev->addr_len)
		return -EINVAL;

	return insert_neigh(xtbl, cfg->xfc_dst->xid_id, cfg->xfc_odev,
		cfg->xfc_lladdr);
}

static int main_delroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
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
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 pid = NETLINK_CB(cb->skb).pid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_hid_main *mhid = (struct fib_xid_hid_main *)fxid;
	struct xia_xid dst;
	struct nlattr *ha_attr;
	struct hrdw_addr *pos_ha;

	nlh = nlmsg_put(skb, pid, seq, RTM_NEWROUTE, sizeof(*rtm), NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = rtbl->tbl_id;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;

	BUG_ON(rtbl->tbl_id != XRTABLE_MAIN_INDEX);
	rtm->rtm_type = RTN_UNICAST;

	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;
	
	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	NLA_PUT_TYPE(skb, struct xia_xid, RTA_DST, dst);

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
		rtha->hha_len = nlmsg_get_pos(skb) - (void *) rtha;
	}
	nla_nest_end(skb, ha_attr);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void main_free_hid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	free_mhid((struct fib_xid_hid_main *)fxid);
}

static const struct xia_ppal_rt_eops hid_rt_eops_main = {
	.newroute = main_newroute,
	.delroute = main_delroute,
	.dump_fxid = main_dump_hid,
	.free_fxid = main_free_hid,
};

/*
 *	Network namespace
 */

/* See function local_newroute to understand
 * why @localhid_locktbl is necessary.
 */
static struct xia_lock_table localhid_locktbl __read_mostly;

static int __net_init hid_net_init(struct net *net)
{
	int rc;

	rc = init_xid_table(net->xia.local_rtbl, XIDTYPE_HID,
		&localhid_locktbl, &hid_rt_eops_local);
	if (rc)
		goto out;

	rc = init_xid_table(net->xia.main_rtbl, XIDTYPE_HID,
		&xia_main_lock_table, &hid_rt_eops_main);
	if (rc)
		goto local_rtbl;

	rc = hid_new_hid_state(net);
	if (rc)
		goto main_rtbl;

	goto out;

main_rtbl:
	end_xid_table(net->xia.main_rtbl, XIDTYPE_HID);
local_rtbl:
	end_xid_table(net->xia.local_rtbl, XIDTYPE_HID);
out:
	return rc;
}

static void __net_exit hid_net_exit(struct net *net)
{
	rtnl_lock();
	hid_free_hid_state(net);
	end_xid_table(net->xia.main_rtbl, XIDTYPE_HID);
	end_xid_table(net->xia.local_rtbl, XIDTYPE_HID);
	rtnl_unlock();
}

static struct pernet_operations hid_net_ops __read_mostly = {
	.init = hid_net_init,
	.exit = hid_net_exit,
};

/*
 *	HID Routing
 */

static int hid_local_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, struct xip_dst *xdst)
{
	struct fib_xid_table *local_xtbl;
	struct fib_xid *fxid;
	int rc;

	if (xdst) {
		/* An HID cannot be a sink. */
		return -ENOENT;
	}

	rcu_read_lock();
	local_xtbl = xia_find_xtbl_rcu(net->xia.local_rtbl, XIDTYPE_HID);
	BUG_ON(!local_xtbl);
	fxid = xia_find_xid_rcu(local_xtbl, xid);
	rc = fxid ? 0 : -ENOENT;
	rcu_read_unlock();
	return rc;
}

/* Forward packets. */

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
		/* XXX An ICMP-like error should be genererated here. */
		if (net_ratelimit())
			printk("%s: hop limit reached\n", __FUNCTION__);
		goto drop;
	}

	xdst = skb_xdst(skb);

	if (unlikely(skb->len > dst_mtu(&xdst->dst))) {
		/* XXX An ICMP-like error should be genererated here. */
		if (net_ratelimit())
			printk("%s: packet is larger than MTU (%i > %i)\n",
				__FUNCTION__, skb->len, dst_mtu(&xdst->dst));
		goto drop;
	}

	/* We are about to mangle packet. Copy it! */
	ha = (struct hrdw_addr *)xdst->info;
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
	return (struct hrdw_addr *)skb_xdst(skb)->info;
}

static inline int xip_skb_dst_mtu(struct sk_buff *skb)
{
	/* TODO Allow a transport protocol to probe the Path MTU, and
	 * use skb_ha(skb)->dev-mtu in that case.
	 * See net/ipv4/ip_output.c:ip_skb_dst_mtu for an example.
	 */
	return dst_mtu(skb_dst(skb));
}

static int main_input_output(struct sk_buff *skb)
{
	struct hrdw_addr *ha = skb_ha(skb);
	struct net_device *dev = ha->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	int rc;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_XIP);

	if (skb->len > xip_skb_dst_mtu(skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	/* Be paranoid, rather than too clever. */
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

	/* TODO Implement link-layer header cache here.
	 * See net/ipv4/ip_output.c:ip_finish_output2,
	 * include/net/neighbour.h:neigh_output, and
	 * include/net/neighbour.h:neigh_hh_output.
	 */
	/* Fill the device header. */
	rc = dev_hard_header(skb, skb->dev, skb->protocol, ha->ha,
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

static int hid_main_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, struct xia_xid *next_xid, struct xip_dst *xdst)
{
	struct fib_xid_table *main_xtbl;
	struct fib_xid_hid_main *mhid;
	struct hrdw_addr *ha;
	int rc;

	rcu_read_lock();
	main_xtbl = xia_find_xtbl_rcu(net->xia.main_rtbl, XIDTYPE_HID);
	BUG_ON(!main_xtbl);
	mhid = (struct fib_xid_hid_main *)xia_find_xid_rcu(main_xtbl, xid);

	rc = XRP_ACT_NEXT_EDGE;
	if (!mhid)
		goto out;
	/* TODO Carefully read @list_first_entry_rcu to understand what happens
	 * when the list is empty!
	 */
	ha = list_first_entry_rcu(&mhid->xhm_haddrs, struct hrdw_addr, ha_list);
	if (unlikely(!ha)) {
		/* @ha may be NULL because we don't have a lock over @mhid,
		 * we're just browsing under RCU protection.
		 */
		goto out;
	}

	if (xdst->input) {
		xdst->dst.input = main_input_input;
		xdst->dst.output = main_input_output;
	} else {
		xdst->dst.input = main_output_input;
		xdst->dst.output = main_output_output;
	}

	/* TODO One needs positive dependency for this assignment! */
	xdst->info = ha;

	rc = XRP_ACT_FORWARD;

out:
	rcu_read_unlock();
	return rc;
}

static struct xip_route_proc hid_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_HID,
	.local_deliver = hid_local_deliver,
	.main_deliver = hid_main_deliver,
};

/*
 * xia_hid_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_hid_init(void)
{
	int rc;

	rc = xia_lock_table_init(&localhid_locktbl, XIA_LTBL_SPREAD_SMALL);
	if (rc < 0)
		goto out;

	rc = xia_register_pernet_subsys(&hid_net_ops);
	if (rc)
		goto locktbl;

	rc = hid_nwp_init();
	if (rc)
		goto net;

	rc = xip_add_router(&hid_rt_proc);
	if (rc)
		goto nwp;

	rc = ppal_add_map("hid", XIDTYPE_HID);
	if (rc)
		goto route;

	printk(KERN_ALERT "XIA Principal HID loaded\n");
	goto out;

route:
	xip_del_router(&hid_rt_proc);
nwp:
	hid_nwp_exit();
net:
	xia_unregister_pernet_subsys(&hid_net_ops);
locktbl:
	xia_lock_table_finish(&localhid_locktbl);
out:
	return rc;
}

/*
 * xia_hid_exit - this function is called when the modlule is removed.
 */
static void __exit xia_hid_exit(void)
{
	ppal_del_map(XIDTYPE_HID);
	xip_del_router(&hid_rt_proc);
	hid_nwp_exit();
	xia_unregister_pernet_subsys(&hid_net_ops);
	xia_lock_table_finish(&localhid_locktbl);

	rcu_barrier();
	flush_scheduled_work();

	/* TODO Make sure that no DST entry refers an HID. */

	printk(KERN_ALERT "XIA Principal HID UNloaded\n");
}

module_init(xia_hid_init);
module_exit(xia_hid_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Host Principal");

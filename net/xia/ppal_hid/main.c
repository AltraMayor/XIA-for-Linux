#include <linux/module.h>
#include <net/xia_dag.h>
#include <net/xia_hid.h>

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
	 */

	/* XXX This code assumes that @local_bucket and @main_bucket don't
	 * fall on the same lock, and this is not guaranteed!
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
	BUG_ON(net != xtbl_net(main_xtbl));
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

static const struct xia_ppal_rt_eops hid_rt_eops_local = {
	.newroute = local_newroute,
	.delroute = local_delroute,
	.dump_fxid = local_dump_hid,
};

static const struct xia_ppal_rt_eops hid_rt_eops_main = {
	.newroute = main_newroute,
	.delroute = main_delroute,
	.dump_fxid = main_dump_hid,
	.free_fxid = main_free_hid,
};

/*
 *	Network namespace
 */

static int __net_init hid_net_init(struct net *net)
{
	int rc;

	rc = init_xid_table(net->xia.local_rtbl, XIDTYPE_HID,
		&hid_rt_eops_local);
	if (rc)
		goto out;

	rc = init_xid_table(net->xia.main_rtbl, XIDTYPE_HID,
		&hid_rt_eops_main);
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
 * xia_hid_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_hid_init(void)
{
	int rc;

	rc = xia_register_pernet_subsys(&hid_net_ops);
	if (rc)
		goto out;

	rc = hid_nwp_init();
	if (rc)
		goto net;

	rc = ppal_add_map("hid", XIDTYPE_HID);
	if (rc)
		goto nwp;

	printk(KERN_ALERT "XIA Principal HID loaded\n");
	goto out;

nwp:
	hid_nwp_exit();
net:
	xia_unregister_pernet_subsys(&hid_net_ops);
out:
	return rc;
}

/*
 * xia_hid_exit - this function is called when the modlule is removed.
 */
static void __exit xia_hid_exit(void)
{
	ppal_del_map(XIDTYPE_HID);
	hid_nwp_exit();
	xia_unregister_pernet_subsys(&hid_net_ops);

	rcu_barrier();
	flush_scheduled_work();

	printk(KERN_ALERT "XIA Principal HID UNloaded\n");
}

module_init(xia_hid_init);
module_exit(xia_hid_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Host Principal");

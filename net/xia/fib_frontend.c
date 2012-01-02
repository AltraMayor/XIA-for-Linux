#include <linux/init.h>
#include <linux/socket.h>
#include <linux/export.h>
#include <net/rtnetlink.h>
#include <net/xia_fib.h>

#define XID_NLATTR	{ .len = sizeof(struct xia_xid) }

static const struct nla_policy rtm_xia_policy[RTA_MAX + 1] = {
	[RTA_DST]		= XID_NLATTR,
	[RTA_OIF]		= { .type = NLA_U32 },
	[RTA_GATEWAY]		= XID_NLATTR,
	[RTA_LLADDR]		= { .type = NLA_BINARY, .len = MAX_ADDR_LEN },
};

static int rtm_to_fib_config(struct net *net, struct sk_buff *skb,
			     struct nlmsghdr *nlh, struct xia_fib_config *cfg)
{
	int rc, remaining;
	struct rtmsg *rtm;
	struct nlattr *attr;

	rc = nlmsg_validate(nlh, sizeof(*rtm), RTA_MAX, rtm_xia_policy);
	if (rc < 0)
		return rc;

	rtm = nlmsg_data(nlh);
	if (rtm->rtm_type > RTN_MAX)
		return -EINVAL;

	memset(cfg, 0, sizeof(*cfg));

	cfg->xfc_dst_len = rtm->rtm_dst_len;
	cfg->xfc_tos = rtm->rtm_tos;
	cfg->xfc_table = rtm->rtm_table;
	cfg->xfc_protocol = rtm->rtm_protocol;
	cfg->xfc_scope = rtm->rtm_scope;
	cfg->xfc_type = rtm->rtm_type;
	cfg->xfc_flags = rtm->rtm_flags;

	cfg->xfc_nlflags = nlh->nlmsg_flags;
	cfg->xfc_nlinfo.nlh = nlh;
	cfg->xfc_nlinfo.nl_net = net;
	cfg->xfc_nlinfo.pid = NETLINK_CB(skb).pid;

	nlmsg_for_each_attr(attr, nlh, sizeof(struct rtmsg), remaining) {
		switch (nla_type(attr)) {
		case RTA_DST:
			cfg->xfc_dst = nla_data(attr);
			if (cfg->xfc_dst_len != nla_len(attr))
				return -EINVAL;
			break;
		case RTA_OIF: {
			ASSERT_RTNL();
			cfg->xfc_odev = __dev_get_by_index(net,
				nla_get_u32(attr));
			if (!cfg->xfc_odev)
				return -EINVAL;
			break;
		}
		case RTA_GATEWAY:
			cfg->xfc_gw = nla_data(attr);
			break;
		case RTA_LLADDR:
			cfg->xfc_lladdr = nla_data(attr);
			cfg->xfc_lladdr_len = nla_len(attr);
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int xia_rtm_newroute(struct sk_buff *skb, struct nlmsghdr *nlh,
				void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct xia_fib_config cfg;
	struct fib_xia_rtable *rtbl;
	struct fib_xid_table *xtbl;
	int rc;

	rc = rtm_to_fib_config(net, skb, nlh, &cfg);
	if (rc < 0)
		return rc;

	if (!cfg.xfc_dst)
		return -EINVAL;
	rtbl = xia_fib_get_table(net, cfg.xfc_table);
	if (rtbl == NULL)
		return -EINVAL;

	xtbl = xia_find_xtbl_hold(rtbl, cfg.xfc_dst->xid_type);
	if (!xtbl)
		return -EXTYNOSUPPORT;

	rc = xtbl->fxt_eops->newroute(xtbl, &cfg);
	xtbl_put(xtbl);
	return rc;
}

static int xia_rtm_delroute(struct sk_buff *skb, struct nlmsghdr *nlh,
				void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct xia_fib_config cfg;
	struct fib_xia_rtable *rtbl;
	struct fib_xid_table *xtbl;
	int rc;

	rc = rtm_to_fib_config(net, skb, nlh, &cfg);
	if (rc < 0)
		return rc;

	if (!cfg.xfc_dst)
		return -EINVAL;
	rtbl = xia_fib_get_table(net, cfg.xfc_table);
	if (rtbl == NULL)
		return -EINVAL;

	xtbl = xia_find_xtbl_hold(rtbl, cfg.xfc_dst->xid_type);
	if (!xtbl)
		return -EXTYNOSUPPORT;

	rc = xtbl->fxt_eops->delroute(xtbl, &cfg);
	xtbl_put(xtbl);
	return rc;
}

static int xia_fib_dump_ppal(struct fib_xid_table *xtbl,
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct fib_xid_buckets *abranch;
	long i, j = 0;
	long first_j = cb->args[4];
	int dumped = 0;
	int divisor, aindex;

	rcu_read_lock();
	abranch = rcu_dereference(xtbl->fxt_active_branch);
	divisor = abranch->divisor;
	aindex = abranch->index;
	for (i = cb->args[3]; i < divisor; i++, first_j = 0) {
		struct fib_xid *fxid;
		struct hlist_node *p;
		struct hlist_head *head = &abranch->buckets[i];
		j = 0;
		hlist_for_each_entry_rcu(fxid, p, head,
			fx_branch_list[aindex]) {
			if (j < first_j)
				goto next;
			if (dumped)
				memset(&cb->args[5], 0, sizeof(cb->args) -
						 5 *	sizeof(cb->args[0]));
			if (xtbl->fxt_eops->dump_fxid(fxid, xtbl, rtbl, skb, cb)
				< 0)
				goto out;
			dumped = 1;
next:
			j++;
		}
	}
out:
	rcu_read_unlock();
	cb->args[3] = i;
	cb->args[4] = j;
	return skb->len;
}

static int xia_fib_dump_rtable(struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	long i, j = 0;
	long first_j = cb->args[2];
	int dumped = 0;

	for (i = cb->args[1]; i < NUM_PRINCIPAL_HINT; i++, first_j = 0) {
		struct fib_xid_table *xtbl;
		struct hlist_node *p;
		struct hlist_head *head = &rtbl->ppal[i];
		j = 0;
		rcu_read_lock();
		hlist_for_each_entry_rcu(xtbl, p, head, fxt_list) {
			if (j < first_j)
				goto next;
			if (dumped)
				memset(&cb->args[3], 0, sizeof(cb->args) -
						 3 *	sizeof(cb->args[0]));
			if (xia_fib_dump_ppal(xtbl, rtbl, skb, cb) < 0) {
				rcu_read_unlock();
				goto out;
			}
			dumped = 1;
next:
			j++;
		}
		rcu_read_unlock();
	}
out:
	cb->args[1] = i;
	cb->args[2] = j;
	return skb->len;
}

static int xia_dump_fib(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	long i;
	int dumped = 0;

	/* XXX Once XIA stack implements DST's interface,
	 * this lines should implement its dump.
	 */
	/*
	if (nlmsg_len(cb->nlh) >= sizeof(struct rtmsg) &&
	    ((struct rtmsg *) nlmsg_data(cb->nlh))->rtm_flags & RTM_F_CLONED)
		return ip_rt_dump(skb, cb);
	*/

	for (i = cb->args[0]; i < XRTABLE_MAX_INDEX; i++) {
		struct fib_xia_rtable *rtbl = xia_fib_get_table(net, i);
		if (dumped)
			memset(&cb->args[1], 0, sizeof(cb->args) -
					 1 *	sizeof(cb->args[0]));
		if (xia_fib_dump_rtable(rtbl, skb, cb) < 0)
			break;
		dumped = 1;
	}
	cb->args[0] = i;
	return skb->len;
}

/*
 *	Network namespace
 */

static int __net_init fib_net_init(struct net *net)
{
	RCU_INIT_POINTER(net->xia.local_rtbl,
		create_xia_rtable(net, XRTABLE_LOCAL_INDEX));
	if (!net->xia.local_rtbl)
		goto error;
	RCU_INIT_POINTER(net->xia.main_rtbl,
		create_xia_rtable(net, XRTABLE_MAIN_INDEX));
	if (!net->xia.main_rtbl)
		goto local;
	return 0;

local:
	destroy_xia_rtable(&net->xia.local_rtbl);
error:
	return -ENOMEM;
}

static void __net_exit fib_net_exit(struct net *net)
{
	rtnl_lock();
	destroy_xia_rtable(&net->xia.main_rtbl);
	destroy_xia_rtable(&net->xia.local_rtbl);
	rtnl_unlock();
}

static struct pernet_operations fib_net_ops __read_mostly = {
	.init = fib_net_init,
	.exit = fib_net_exit,
};

int xia_register_pernet_subsys(struct pernet_operations *ops)
{
	return register_pernet_subsys(ops);
}
EXPORT_SYMBOL_GPL(xia_register_pernet_subsys);

int xia_fib_init(void)
{
	int rc, size, n;

	rc = init_main_lock_table(&size, &n);
	if (rc)
		goto out;

	rc = register_pernet_subsys(&fib_net_ops);
	if (rc)
		goto locks;

	rtnl_register(PF_XIA, RTM_NEWROUTE, xia_rtm_newroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_DELROUTE, xia_rtm_delroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_GETROUTE, NULL, xia_dump_fib, NULL);

	printk(KERN_INFO "XIA lock table entries: %i = 2^%i (%i bytes)\n",
		n, ilog2(n), size);
	goto out;

/*
rtnl:
	rtnl_unregister_all(PF_XIA);
net:
	unregister_pernet_subsys(&fib_net_ops);
*/
locks:
	destroy_main_lock_table();
out:
	return rc;
}

void xia_fib_exit(void)
{
	rtnl_unregister_all(PF_XIA);
	unregister_pernet_subsys(&fib_net_ops);
	destroy_main_lock_table();
}

#include <linux/init.h>
#include <linux/socket.h>
#include <net/rtnetlink.h>
#include <net/xia_fib.h>

#define XID_NLATTR	{ .len = sizeof(struct xia_xid) }

const struct nla_policy rtm_xia_policy[RTA_MAX + 1] = {
	[RTA_DST]		= XID_NLATTR,
	[RTA_OIF]		= { .type = NLA_U32 },
	[RTA_GATEWAY]		= XID_NLATTR,
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
		case RTA_OIF:
			cfg->xfc_oif = nla_get_u32(attr);
			break;
		case RTA_GATEWAY:
			cfg->xfc_gw = nla_data(attr);
			cfg->xfc_gw_len = nla_len(attr);
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
	struct fib_xia_rtable *rtb;
	int rc;

	rc = rtm_to_fib_config(net, skb, nlh, &cfg);
	if (rc < 0)
		return rc;

	rtb = xia_fib_get_table(net, cfg.xfc_table);
	if (rtb == NULL)
		return -ESRCH;

	return -ENOPROTOOPT;
	/* XXX Implement me! rc = fib_table_insert(tb, &cfg); */
}

static int xia_rtm_delroute(struct sk_buff *skb, struct nlmsghdr *nlh,
				void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct xia_fib_config cfg;
	struct fib_xia_rtable *rtb;
	int rc;

	rc = rtm_to_fib_config(net, skb, nlh, &cfg);
	if (rc < 0)
		return rc;

	rtb = xia_fib_get_table(net, cfg.xfc_table);
	if (rtb == NULL)
		return -ESRCH;

	return -ENOPROTOOPT;
	/* XXX Implement me! err = fib_table_delete(tb, &cfg); */
}

static int xia_fib_dump_xid(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	/* XXX Implement this function!
	 * See net/ipv4/fib_semantics.c:fib_dump_info and its call in
	 * net/ipv4/fib_trie.c:fn_trie_dump_fa
	 */
	return -1;
}

static int xia_fib_dump_ppal(struct fib_xid_table *xtbl,
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	long i, j = 0;
	long first_j = cb->args[4];
	int dumped = 0;
	int divisor = xtbl->fxt_divisor;

	for (i = cb->args[3]; i < divisor; i++, first_j = 0) {
		struct fib_xid *fxid;
		struct hlist_node *p;
		struct hlist_head *head = &xtbl->fxt_buckets[i];
		j = 0;
		hlist_for_each_entry(fxid, p, head, fx_list) {
			if (j < first_j)
				goto next;
			if (dumped)
				memset(&cb->args[5], 0, sizeof(cb->args) -
						 5 *	sizeof(cb->args[0]));
			if (xia_fib_dump_xid(fxid, xtbl, rtbl, skb, cb) < 0)
				goto out;
			dumped = 1;
next:
			j++;
		}

	}
out:
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
		hlist_for_each_entry(xtbl, p, head, fxt_list) {
			if (j < first_j)
				goto next;
			if (dumped)
				memset(&cb->args[3], 0, sizeof(cb->args) -
						 3 *	sizeof(cb->args[0]));
			if (xia_fib_dump_ppal(xtbl, rtbl, skb, cb) < 0)
				goto out;
			dumped = 1;
next:
			j++;
		}

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

static int __net_init xia_fib_net_init(struct net *net)
{
	net->xia.main_rtbl = create_xia_rtable();
	if (!net->xia.main_rtbl)
		goto error;
	net->xia.local_rtbl = create_xia_rtable();
	if (!net->xia.local_rtbl)
		goto main_rtbl;
	return 0;

main_rtbl:
	destroy_xia_rtable(net->xia.main_rtbl);
error:
	return -ENOMEM;
}

static void __net_exit xia_fib_net_exit(struct net *net)
{
	rtnl_lock();
	destroy_xia_rtable(net->xia.main_rtbl);
	destroy_xia_rtable(net->xia.local_rtbl);
	rtnl_unlock();
}

static int __net_init fib_net_init(struct net *net)
{
	return xia_fib_net_init(net);
}

static void __net_exit fib_net_exit(struct net *net)
{
	xia_fib_net_exit(net);
}

static struct pernet_operations fib_net_ops = {
	.init = fib_net_init,
	.exit = fib_net_exit,
};

void __init xia_fib_init(void)
{
	rtnl_register(PF_XIA, RTM_NEWROUTE, xia_rtm_newroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_DELROUTE, xia_rtm_delroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_GETROUTE, NULL, xia_dump_fib, NULL);

	register_pernet_subsys(&fib_net_ops);
	/* XXX Don't we need to listen to notifiers as well?
	register_netdevice_notifier(&fib_netdev_notifier);
	register_inetaddr_notifier(&fib_inetaddr_notifier);
	*/
}

#include <linux/init.h>
#include <linux/socket.h>
#include <net/rtnetlink.h>
#include <net/xia_fib.h>

/*
const struct nla_policy rtm_ipv4_policy[RTA_MAX + 1] = {
	[RTA_DST]		= { .type = NLA_U32 },
	[RTA_SRC]		= { .type = NLA_U32 },
	[RTA_IIF]		= { .type = NLA_U32 },
	[RTA_OIF]		= { .type = NLA_U32 },
	[RTA_GATEWAY]		= { .type = NLA_U32 },
	[RTA_PRIORITY]		= { .type = NLA_U32 },
	[RTA_PREFSRC]		= { .type = NLA_U32 },
	[RTA_METRICS]		= { .type = NLA_NESTED },
	[RTA_MULTIPATH]		= { .len = sizeof(struct rtnexthop) },
	[RTA_FLOW]		= { .type = NLA_U32 },
};

static int rtm_to_fib_config(struct net *net, struct sk_buff *skb,
			     struct nlmsghdr *nlh, struct fib_config *cfg)
{
	struct nlattr *attr;
	int err, remaining;
	struct rtmsg *rtm;

	err = nlmsg_validate(nlh, sizeof(*rtm), RTA_MAX, rtm_ipv4_policy);
	if (err < 0)
		goto errout;

	memset(cfg, 0, sizeof(*cfg));

	rtm = nlmsg_data(nlh);
	cfg->fc_dst_len = rtm->rtm_dst_len;
	cfg->fc_tos = rtm->rtm_tos;
	cfg->fc_table = rtm->rtm_table;
	cfg->fc_protocol = rtm->rtm_protocol;
	cfg->fc_scope = rtm->rtm_scope;
	cfg->fc_type = rtm->rtm_type;
	cfg->fc_flags = rtm->rtm_flags;
	cfg->fc_nlflags = nlh->nlmsg_flags;

	cfg->fc_nlinfo.pid = NETLINK_CB(skb).pid;
	cfg->fc_nlinfo.nlh = nlh;
	cfg->fc_nlinfo.nl_net = net;

	if (cfg->fc_type > RTN_MAX) {
		err = -EINVAL;
		goto errout;
	}

	nlmsg_for_each_attr(attr, nlh, sizeof(struct rtmsg), remaining) {
		switch (nla_type(attr)) {
		case RTA_DST:
			cfg->fc_dst = nla_get_be32(attr);
			break;
		case RTA_OIF:
			cfg->fc_oif = nla_get_u32(attr);
			break;
		case RTA_GATEWAY:
			cfg->fc_gw = nla_get_be32(attr);
			break;
		case RTA_PRIORITY:
			cfg->fc_priority = nla_get_u32(attr);
			break;
		case RTA_PREFSRC:
			cfg->fc_prefsrc = nla_get_be32(attr);
			break;
		case RTA_METRICS:
			cfg->fc_mx = nla_data(attr);
			cfg->fc_mx_len = nla_len(attr);
			break;
		case RTA_MULTIPATH:
			cfg->fc_mp = nla_data(attr);
			cfg->fc_mp_len = nla_len(attr);
			break;
		case RTA_FLOW:
			cfg->fc_flow = nla_get_u32(attr);
			break;
		case RTA_TABLE:
			cfg->fc_table = nla_get_u32(attr);
			break;
		}
	}

	return 0;
errout:
	return err;
}

static int xia_rtm_newroute(struct sk_buff *skb, struct nlmsghdr *nlh,
				void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct fib_config cfg;
	struct fib_table *tb;
	int rc;

	rc = rtm_to_fib_config(net, skb, nlh, &cfg);
	if (rc < 0)
		goto out;

	tb = fib_new_table(net, cfg.fc_table);
	if (tb == NULL) {
		rc = -ENOBUFS;
		goto out;
	}

	rc = fib_table_insert(tb, &cfg);
out:
	return rc;
}
*/

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
/* TODO Implement theses calls!
	rtnl_register(PF_XIA, RTM_NEWROUTE, xia_rtm_newroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_DELROUTE, xia_rtm_delroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_GETROUTE, NULL, xia_dump_fib, NULL);
*/

	register_pernet_subsys(&fib_net_ops);
	/* XXX Don't we need to listen to notifiers as well?
	register_netdevice_notifier(&fib_netdev_notifier);
	register_inetaddr_notifier(&fib_inetaddr_notifier);
	*/
}

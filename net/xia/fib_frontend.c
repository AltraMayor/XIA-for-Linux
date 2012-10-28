#include <linux/init.h>
#include <linux/socket.h>
#include <linux/export.h>
#include <net/rtnetlink.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>

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
	cfg->xfc_nlinfo.portid = NETLINK_CB(skb).portid;

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
				return -ENODEV;
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

static inline int is_cloned(const struct nlmsghdr *nlh)
{
	return nlmsg_len(nlh) >= sizeof(struct rtmsg) &&
		((const struct rtmsg *)nlmsg_data(nlh))->rtm_flags &
			RTM_F_CLONED;
}

static int xia_rtm_delroute(struct sk_buff *skb, struct nlmsghdr *nlh,
				void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct xia_fib_config cfg;
	struct fib_xia_rtable *rtbl;
	struct fib_xid_table *xtbl;
	int rc;

	if (is_cloned(nlh)) {
		clear_xdst_table(net);
		return 0;
	}

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

static inline void clear_cb_from(struct netlink_callback *cb, int from)
{
	memset(&cb->args[from], 0, sizeof(cb->args) -
		from * sizeof(cb->args[0]));
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
	aindex = xtbl_branch_index(xtbl, abranch);
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
				clear_cb_from(cb, 5);
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
				clear_cb_from(cb, 3);
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

static int xia_dst_dump_entry(struct xip_dst *xdst, struct sk_buff *skb,
	struct netlink_callback *cb)
{
#define SIZE_OF_DEST	(sizeof(struct xia_xid[XIA_OUTDEGREE_MAX]))

	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct xip_dst_cachinfo ci;

	nlh = nlmsg_put(skb, portid, seq, RTM_NEWROUTE, sizeof(*rtm),
		NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = SIZE_OF_DEST;
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	/* It comes from XIA's DST, not from a routing table. */
	rtm->rtm_table = -1;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	/* XXX One may want to vary here. */
	rtm->rtm_type = RTN_LOCAL;
	rtm->rtm_flags = RTM_F_CLONED;

	if (unlikely(nla_put(skb, RTA_DST, SIZE_OF_DEST, xdst->xids)))
		goto nla_put_failure;

	ci.key_hash = xdst->key_hash;
	ci.input = xdst->input;
	ci.passthrough_action = xdst->passthrough_action;
	ci.sink_action = xdst->sink_action;
	ci.chosen_edge =xdst->chosen_edge;

	if (unlikely(nla_put(skb, RTA_PROTOINFO,
		sizeof(struct xip_dst_cachinfo), &ci)))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Dump XIA's DST table. */
static int xia_dst_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	long i, j = 0;
	long first_j = cb->args[1];
	int dumped = 0;

	for (i = cb->args[0]; i < XIP_DST_TABLE_SIZE; i++, first_j = 0) {
		struct dst_entry *dsth;
		j = 0;
		rcu_read_lock();
		for (dsth = rcu_dereference(net->xia.xip_dst_table.buckets[i]);
			dsth; dsth = rcu_dereference(dsth->next)) {
			if (j < first_j)
				goto next;
			if (dumped)
				clear_cb_from(cb, 2);
			if (xia_dst_dump_entry(dst_xdst(dsth), skb, cb) < 0) {
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
	cb->args[0] = i;
	cb->args[1] = j;
	return skb->len;
}

static int xia_dump_fib(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net;
	long i;
	int dumped;

	if (is_cloned(cb->nlh))
		return xia_dst_dump(skb, cb);

	net = sock_net(skb->sk);
	dumped = 0;
	for (i = cb->args[0]; i < XRTABLE_MAX_INDEX; i++) {
		struct fib_xia_rtable *rtbl = xia_fib_get_table(net, i);
		if (dumped)
			clear_cb_from(cb, 1);
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

int __init xia_fib_init(void)
{
	int rc;

	rc = register_pernet_subsys(&fib_net_ops);
	if (rc)
		goto out;

	rtnl_register(PF_XIA, RTM_NEWROUTE, xia_rtm_newroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_DELROUTE, xia_rtm_delroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_GETROUTE, NULL, xia_dump_fib, NULL);

	goto out;

/*
rtnl:
	rtnl_unregister_all(PF_XIA);
net:
	unregister_pernet_subsys(&fib_net_ops);
*/
out:
	return rc;
}

void xia_fib_exit(void)
{
	rtnl_unregister_all(PF_XIA);
	unregister_pernet_subsys(&fib_net_ops);
}

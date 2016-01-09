#include <linux/init.h>
#include <linux/socket.h>
#include <linux/export.h>
#include <net/rtnetlink.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>

#define FIELD_TYPE(t, f)	typeof(((struct t *)0)->f)

#define XID_NLATTR		{ .len = sizeof(struct xia_xid) }
#define PROTOINFO_NLATTR	{					\
	.type = NLA_BINARY,						\
	.len = ((FIELD_TYPE(xia_fib_config, xfc_protoinfo_len))(~0U))	\
}

static const struct nla_policy rtm_xia_policy[RTA_MAX + 1] = {
	[RTA_DST]		= XID_NLATTR,
	[RTA_OIF]		= { .type = NLA_U32 },
	[RTA_GATEWAY]		= XID_NLATTR,
	[RTA_LLADDR]		= { .type = NLA_BINARY, .len = MAX_ADDR_LEN },
	[RTA_PROTOINFO]		= PROTOINFO_NLATTR,
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
	if (rtm->rtm_table >= XRTABLE_MAX_INDEX)
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
		case RTA_PROTOINFO:
			cfg->xfc_protoinfo = nla_data(attr);
			cfg->xfc_protoinfo_len = nla_len(attr);
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int xip_rtm_froute(int to_add, struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct xia_fib_config cfg;
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *xtbl;
	int rc;

	rc = rtm_to_fib_config(net, skb, nlh, &cfg);
	if (rc < 0)
		return rc;

	if (!cfg.xfc_dst)
		return -EINVAL;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_rcu(net, cfg.xfc_dst->xid_type);
	if (!ctx) {
		rcu_read_unlock();
		return -EXTYNOSUPPORT;
	}
	xtbl = ctx->xpc_xtbl;
	if (!xtbl) {
		rcu_read_unlock();
		return -EINVAL;
	}

	rc = to_add
		? xtbl->all_eops[cfg.xfc_table].newroute(ctx, xtbl, &cfg)
		: xtbl->all_eops[cfg.xfc_table].delroute(ctx, xtbl, &cfg);
	rcu_read_unlock();
	return rc;
}

static int xip_rtm_newroute(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	return xip_rtm_froute(1, skb, nlh);
}

static inline int is_cloned(const struct nlmsghdr *nlh)
{
	return nlmsg_len(nlh) >= sizeof(struct rtmsg) &&
		((const struct rtmsg *)nlmsg_data(nlh))->rtm_flags &
			RTM_F_CLONED;
}

static int xip_rtm_delroute(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	if (is_cloned(nlh)) {
		struct net *net = sock_net(skb->sk);

		clear_xdst_table(net);
		return 0;
	}

	return xip_rtm_froute(0, skb, nlh);
}

static inline void clear_cb_from(struct netlink_callback *cb, int from)
{
	memset(&cb->args[from], 0, sizeof(cb->args) -
		from * sizeof(cb->args[0]));
}

static int xip_fib_dump_ppals(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	long i;
	int dumped = 0;

	rcu_read_lock();
	for (i = cb->args[0]; i < XIP_MAX_XID_TYPES; i++) {
		struct xip_ppal_ctx *ctx = xip_find_ppal_ctx_vxt_rcu(net, i);

		if (!ctx || !ctx->xpc_xtbl)
			continue;
		if (dumped)
			clear_cb_from(cb, 1);
		if (ctx->xpc_xtbl->all_iops->xtbl_dump_rcu(ctx->xpc_xtbl,
							   ctx, skb, cb) < 0)
			break;
		dumped = 1;
	}
	rcu_read_unlock();

	cb->args[0] = i;
	return skb->len;
}

static int xip_dst_dump_entry(struct xip_dst *xdst, struct sk_buff *skb,
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
	ci.chosen_edge = xdst->chosen_edge;

	if (unlikely(nla_put(skb, RTA_PROTOINFO,
			     sizeof(struct xip_dst_cachinfo), &ci)))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Dump XIP's DST table. */
static int xip_dst_dump(struct sk_buff *skb, struct netlink_callback *cb)
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
			if (xip_dst_dump_entry(dst_xdst(dsth), skb, cb) < 0) {
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

static int xip_dump_fib(struct sk_buff *skb, struct netlink_callback *cb)
{
	if (is_cloned(cb->nlh))
		return xip_dst_dump(skb, cb);
	return xip_fib_dump_ppals(skb, cb);
}

/* Network namespace */

static int __net_init fib_net_init(struct net *net)
{
	return init_fib_ppal_ctx(net);
}

static void __net_exit fib_net_exit(struct net *net)
{
	release_fib_ppal_ctx(net);
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

	rtnl_register(PF_XIA, RTM_NEWROUTE, xip_rtm_newroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_DELROUTE, xip_rtm_delroute, NULL, NULL);
	rtnl_register(PF_XIA, RTM_GETROUTE, NULL, xip_dump_fib, NULL);

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

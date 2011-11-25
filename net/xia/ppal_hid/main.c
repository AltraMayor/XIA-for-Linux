#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>
#include <net/xia_hid.h>

struct fib_xid_hid_local {
	struct fib_xid	xhl_common;

	/* Empty. */
};

static int local_newroute(struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	struct fib_xid_hid_local *lhid;
	int rc;

	/* XXX Shouldn't one have a slab here? */
	rc = -ENOMEM;
	lhid = kmalloc(sizeof(*lhid), GFP_KERNEL);
	if (!lhid)
		goto out;
	memset(lhid, 0, sizeof(*lhid));

	memmove(lhid->xhl_common.fx_xid, cfg->xfc_dst->xid_id, XIA_XID_MAX);

	rc = fib_add_xid(xtbl, (struct fib_xid *)lhid);
	if (rc)
		goto lhid;
	goto out;

lhid:
	kfree(lhid);
out:
	return rc;
}

static int local_delroute(struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg)
{
	struct fib_xid *fxid = fib_rm_xid(xtbl, cfg->xfc_dst->xid_id);
	if (!fxid)
		return -ESRCH;
	kfree(fxid);
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

/* Hardware Address. */
struct hrdw_addr {
	struct list_head	next;
	struct net_device	*dev;
	/* Since @ha is at the end of struct hrdw_addr, one doesn't need to
	 * enforce alignment, otherwise use the following line:
	 * u8 ha[ALIGN(MAX_ADDR_LEN, sizeof(long))];
	 */
	u8			ha[MAX_ADDR_LEN];
};

struct fib_xid_hid_main {
	struct fib_xid		xhm_common;
	struct list_head	xhm_haddrs;
};

static struct hrdw_addr *new_ha(struct net_device *dev, u8 *lladdr)
{
	struct hrdw_addr *ha = kmalloc(sizeof(*ha), GFP_KERNEL);
	if (!ha)
		return NULL;
	memset(ha, 0, sizeof(*ha));
	INIT_LIST_HEAD(&ha->next);
	ha->dev = dev;
	dev_hold(dev);
	memmove(ha->ha, lladdr, dev->addr_len);
	return ha;
}

/* ATTENTION! @ha should not be inserted in a list! */
static inline void free_ha(struct hrdw_addr *ha)
{
	dev_put(ha->dev);
	ha->dev = NULL;
	kfree(ha);
}

/* ATTENTION! If @ha is duplicated, it frees ha! */
static int add_ha(struct list_head *head, struct hrdw_addr *ha)
{
	struct hrdw_addr *pos_ha;

	list_for_each_entry(pos_ha, head, next) {
		int c1 = memcmp(pos_ha->ha, ha->ha, ha->dev->addr_len);
		int c2 = pos_ha->dev->ifindex - ha->dev->ifindex;
		if (unlikely(!c1 && !c2)) {
			/* It's a duplicate. */
			free_ha(ha);
			return -ESRCH;
		}
		/* Keep listed sorted. */
		if (c1 > 0 || (!c1 && c2 > 0))
			break;
	}

	list_add_tail(&ha->next, &pos_ha->next);
	return 0;
}

static void del_ha(struct list_head *head, u8 *str_ha, struct net_device *dev)
{
	struct hrdw_addr *pos_ha, *nxt;

	/* Notice that one could use list_for_each_entry here, but
	 * it could break if someone changes the code later and doesn't pay
	 * attention to this detail; playing safe!
	 */
	list_for_each_entry_safe(pos_ha, nxt, head, next) {
		int c1 = memcmp(pos_ha->ha, str_ha, dev->addr_len);
		int c2 = pos_ha->dev->ifindex - dev->ifindex;
		if (unlikely(!c1 && !c2)) {
			list_del(&pos_ha->next);
			free_ha(pos_ha);
			break;
		}
		/* Listed is sorted. */
		if (c1 > 0 || (!c1 && c2 > 0))
			break;
	}
}

static void free_haddrs(struct list_head *head)
{
	struct hrdw_addr *pos_ha, *nxt;
	list_for_each_entry_safe(pos_ha, nxt, head, next) {
		list_del(&pos_ha->next);
		free_ha(pos_ha);
	}
}

static int main_newroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid_hid_main *mhid;
	struct hrdw_addr *ha;
	int rc;

	rc = -EINVAL;
	if (!cfg->xfc_odev)
		goto out;
	if (!cfg->xfc_lladdr)
		goto out;
	if (cfg->xfc_lladdr_len != cfg->xfc_odev->addr_len)
		goto out;

	/* XXX Shouldn't one have a slab here? */
	rc = -ENOMEM;
	ha = new_ha(cfg->xfc_odev, cfg->xfc_lladdr);
	if (!ha)
		goto out;

	mhid = (struct fib_xid_hid_main *)
		xia_find_xid(xtbl, cfg->xfc_dst->xid_id);
	if (!mhid) {
		/* XXX Shouldn't one have a slab here? */
		rc = -ENOMEM;
		mhid = kmalloc(sizeof(*mhid), GFP_KERNEL);
		if (!mhid)
			goto ha;
		memset(mhid, 0, sizeof(*mhid));
		memmove(mhid->xhm_common.fx_xid, cfg->xfc_dst->xid_id,
			XIA_XID_MAX);
		INIT_LIST_HEAD(&mhid->xhm_haddrs);
		rc = fib_add_xid(xtbl, (struct fib_xid *)mhid);
		if (rc) {
			kfree(mhid);
			goto ha;
		}
	}

	rc = add_ha(&mhid->xhm_haddrs, ha);
	goto out;

ha:
	free_ha(ha);
out:
	return rc;
}

static int main_delroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid_hid_main *mhid;

	if (!cfg->xfc_odev)
		return -EINVAL;
	if (!cfg->xfc_lladdr)
		return -EINVAL;
	if (cfg->xfc_lladdr_len != cfg->xfc_odev->addr_len)
		return -EINVAL;

	mhid = (struct fib_xid_hid_main *)
		xia_find_xid(xtbl, cfg->xfc_dst->xid_id);
	if (!mhid)
		return -ESRCH;

	del_ha(&mhid->xhm_haddrs, cfg->xfc_lladdr, cfg->xfc_odev);
	if (list_empty(&mhid->xhm_haddrs)) {
		fib_rm_fxid(xtbl, (struct fib_xid *)mhid);
		kfree(mhid);
	}
	return 0;
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
	list_for_each_entry(pos_ha, &mhid->xhm_haddrs, next) {
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

static void main_free_hid(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_hid_main *mhid = (struct fib_xid_hid_main *)fxid;
	free_haddrs(&mhid->xhm_haddrs);
	kfree(fxid);
}

static const struct xia_ppal_rt_ops hid_rt_ops_local = {
	.newroute = local_newroute,
	.delroute = local_delroute,
	.dump_fxid = local_dump_hid,
};

static const struct xia_ppal_rt_ops hid_rt_ops_main = {
	.newroute = main_newroute,
	.delroute = main_delroute,
	.dump_fxid = main_dump_hid,
	.free_fxid = main_free_hid,
};

/* Autonomous Domain Principal */
#define XIDTYPE_HID (__cpu_to_be32(0x11))

/*
 *	Network namespace
 */

static int __net_init hid_net_init(struct net *net)
{
	int rc;

	rc = init_xid_table(net->xia.local_rtbl, XIDTYPE_HID,
		&hid_rt_ops_local);
	if (rc)
		goto out;
	rc = init_xid_table(net->xia.main_rtbl, XIDTYPE_HID,
		&hid_rt_ops_main);
	if (rc)
		goto local_rtbl;
	goto out;

local_rtbl:
	end_xid_table(net->xia.local_rtbl, XIDTYPE_HID);
out:
	return rc;
}

static void __net_exit hid_net_exit(struct net *net)
{
	rtnl_lock();
	end_xid_table(net->xia.main_rtbl, XIDTYPE_HID);
	end_xid_table(net->xia.local_rtbl, XIDTYPE_HID);
	rtnl_unlock();
}

static struct pernet_operations hid_net_ops = {
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

	rc = ppal_add_map("hid", XIDTYPE_HID);
	if (rc)
		goto net;

	printk(KERN_ALERT "XIA Principal HID loaded\n");
	goto out;

net:
	unregister_pernet_subsys(&hid_net_ops);
out:
	return rc;
}

/*
 * xia_hid_exit - this function is called when the modlule is removed.
 */
static void __exit xia_hid_exit(void)
{
	ppal_del_map(XIDTYPE_HID);
	xia_unregister_pernet_subsys(&hid_net_ops);
	printk(KERN_ALERT "XIA Principal HID UNloaded\n");
}

module_init(xia_hid_init);
module_exit(xia_hid_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Host Principal");

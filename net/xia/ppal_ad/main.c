#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>

/* XXX Likely, this struct must vary for the main and local table! */
struct fib_xid_ad {
	struct fib_xid	xad_common;
	struct xia_xid	xad_gw;
};

static int newroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid_ad *xad;
	int rc;

	rc = -EINVAL;
	if (!cfg->xfc_gw)
		goto out;

	rc = -ENOMEM;
	xad = kmalloc(sizeof(*xad), GFP_KERNEL);
	if (!xad)
		goto out;
	memset(xad, 0, sizeof(*xad));

	memmove(xad->xad_common.fx_xid, cfg->xfc_dst->xid_id, XIA_XID_MAX);
	xad->xad_gw	= *cfg->xfc_gw;

	rc = fib_add_xid(xtbl, (struct fib_xid *)xad);
	if (rc)
		goto xad;
	goto out;

xad:
	kfree(xad);
out:
	return rc;
}

static int delroute(struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid *fxid = fib_rm_xid(xtbl, cfg->xfc_dst->xid_id);
	if (!fxid)
		return -ESRCH;
	kfree(fxid);
	return 0;
}

/* Based on net/ipv4/fib_semantics.c:fib_dump_info and its call in
 * net/ipv4/fib_trie.c:fn_trie_dump_fa.
 */
static int dump_ad(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct fib_xia_rtable *rtbl, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 pid = NETLINK_CB(cb->skb).pid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_ad *ad = (struct fib_xid_ad *)fxid;
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
	rtm->rtm_type = rtbl->tbl_id == XRTABLE_LOCAL_INDEX
		? RTN_LOCAL : RTN_UNICAST;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;
	
	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	NLA_PUT_TYPE(skb, struct xia_xid, RTA_DST, dst);

	NLA_PUT_TYPE(skb, struct xia_xid, RTA_GATEWAY, ad->xad_gw);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static const struct xia_ppal_rt_ops ad_rt_ops = {
	.newroute = newroute,
	.delroute = delroute,
	.dump_xid = dump_ad,
};

/* Autonomous Domain Principal */
#define XIDTYPE_AD (__cpu_to_be32(0x10))

/*
 * xia_ad_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_ad_init(void)
{
	int rc;

	/* XXX Add support to all/new struct nets. See xia_ad_exit as well. */
	/* XXX A synchonizing lock is likely necessary here.
	 * See xia_ad_exit as well.
	 */
	rc = init_xid_table(init_net.xia.local_rtbl, XIDTYPE_AD, &ad_rt_ops);
	if (rc)
		goto out;
	rc = init_xid_table(init_net.xia.main_rtbl, XIDTYPE_AD, &ad_rt_ops);
	if (rc)
		goto local_rtbl;

	rc = ppal_add_map("ad", XIDTYPE_AD);
	if (rc)
		goto main_rtbl;

	printk(KERN_ALERT "XIA Principal AD loaded\n");
	rc = 0;
	goto out;

main_rtbl:
	end_xid_table(init_net.xia.main_rtbl, XIDTYPE_AD);
local_rtbl:
	end_xid_table(init_net.xia.local_rtbl, XIDTYPE_AD);
out:
	return rc;
}

/*
 * xia_ad_exit - this function is called when the modlule is removed.
 */
static void __exit xia_ad_exit(void)
{
	/* XXX Is it really safe to unload a principal? */
	ppal_del_map(XIDTYPE_AD);
	end_xid_table(init_net.xia.main_rtbl, XIDTYPE_AD);
	end_xid_table(init_net.xia.local_rtbl, XIDTYPE_AD);
	printk(KERN_ALERT "XIA Principal AD UNloaded\n");
}

module_init(xia_ad_init);
module_exit(xia_ad_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Autonomous Domain Principal");

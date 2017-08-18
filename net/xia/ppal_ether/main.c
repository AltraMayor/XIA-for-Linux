#include <linux/module.h>
#include <net/xia_dag.h>
#include <net/xia_output.h>
#include <net/xia_vxidty.h>
#include <linux/rwlock.h>
#include <net/xia_ether.h>

/* ETHER_FIB table internal operations */
const struct xia_ppal_rt_iops *ether_rt_iops = &xia_ppal_list_rt_iops;

/* ETHER local table operations */
static int local_newroute(struct xip_ppal_ctx *ctx,
			  struct fib_xid_table *xtbl,
			  struct xia_fib_config *cfg)
{
	struct fib_xid_ether_local *leid;
	int rc;

	/* Allocate memory to new local ether xid*/
	leid = ether_rt_iops->fxid_ppal_alloc(sizeof(*leid), GFP_KERNEL);
	// If not enough space
	if (!leid)
		return -ENOMEM;
	// Initialize the fib_xid inside the local ether xid
	fxid_init(xtbl, &leid->xel_common, cfg->xfc_dst->xid_id,
		  XRTABLE_LOCAL_INDEX, 0);
	// Initialize the anchor inside the local ether xid
	xdst_init_anchor(&leid->xel_anchor);

	/* Call to form a new entry in the ppal table in the current ctx */
	rc = ether_rt_iops->fib_newroute(&leid->xel_common, xtbl, cfg, NULL);

	/* If not formed succesfully */
	if (rc) {
		fxid_free_norcu(xtbl, &leid->xel_common);
	}
	return rc;
}

static int local_delroute(struct xip_ppal_ctx *ctx,
			  struct fib_xid_table *xtbl,
			  struct xia_fib_config *cfg)
{
	//call fib route deleting function
	int rc = ether_rt_iops->fib_delroute(ctx, xtbl, cfg);
	return rc;
}

static void local_free_ether(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	//fetch the local ether object containing the fib_xid object
	struct fib_xid_ether_local *leid = fxid_lether(fxid);

	//free the anchors starting from the anchor of this local ether
	xdst_free_anchor(&leid->xel_anchor);
	//free kernel memory
	kfree(leid);
}

static int local_dump_ether(struct fib_xid *fxid, struct fib_xid_table *xtbl,
			  struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			  struct netlink_callback *cb)
{
	//used for communication b/w userspace and kernel
	struct nlmsghdr *nlh;
	//get process-id
	//NETLINK_CB:typecast sk_buff in cb to netlink_skb_parms
	u32 portid = NETLINK_CB(cb->skb).portid;
	//get sequence number of message
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct xia_xid dst;

	//add a new netlink msg header with the following info
	nlh = nlmsg_put(skb, portid, seq, RTM_NEWROUTE, sizeof(*rtm),
			NLM_F_MULTI);
	//if not allocated
	if (nlh == NULL)
		return -EMSGSIZE;

	//fetch the pointer to start of router-related payload associated with this header
	rtm = nlmsg_data(nlh);
	//start setting the fields one by one
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = XRTABLE_LOCAL_INDEX;
	/* COULD GIVE OVER HERE RTPROT_XIA*/
	/* Values higher than RTPROT_STATIC not interpreted by kernel and define inside rtnetlink.h */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_LOCAL;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	//set the principal type
	dst.xid_type = xtbl->fxt_ppal_type;
	//set the xia-xid
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	//add the netlink attribute "destination address" to the nl_msg contained inside the skb
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	//update message payload length
	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	//remove the netlink message from the skb completely
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* ETHER main table operations */
static int main_newroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
			 struct xia_fib_config *cfg)
{
	struct xip_deferred_negdep_flush *dnf;
	struct net_device		*out_interface;
	struct interface_addr 	*neigh_addr,*exist_addr;
	struct fib_xid 			*cur_fxid;
	u32						bucket;
	struct fib_xid_ether_main *mether;
	u32						nl_flags;
	const char 				*id;
	int rc;

	//check for errors in cfg
	if(!cfg->xfc_dst || !cfg->xfc_odev || !cfg->xfc_lladdr || cfg->xfc_lladdr_len != cfg->xfc_odev->addr_len)
		return -EINVAL;
	
	//assign values to corresponding variables
	out_interface 	= cfg->xfc_odev;
	nl_flags 		= cfg->xfc_nlflags;
	id 				= cfg->xfc_dst->xid_id;

	//check if device is down or is loopback
	if (!(out_interface->flags & IFF_UP) || (out_interface->flags & IFF_LOOPBACK))
		return -EINVAL;

	//allocate a new neighbour interface address structure
	neigh_addr 		= allocate_interface_addr(out_interface , cfg->xfc_lladdr , GFP_ATOMIC);
	// Not enough memory
	if(!neigh_addr)
		return -ENOMEM;

	cur_fxid = ether_rt_iops->fxid_find_lock(&bucket, xtbl, id);

	if(cur_fxid)
	{
		//found an xid with the same xia-xid
		if (cur_fxid->fx_table_id != XRTABLE_MAIN_INDEX) {
			//found the xid not in main table
			rc = -EINVAL;
			goto unlock_bucket;
		}
		//fetch the container main ether xid
		mether = fxid_mether(cur_fxid);

		//if found the new addr and old addr same
		if(cmp_addr(mether->neigh_addr, neigh_addr->ha, neigh_addr->outgress_interface))
		{
			//if don't touch existing or not allowed to replace
			if ( (nl_flags & NLM_F_EXCL) || !(nl_flags & NLM_F_REPLACE) ) 
			{
				rc = -EEXIST;
				goto unlock_bucket;
			}
			//can be replaced but already same
			rc = 0;
			goto unlock_bucket;
		}

		//if interface_addr field is not NULL
		if(mether->neigh_addr)
		{
			//if not allowed to replace
			if(!(nl_flags & NLM_F_REPLACE)){
				rc = -EEXIST;
				goto unlock_bucket;
			}

			//Remove the current allocated addr
			exist_addr = mether->neigh_addr;
			del_interface_addr(exist_addr);
			free_interface_addr(exist_addr);
		}
		else
		{
			if (!(nl_flags & NLM_F_CREATE)) {
				rc = -ENOENT;
				goto unlock_bucket;
			}
		}
		//attach to this main table entry
		rc = attach_neigh_addr_to_fib_entry(mether , neigh_addr);
		ether_rt_iops->fib_unlock(xtbl, &bucket);
		if (rc)
			goto free_addr;
		return 0;
	}

	if (!(nl_flags & NLM_F_CREATE)) {
		rc = -ENOENT;
		goto unlock_bucket;
	}

	dnf = fib_alloc_dnf(GFP_ATOMIC);
	if (!dnf) {
		rc = -ENOMEM;
		goto unlock_bucket;
	}

	mether = ether_rt_iops->fxid_ppal_alloc(sizeof(*mether),GFP_ATOMIC);
	if(!mether){
		rc = -ENOMEM;
		goto def_upd;
	}
	fxid_init(xtbl, &mether->xem_common, id, XRTABLE_MAIN_INDEX, 0);
	mether->xem_dead = false;
	xdst_init_anchor(&mether->xem_anchor);
	mether->host_interface = out_interface;
	
	rc = attach_neigh_addr_to_fib_entry(mether , neigh_addr);
	BUG_ON(rc);

	mether->cached_hdr.hh_len = 0;
	mether->output = mfxid_blackhole;

	rwlock_init(&mether->chdr_lock);
	seqlock_init(&mether->cached_hdr.hh_lock);

	mfxid_hh_init(mether);

	BUG_ON(ether_rt_iops->fxid_add_locked(&bucket, xtbl, &mether->xem_common));

	ether_rt_iops->fib_unlock(xtbl, &bucket);
	fib_defer_dnf(dnf, ctx_ether(ctx)->net, XIDTYPE_ETHER);
	return 0;

def_upd:
	fib_free_dnf(dnf);
unlock_bucket:
	ether_rt_iops->fib_unlock(xtbl, &bucket);
free_addr:
	free_ia_norcu(neigh_addr);
	return rc;
}

static int main_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	u32 bucket;
	struct fib_xid *fxid;
	struct fib_xid_ether_main *mether;
	struct interface_addr 	*neigh_addr;
	struct net_device *dev;
	int rc;
	const char *id;

	//check for errors in cfg
	if(!cfg->xfc_dst || !cfg->xfc_odev || !cfg->xfc_lladdr || cfg->xfc_lladdr_len != cfg->xfc_odev->addr_len)
		return -EINVAL;

	id 	= cfg->xfc_dst->xid_id;
	dev = cfg->xfc_odev;

	fxid = ether_rt_iops->fxid_find_lock(&bucket, xtbl, id);
	if (!fxid) {
		rc = -ENOENT;
		goto unlock_bucket;
	}
	if (fxid->fx_table_id != XRTABLE_MAIN_INDEX) {
		rc = -EINVAL;
		goto unlock_bucket;
	}
	mether = fxid_mether(fxid);

	if(!cmp_addr(mether->neigh_addr,cfg->xfc_lladdr,dev)){
		rc = -EINVAL;
		goto unlock_bucket;
	}

	mether->cached_hdr.hh_len = 0;
	mether->output = mfxid_blackhole;

	neigh_addr = mether->neigh_addr;
	del_interface_addr(neigh_addr);
	free_interface_addr(neigh_addr);

	ether_rt_iops->fxid_rm_locked(&bucket, xtbl, fxid);
	fxid_free(xtbl, fxid);
	rc = 0;

unlock_bucket:
	ether_rt_iops->fib_unlock(xtbl, &bucket);
	return rc;
}

static int main_dump_ether(struct fib_xid *fxid, struct fib_xid_table *xtbl,
			 struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			 struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_ether_main *mether = fxid_mether(fxid);
	struct xia_xid dst;
	struct nlattr *ha_attr;
	struct rtnl_xia_ether_addrs *rtha;
	struct interface_addr *pos_ia;

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

	rtha = nla_reserve_nohdr(skb, sizeof(*rtha));
	if (!rtha)
		goto nla_put_failure;

	rcu_read_lock();
	pos_ia = rcu_dereference(mether->neigh_addr);

	rtha->interface_addr_len = pos_ia->outgress_interface->addr_len;
	memmove(rtha->interface_addr, pos_ia->ha, rtha->interface_addr_len);
	rtha->interface_index = pos_ia->outgress_interface->ifindex;
	
	rcu_read_unlock();
	
	/* No attributes. */

	/* length of rtnetlink header + attributes */
	rtha->attr_len = nlmsg_get_pos(skb) - (void *)rtha;

	nla_nest_end(skb, ha_attr);

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* call using fxid_free only */
void main_free_ether(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_ether_main *mether = fxid_mether(fxid);

	xdst_free_anchor(&mether->xem_anchor);
	mether->xem_dead = true;
	mether_finish_destroy(mether);
}

/* ETHER_FIB all table external operations */
static const xia_ppal_all_rt_eops_t ether_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = local_newroute,
		.delroute = local_delroute,
		.dump_fxid = local_dump_ether,
		.free_fxid = local_free_ether,
	},

	[XRTABLE_MAIN_INDEX] = {
		.newroute = main_newroute,
		.delroute = main_delroute,
		.dump_fxid = main_dump_ether,
		.free_fxid = main_free_ether,
	},
};

/* routing process per principal struct */

static inline struct interface_addr *xdst_naddr(struct xip_dst *xdst)
{
	return xdst->info;
}

static int main_input_input(struct sk_buff *skb)
{
	struct xiphdr *xiph;
	struct xip_dst *xdst;
	struct interface_addr *naddr;

	/* XXX We should test that forwarding is enable per struct net.
	 * See example in net/ipv6/ip6_output.c:ip6_forward.
	 * TODO:ask why needed to test coz already path has been decided
	 *      and we are filling in the header over here.
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
	naddr = xdst_naddr(xdst);
	if (skb_cow(skb, LL_RESERVED_SPACE(naddr->outgress_interface) + xdst->dst.header_len))
		goto drop;
	xiph = xip_hdr(skb);

	/* Decrease ttl after skb cow done. */
	xiph->hop_limit--;

	return dst_output(xdst_net(xdst), skb->sk, skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static inline struct interface_addr *skb_naddr(struct sk_buff *skb)
{
	return xdst_naddr(skb_xdst(skb));
}

static inline int xip_skb_dst_mtu(struct sk_buff *skb)
{
	return dst_mtu(skb_dst(skb));
}

static inline int neighinterface_hh_output(const struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int seq;
	int hh_len;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		if (likely(hh_len <= HH_DATA_MOD)) 
		{
			memcpy(skb->data - HH_DATA_MOD, hh->hh_data, HH_DATA_MOD);
		} 
		else 
		{
			int hh_alen = HH_DATA_ALIGN(hh_len);
			memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
		}
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return dev_queue_xmit(skb);
}

static inline int interface_neigh_output(struct fib_xid_ether_main *mfxid, struct sk_buff *skb)
{
	const struct hh_cache *hh = &mfxid->cached_hdr;

	if (hh->hh_len)
		return neighinterface_hh_output(hh, skb);
	else
		return mfxid->output(mfxid, skb);
}

static int main_input_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct interface_addr *naddr = skb_naddr(skb);
	struct net_device *dev;
	unsigned int hh_len;
	int rc;

	skb = xip_trim_packet_if_needed(skb, xip_skb_dst_mtu(skb));
	if (!skb)
		return NET_RX_DROP;

	dev = naddr->outgress_interface;
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

	return interface_neigh_output(naddr->mfxid, skb);
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

static int ether_deliver(struct xip_route_proc *rproc, struct net *net,
		       const u8 *xid, struct xia_xid *next_xid,
		       int anchor_index, struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct fib_xid *fxid;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, ether_vxt);

	fxid = ether_rt_iops->fxid_find_rcu(ctx->xpc_xtbl, xid);
	if (!fxid)
		goto out;

	switch (fxid->fx_table_id) 
	{
		case XRTABLE_LOCAL_INDEX: {
			struct fib_xid_ether_local *lether = fxid_lether(fxid);

			xdst->passthrough_action = XDA_DIG;
			xdst->sink_action = XDA_ERROR; /* An HID cannot be a sink. */
			xdst_attach_to_anchor(xdst, anchor_index, &lether->xel_anchor);
			rcu_read_unlock();
			return XRP_ACT_FORWARD;
		}

		case XRTABLE_MAIN_INDEX: {
			struct fib_xid_ether_main *mether = fxid_mether(fxid);
			struct interface_addr *naddr = rcu_dereference(mether->neigh_addr);

			if (unlikely(!naddr)) {
				goto out;
			}

			xdst->passthrough_action = XDA_METHOD;
			xdst->sink_action = XDA_METHOD;
			xdst->info = naddr;
			BUG_ON(xdst->dst.dev);
			xdst->dst.dev = naddr->outgress_interface;
			dev_hold(xdst->dst.dev);
			if (xdst->input) {
				xdst->dst.input = main_input_input;
				xdst->dst.output = main_input_output;
			} else {
				xdst->dst.input = main_output_input;
				xdst->dst.output = main_output_output;
			}
			xdst_attach_to_anchor(xdst, anchor_index, &mether->xem_anchor);
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

static struct xip_route_proc ether_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_ETHER,
	.deliver = ether_deliver,
};

/* Interface intialization and exit functions */
static struct ether_interface *eint_init(struct net_device *dev)
{
	struct ether_interface *eint;

	ASSERT_RTNL();

	eint = kzalloc(sizeof(*eint), GFP_KERNEL);
	if (!eint)
		return NULL;

	eint->dead = 0;
	eint->dev = dev;
	dev_hold(dev);
	atomic_set(&eint->refcnt, 0);
	atomic_set(&eint->neigh_cnt, 0);

	spin_lock_init(&eint->interface_lock);
	INIT_LIST_HEAD(&eint->list_interface_common_addr);

	einterface_hold(eint);
	RCU_INIT_POINTER(dev->eth_ptr, eint);
	return eint;
}

/* Caller must hold RTNL lock, and makes sure that nobody adds entries
 * in hdev->neighs while it's running.
 */
static void free_neighs_by_interface(struct ether_interface *eint)
{
	struct net_device *dev;
	struct net *net;
	struct xip_ppal_ctx *ctx;
	struct fib_xid_table *xtbl;

	ASSERT_RTNL();

	dev = eint->dev;
	net = dev_net(dev);
	ctx = xip_find_my_ppal_ctx_vxt(net, ether_vxt);
	xtbl = ctx->xpc_xtbl;

	while (1) {
		struct interface_addr *ha;
		u8 xid[XIA_XID_MAX];
		struct fib_xid *fxid;
		u32 bucket;

		/* Obtain xid of the first entry in @hdev->neighs.
		 *
		 * We use rcu_read_lock() here to allow one to remove
		 * entries in parallel.
		 */
		rcu_read_lock();
		ha = list_first_or_null_rcu(&eint->list_interface_common_addr, struct interface_addr,
					    interface_common_addr);
		if (!ha) {
			rcu_read_unlock();
			break;
		}
		memmove(xid, ha->mfxid->xem_common.fx_xid, XIA_XID_MAX);
		rcu_read_unlock();

		/* We don't lock eint->interface_lock to avoid deadlock. */
		fxid = ether_rt_iops->fxid_find_lock(&bucket, xtbl, xid);
		if (fxid && fxid->fx_table_id == XRTABLE_MAIN_INDEX) 
		{
			del_interface_addr(ha);
			free_interface_addr(ha);

			ether_rt_iops->fxid_rm_locked(&bucket, xtbl, fxid);
			fxid_free(xtbl, fxid);
		}
		ether_rt_iops->fib_unlock(xtbl, &bucket);
	}
}

static void update_neighs_by_interface(struct ether_interface *eint)
{
	struct interface_addr *ha;
	ASSERT_RTNL();

	rcu_read_lock();
	list_for_each_entry_rcu(ha, &eint->list_interface_common_addr, interface_common_addr) {
		if(ha->mfxid)
			mfxid_update_hhs(ha->mfxid,0);
	}
	rcu_read_unlock();
}

static void ether_interface_rcu_put(struct rcu_head *head)
{
	struct ether_interface *eint = container_of(head, struct ether_interface, rcu_head);
	ether_interface_put(eint);
}

static void eint_destroy(struct ether_interface *eint)
{
	ASSERT_RTNL();
	eint->dead = 1;

	free_neighs_by_interface(eint);

	RCU_INIT_POINTER(eint->dev->eth_ptr, NULL);
	call_rcu(&eint->rcu_head, ether_interface_rcu_put);
}

static int ether_interface_event(struct notifier_block *nb,
			    unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct ether_interface *eint;

	ASSERT_RTNL();
	eint = __ether_get_rtnl(dev);

	switch (event) {
	case NETDEV_REGISTER:
		BUG_ON(eint);
		eint = eint_init(dev);
		if (!eint)
			return notifier_from_errno(-ENOMEM);
		break;
	case NETDEV_UNREGISTER:
		eint_destroy(eint);
		break;
	case NETDEV_DOWN:
		free_neighs_by_interface(eint);
		break;
	case NETDEV_CHANGEADDR:
		update_neighs_by_interface(eint);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block interface_notifier __read_mostly = {
	.notifier_call = ether_interface_event,
};

int register_dev(void)
{
	return register_netdevice_notifier(&interface_notifier);
}

void unregister_dev(void)
{
	unregister_netdevice_notifier(&interface_notifier);
}

/* Network namespace subsystem registration*/

static struct xip_ether_ctx *create_ether_ctx(struct net *net)
{
	struct xip_ether_ctx *ether_ctx = kmalloc(sizeof(*ether_ctx), GFP_KERNEL);

	if (!ether_ctx)
		return NULL;
	xip_init_ppal_ctx(&ether_ctx->ctx, XIDTYPE_ETHER);
	ether_ctx->net = net;
	return ether_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function,i.e., wait till all readers before have finished */
static void free_ether_ctx(struct xip_ether_ctx *ether_ctx)
{
	ether_ctx->net = NULL;
	xip_release_ppal_ctx(&ether_ctx->ctx);
	kfree(ether_ctx);
}

static int __net_init ether_net_init(struct net *net)
{
	struct xip_ether_ctx *ether_ctx;
	int rc;

	ether_ctx = create_ether_ctx(net);
	if (!ether_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = ether_rt_iops->xtbl_init(&ether_ctx->ctx, net, &xia_main_lock_table,
				    ether_all_rt_eops, ether_rt_iops);
	if (rc)
		goto ether_ctx;

	rc = xip_add_ppal_ctx(net, &ether_ctx->ctx);
	if (rc)
		goto ether_ctx;
	goto out;

ether_ctx:
	free_ether_ctx(ether_ctx);
out:
	return rc;
}

static void __net_exit ether_net_exit(struct net *net)
{
	/* synchronize_rcu() called inside xip_del_ppal_ctx */
	struct xip_ether_ctx *ether_ctx =
		ctx_ether(xip_del_ppal_ctx(net, XIDTYPE_ETHER));
	free_ether_ctx(ether_ctx);
}

static struct pernet_operations ether_net_ops __read_mostly = {
	.init = ether_net_init,
	.exit = ether_net_exit,
};

/* xia_ether_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_ether_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_ETHER);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for ETHER\n");
		goto out;
	}
	ether_vxt = rc;

	rc = xia_register_pernet_subsys(&ether_net_ops);
	if (rc)
		goto vxt;

	rc = register_dev();
	if (rc)
		goto devicereg;

	rc = xip_add_router(&ether_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("ether", XIDTYPE_ETHER);
	if (rc)
		goto route;

	pr_alert("XIA Principal ETHER loaded\n");
	goto out;

route:
	xip_del_router(&ether_rt_proc);
devicereg:
	unregister_dev();
net:
	xia_unregister_pernet_subsys(&ether_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_ETHER));
out:
	return rc;
}

/* xia_ether_exit - this function is called when the module is removed. */
static void __exit xia_ether_exit(void)
{
	ppal_del_map(XIDTYPE_ETHER);
	xip_del_router(&ether_rt_proc);
	unregister_dev();
	xia_unregister_pernet_subsys(&ether_net_ops);

	rcu_barrier();
	flush_scheduled_work();

	BUG_ON(vxt_unregister_xidty(XIDTYPE_ETHER));
	pr_alert("XIA Principal ETHER UNloaded\n");
}


module_init(xia_ether_init);
module_exit(xia_ether_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("XIA Ethernet Principal");
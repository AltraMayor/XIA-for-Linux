#include <linux/inet.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/xia_dag.h>
#include <net/xia_fib.h>
#include <net/xia_output.h>
#include <net/xia_u4id.h>
#include <net/xia_vxidty.h>
#include <uapi/linux/udp.h>

/*
 *	U4ID context
 */

struct xip_u4id_ctx {
	struct xip_ppal_ctx	ctx;

	struct socket __rcu	*tunnel_sock;

	/* Anchor for ill-formed U4ID XIDs. */
	struct xip_dst_anchor	ill_anchor;

	/* Anchor for non-local, well-formed U4IDs,
	 * which represent tunnel destinations.
	 * When one of the local U4IDs is a tunnel
	 * source then the destination is assumed
	 * to be reachable, so this anchor is
	 * positive. When there is no tunnel source,
	 * this anchor is negative.
	 */
	struct xip_dst_anchor	forward_anchor;
};

static inline struct xip_u4id_ctx *ctx_u4id(struct xip_ppal_ctx *ctx)
{
	return likely(ctx)
		? container_of(ctx, struct xip_u4id_ctx, ctx)
		: NULL;
}

static int my_vxt __read_mostly = -1;

static inline void destroy_sock(struct socket *sock)
{
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sk_release_kernel(sock->sk);
}

/*
 *	Local U4IDs
 */

struct u4id_xid {
	u32	ip_addr;
	u16	udp_port;
	u16	zero1;
	u32	zero2;
	u32	zero3;
	u32	zero4;
};

static inline int u4id_well_formed(const u8 *xid)
{
	struct u4id_xid *st_xid = (struct u4id_xid *)xid;
	BUILD_BUG_ON(sizeof(struct u4id_xid) != XIA_XID_MAX);
	return st_xid->ip_addr && st_xid->udp_port && !st_xid->zero1 &&
		!st_xid->zero2 && !st_xid->zero3 && !st_xid->zero4;
}

/* XXX Add ability to determine when an IP
 * address on which a U4ID relies is removed.
 */

struct fib_xid_u4id_local {
	struct fib_xid		common;
	struct xip_dst_anchor	anchor;
	struct socket		*sock;
	struct work_struct	del_work;

	/* True if @sock represents a tunnel source. */
	bool			tunnel;

	/* True if checksums are disabled when using
	 * @sock as a tunnel source.
	 */
	bool			checksum_disabled;

	/* Two free bytes. */
};

static inline struct fib_xid_u4id_local *fxid_lu4id(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct fib_xid_u4id_local, common)
		: NULL;
}

/* Callback function to handle UDP datagrams delivered
 * to a socket assigned to a local U4ID.
 */
static int u4id_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	if (!sk)
		goto pass_up;

	/* To reuse @skb, we need to remove the UDP
	 * header, release the old dst, and reset
	 * the netfilter data.
	 */
	__skb_pull(skb, sizeof(struct udphdr));
	skb_dst_drop(skb);
	nf_reset(skb);

	skb->dev = sk->sk_net->loopback_dev;
	skb->protocol = __cpu_to_be16(ETH_P_XIP);
	skb_reset_network_header(skb);

	if (dev_hard_header(skb, skb->dev, ETH_P_XIP, skb->dev->dev_addr,
		skb->dev->dev_addr, skb->len) < 0) {
		kfree_skb(skb);
		goto pass_up;
	}

	/* Deliver @skb to XIA routing mechanism via lo. */
	return dev_queue_xmit(skb);

pass_up:
	return 1;
}

static int create_lu4id_socket(struct fib_xid_u4id_local *lu4id,
	struct net *net, __u8 *xid_p)
{
	struct socket *sock;
	struct sockaddr_in udp_addr;
	int rc;
	__be32 xid_addr;
	__be16 xid_port;

	rc = __sock_create(net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock, 1);
	if (rc)
		goto out;

	/* Fetch IPv4 address and port number from U4ID XID. */
	xid_addr = *(__be32 *)xid_p;
	xid_p += sizeof(xid_addr);
	xid_port = *(__be16 *)xid_p;

	udp_addr.sin_family = AF_INET;
	udp_addr.sin_addr.s_addr = xid_addr;
	udp_addr.sin_port = xid_port;

	rc = kernel_bind(sock, (struct sockaddr *)&udp_addr, sizeof(udp_addr));
	if (rc)
		goto sock;

	/* Mark socket as an encapsulation socket. */
	udp_sk(sock->sk)->encap_type = UDP_ENCAP_XIPINUDP;
	udp_sk(sock->sk)->encap_rcv = u4id_udp_encap_recv;
	udp_encap_enable();

	lu4id->sock = sock;
	goto out;

sock:
	destroy_sock(sock);
out:
	return rc;
}

/* Workqueue local U4ID deletion function. */
static void u4id_local_del_work(struct work_struct *work)
{
	struct fib_xid_u4id_local *lu4id =
		container_of(work, struct fib_xid_u4id_local, del_work);
	if (lu4id->sock) {
		destroy_sock(lu4id->sock);
		lu4id->sock = NULL;
	}
	xdst_free_anchor(&lu4id->anchor);
	kfree(lu4id);
}

/* XXX This function should support updating local entries for:
 *       - changing the tunnel status of an entry.
 *       - changing the checksum status of a tunnel entry.
 */
static int local_newroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid_u4id_local *lu4id;
	struct xip_u4id_ctx *u4id_ctx;
	struct local_u4id_info *lu4id_info;
	int rc;

	if (!u4id_well_formed(cfg->xfc_dst->xid_id) || !cfg->xfc_protoinfo ||
		cfg->xfc_protoinfo_len != sizeof(*lu4id_info))
		return -EINVAL;

	lu4id_info = cfg->xfc_protoinfo;
	u4id_ctx = ctx_u4id(ctx);
	if (lu4id_info->tunnel && u4id_ctx->tunnel_sock)
		return -EEXIST;

	lu4id = kmalloc(sizeof(*lu4id), GFP_KERNEL);
	if (!lu4id)
		return -ENOMEM;
	init_fxid(&lu4id->common, cfg->xfc_dst->xid_id,
		XRTABLE_LOCAL_INDEX, 0);
	xdst_init_anchor(&lu4id->anchor);
	lu4id->sock = NULL;
	INIT_WORK(&lu4id->del_work, u4id_local_del_work);
	lu4id->tunnel = lu4id_info->tunnel;
	lu4id->checksum_disabled = lu4id_info->checksum_disabled;

	rc = create_lu4id_socket(lu4id, xtbl->fxt_net, cfg->xfc_dst->xid_id);
	if (rc)
		goto lu4id;

	rc = fib_build_newroute(&lu4id->common, xtbl, cfg, NULL);
	if (rc)
		goto lu4id;

	/* We need to initialize the tunnel after the entry is
	 * added, so that u4id_deliver() does not see the tunnel
	 * when adding the local entry fails.
	 */
	if (lu4id_info->tunnel) {
		lu4id->sock->sk->sk_no_check = lu4id_info->checksum_disabled
			? UDP_CSUM_NOXMIT
			: UDP_CSUM_DEFAULT;
		rcu_assign_pointer(u4id_ctx->tunnel_sock, lu4id->sock);
		/* Wait an RCU cycle before flushing the anchor.
		 * Otherwise, a thread in u4id_deliver() could see the tunnel
		 * socket as NULL, but before it could add a negative
		 * dependency, another thread running this function
		 * adds the tunnel and flushes the negative dependencies.
		 * Then the first thread would be adding an incorrect
		 * negative dependency that won't be flushed soon.
		 */
		synchronize_rcu();
		xdst_free_anchor(&u4id_ctx->forward_anchor);
	}

	goto out;

lu4id:
	u4id_local_del_work(&lu4id->del_work);
out:
	return rc;
}

static int local_delroute(struct xip_ppal_ctx *ctx,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg)
{
	struct fib_xid *fxid;
	struct fib_xid_u4id_local *lu4id;

	fxid = fib_rm_xid(xtbl, cfg->xfc_dst->xid_id);
	if (!fxid)
		return -ENOENT;
	lu4id = fxid_lu4id(fxid);

	if (lu4id->tunnel) {
		/* Notice that we remove the local entry, then
		 * drop the tunnel socket in the same order
		 * we add them in local_newroute() instead of
		 * the reverse order for convenience.
		 */

		struct xip_u4id_ctx *u4id_ctx = ctx_u4id(ctx);
		BUG_ON(!u4id_ctx->tunnel_sock);
		RCU_INIT_POINTER(u4id_ctx->tunnel_sock, NULL);

		/* Wait an RCU cycle before flushing positive dependencies.
		 * Otherwise, a thread in u4id_deliver() could see the tunnel
		 * socket as available, but before it could add a positive
		 * dependency, another thread running this function
		 * deletes the tunnel and flush the positive dependencies.
		 * Then the first thread would be adding an incorrect
		 * positive dependency for a tunnel source that
		 * no longer exists.
		 *
		 * It's also needed for u4id_local_del_work() below.
		 */
		synchronize_rcu();
		xdst_free_anchor(&u4id_ctx->forward_anchor);
	} else {
		/* Needed for u4id_local_del_work() below. */
		synchronize_rcu();
	}

	/* We want to free @fxid before returning to make sure that
	 * the socket associated to @fxid is released.
	 * Otherwise, applications removing and adding the same entry
	 * would ocasionally fail when the socket wasn't released while
	 * the application try to add the entry back.
	 */
	u4id_local_del_work(&lu4id->del_work);
	return 0;
}

static int local_dump_u4id(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct xip_ppal_ctx *ctx, struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct xia_xid dst;
	struct local_u4id_info lu4id_info;

	nlh = nlmsg_put(skb, portid, seq, RTM_NEWROUTE, sizeof(*rtm),
		NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = XRTABLE_LOCAL_INDEX;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_LOCAL;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl->fxt_ppal_type;
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);
	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst)))
		goto nla_put_failure;

	lu4id_info.tunnel = fxid_lu4id(fxid)->tunnel;
	lu4id_info.checksum_disabled = fxid_lu4id(fxid)->checksum_disabled;
	if (unlikely(nla_put(skb, RTA_PROTOINFO, sizeof(lu4id_info),
		&lu4id_info)))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Don't call this function! Use free_fxid instead. */
static void local_free_u4id(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	struct fib_xid_u4id_local *lu4id = fxid_lu4id(fxid);
	BUG_ON(!lu4id->sock);
	schedule_work(&lu4id->del_work);
}

static const xia_ppal_all_rt_eops_t u4id_all_rt_eops = {
	[XRTABLE_LOCAL_INDEX] = {
		.newroute = local_newroute,
		.delroute = local_delroute,
		.dump_fxid = local_dump_u4id,
		.free_fxid = local_free_u4id,
	},
};

/*
 *	Network namespace
 */

static struct xip_u4id_ctx *create_u4id_ctx(void)
{
	struct xip_u4id_ctx *u4id_ctx = kmalloc(sizeof(*u4id_ctx), GFP_KERNEL);
	if (!u4id_ctx)
		return NULL;
	xip_init_ppal_ctx(&u4id_ctx->ctx, XIDTYPE_U4ID);
	xdst_init_anchor(&u4id_ctx->ill_anchor);
	xdst_init_anchor(&u4id_ctx->forward_anchor);
	RCU_INIT_POINTER(u4id_ctx->tunnel_sock, NULL);
	return u4id_ctx;
}

/* IMPORTANT! Caller must RCU synch before calling this function. */
static void free_u4id_ctx(struct xip_u4id_ctx *u4id_ctx)
{
	/* There are no other writers for the tunnel socket, since
	 * no local entries can be added or removed by the user
	 * since xip_del_ppal_ctx has already been called.
	 */
	RCU_INIT_POINTER(u4id_ctx->tunnel_sock, NULL);

	/* There is no need to find the struct fib_xid_u4id_local
	 * that held the tunnel socket in order to set its
	 * tunnel field to false. The only read of the tunnel
	 * field happens in local_delroute, which can no longer
	 * be invoked since xip_del_ppal_ctx has already been called.
	 *
	 * Therefore, a local entry can incorrectly yet harmlessly hold
	 * a tunnel field of true for a brief time until it is freed
	 * even though the tunnel is no longer active.
	 */

	xdst_free_anchor(&u4id_ctx->forward_anchor);
	xdst_free_anchor(&u4id_ctx->ill_anchor);
	xip_release_ppal_ctx(&u4id_ctx->ctx);
	kfree(u4id_ctx);
}

static int __net_init u4id_net_init(struct net *net)
{
	struct xip_u4id_ctx *u4id_ctx;
	int rc;

	u4id_ctx = create_u4id_ctx();
	if (!u4id_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	rc = init_xid_table(&u4id_ctx->ctx, net, &xia_main_lock_table,
		u4id_all_rt_eops);
	if (rc)
		goto u4id_ctx;

	rc = xip_add_ppal_ctx(net, &u4id_ctx->ctx);
	if (rc)
		goto u4id_ctx;
	goto out;

u4id_ctx:
	free_u4id_ctx(u4id_ctx);
out:
	return rc;
}

static void __net_exit u4id_net_exit(struct net *net)
{
	struct xip_u4id_ctx *u4id_ctx =
		ctx_u4id(xip_del_ppal_ctx(net, XIDTYPE_U4ID));
	free_u4id_ctx(u4id_ctx);
}

static struct pernet_operations u4id_net_ops __read_mostly = {
	.init = u4id_net_init,
	.exit = u4id_net_exit,
};

/*
 *	U4ID Routing
 */

/* Tunnel destination information held in a DST entry. */
struct u4id_tunnel_dest {
	__be32	dest_ip_addr;
	__be16	dest_port;
};

static struct u4id_tunnel_dest *create_u4id_tunnel_dest(const u8 *xid)
{
	struct u4id_tunnel_dest *tunnel = kmalloc(sizeof(*tunnel), GFP_ATOMIC);
	if (!tunnel)
		return NULL;
	tunnel->dest_ip_addr = *(__be32 *)xid;
	tunnel->dest_port = *(__be16 *)(xid + sizeof(tunnel->dest_ip_addr));
	return tunnel;
}

/* Automatically called when the @skb is freed. */
static void u4id_sock_free(struct sk_buff *skb)
{
	sock_put(skb->sk);
}

static struct sock *get_tunnel_sock(struct net *net)
{
	struct xip_u4id_ctx *u4id_ctx;
	struct socket *tunnel_sock;
	struct sock *sk;

	rcu_read_lock();
	u4id_ctx = ctx_u4id(xip_find_ppal_ctx_rcu(net, XIDTYPE_U4ID));
	tunnel_sock = rcu_dereference(u4id_ctx->tunnel_sock);
	if (!tunnel_sock) {
		rcu_read_unlock();
		return NULL;
	}
	sk = tunnel_sock->sk;
	sock_hold(sk);
	rcu_read_unlock();
	return sk;
}

static void push_udp_header(struct sk_buff *skb,
	__be32 dest_ip_addr, __be16 dest_port)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);

	struct udphdr *uh;
	int uhlen = sizeof(*uh);
	int udp_payload_len = skb->len;

	/* Set up UDP header. */
	skb_push(skb, uhlen);
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = dest_port;
	uh->len = htons(uhlen + udp_payload_len);
	uh->check = 0;

	/* XXX It'd be nice to support hardware checksummig. */
	switch (sk->sk_no_check) {
	case UDP_CSUM_NOXMIT:
		skb->ip_summed = CHECKSUM_NONE;
		break;
	case UDP_CSUM_DEFAULT:
		skb->ip_summed = CHECKSUM_COMPLETE;
		uh->check = csum_tcpudp_magic(inet->inet_saddr, dest_ip_addr,
			skb->len, sk->sk_protocol, udp_csum(skb));
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
		break;
	default:
		BUG();
	}
}

static int handle_skb_to_ipv4(struct sk_buff *skb,
	__be32 dest_ip_addr, __be16 dest_port)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct flowi4 fl4;
	struct rtable *rt;

	/* Reset @skb netfilter state. */
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
		IPSKB_REROUTED);
	nf_reset(skb);

	/* Set up @skb. */
	skb->protocol = __cpu_to_be16(ETH_P_IP);
	skb->local_df = 1;

	/* Set up IP DST. */
	skb_dst_drop(skb);
	flowi4_init_output(&fl4, sk->sk_bound_dev_if, sk->sk_mark,
		RT_TOS(inet->tos), RT_SCOPE_UNIVERSE, sk->sk_protocol,
		inet_sk_flowi_flags(sk), dest_ip_addr, inet->inet_saddr,
		dest_port, inet->inet_sport);
	security_sk_classify_flow(sk, flowi4_to_flowi(&fl4));
	rt = ip_route_output_flow(net, &fl4, sk);
	if (IS_ERR(rt)) {
		int rc = PTR_ERR(rt);
		if (rc == -ENETUNREACH)
			IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
		kfree_skb(skb);
		return rc;
	}
	skb_dst_set(skb, dst_clone(&rt->dst));
	ip_rt_put(rt);

	return ip_queue_xmit(skb, flowi4_to_flowi(&fl4));
}

static int u4id_output(struct sk_buff *skb)
{
	struct sock *sk;
	struct u4id_tunnel_dest *tunnel;
	__be32 dest_ip_addr;
	__be16 dest_port;

	/* Check that there's enough headroom in the @skb to
	 * insert the IP and UDP headers. If not enough,
	 * expand it to make room. Adjust truesize.
	 */
	if (skb_cow_head(skb,
		NET_SKB_PAD + sizeof(struct iphdr) + sizeof(struct udphdr))) {
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	/* The tunnel socket is *not* guaranteed to be here.
	 * If this point was reached between deleting the tunnel socket and
	 * flushing the forward anchor, it will be NULL.
	 */
	sk = get_tunnel_sock(dev_net(skb_dst(skb)->dev));
	if (unlikely(!sk)) {
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = u4id_sock_free;

	/* Fetch U4ID from XDST entry to get IP address and port. */
	tunnel = (struct u4id_tunnel_dest *)skb_xdst(skb)->info;
	dest_ip_addr = tunnel->dest_ip_addr;
	dest_port = tunnel->dest_port;

	push_udp_header(skb, dest_ip_addr, dest_port);

	/* Send UDP packet with XIP and data as payload. */
	return handle_skb_to_ipv4(skb, dest_ip_addr, dest_port);
}

static int u4id_deliver(struct xip_route_proc *rproc, struct net *net,
	const u8 *xid, struct xia_xid *next_xid, int anchor_index,
	struct xip_dst *xdst)
{
	struct xip_ppal_ctx *ctx;
	struct xip_u4id_ctx *u4id_ctx;
	struct fib_xid *fxid;
	struct u4id_tunnel_dest *tunnel;

	rcu_read_lock();
	ctx = xip_find_ppal_ctx_vxt_rcu(net, my_vxt);
	u4id_ctx = ctx_u4id(ctx);

	if (unlikely(!u4id_well_formed(xid))) {
		/* This XID is malformed. */
		xdst->passthrough_action = XDA_ERROR;
		xdst->sink_action = XDA_ERROR;
		xdst_attach_to_anchor(xdst, anchor_index,
			&u4id_ctx->ill_anchor);
		rcu_read_unlock();
		return XRP_ACT_FORWARD;
	}

	fxid = xia_find_xid_rcu(ctx->xpc_xtbl, xid);
	if (fxid) {
		/* Reached tunnel destination; advance last node. */
		struct fib_xid_u4id_local *lu4id = fxid_lu4id(fxid);
		xdst->passthrough_action = XDA_DIG;
		xdst->sink_action = XDA_ERROR; /* A U4ID cannot be a sink. */
		xdst_attach_to_anchor(xdst, anchor_index, &lu4id->anchor);
		rcu_read_unlock();
		return XRP_ACT_FORWARD;
	}

	/* Assume an unknown, well-formed U4ID is a tunnel destination. */
	if (!rcu_dereference(u4id_ctx->tunnel_sock)) {
		xdst_attach_to_anchor(xdst, anchor_index,
			&u4id_ctx->forward_anchor);
		rcu_read_unlock();
		return XRP_ACT_NEXT_EDGE;
	}

	/* Tunnel socket exists; set up XDST entry. */
	tunnel = create_u4id_tunnel_dest(xid);
	if (unlikely(!tunnel)) {
		rcu_read_unlock();
		/* Not enough memory to conclude this operation. */
		return XRP_ACT_ABRUPT_FAILURE;
	}
	xdst->info = tunnel;
	xdst->ppal_destroy = def_ppal_destroy;

	xdst->passthrough_action = XDA_METHOD;
	xdst->sink_action = XDA_ERROR;
	BUG_ON(xdst->dst.dev);
	xdst->dst.dev = net->loopback_dev;
	dev_hold(xdst->dst.dev);
	xdst->dst.input = xdst_def_hop_limit_input_method;
	xdst->dst.output = u4id_output;
	xdst_attach_to_anchor(xdst, anchor_index, &u4id_ctx->forward_anchor);
	rcu_read_unlock();
	return XRP_ACT_FORWARD;
}

static struct xip_route_proc u4id_rt_proc __read_mostly = {
	.xrp_ppal_type = XIDTYPE_U4ID,
	.deliver = u4id_deliver,
};

static int __init xia_u4id_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_U4ID);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for U4ID\n");
		goto out;
	}
	my_vxt = rc;

	rc = xia_register_pernet_subsys(&u4id_net_ops);
	if (rc)
		goto vxt;

	rc = xip_add_router(&u4id_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("u4id", XIDTYPE_U4ID);
	if (rc)
		goto route;

	printk(KERN_ALERT "XIA Principal U4ID loaded\n");
	goto out;

route:
	xip_del_router(&u4id_rt_proc);
net:
	xia_unregister_pernet_subsys(&u4id_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_U4ID));
out:
	return rc;
}

static void __exit xia_u4id_exit(void)
{
	ppal_del_map(XIDTYPE_U4ID);
	xip_del_router(&u4id_rt_proc);
	xia_unregister_pernet_subsys(&u4id_net_ops);
	BUG_ON(vxt_unregister_xidty(XIDTYPE_U4ID));

	rcu_barrier();
	flush_scheduled_work();

	printk(KERN_ALERT "XIA Principal U4ID UNloaded\n");
}

module_init(xia_u4id_init);
module_exit(xia_u4id_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cody Doucette <doucette@bu.edu>");
MODULE_DESCRIPTION("XIA UDP/IPv4 Principal");

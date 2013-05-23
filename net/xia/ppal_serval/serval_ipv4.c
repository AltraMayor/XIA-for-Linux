/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * IPv4 functionality for Serval.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <platform.h>
#include <debug.h>
#include <netdevice.h>
#include <serval_sock.h>
#include <serval_ipv4.h>
#include <serval_sal.h>
#include <input.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_ipv4.h>
#include <net/route.h>
#include <net/ip.h>

extern int serval_sal_rcv(struct sk_buff *);

int serval_ipv4_forward_out(struct sk_buff *skb)
{
        struct iphdr *iph = ip_hdr(skb);
        int err;

#if defined(ENABLE_DEBUG)
        {
                char srcstr[18], dststr[18];
                LOG_DBG("%s %s->%s skb->len=%u iph_len=[%u] %u\n",
                        skb->dev ? skb->dev->name : "no dev",
                        inet_ntop(AF_INET, &iph->saddr, srcstr, 18),
                        inet_ntop(AF_INET, &iph->daddr, dststr, 18),
                        skb->len, iph->ihl << 2, iph->tos);
        }
#endif
	skb->protocol = htons(ETH_P_IP);

#if defined(OS_LINUX_KERNEL)
        /* Redo input routing with new destination address. IP
           forwarding must be enabled for this to work. */
        err = ip_route_input_noref(skb, 
                                   iph->daddr, 
                                   iph->saddr, 
                                   iph->tos, 
                                   skb->dev);
        
        if (err < 0) {
                LOG_ERR("Could not forward SAL packet, NO route [err=%d]\n", err);
                kfree_skb(skb);
                return NET_RX_DROP;
        }
#else
        iph->ttl = iph->ttl - 1;
#endif

        /* Update tot_len, we might have added SAL extension
           headers. */
        iph->tot_len = htons(skb->len);

        LOG_DBG("Forwarding skb->len=%u\n",
                skb->len);

        /* Update checksum */
        ip_send_check(iph);

        /* It may seem counter intuitive that we call dst_input
           here. The reason is that we want to call ip_forward, but
           that function is not exported in the kernel. However, if we
           re-route the packet in the kernel (using a new dst
           address), the input function (as called by dst_input) will
           point to ip_forward. The ip_forward function will
           eventually call dst_output, after having updated TTL, etc.
        */
#if defined(OS_LINUX_KERNEL)
        err = dst_input(skb);
#else
        err = dev_queue_xmit(skb);
#endif
        return err;
}

static inline int serval_ip_local_out(struct sk_buff *skb)
{
        int err;
        
#if defined(OS_LINUX_KERNEL)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	err = ip_local_out(skb);
#else
        struct iphdr *iph = ip_hdr(skb);
        
        iph->tot_len = htons(skb->len);
	ip_send_check(iph);

        err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, skb->dst->dev,
                      dst_output);
#endif
#else /* OS_USER */
       
        /* Calculate checksum */
        ip_send_check(ip_hdr(skb));

        err = dev_queue_xmit(skb);
#endif

        if (err < 0) {
		LOG_ERR("packet_xmit failed err=%d\n", err);
	}

        return err;
}

#if defined(OS_LINUX_KERNEL)
/*
  This will route a SYN-ACK, i.e., the response to a request to open a
  new connection.
 */
struct dst_entry *serval_ipv4_route(struct sock *sk,
                                    struct request_sock *rsk,
                                    int protocol,
                                    u32 saddr,
                                    u32 daddr)
{
	struct rtable *rt;
	struct ip_options *opt = NULL; /* inet_rsk(req)->opt; */
        struct flowi fl;

        serval_flow_init_output(&fl, sk->sk_bound_dev_if, sk->sk_mark,
                                RT_CONN_FLAGS(sk), 0, protocol,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
                                inet_sk_flowi_flags(sk),
#else
                                0,
#endif
                                daddr, saddr, 0, 0);
        
	serval_security_req_classify_flow(rsk, &fl);

	rt = serval_ip_route_output_flow(sock_net(sk), &fl, sk, 0);
        
        if (!rt)
		goto no_route;
        
	if (opt && opt->is_strictroute && rt->rt_gateway)
		goto route_err;

	return route_dst(rt);

route_err:
	ip_rt_put(rt);
no_route:
	return NULL;
}

#endif

const char *ipv4_hdr_dump(const void *hdr, char *buf, int buflen)
{
        int i = 0, len = 0;
        const unsigned char *h = (const unsigned char *)hdr;

        while (i < 20) {
                len += snprintf(buf + len, buflen - len, 
                                "%02x%02x ", h[i], h[i+1]);
                i += 2;
        }
        return buf;
}

int serval_ipv4_fill_in_hdr(struct sock *sk, struct sk_buff *skb,
                            u32 saddr, u32 daddr)
{
        struct iphdr *iph;
        unsigned int iph_len = sizeof(struct iphdr);
        u8 tos = 0, ttl = SERVAL_DEFTTL;
        u32 priority = 0, mark = 0;

        if (sk) {
                struct inet_sock *inet = inet_sk(sk);
                tos = inet->tos;
                priority = sk->sk_priority;
                mark = sk->sk_mark;
                if (inet->uc_ttl >= 0)
                        ttl = inet->uc_ttl;
        }
        
        iph = (struct iphdr *)skb_push(skb, iph_len);
	skb_reset_network_header(skb);

        /* Build IP header */
        memset(iph, 0, iph_len);
        iph->version = 4; 
        iph->ihl = iph_len >> 2;
        iph->tos = tos;
#if defined(OS_USER) && defined(OS_BSD)
        /* BSD/Mac OS X requires tot_len to be in host byte order when
         * sending over IP raw socket */
        iph->tot_len = skb->len;
#else
        iph->tot_len = htons(skb->len);
#endif
        iph->id = 0;
        iph->frag_off = 0;
        iph->ttl = ttl;
        iph->protocol = skb->protocol;
        iph->saddr = saddr;
        iph->daddr = daddr;
	skb->protocol = htons(ETH_P_IP);
	skb->priority = priority;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	skb->mark = mark;
#endif

#if defined(ENABLE_DEBUG)
        {
                unsigned int iph_len = iph->ihl << 2;
                char srcstr[18], dststr[18];
                /* 
                   char buf[256];
                   LOG_DBG("ip dump %s\n", ipv4_hdr_dump(iph, buf, 256));
                */

                LOG_DBG("%s %s->%s tot_len=%u iph_len=[%u %u]\n",
                        skb->dev ? skb->dev->name : "no dev",
                        inet_ntop(AF_INET, &iph->saddr, srcstr, 18),
                        inet_ntop(AF_INET, &iph->daddr, dststr, 18),
                        skb->len, iph_len, iph->ihl);
        }
#endif
        
        return 0;
}

int serval_ipv4_build_and_send_pkt(struct sk_buff *skb, 
                                   struct sock *sk,
                                   u32 saddr, u32 daddr, 
                                   struct ip_options *opt)
{
        int err = 0;

#if defined(OS_LINUX_KERNEL)
	/* 
	We need to initialize the IP control block since SAL 
	might have dirtied it.
	*/
        memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
#endif

        if (saddr == 0) {
                if (!skb->dev) {
                        LOG_ERR("no device set\n");
                        kfree_skb(skb);
                        return -ENODEV;
                }
                dev_get_ipv4_addr(skb->dev, IFADDR_LOCAL, &saddr);
        }

        err = serval_ipv4_fill_in_hdr(sk, skb, saddr, daddr);
        
        if (err < 0) {
                LOG_ERR("hdr failed\n");
                kfree_skb(skb);
                return err;
        }

        /* Transmit */
        err = serval_ip_local_out(skb);

        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }

        return err;
}

#if defined(OS_LINUX_KERNEL)
static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

        if (ttl < 0) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
                ttl = ip4_dst_hoplimit(dst);        
#else
                ttl = dst_metric(dst, RTAX_HOPLIMIT);
#endif
        }
	return ttl;
}
#endif

int serval_ipv4_xmit(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        int err = 0;
#if defined(OS_LINUX_KERNEL)

	/*
          This is pretty much a copy paste from ip_queue_xmit
          (ip_output.c), but which modifications that take into
          account Serval specific stuff.
          
          It will route the packet according to the IP stack's routing
          table and output for standard IP output processing.
         */
        struct iphdr *iph;
        struct rtable *rt;
        struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = NULL; /*inet->inet_opt; */
        int ifindex;

	/*
	   The SAL has dirtied the control block that IP expects to be
	zeroed out. 
	We need to make sure it is initialized again. Otherwise, there
	might be stack corruptions when IP functions try to read the
	IPCB. (This happens in, e.g., icmp_send when reading ip options.)  
	*/
        memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
        
	/* 
         * Skip all of this if the packet is already routed,
         */
        rcu_read_lock();

        rt = skb_rtable(skb);

        if (rt != NULL) {
                LOG_PKT("Packet already routed\n");
                goto packet_routed;
        }
        /* Make sure we can route this packet. */
        rt = (struct rtable *)__sk_dst_check(sk, 0);

        if (skb->dev) {
                ifindex = skb->dev->ifindex;
        } else {
                ifindex = sk->sk_bound_dev_if;
        }

        if (rt == NULL) {
                struct flowi fl;

                serval_flow_init_output(&fl, ifindex, 
                                        sk->sk_mark, 
                                        RT_CONN_FLAGS(sk), 0,
                                        skb->protocol,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
                                        inet_sk_flowi_flags(sk),
#else
                                        0,
#endif
                                        inet->inet_daddr,
                                        inet->inet_saddr,
                                        0, 0);
                
                serval_security_sk_classify_flow(sk, &fl);
                
                rt = serval_ip_route_output_flow(sock_net(sk), &fl, sk, 0);

                if (!rt) {
#if defined(ENABLE_DEBUG)
                        {
                                char ip[18];
                                LOG_SSK(sk, "No route for %s on if=%d bound_if=%d!\n",
                                        inet_ntop(AF_INET, &inet->inet_daddr, ip, 18),
                                        ifindex, sk->sk_bound_dev_if);
                        }
#endif
                        err = -EHOSTUNREACH;
                        rcu_read_unlock();
                        goto drop;
                }

                /* Setup the socket to use this route in the future */
                sk_setup_caps(sk, route_dst(rt));

        } else {
                LOG_SSK(sk, "Using existing sock route\n");
        }
        
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
        skb_dst_set(skb, dst_clone(route_dst(rt)));
#else
        skb_dst_set_noref(skb, route_dst(rt));
#endif
 packet_routed:
        if (opt && opt->is_strictroute && rt->rt_gateway) {
                err = -EHOSTUNREACH;
                rcu_read_unlock();
                LOG_DBG("dest is not gateway!\n");
                goto drop;
        }


	/* OK, we know where to send it, allocate and build IP header. */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	if (ip_dont_fragment(sk, route_dst(rt)) && !skb->local_df)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, route_dst(rt));
	iph->protocol = skb->protocol;
	iph->saddr    = inet->inet_saddr; //rt->rt_src;
	iph->daddr    = inet->inet_daddr; //rt->rt_dst;

	if (opt && opt->optlen) {
                LOG_WARN("IP options not implemented\n");
                /* For some reason, enabling the code below gives the
                 * error: "Unknown symbol ip_options_build (err 0)"
                 * when loading the serval.ko module. Seems the
                 * ip_options_build function is not exported.
                 */
                /*
		iph->ihl += opt->optlen >> 2;
		ip_options_build(skb, opt, inet->inet_daddr, rt, 0);
                */
	}
        
        ip_select_ident_more(iph, route_dst(rt), sk,
			     (skb_shinfo(skb)->gso_segs ?: 1) - 1);

	skb->priority = sk->sk_priority;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	skb->mark = sk->sk_mark;
#endif
	err = serval_ip_local_out(skb);

	rcu_read_unlock();
#else
        /*
          FIXME: We should not rely on an outgoing interface here.
          Instead, we should route the packet like we do in the
          kernel. But, we currently do not have an IP routing table
          for userlevel.
         */

        if (!skb->dev)
                skb->dev = __dev_get_by_index(sock_net(sk),
                                              sk->sk_bound_dev_if);

        if (!skb->dev) {
                LOG_ERR("no output device set in skb!\n");
                err = -ENODEV;
                goto drop;
        }
        err = serval_ipv4_fill_in_hdr(sk, skb, inet_sk(sk)->inet_saddr,
                                      inet_sk(sk)->inet_daddr);
        
        if (err < 0) {
                LOG_ERR("hdr failed\n");
                goto drop;
        }

        /* Transmit */
        err = serval_ip_local_out(skb);
#endif /* OS_LINUX_KERNEL */    
 out:
        if (err < 0) {
                LOG_ERR("xmit failed: %d\n", err);
        }

        return err;
drop:
        LOG_DBG("Dropping skb!\n");

        kfree_skb(skb);
        
        goto out;
}

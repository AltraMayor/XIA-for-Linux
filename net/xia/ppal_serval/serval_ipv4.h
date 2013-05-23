/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_IPV4_H_
#define _SERVAL_IPV4_H_

#include <skbuff.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/kernel.h>
#include <linux/version.h>
#include <net/ip.h>
#include <net/route.h>

/*
  A bunch of routing wrapper functions to handle differences in
  routing API between kernel versions.
 */
static inline void serval_flow_init_output(struct flowi *fl, int oif,
                                           __u32 mark, __u8 tos, __u8 scope,
                                           __u8 proto, __u8 flags,
                                           __be32 daddr, __be32 saddr,
                                           __be16 dport, __be32 sport)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
        flowi4_init_output(&fl->u.ip4, oif, mark, tos, scope,
                           proto, flags, daddr, saddr, dport, sport);
#else
        memset(fl, 0, sizeof(*fl));
        fl->oif = oif;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
        fl->mark = mark;
#endif
        fl->fl4_dst = daddr;
        fl->fl4_src = saddr;
        fl->fl4_tos = tos;
        fl->proto = proto;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
        fl->flags = flags;
#endif
        fl->fl_ip_sport = dport;
        fl->fl_ip_dport = sport;
#endif /* LINUX_VERSION(2,6,39) */
}

static inline
struct rtable *serval_ip_route_output_flow(struct net *net, 
					   struct flowi *fl,
					   struct sock *sk, 
					   int flags)
{
        struct rtable *rt = NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
        rt = ip_route_output_flow(net, &fl->u.ip4, sk);

        if (IS_ERR(rt))
                return NULL;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
        if (ip_route_output_flow(net, &rt, fl, sk, flags))
                return NULL;
#else
        if (ip_route_output_flow(&rt, fl, sk, flags))
                return NULL;
#endif
        return rt;
}

static inline struct rtable *serval_ip_route_output_key(struct net *net, 
                                                        struct flowi *fl)
{
	return serval_ip_route_output_flow(net, fl, NULL, 0);
}

static inline struct rtable *serval_ip_route_output(struct net *net, 
                                                    __be32 daddr,
                                                    __be32 saddr, 
                                                    u8 tos, int oif)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
        struct rtable *rt = ip_route_output(net, daddr, saddr, tos, oif);

        return IS_ERR(rt) ? NULL : rt; 
#else
        struct flowi fl;

        serval_flow_init_output(&fl, oif, 0, tos, 0, 0, 0,
                                daddr, saddr, 0, 0);
        
        return serval_ip_route_output_key(net, &fl);
#endif
}

static inline void serval_security_sk_classify_flow(struct sock *sk,
                                                    struct flowi *fl)
{
        security_sk_classify_flow(sk, fl);
}

static inline void serval_security_req_classify_flow(struct request_sock *req,
                                                     struct flowi *fl)
{
        security_req_classify_flow(req, fl);
}

struct dst_entry *serval_ipv4_req_route(struct sock *sk,
					struct request_sock *rsk,
					int protocol,
					u32 saddr,
					u32 daddr);
#endif

#define SERVAL_DEFTTL 64

int serval_ipv4_forward_out(struct sk_buff *skb);

int serval_ipv4_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
				   u32 saddr, u32 daddr, 
				   struct ip_options *opt);
int serval_ipv4_xmit(struct sk_buff *skb);

const char *ipv4_hdr_dump(const void *hdr, char *buf, int buflen);

#endif /* _SERVAL_IPV4_H_ */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <platform.h>
#include <debug.h>
#include <netdevice.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <input.h>

/*#define USE_NETFILTER 0 */
#define USE_IPPROTO 1

#if defined(USE_NETFILTER)
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define NF_INET_PRE_ROUTING NF_IP_PRE_ROUTING
#endif

static unsigned int serval_packet_rcv(unsigned int hooknum,
                                        struct sk_buff *skb,
                                        const struct net_device *in,
                                        const struct net_device *out,
                                        int (*okfn)(struct sk_buff *))
{
        int ret;

        switch (skb->pkt_type) {
        case PACKET_HOST:
        case PACKET_BROADCAST:
        case PACKET_MULTICAST:
                break;
        case PACKET_OTHERHOST:
        case PACKET_OUTGOING:
        default:
                goto accept;
        }

        /* serval_input assumes receive happens on mac layer */
        skb_push(skb, skb->dev->hard_header_len);

	ret = serval_input(skb);
        
	switch (ret) {
        case INPUT_DROP:
                goto drop;
        case INPUT_OK:
                goto keep;
        case INPUT_DELIVER:
                goto accept;
        case INPUT_ERROR:
        default:
                /* Packet should be freed by upper layers */
                if (IS_INPUT_ERROR(ret)) {
                        LOG_ERR("input error\n");
                }
                goto keep;
        }
accept:
        /* LOG_DBG("Returning NF_ACCEPT\n"); */
        return NF_ACCEPT;
drop:   
        LOG_DBG("Returning NF_DROP\n");
        return NF_DROP;
keep:
        LOG_DBG("Returning NF_STOLEN\n");
	return NF_STOLEN;
}

static struct nf_hook_ops ip_hook = { 
        .hook = serval_packet_rcv, 
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST,
};

#endif /* USE_NETFILTER */

#if defined(USE_PACKET)
#include <linux/netdevice.h>

static int serval_packet_rcv(struct sk_buff *skb, struct net_device *dev,
			       struct packet_type *pt, struct net_device *orig_dev)
{        
        int ret;

        switch (skb->pkt_type) {
        case PACKET_HOST:
                break;
        case PACKET_OTHERHOST:
                goto drop;
        case PACKET_OUTGOING:
                goto finish;
        case PACKET_BROADCAST:
        case PACKET_MULTICAST:
        default:
                goto drop;
        }
        
	ret = serval_input(skb);
        
	switch (ret) {
        case INPUT_KEEP:
                goto keep;
        case INPUT_DROP:
                goto drop;
        case INPUT_OK:
                goto drop;
        case INPUT_DELIVER:
                break;
        case INPUT_ERROR:
        default:
                if (IS_INPUT_ERROR(ret)) {
                        LOG_ERR("input error\n");
                }
                goto drop;
        }		
finish:
        /* Returning NET_RX_SUCCESS will deliver the packet to other
         * modules, e.g., normal IP */
        LOG_DBG("Returning NET_RX_SUCCESS\n");
        return NET_RX_SUCCESS;
drop:   
        LOG_DBG("freeing skb\n");
        kfree_skb(skb);
keep:
        LOG_DBG("Returning NET_RX_DROP\n");
	return NET_RX_DROP;
}

/* Serval packet type for Serval over Ethernet */
static struct packet_type serval_packet_type = {
        .type = __constant_htons(ETH_P_IP),
        .func = serval_packet_rcv,
};

#endif /* USE_PACKET */

#if defined(USE_IPPROTO)
#include <netinet_serval.h>
#include <net/protocol.h>

extern int serval_sal_rcv(struct sk_buff *);
extern void serval_sal_error_rcv(struct sk_buff *, u32 info);

static struct net_protocol serval_protocol = {
	.handler =      serval_sal_rcv,
        .err_handler =  serval_sal_error_rcv,
	.no_policy =	1,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26))
	.netns_ok =	1,
#endif
};

#endif /* USE_IPPROTO */

int packet_init(void)
{
#if defined(USE_NETFILTER)
        if (nf_register_hook(&ip_hook) < 0)
                return -1;
#endif
#if defined(USE_PACKET)
	dev_add_pack(&serval_packet_type);
#endif
#if defined(USE_IPPROTO)  
        if (inet_add_protocol(&serval_protocol, IPPROTO_SERVAL) < 0) {
                return -1;
        }
#endif
	return 0;
}

void packet_fini(void)
{
#if defined(USE_NETFILTER)
        nf_unregister_hook(&ip_hook);
#endif
#if defined(USE_PACKET)
        dev_remove_pack(&serval_packet_type);
#endif
#if defined(USE_IPPROTO) 
        inet_del_protocol(&serval_protocol, IPPROTO_SERVAL);
#endif
}

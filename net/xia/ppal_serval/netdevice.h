/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _NETDEVICE_H_
#define _NETDEVICE_H_

#include <platform.h>

enum addr_type {
        IFADDR_LOCAL,
        IFADDR_ADDRESS,
        IFADDR_BROADCAST,
        IFADDR_NETMASK,
};

#if defined(OS_LINUX_KERNEL)
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

static inline int dev_get_ipv4_addr(struct net_device *dev, 
                                    enum addr_type type, void *addr)
{
        struct in_device *in_dev;
        int ret = 0;
        
	rcu_read_lock();

	in_dev = __in_dev_get_rcu(dev);

        if (in_dev) {
                for_primary_ifa(in_dev) {
                        switch (type) {
                        case IFADDR_LOCAL:
                                memcpy(addr, &ifa->ifa_local, 4);
                                break;
                        case IFADDR_ADDRESS:
                                memcpy(addr, &ifa->ifa_address, 4);
                                break;
                        case IFADDR_BROADCAST:
                                memcpy(addr, &ifa->ifa_broadcast, 4);
                                break;
                        case IFADDR_NETMASK:
                                memcpy(addr, &ifa->ifa_mask, 4);
                                break;
                        }
                        ret = 1;
                        break;
                }
                endfor_ifa(indev);
        }
	rcu_read_unlock();

        return ret;
}

#endif /* OS_LINUX_KERNEL */

#if defined(OS_USER)
#include <serval/platform.h>
#include <serval/atomic.h>
#include <serval/lock.h>
#include <serval/net.h>
#include <serval/skbuff.h>
#include <net/if.h>
#include <pthread.h>
#include <string.h>
#if defined(OS_ANDROID)
#define ETH_HLEN 14
#else
#include <net/ethernet.h>
#endif
#if defined(OS_BSD)
#define ETH_ALEN ETHER_ADDR_LEN
#define ETH_HLEN 14

#define ETH_P_IP ETHERTYPE_IP

struct ethhdr {
        u_char  h_dest[ETHER_ADDR_LEN];
        u_char  h_source[ETHER_ADDR_LEN];
        u_short h_proto;
};

#endif

struct sk_buff;
struct packet_ops;

#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN ETH_HLEN
#endif
#define LL_MAX_HEADER 32
#define MAX_HEADER LL_MAX_HEADER

/* Backlog congestion levels */
#define NET_RX_SUCCESS		0	/* keep 'em coming, baby */
#define NET_RX_DROP		1	/* packet dropped */

#define NET_XMIT_SUCCESS	0x00
#define NET_XMIT_DROP		0x01	/* skb dropped			*/
#define NET_XMIT_CN		0x02	/* congestion notification	*/
#define NET_XMIT_POLICED	0x03	/* skb is shot by police	*/
#define NET_XMIT_MASK		0x0f	/* qdisc flags in net/sch_generic.h */

/* NET_XMIT_CN is special. It does not guarantee that this packet is lost. It
 * indicates that the device will soon be dropping packets, or already drops
 * some packets of the same priority; prompting us to send less aggressively. */
#define net_xmit_eval(e)	((e) == NET_XMIT_CN ? 0 : (e))
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)

struct netdev_queue {
	struct net_device	*dev;
	struct sk_buff_head	q;
};

struct net_device {        
	int                     ifindex;
        char                    name[IFNAMSIZ];
	unsigned short		hard_header_len; /* hardware hdr length	*/
	unsigned char		*dev_addr;
	unsigned char		perm_addr[MAX_ADDR_LEN]; /* permanent hw address */
	unsigned char		addr_len;  /* hardware address length	*/
	unsigned char		broadcast[MAX_ADDR_LEN]; /* hw bcast add	*/
	unsigned int		flags;	/* interface flags (a la BSD)	*/
	spinlock_t              lock;
	atomic_t		refcnt;
	/* device name hash chain */
	struct hlist_node	name_hlist;
	/* Net device features */
	unsigned long		features;
#define NETIF_F_SG		1	/* Scatter/gather IO. */
#define NETIF_F_IP_CSUM		2	/* Can checksum TCP/UDP over IPv4. */
#define NETIF_F_NO_CSUM		4	/* Does not require checksum. F.e. loopack. */
#define NETIF_F_HW_CSUM		8	/* Can checksum all the packets. */
#define NETIF_F_IPV6_CSUM	16	/* Can checksum TCP/UDP over IPV6 */
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packets */
#define NETIF_F_GSO		2048	/* Enable software GSO. */
#define NETIF_F_LLTX		4096	/* LockLess TX - deprecated. Please */
					/* do not use LLTX in new drivers */
#define NETIF_F_NETNS_LOCAL	8192	/* Does not change network namespaces */
#define NETIF_F_GRO		16384	/* Generic receive offload */
#define NETIF_F_LRO		32768	/* large receive offload */

/* the GSO_MASK reserves bits 16 through 23 */
#define NETIF_F_FCOE_CRC	(1 << 24) /* FCoE CRC32 */
#define NETIF_F_SCTP_CSUM	(1 << 25) /* SCTP checksum offload */
#define NETIF_F_FCOE_MTU	(1 << 26) /* Supports max FCoE MTU, 2158 bytes*/
#define NETIF_F_NTUPLE		(1 << 27) /* N-tuple filters supported */
#define NETIF_F_RXHASH		(1 << 28) /* Receive hashing offload */

	/* Segmentation offload features */
#define NETIF_F_GSO_SHIFT	16
#define NETIF_F_GSO_MASK	0x00ff0000
#define NETIF_F_TSO		(SKB_GSO_TCPV4 << NETIF_F_GSO_SHIFT)
#define NETIF_F_UFO		(SKB_GSO_UDP << NETIF_F_GSO_SHIFT)
#define NETIF_F_GSO_ROBUST	(SKB_GSO_DODGY << NETIF_F_GSO_SHIFT)
#define NETIF_F_TSO_ECN		(SKB_GSO_TCP_ECN << NETIF_F_GSO_SHIFT)
#define NETIF_F_TSO6		(SKB_GSO_TCPV6 << NETIF_F_GSO_SHIFT)
#define NETIF_F_FSO		(SKB_GSO_FCOE << NETIF_F_GSO_SHIFT)

	/* List of features with software fallbacks. */
#define NETIF_F_GSO_SOFTWARE	(NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6)


#define NETIF_F_GEN_CSUM	(NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)
#define NETIF_F_V4_CSUM		(NETIF_F_GEN_CSUM | NETIF_F_IP_CSUM)
#define NETIF_F_V6_CSUM		(NETIF_F_GEN_CSUM | NETIF_F_IPV6_CSUM)
#define NETIF_F_ALL_CSUM	(NETIF_F_V4_CSUM | NETIF_F_V6_CSUM)

	/*
	 * If one device supports one of these features, then enable them
	 * for all in netdev_increment_features.
	 */
#define NETIF_F_ONE_FOR_ALL	(NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ROBUST | \
				 NETIF_F_SG | NETIF_F_HIGHDMA |		\
				 NETIF_F_FRAGLIST)
	/* device index hash chain */
	struct hlist_node	index_hlist;
	struct list_head	dev_list;
        struct netdev_queue     tx_queue;
        unsigned long           tx_queue_len; /* Max len allowed */
        struct {
                uint32_t addr;
                uint32_t broadcast;
                uint32_t netmask;
        } ipv4;
        /* Stuff for packet thread that reads packets from the
         * device */
        int fd;
        int pipefd[2];
        int should_exit;
        pthread_t thr;
        struct packet_ops *pack_ops;
        /* Here follows private data */
};

#define LL_RESERVED_SPACE(dev) ((dev)->hard_header_len)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) ((dev)->hard_header_len + (extra))
#define LL_ALLOCATED_SPACE(dev) ((dev)->hard_header_len)

#include <serval/skbuff.h>

static inline void skb_set_dev(struct sk_buff *skb, struct net_device *dev)
{
	skb->dev = dev;
}

static inline int dev_hard_header(struct sk_buff *skb, struct net_device *dev,
				  unsigned short type,
				  const void *daddr, const void *saddr,
				  unsigned len)
{
	struct ethhdr *ethh = (struct ethhdr *)skb_push(skb, ETH_HLEN);

	ethh->h_proto = htons(type);

	if (!dev) {
		if (!skb->dev)
			return -ETH_HLEN;
		dev = skb->dev;
	}

	if (!saddr)
		saddr = dev->dev_addr;
       
	memcpy(ethh->h_source, saddr, ETH_ALEN);

        if (daddr) {
                memcpy(ethh->h_dest, daddr, ETH_ALEN);
                return ETH_HLEN;
        }

	return -ETH_HLEN;
}

void ether_setup(struct net_device *dev);
struct net_device *alloc_netdev(int sizeof_priv, const char *name,
				void (*setup)(struct net_device *));
void free_netdev(struct net_device *dev);
int register_netdev(struct net_device *dev);
void unregister_netdev(struct net_device *dev);

static inline void dev_put(struct net_device *dev)
{
	free_netdev(dev);
}

static inline void dev_hold(struct net_device *dev)
{
	atomic_inc(&dev->refcnt);
}

struct net_device *__dev_get_by_name(struct net *net, const char *name);
struct net_device *__dev_get_by_index(struct net *net, int ifindex);
struct net_device *dev_get_by_name(struct net *net, const char *name);
struct net_device *dev_get_by_index(struct net *net, int ifindex);

static inline void *dev_get_priv(struct net_device *dev)
{
        return (void *)((char *)dev + sizeof(*dev));
}

int netdev_populate_table(int sizeof_priv, 
                          void (*setup)(struct net_device *));

int dev_queue_xmit(struct sk_buff *skb);

int netdev_init(void);
void netdev_fini(void);

int dev_get_ipv4_addr(struct net_device *dev, enum addr_type type, void *addr);

#endif /* OS_USER */

#endif /* _NETDEVICE_H_ */

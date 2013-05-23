/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <net/sock.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <linux/net.h>
#include <linux/file.h>
#include <af_serval.h>
#include <serval_sock.h>
#include <serval_sal.h>
#include <serval_ipv4.h>
#include <debug.h>
#include <serval_udp.h>

#define UDP_ENCAP_SALINUDP 7 /* This must be something which is not
                                defined in linux/udp.h */

#define UDP_ENCAP_CLIENT_PORT 54324
#define UDP_ENCAP_SERVER_PORT 54325
#define UDP_ENCAP_MAGIC	0x61114EDA

struct udp_encap {
        int                     magic;
        struct sock		*sk_parent;		/* Parent socket */
        struct sock		*sk;
	void (*old_sk_destruct)(struct sock *);
};

static struct sock *encap_client_sk = NULL;
static struct sock *encap_server_sk = NULL;

int serval_udp_encap_skb(struct sk_buff *skb, 
                         __u32 saddr, __u32 daddr,
                         u16 sport, u16 dport)
{
        struct udphdr *uh;

        uh = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
        
        if (!uh)
                return -1;

        skb_reset_transport_header(skb);
        dport = dport == 0 ? ((unsigned short)net_serval.sysctl_udp_encap_server_port) : dport;
        sport = sport == 0 ? ((unsigned short)net_serval.sysctl_udp_encap_client_port) : sport;

        LOG_DBG("UDP encapsulating [%u:%u] skb->len=%u\n",
                sport, dport, skb->len);

        /* Build UDP header */
        uh->source = htons(sport);
        uh->dest = htons(dport);
        uh->len = htons(skb->len);
        skb->ip_summed = CHECKSUM_NONE;
        uh->check = 0;
        uh->check = csum_tcpudp_magic(saddr,
                                      daddr, 
                                      skb->len,
                                      IPPROTO_UDP,
                                      csum_partial(uh, skb->len, 0));
        skb->protocol = IPPROTO_UDP;

        return 0;
}

int serval_udp_encap_xmit(struct sk_buff *skb)
{ 
        struct sock *sk = skb->sk;
        struct serval_sock *ssk;
        unsigned short udp_encap_dport;
        
        if (!sk)
                return -1;
        
        ssk = serval_sk(sk);

        if (ssk->sal_state == SAL_RSYN_RECV ||
            ssk->sal_state == SAL_RSYN_SENT_RECV) {
                udp_encap_dport = ssk->udp_encap_migration_dport;
        } else {
                udp_encap_dport = ssk->udp_encap_dport;
        }
        if (serval_udp_encap_skb(skb, 
                                 inet_sk(sk)->inet_saddr, 
                                 inet_sk(sk)->inet_daddr,
                                 ssk->udp_encap_sport,
                                 udp_encap_dport)) {
                kfree_skb(skb);
                return NET_RX_DROP;
        }
        
        return ssk->af_ops->encap_queue_xmit(skb);
}

static inline struct udp_encap *sock_to_encap(struct sock *sk)
{
	struct udp_encap *encap;

	if (sk == NULL)
		return NULL;

	encap = (struct udp_encap *)(sk->sk_user_data);

	if (encap == NULL)
		goto out;

	BUG_ON(encap->magic != UDP_ENCAP_MAGIC);

out:
	return encap;
}

/* UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes:
 * 0 : success.
 * <0: error
 * >0: skb should be passed up to userspace as UDP.
 */
int udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
        struct udphdr *uh = udp_hdr(skb);
	struct udp_encap *encap;

        LOG_PKT("UDP encapsulated packet [%u:%u len=%u] skb->len=%u\n",
                ntohs(uh->source),
                ntohs(uh->dest),
                ntohs(uh->len),
                skb->len);

	encap = sock_to_encap(sk);

	if (encap == NULL)
		goto pass_up;

        if (serval_udp_csum_init(skb, uh, IPPROTO_UDP)) {
                kfree_skb(skb);
                return 0;
        }
                
        if (serval_udp_checksum_complete(skb)) {
                LOG_DBG("Checksum error, dropping.\n");
                kfree_skb(skb);
                return 0;
        }

	__skb_pull(skb, sizeof(struct udphdr));
        skb_reset_transport_header(skb);
        
        serval_sal_rcv(skb);

        return 0;
pass_up:
	return 1;
}

static int udp_sock_create(u16 src_port, u16 dst_port, struct socket **sockp)
{
        int err = -EINVAL;
        struct sockaddr_in udp_addr;
        struct socket *sock = NULL;

        err = sock_create(AF_INET, SOCK_DGRAM, 0, sockp);
        
        if (err < 0)
                goto out;
        
        sock = *sockp;
        memset(&udp_addr, 0, sizeof(udp_addr));
        udp_addr.sin_family = AF_INET;
        udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        udp_addr.sin_port = htons(src_port);
        inet_sk(sock->sk)->inet_sport = src_port;
        inet_sk(sock->sk)->inet_dport = src_port;

        err = kernel_bind(sock, (struct sockaddr *) &udp_addr, 
                          sizeof(udp_addr));
 out:
        if ((err < 0) && sock) {
                sock_release(sock);
		*sockp = NULL;
	}

        return err;
}

static void udp_encap_destruct(struct sock *sk)
{
        struct udp_encap *encap = sk->sk_user_data;

	udp_sk(sk)->encap_type = 0;
        udp_sk(sk)->encap_rcv = NULL;

        sk->sk_destruct = encap->old_sk_destruct;
	sk->sk_user_data = NULL;

        /* Call the original destructor */
	if (sk->sk_destruct)
		(*sk->sk_destruct)(sk);
        
        LOG_DBG("encap destroyed\n");

        kfree(encap);
}        

static struct udp_encap *udp_encap_create(unsigned short port)
{
        struct socket *sock = NULL;
        struct udp_encap *encap = NULL;
        struct sock *sk;
        int err;

        err = udp_sock_create(port, port, &sock);

        if (err < 0) {
                LOG_ERR("Could not create UDP socket\n");
                goto error;
        }

	sk = sock->sk;

        encap = kzalloc(sizeof(struct udp_encap), gfp_any());
        
        if (!encap) {
                inet_release(sock);
                sock = NULL;
                goto error;
        }

        encap->magic = UDP_ENCAP_MAGIC;
        encap->sk = sk;
        encap->old_sk_destruct = sk->sk_destruct;
	sk->sk_user_data = encap;
        sk->sk_destruct = udp_encap_destruct;

        udp_sk(sk)->encap_type = UDP_ENCAP_SALINUDP; /* This is an
                                                        unallocated
                                                        type */
        udp_sk(sk)->encap_rcv = udp_encap_recv;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0))
        udp_encap_enable();
#endif
        LOG_DBG("UDP encap initialized\n");
 error:
	/* If tunnel's socket was created by the kernel, it doesn't
	 *  have a file.
	 */
	if (sock && sock->file)
		sockfd_put(sock);
               
        return encap;
}

static int udp_encap_init_sock(struct sock **sk, unsigned short port)
{
        struct udp_encap *encap;

        encap = udp_encap_create(port);
        
        if (!encap)
                return -ENOMEM;
        
        *sk = encap->sk;

        return 0;
}

int udp_encap_client_init(unsigned short port)
{
        if (encap_client_sk != NULL) {
                LOG_ERR("UDP client sock already initialized\n");
                return -1;
        }
        LOG_DBG("UDP encapsulation client sock on port %u\n", port); 
        pr_alert("UDP encapsulation client sock on port %u\n", port); 
        return udp_encap_init_sock(&encap_client_sk, port);
}

int udp_encap_server_init(unsigned short port)
{
        if (encap_server_sk != NULL) {
                LOG_ERR("UDP server sock already initialized\n");
                return -1;
        }

        LOG_DBG("UDP encapsulation server sock on port %u\n", port); 
        pr_alert("UDP encapsulation server sock on port %u\n", port); 
        return udp_encap_init_sock(&encap_server_sk, port);
}

int udp_encap_init(void)
{
        int err;

        net_serval.sysctl_udp_encap_client_port = UDP_ENCAP_CLIENT_PORT;
        net_serval.sysctl_udp_encap_server_port = UDP_ENCAP_SERVER_PORT;
        
        err = udp_encap_client_init(UDP_ENCAP_CLIENT_PORT);

        if (err)
                return err;

        return udp_encap_server_init(UDP_ENCAP_SERVER_PORT);
}

static void udp_encap_fini_sock(struct sock **sk)
{
        if (!(*sk))
                return;

        LOG_DBG("UDP encapsulation socket on port %u destroyed\n",
                inet_sk((*sk))->inet_sport);
        
        inet_release((*sk)->sk_socket);
        
        *sk = NULL;
}

void udp_encap_client_fini(void)
{
        udp_encap_fini_sock(&encap_client_sk);
        encap_client_sk = NULL;
}

void udp_encap_server_fini(void)
{
        udp_encap_fini_sock(&encap_server_sk);
        encap_server_sk = NULL;
}

void udp_encap_fini(void)
{
        udp_encap_fini_sock(&encap_client_sk);
        udp_encap_fini_sock(&encap_server_sk);
}

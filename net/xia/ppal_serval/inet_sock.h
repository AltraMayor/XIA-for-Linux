/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _INET_SOCK_H_
#define _INET_SOCK_H_

#include <platform.h>

#if defined(OS_LINUX_KERNEL)
#include <net/inet_sock.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
/* This is for compatibility with naming in the inet_sock structures
 * of older kernels. */
#define inet_daddr daddr
#define inet_saddr saddr
#define inet_rcv_saddr rcv_saddr
#define inet_sport sport
#define inet_dport dport
#endif 
#endif /* OS_LINUX_KERNEL */
#if defined(OS_USER)
#include <serval/sock.h>
#include <serval/request_sock.h>

struct ip_options {
        /* Nothing here now. */
	int dummy;
};

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @inet_daddr - Foreign IPv4 addr
 * @inet_rcv_saddr - Bound local IPv4 addr
 * @inet_num - Local port
 * @inet_saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @inet_id - ID counter for DF pkts
 * @tos - TOS
 */
struct inet_sock {
	struct sock	        sk;
	/* Socket demultiplex comparisons on incoming packets. */
	uint32_t		inet_daddr;
	uint32_t		inet_rcv_saddr;
	uint16_t		inet_num;
	uint32_t		inet_saddr;
	int16_t		        uc_ttl;
	uint16_t		cmsg_flags;
	uint16_t		inet_id;
	struct ip_options	*opt;
	uint8_t			tos;
	uint8_t			min_ttl;
	uint8_t			recverr:1,
				freebind:1,
				hdrincl:1,
				mc_loop:1,
		                transparent:1;
};

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct inet_request_sock {
	struct request_sock	req;
	__be16			loc_port;
	__be32			loc_addr;
	__be32			rmt_addr;
	__be16			rmt_port;
	u16			snd_wscale : 4,
				rcv_wscale : 4,
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1,
				no_srccheck: 1;
	struct ip_options	*opt;
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

#endif /* OS_USER */

#endif /* _INET_SOCK_H */

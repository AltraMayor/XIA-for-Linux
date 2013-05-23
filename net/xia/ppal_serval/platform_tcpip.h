/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _PLATFORM_TCPIP_H
#define _PLATFORM_TCPIP_H

#if defined(OS_LINUX)
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#endif

#if defined(OS_BSD)
#if defined(OS_MACOSX)
#include <machine/endian.h>
#else
#include <sys/endian.h>
#endif
#include <stdint.h>
#include <serval/checksum.h>

/* From linux/ip.h */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error "Undefined byte order!"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
};

struct udphdr {
        __be16  source;
        __be16  dest;
        __be16  len;
        __sum16 check;
};

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

#endif /* OS_BSD */

#endif /* _PLATFORM_TCPIP_H */

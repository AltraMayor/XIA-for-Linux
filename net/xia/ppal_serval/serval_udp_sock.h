/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_UDP_SOCK_H
#define _SERVAL_UDP_SOCK_H

#include <netdevice.h>
#include <serval_sock.h>

/* The AF_SERVAL socket */
struct serval_udp_sock {
	/* NOTE: serval_sock has to be the first member */
	struct serval_sock ssk;
};

static inline struct serval_udp_sock *serval_udp_sk(const struct sock *sk)
{
	return (struct serval_udp_sock *)sk;
}

#endif /* _SERVAL_UDP_SOCK_H */

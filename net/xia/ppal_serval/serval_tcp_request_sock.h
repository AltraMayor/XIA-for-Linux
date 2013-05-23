/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_TCP_REQUEST_SOCK_H_
#define _SERVAL_TCP_REQUEST_SOCK_H_

#include <platform.h>
#include <list.h>
#include <sock.h>
#include <request_sock.h>
#include <netinet_serval.h>
#if defined(OS_USER)
#include <string.h>
#endif
#include <serval_request_sock.h>

struct serval_tcp_request_sock {
        struct serval_request_sock rsk;
	__u32 snt_isn;
	__u32 rcv_isn;
};

static inline struct serval_tcp_request_sock *
serval_tcp_rsk(struct request_sock *rsk)
{
	return (struct serval_tcp_request_sock *)rsk;
}

static inline struct request_sock *
serval_tcp_reqsk_alloc(const struct request_sock_ops *ops)
{
        struct request_sock *rsk;

        rsk = serval_reqsk_alloc(ops);

        if (!rsk)
                return NULL;
	
        return rsk;
}

#endif /* _SERVAL_TCP_REQUEST_SOCK_H_ */

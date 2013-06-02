/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_REQUEST_SOCK_H_
#define _SERVAL_REQUEST_SOCK_H_

#include <platform.h>
#include <net/request_sock.h>
#include <netinet_serval.h>
#if defined(OS_USER)
#include <string.h>
#endif
#include "serval_sock.h"

struct serval_request_sock {
        struct inet_request_sock rsk;
        struct service_id peer_srvid;
        struct service_id target_srvid;
        struct flow_id local_flowid;
        struct flow_id peer_flowid;
        __u32 reply_saddr; /* The address to use as source in the
                               * reply */
        u32 rcv_seq;
        u32 iss_seq;
        u8 local_nonce[SAL_NONCE_SIZE];
        u8 peer_nonce[SAL_NONCE_SIZE];
        struct list_head lh;
};

static inline struct serval_request_sock *serval_rsk(struct request_sock *rsk)
{
        return (struct serval_request_sock *)rsk;
}

static inline struct request_sock *
serval_reqsk_alloc(const struct request_sock_ops *ops)
{
        struct request_sock *rsk;
        struct serval_request_sock *srsk;

        rsk = reqsk_alloc(ops);

        if (!rsk)
                return NULL;

        srsk = serval_rsk(rsk);

        INIT_LIST_HEAD(&srsk->lh);

        serval_sock_get_flowid(&srsk->local_flowid);

#if defined(OS_LINUX_KERNEL)
        get_random_bytes(srsk->local_nonce, SAL_NONCE_SIZE);
        get_random_bytes(&srsk->iss_seq, sizeof(srsk->iss_seq));
#else
        {
                unsigned int i;
                unsigned char *seqno = (unsigned char *)&srsk->iss_seq;
                for (i = 0; i < SAL_NONCE_SIZE; i++) {
                        srsk->local_nonce[i] = random() & 0xff;
                }
                for (i = 0; i < sizeof(srsk->iss_seq); i++) {
                        seqno[i] = random() & 0xff;
                }
        }       
#endif
        return rsk;
}

#endif /* _SERVAL_REQUEST_SOCK_H_ */

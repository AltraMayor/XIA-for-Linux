/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * PF_INET to PF_SERVAL socket layer.
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
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <netinet_serval.h>
#include <debug.h>
#include <serval_sock.h>
#include <af_serval.h>

extern struct proto tcp_prot;
extern struct proto serval_tcp_proto;
extern const struct proto_ops serval_stream_ops;
extern const struct proto_ops inet_stream_ops;
static struct proto old_tcp_prot;
static int enabled = 0;
static struct proto_ops serval_inet_stream_ops;

extern int inet_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer);

static void inet_addr_to_service(struct sockaddr_in *in,
                                 struct sockaddr_sv *sv)
{
        memset(sv, 0, sizeof(*sv));
        sv->sv_family = AF_SERVAL;
        sv->sv_srvid.s_sid32[0] = htonl(8080); 
        sv->sv_srvid.s_sid16[13] = in->sin_port;
        sv->sv_srvid.s_sid32[7] = in->sin_addr.s_addr;
}

static int serval_inet_bind(struct socket *sock, struct sockaddr *addr, 
                            int addr_len)
{
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        struct sockaddr_sv sv;

        if (addr_len < sizeof(addr->sa_family))
		return -EINVAL;

        if (addr->sa_family != AF_INET)
                return -EAFNOSUPPORT;

        inet_addr_to_service(in, &sv);
        addr_len = sizeof(sv);

        return serval_stream_ops.bind(sock, (struct sockaddr *)&sv, addr_len);
}

static int serval_inet_connect(struct socket *sock, struct sockaddr *addr,
                               int alen, int flags)
{
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        struct sockaddr_sv sv;
        unsigned char localhost[4] = { 0x7f, 0x0, 0x0, 0x1 };
        struct sock *sk = sock->sk;
        
        if (alen < sizeof(addr->sa_family))
		return -EINVAL;

        if (addr->sa_family != AF_INET)
                return -EAFNOSUPPORT;

        if (memcmp(&in->sin_addr, &localhost, sizeof(in->sin_addr)) == 0) {
                /* Give back control to legacy TCP in case of localhost */
                LOG_DBG("Dest is localhost, giving back sock\n");
                sock->ops = &inet_stream_ops;
		sock->sk = serval_sk(sk)->old_sk;
                module_put(serval_inet_stream_ops.owner);
                sk_common_release(sk);
                sk = sock->sk;
                sock_put(sk);
                sk->sk_type = sock->type;
		sk->sk_wq = sock->wq;
                return inet_stream_ops.connect(sock, addr, alen, flags);
        }
        
        /* Release old TCP sock */
        module_put(inet_stream_ops.owner);
        sock_put(serval_sk(sk)->old_sk);
        sk_common_release(serval_sk(sk)->old_sk);
        serval_sk(sk)->old_sk = NULL;

        inet_addr_to_service(in, &sv);
        alen = sizeof(sv);

        return serval_stream_ops.connect(sock, (struct sockaddr *)&sv,
                                         alen, flags);
}

static int serval_inet_tcp_init_sock(struct sock *sk)
{
        struct socket *sock = sk->sk_socket;
        struct sock *old_sk = sk;
        const struct proto_ops *old_ops = sock->ops;
        struct inet_sock *inet;
        int err = 0;

        LOG_DBG("init sock\n");

        /* First fully initialize the old sock. Otherwise, the release
           function will fail. */
        err = old_tcp_prot.init(sk);
        
        if (err)
                return err;
        
        sock->ops = &serval_inet_stream_ops;
        sk = serval_sk_alloc(sock_net(sk), sock,
                             GFP_KERNEL,
                             SERVAL_PROTO_TCP,
                             &serval_tcp_proto);
        
        if (!sk) {
                LOG_ERR("Fail alloc\n");
                goto out_fail_alloc;
        }
        /* Initialize serval sock part of socket */
        serval_sock_init(sk);

        /* Initialize inet part */
        inet = inet_sk(sk);
	inet->uc_ttl	= -1; /* Let IP decide TTL */
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;

        if (sk->sk_prot->init) {
                /* Call protocol specific init */
                err = sk->sk_prot->init(sk);

		if (err < 0) {
                        LOG_ERR("Fail init\n");
                        goto out_fail_init;
                }
	}
 
        sock_hold(old_sk);
        serval_sk(sk)->old_sk = old_sk;

        LOG_DBG("Successfully hijacked sock\n");

        return 0;
        
 out_fail_init:
        sk_common_release(sk);
 out_fail_alloc:
        sock->ops = old_ops;
        sock->sk = old_sk;
        return 0;
}

int inet_to_serval_enable(void)
{
        if (enabled)
                return -1;

        tcp_prot.init = serval_inet_tcp_init_sock;
        LOG_DBG("INET to SERVAL translation enabled\n");
        enabled = 1;

        return 0;
}

void inet_to_serval_disable(void)
{
        if (enabled) {
                tcp_prot = old_tcp_prot;
                LOG_DBG("INET to SERVAL translation disabled\n");
                enabled = 0;
        }
}

int inet_to_serval_init(void)
{
        memcpy(&serval_inet_stream_ops, &serval_stream_ops, 
               sizeof(serval_inet_stream_ops));
        serval_inet_stream_ops.bind = serval_inet_bind;
        serval_inet_stream_ops.connect = serval_inet_connect;
        serval_inet_stream_ops.getname = inet_getname;
        memcpy(&old_tcp_prot, &tcp_prot, sizeof(old_tcp_prot));
        return 0;
}

void inet_to_serval_fini(void)
{
        inet_to_serval_disable();
}



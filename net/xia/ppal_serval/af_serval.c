/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * The backends for Serval's BSD socket protocol family (PF_SERVAL).
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
#if defined(OS_LINUX_KERNEL)
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <net/protocol.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
#include <linux/export.h>
#endif

extern int inet_to_serval_init(void);
extern void inet_to_serval_fini(void);

#elif defined(OS_USER)
/* User-level declarations */
#include <errno.h>
#endif /* OS_LINUX_KERNEL */

/* Common includes */
#include <debug.h>
#include <list.h>
#include <atomic.h>
#include <wait.h>
#include <sock.h>
#include <net.h>
#include <skbuff.h>
#include <inet_sock.h>
#include <netinet_serval.h>
#include <serval_sock.h>
#include <serval_request_sock.h>
#include <serval_udp_sock.h>
#include <serval_tcp_sock.h>
#include <delay_queue.h>
#include <ctrl.h>
#include <af_serval.h>
#include <serval_sal.h>
#include <service.h>

extern int packet_init(void);
extern void packet_fini(void);
extern int service_init(void);
extern void service_fini(void);
extern int delay_queue_init(void);
extern void delay_queue_fini(void);

extern struct proto serval_udp_proto;
extern struct proto serval_tcp_proto;

struct netns_serval net_serval = {
        .sysctl_sal_forward = 0,
        .sysctl_inet_to_serval = 0,
        .sysctl_auto_migrate = 0,
        .sysctl_debug = 0,
        .sysctl_udp_encap = 0,
        .sysctl_sal_max_retransmits = SAL_RETRANSMITS_MAX,
        .sysctl_resolution_mode = SERVICE_ITER_ANYCAST,
};

extern void serval_tcp_init(void);

static struct sock *serval_accept_dequeue(struct sock *parent,
                                          struct socket *newsock);

/*
  Automatically assigns a random service id.
*/
static int serval_autobind(struct sock *sk)
{
        struct serval_sock *ssk;
         /*
          Assign a random service id until the socket is assigned one
          with bind (if ever).

          TODO: check for conflicts.
        */
        lock_sock(sk);
        ssk = serval_sk(sk);
#if defined(OS_LINUX_KERNEL)
        get_random_bytes(&ssk->local_srvid, sizeof(struct service_id));
#else
        {
                unsigned int i;
                unsigned char *byte = (unsigned char *)&ssk->local_srvid;

                for (i = 0; i  < sizeof(struct service_id); i++) {
                        byte[i] = random() & 0xff;
                }
        }
#endif
        serval_sock_set_flag(ssk, SSK_FLAG_BOUND);
        serval_sock_set_flag(ssk, SSK_FLAG_AUTOBOUND);
        serval_sk(sk)->srvid_prefix_bits = 0;
        serval_sk(sk)->srvid_flags = 0;

        /* Add to protocol hash chains. */
        sk->sk_prot->hash(sk);

        release_sock(sk);

        return 0;
}

int serval_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
        struct sock *sk = sock->sk;
        struct serval_sock *ssk = serval_sk(sk);
        struct sockaddr_sv *svaddr = (struct sockaddr_sv *)addr;
        struct ctrlmsg_register cm;
        struct service_id null_service = { .s_sid = { 0 } };

        if ((unsigned int)addr_len < sizeof(*svaddr))
                return -EINVAL;
        else if (addr_len % sizeof(*svaddr) != 0)
                return -EINVAL;

        /* TODO: Handle binding to a serviceID and an IP address at
           the same time */

        LOG_INF("SERVAL bind on SID(%u:%u) %s\n", 
                svaddr->sv_flags, 
                svaddr->sv_prefix_bits, 
                service_id_to_str(&svaddr->sv_srvid));
        
        if (memcmp(&svaddr->sv_srvid, &null_service, 
                   sizeof(null_service)) == 0) {
                LOG_ERR("Cannot bind on null serviceID\n");
                return -EINVAL;
        }
        
        /* Call the protocol's own bind, if it exists */
	if (sk->sk_prot->bind) {
                int err = sk->sk_prot->bind(sk, addr, addr_len);
               
                if (err == 0) 
                        return err;
        } else {
                lock_sock(sk);
                
                /* Already bound? */
                if (serval_sock_flag(ssk, SSK_FLAG_BOUND)) {
                        sk->sk_prot->unhash(sk);
                } else {
                        /* Mark socket as bound */
                        serval_sock_set_flag(ssk, SSK_FLAG_BOUND);
                }
                
                memcpy(&serval_sk(sk)->local_srvid, &svaddr->sv_srvid,
                       sizeof(svaddr->sv_srvid));
                serval_sk(sk)->srvid_prefix_bits = svaddr->sv_prefix_bits;
                serval_sk(sk)->srvid_flags = svaddr->sv_flags;
                                
                release_sock(sk);
        }

        /* Add protocol. */
        sk->sk_prot->hash(sk);
               
        if (!serval_sock_flag(ssk, SSK_FLAG_HASHED)) {
                LOG_SSK(sk, "Could not bind socket, hashing failed\n");
                return -EINVAL;
        }

        /* Notify the service daemon */
        memset(&cm, 0, sizeof(cm));
        cm.cmh.type = CTRLMSG_TYPE_REGISTER;
        cm.cmh.len = sizeof(cm);
        cm.srvid_flags = ssk->srvid_flags;
        cm.srvid_prefix_bits = ssk->srvid_prefix_bits;
        memcpy(&cm.srvid, &ssk->local_srvid, sizeof(ssk->local_srvid));

        if (ctrl_sendmsg(&cm.cmh, 0, GFP_KERNEL) < 0) {
                LOG_INF("No service daemon running?\n");
        }

        return 0;
}

/*
 *	This does both peername and sockname.
 */
static int serval_getname(struct socket *sock, struct sockaddr *uaddr,
                          int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct inet_sock *inet	= inet_sk(sk);
        struct serval_sock *ssk = serval_sk(sk);
        
        /* 
           The uaddr_len variable is always undefined, because the
           system call passes a sockaddr_storage here instead of the
           user-level passed memory area and does not specifiy the
           length. Thus, there is no way to signal what address to
           return in the system call. We therefore default to
           returning both serviceID and IP address.
         */
        *uaddr_len = sizeof(struct sockaddr_sv) + 
                sizeof(struct sockaddr_in);
	
        if (peer) {
		if ((((1 << sk->sk_state) & (SALF_CLOSED | 
                                             SALF_REQUEST)) &&
		     peer == 1))
			return -ENOTCONN;
                
                if (*uaddr_len >= sizeof(struct sockaddr_in) + 
                    sizeof(struct sockaddr_sv)) {
                        struct sockaddr_sv *sv = (struct sockaddr_sv *)uaddr;
                        struct sockaddr_in *sin = 
                                (struct sockaddr_in *)(sv + 1);
                        sv->sv_family = AF_SERVAL;
                        memcpy(&sv->sv_srvid, &ssk->peer_srvid, 
                               sizeof(ssk->peer_srvid));
                        sv->sv_prefix_bits = 0;
                        sv->sv_flags = 0;

                        sin->sin_family = AF_INET;
                        sin->sin_port = 0; /* inet->inet_dport; */
                        sin->sin_addr.s_addr = inet->inet_daddr;
                        memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
                        *uaddr_len = sizeof(*sv) + sizeof(*sin);
                } else if (*uaddr_len >= sizeof(struct sockaddr_sv)) {
                        struct sockaddr_sv *sv = (struct sockaddr_sv *)uaddr;
                        sv->sv_family = AF_SERVAL;
                        memcpy(&sv->sv_srvid, &ssk->peer_srvid, 
                               sizeof(ssk->peer_srvid));
                        sv->sv_prefix_bits = 0;
                        sv->sv_flags = 0;
                        *uaddr_len = sizeof(*sv);
                } else {
                        struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
                        sin->sin_family = AF_INET;
                        sin->sin_port = 0; /* inet->inet_dport; */
                        sin->sin_addr.s_addr = inet->inet_daddr;
                        memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
                        *uaddr_len = sizeof(*sin);
                }
	} else {
                if (*uaddr_len >= sizeof(struct sockaddr_in) + 
                    sizeof(struct sockaddr_sv)) {
                        struct sockaddr_sv *sv = (struct sockaddr_sv *)uaddr;
                        struct sockaddr_in *sin = 
                                (struct sockaddr_in *)(sv + 1);
                        __be32 addr = inet->inet_rcv_saddr;

                        sv->sv_family = AF_SERVAL;
                        memcpy(&sv->sv_srvid, &ssk->local_srvid, 
                               sizeof(ssk->local_srvid));
                        sv->sv_prefix_bits = ssk->srvid_prefix_bits;
                        sv->sv_flags = ssk->srvid_flags;

                        sin->sin_family = AF_INET;
                        if (!addr)
                                addr = inet->inet_saddr;
                        sin->sin_port = 0; /* inet->inet_sport; */
                        sin->sin_addr.s_addr = addr;
                        memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
                        *uaddr_len = sizeof(*sv) + sizeof(*sin);
                } else if (*uaddr_len >= sizeof(struct sockaddr_sv)) {
                        struct sockaddr_sv *sv = (struct sockaddr_sv *)uaddr;
                        sv->sv_family = AF_SERVAL;
                        memcpy(&sv->sv_srvid, &ssk->local_srvid, 
                               sizeof(ssk->local_srvid));
                        sv->sv_prefix_bits = ssk->srvid_prefix_bits;
                        sv->sv_flags = ssk->srvid_flags;
                        *uaddr_len = sizeof(*sv);
                } else {
                        struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
                        __be32 addr = inet->inet_rcv_saddr;
                        if (!addr)
                                addr = inet->inet_saddr;
                        sin->sin_family = AF_INET;
                        sin->sin_port = 0; /* inet->inet_sport; */
                        sin->sin_addr.s_addr = addr;
                        memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
                        *uaddr_len = sizeof(*sin);
                }
	}
	return 0;
}

static int serval_listen_start(struct sock *sk, int backlog)
{
        serval_sock_set_state(sk, SAL_LISTEN);
        sk->sk_ack_backlog = 0;
 
        return 0;
}

static int serval_listen_stop(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);

        serval_sock_delete_keepalive_timer(sk);

        /* Destroy queue of sockets that haven't completed three-way
         * handshake */
        while (1) {
                struct serval_request_sock *srsk;
                
                if (list_empty(&ssk->syn_queue))
                        break;
                
                srsk = list_first_entry(&ssk->syn_queue, 
                                        struct serval_request_sock, lh);
                
                list_del(&srsk->lh);

                LOG_SSK(sk, "deleting SYN queued request socket\n");

                reqsk_free(&srsk->rsk.req);
                sk->sk_ack_backlog--;
        }
        /* Destroy accept queue of sockets that completed three-way
           handshake (and send appropriate packets to other ends) */
        while (1) {
                struct serval_request_sock *srsk;

                if (list_empty(&ssk->accept_queue))
                        break;
                
                srsk = list_first_entry(&ssk->accept_queue, 
                                        struct serval_request_sock, lh);
                
                list_del(&srsk->lh);

                if (srsk->rsk.req.sk) {
                        struct sock *child = srsk->rsk.req.sk;
                        
                        /* From inet_connection_sock */
                        local_bh_disable();
                        bh_lock_sock(child);
                        /* WARN_ON(sock_owned_by_user(child)); */
                        sock_hold(child);

                        sk->sk_prot->disconnect(child, O_NONBLOCK);

                        /* Orphaning will mark the sock with flag DEAD,
                         * allowing the sock to be destroyed. */
                        sock_orphan(child);

                        LOG_DBG("removing socket from accept queue\n");

                        sk->sk_prot->unhash(child);
                        /* percpu_counter_inc(sk->sk_prot->orphan_count); */

                        /* put for rsk->sk pointer */
                        sock_put(child);

                        bh_unlock_sock(child);
                        local_bh_enable();

                        sock_put(child);
                }
                reqsk_free(&srsk->rsk.req);
                sk->sk_ack_backlog--;
        }

        return 0;
}

static int serval_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
        int err = 0;

        lock_sock(sk);

        if (sock->type != SOCK_DGRAM && sock->type != SOCK_STREAM) {
                LOG_ERR("bad socket type\n");
                err = -EOPNOTSUPP;
                goto out;
        }

        if (sock->state != SS_UNCONNECTED) {
                LOG_ERR("socket not unconnected\n");
                err = -EINVAL;
                goto out;
        }

        if (!serval_sock_flag(serval_sk(sk), SSK_FLAG_BOUND) &&
            serval_autobind(sk) < 0) {
                err =-EAGAIN;
                goto out;
        }

        err = serval_listen_start(sk, backlog);

        if (err == 0) {
                sk->sk_max_ack_backlog = backlog;
        }
 out:
        release_sock(sk);

        return err;
}

struct sock *serval_accept_dequeue(struct sock *parent,
                                   struct socket *newsock)
{
	struct sock *sk = NULL;
        struct serval_sock *pssk = serval_sk(parent);
        struct serval_request_sock *srsk;

        /* Parent sock is already locked... */
        list_for_each_entry(srsk, &pssk->accept_queue, lh) {
                if (!srsk->rsk.req.sk)
                        continue;

                sk = srsk->rsk.req.sk;
               
                if (newsock) {
                        sock_graft(sk, newsock);
                        newsock->state = SS_CONNECTED;
                }

                list_del(&srsk->lh);
                reqsk_free(&srsk->rsk.req);
                parent->sk_ack_backlog--;
                return sk;
        }

	return NULL;
}

static int serval_wait_for_connect(struct sock *sk, long timeo)
{
        struct serval_sock *ssk = serval_sk(sk);
	DEFINE_WAIT(wait);
	int err;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (list_empty(&ssk->accept_queue))
			timeo = schedule_timeout(timeo);
		lock_sock(sk);
		err = 0;
		if (!list_empty(&ssk->accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != SAL_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int serval_accept(struct socket *sock, 
                         struct socket *newsock,
                         int flags)
{
	struct sock *sk = sock->sk, *nsk;
        struct serval_sock *ssk = serval_sk(sk);
	int err = 0;

	lock_sock(sk);

	if (sk->sk_state != SAL_LISTEN) {
		err = -EBADFD;
		goto out;
	}

        if (list_empty(&ssk->accept_queue)) {
                long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		err = -EAGAIN;

		if (!timeo)
			goto out;

		err = serval_wait_for_connect(sk, timeo);

		if (err)
			goto out;
	}

        nsk = serval_accept_dequeue(sk, newsock);

        if (!nsk)
                err = -EAGAIN;
out:
	release_sock(sk);
        return err;
}

static int serval_connect(struct socket *sock, struct sockaddr *addr,
                          int alen, int flags)
{
        struct sock *sk = sock->sk;
        int err = 0;
        int nonblock = flags & O_NONBLOCK;
        long timeo;

        if (addr->sa_family != AF_SERVAL) {
                LOG_ERR("Bad address family %d!\n", addr->sa_family);
                return -EAFNOSUPPORT;
        }

        lock_sock(sk);

        switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;

		if (sk->sk_state == SAL_LISTEN)
			goto out;

                /*
                  We need to rehash the socket because it may be
                  initially hashed on serviceID for being able to
                  receive unconnected datagrams
                */
                if (serval_sock_flag(serval_sk(sk), SSK_FLAG_BOUND))
                        sk->sk_prot->unhash(sk);

                serval_sock_set_state(sk, SAL_REQUEST);

                sk->sk_prot->hash(sk);
                
                err = sk->sk_prot->connect(sk, addr, alen);

		if (err < 0) {
                        serval_sock_set_state(sk, SAL_CLOSED);
			goto out;
                }
		sock->state = SS_CONNECTING;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}
                
        timeo = sock_sndtimeo(sk, nonblock);

        if ((1 << sk->sk_state) & (SALF_REQUEST | SALF_RESPOND)) {
                /* Error code is set above */
                LOG_SSK(sk, "Waiting for connect, timeo=%ld\n", timeo);

                if (!timeo)
                        goto out;

                err = sk_stream_wait_connect(sk, &timeo);

                if (err) {
                        if (err == -ERESTARTSYS) {
                                LOG_SSK(sk, "sk_stream_wait_connect interrupted\n");
                        } else {
                                LOG_SSK(sk, "sk_stream_wait_connect err=%d\n",
                                        err);
                        }
                        goto out;
                }
                
                err = sock_intr_errno(timeo);

                if (signal_pending(current))
                        goto out;
        }

        /* We must be in SERVAL_REQUEST or later state. All those
           states are valid "connected" states, except for CLOSED. */
        if (sk->sk_state == SAL_CLOSED)
                goto sock_error;

        sock->state = SS_CONNECTED;
        err = 0;
out:
        release_sock(sk);

        return err;
sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
        goto out;
}

static int serval_sendmsg(struct kiocb *iocb, struct socket *sock,
                          struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
        int err;

	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		return -EPIPE;

	/* We may need to bind the socket. */
	if (!serval_sock_flag(serval_sk(sk), SSK_FLAG_BOUND) &&
            serval_autobind(sk) < 0)
		return -EAGAIN;

	err = sk->sk_prot->sendmsg(iocb, sk, msg, size);

        return err;
}

static int serval_recvmsg(struct kiocb *iocb, struct socket *sock,
                          struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	int err;

	err = sk->sk_prot->recvmsg(iocb, sk, msg, size, flags & MSG_DONTWAIT,
				   flags & ~MSG_DONTWAIT, &addr_len);
	if (err >= 0)
		msg->msg_namelen = addr_len;

	return err;
}

static void unregister_service(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);

        if (serval_sock_flag(ssk, SSK_FLAG_BOUND) &&
            !serval_sock_flag(ssk, SSK_FLAG_AUTOBOUND) && 
            !serval_sock_flag(ssk, SSK_FLAG_CHILD)) {
                struct ctrlmsg_register cm;
                
                /* Notify user space */
                memset(&cm, 0, sizeof(cm));
                cm.cmh.type = CTRLMSG_TYPE_UNREGISTER;
                cm.cmh.len = sizeof(cm);
                cm.srvid_flags = serval_sk(sk)->srvid_flags;
                cm.srvid_prefix_bits = serval_sk(sk)->srvid_prefix_bits;
                memcpy(&cm.srvid, &serval_sk(sk)->local_srvid, 
                       sizeof(cm.srvid));
                
                if (ctrl_sendmsg(&cm.cmh, 0, GFP_KERNEL) < 0) {
                        LOG_INF("No service daemon running?\n");
                }
        }
}

static int serval_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

        LOG_DBG("\n");

	how++; /* maps 0->1 has the advantage of making bit 1 rcvs and
		       1->2 bit 2 snds.
		       2->3 */
	if ((how & ~SHUTDOWN_MASK) || !how)	/* MAXINT->0 */
		return -EINVAL;

        /*
          Unregister notification only if we previously registered and
          this is not a child socket.
        */

        unregister_service(sk);

	lock_sock(sk);

	if (sock->state == SS_CONNECTING) {
                /*
		if ((1 << sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_CLOSE))
			sock->state = SS_DISCONNECTING;
		else
                */
                sock->state = SS_CONNECTED;
	}

	switch (sk->sk_state) {
	case SAL_CLOSED:
		err = -ENOTCONN;
		/* Hack to wake up other listeners, who can poll for
		   POLLHUP, even on eg. unconnected UDP sockets -- RR */
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown)
			sk->sk_prot->shutdown(sk, how);
		break;

	/* Remaining two branches are temporary solution for missing
	 * close() in multithreaded environment. It is _not_ a good idea,
	 * but we have no choice until close() is repaired at VFS level.
	 */
	case SAL_LISTEN:
		if (!(how & RCV_SHUTDOWN))
			break;
		/* Fall through */
	case SAL_REQUEST:
		err = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);

	release_sock(sk);

        return err;
}

int serval_release(struct socket *sock)
{
        int err = 0;
        struct sock *sk = sock->sk;

	if (sk) {
                int state;
                long timeout = 0;

                LOG_SSK(sk, "\n");

		if (sock_flag(sk, SOCK_LINGER) && 0
                    /*!(current->flags & PF_EXITING) */)
			timeout = sk->sk_lingertime;

                sock->sk = NULL;
                
                unregister_service(sk);

                lock_sock(sk);

                sk->sk_shutdown = SHUTDOWN_MASK;
                
                if (sk->sk_state == SAL_LISTEN) {
                        serval_listen_stop(sk);
                        serval_sock_set_state(sk, SAL_CLOSED);
                } else if (sk->sk_state != SAL_CLOSED) {
                        /* the protocol specific function called here
                         * should not lock sock */
                        sk->sk_prot->close(sk, timeout);
                }

                state = sk->sk_state;
                /* Hold reference so that the sock is not
                   destroyed by a bh when we release lock */
                sock_hold(sk);

                /* Orphaning will mark the sock with flag DEAD,
                 * allowing the sock to be destroyed. */
                sock_orphan(sk);
                
                release_sock(sk);

                /* Purge any packets in the delay queue for this
                   socket */
                delay_queue_purge_sock(sk);

                /* Now socket is owned by kernel and we acquire BH lock
                   to finish close. No need to check for user refs.
                */
                local_bh_disable();
                bh_lock_sock(sk);

                /* Have we already been destroyed by a softirq or backlog? */
                if (state != SAL_CLOSED &&
                    sk->sk_state == SAL_CLOSED)
                        goto out;

                /* Other cleanup stuff goes here */
                if (sk->sk_state == SAL_CLOSED)
                        serval_sock_destroy(sk);
        out:
                bh_unlock_sock(sk);
                local_bh_enable();
                sock_put(sk);
        }

        return err;
}

ssize_t serval_sendpage(struct socket *sock, struct page *page, int offset,
                        size_t size, int flags)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
        
	if (!serval_sock_flag(serval_sk(sk), SSK_FLAG_BOUND) &&
            serval_autobind(sk) < 0)
		return -EAGAIN;

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);

	return sock_no_sendpage(sock, page, offset, size, flags);
}

#if defined(OS_LINUX_KERNEL)
static unsigned int serval_poll(struct file *file, struct socket *sock,
                                poll_table *wait)
{
	struct sock *sk = sock->sk;
	unsigned int mask = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	sock_poll_wait(file, sk_sleep(sk), wait);
#else
        poll_wait(file, sk->sk_sleep, wait);
#endif
        if (sk->sk_state == SAL_LISTEN) {
                struct serval_sock *ssk = serval_sk(sk);
                return list_empty(&ssk->accept_queue) ? 0 :
                        (POLLIN | POLLRDNORM);
        }

        mask = 0;

	if (sk->sk_err)
		mask = POLLERR;

	if (sk->sk_shutdown == SHUTDOWN_MASK ||
            sk->sk_state == SAL_CLOSED)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	if ((1 << sk->sk_state) & ~(SALF_REQUEST | SALF_RESPOND)) {
                if (atomic_read(&sk->sk_rmem_alloc) > 0)
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >=
                            sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >=
                                    sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		}
	}

	return mask;
}

static int serval_ioctl(struct socket *sock, unsigned int cmd,
                        unsigned long arg)
{
	struct sock *sk = sock->sk;
	int ret = 0;

        if (sk->sk_prot->ioctl) 
                ret = sk->sk_prot->ioctl(sk, cmd, arg);
        else
                ret = -ENOIOCTLCMD;

	return ret;
}
#endif

#if defined(OS_LINUX_KERNEL)
extern unsigned int serval_tcp_poll(struct file *file, 
                                    struct socket *sock, 
                                    poll_table *wait);
#if defined(ENABLE_SPLICE)
extern ssize_t serval_udp_splice_read(struct socket *sock, loff_t *ppos,
                                      struct pipe_inode_info *pipe, size_t len,
                                      unsigned int flags);

extern ssize_t serval_tcp_splice_read(struct socket *sock, loff_t *ppos,
                                      struct pipe_inode_info *pipe, size_t len,
                                      unsigned int flags);

#endif /* ENABLE_SPLICE */
#endif /* OS_LINUX_KERNEL */

const struct proto_ops serval_stream_ops = {
	.family =	PF_SERVAL,
	.owner =	THIS_MODULE,
	.release =	serval_release,
	.bind =		serval_bind,
	.connect =	serval_connect,
	.accept =	serval_accept,
	.getname =	serval_getname,
	.listen =	serval_listen,
	.shutdown =	serval_shutdown,
	.sendmsg =	serval_sendmsg,
	.recvmsg =	serval_recvmsg,
	.setsockopt =	sock_common_setsockopt,
	.getsockopt =	sock_common_getsockopt,
#if defined(OS_LINUX_KERNEL)
	.socketpair =	sock_no_socketpair,
	.poll =	        serval_tcp_poll,
	.ioctl =	serval_ioctl,
	.mmap =		sock_no_mmap,
	.sendpage =	serval_sendpage,
#if defined(ENABLE_SPLICE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	.splice_read =  serval_tcp_splice_read,
#endif
#endif
};

static const struct proto_ops serval_dgram_ops = {
	.family =	PF_SERVAL,
	.owner =	THIS_MODULE,
	.release =	serval_release,
	.bind =		serval_bind,
	.connect =	serval_connect,
	.accept =	serval_accept,
	.getname =	serval_getname,
	.listen =	serval_listen,
	.shutdown =	serval_shutdown,
	.sendmsg =	serval_sendmsg,
	.recvmsg =	serval_recvmsg,
	.setsockopt =	sock_common_setsockopt,
	.getsockopt =	sock_common_getsockopt,
#if defined(OS_LINUX_KERNEL)
	.socketpair =	sock_no_socketpair,
	.poll =	        serval_poll,
	.ioctl =	serval_ioctl,
	.mmap =		sock_no_mmap,
	.sendpage =	serval_sendpage,
#if defined(ENABLE_SPLICE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	.splice_read =  serval_udp_splice_read,
#endif
#endif
};

/**
   Create a new Serval socket.
 */
static int serval_create(struct net *net, struct socket *sock, int protocol
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
                           , int kern
#endif
)
{
        struct sock *sk = NULL;
        struct inet_sock *inet = NULL;
        int ret = 0;

        LOG_DBG("Creating SERVAL socket\n");

        if (protocol &&
            (protocol != SERVAL_PROTO_UDP &&
             protocol != SERVAL_PROTO_TCP))
		return -EPROTONOSUPPORT;

	sock->state = SS_UNCONNECTED;

	switch (sock->type) {
                case SOCK_DGRAM:
                        if (!protocol)
                                protocol = SERVAL_PROTO_UDP;
                        sock->ops = &serval_dgram_ops;
                        sk = serval_sk_alloc(net, sock,
                                               GFP_KERNEL,
                                               protocol,
                                               &serval_udp_proto);
                        break;
                case SOCK_STREAM:
                        if (!protocol)
                                protocol = SERVAL_PROTO_TCP;
                        sock->ops = &serval_stream_ops;
                        sk = serval_sk_alloc(net, sock,
                                               GFP_KERNEL,
                                               protocol,
                                               &serval_tcp_proto);
                        break;
                case SOCK_SEQPACKET:
                case SOCK_RAW:
                default:
                        return -ESOCKTNOSUPPORT;
	}

	if (!sk) {
                ret = -ENOMEM;
		goto out;
        }

        /* Initialize serval sock part of socket */
        serval_sock_init(sk);

        /* Initialize inet part */
        inet = inet_sk(sk);
	inet->uc_ttl	= -1; /* Let IP decide TTL */
#if defined(OS_LINUX_KERNEL)
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	/* inet->mc_all	= 1; */
	inet->mc_index	= 0;
	inet->mc_list	= NULL;        
#endif

        if (sk->sk_prot->init) {
                /* Call protocol specific init */
                ret = sk->sk_prot->init(sk);

		if (ret < 0)
			sk_common_release(sk);
	}
out:
        return ret;
}

static struct net_proto_family serval_family_ops = {
	.family = PF_SERVAL,
	.create = serval_create,
	.owner	= THIS_MODULE,
};

int serval_init(void)
{
        int err = 0;

        err = service_init();

        if (err < 0) {
                LOG_CRIT("Cannot initialize service table\n");
                goto fail_service;
        }

        err = serval_sock_tables_init();

        if (err < 0) {
                LOG_CRIT("Cannot initialize serval sockets\n");
                goto fail_sock;
        }

        err = packet_init();

        if (err != 0) {
		        LOG_CRIT("Cannot init packet socket!\n");
		        goto fail_packet;
	    }

        err = proto_register(&serval_udp_proto, 1);

    	if (err != 0) {
		        LOG_CRIT("Cannot register UDP proto\n");
		        goto fail_udp_proto;
	    }
                
        err = proto_register(&serval_tcp_proto, 1);

	    if (err != 0) {
		        LOG_CRIT("Cannot register TCP proto\n");
		        goto fail_tcp_proto;
	    }

        err = sock_register(&serval_family_ops);

        if (err != 0) {
                LOG_CRIT("Cannot register socket family\n");
                goto fail_sock_register;
        }

#if defined(OS_LINUX_KERNEL)
        err = inet_to_serval_init();

        if (err != 0) {
                LOG_CRIT("Cannot initialize INET to SERVAL support\n");
                goto fail_inet_to_serval;
        }
#endif
        serval_tcp_init();
        
        delay_queue_init();
 out:
        return err;
#if defined(OS_LINUX_KERNEL)
 fail_inet_to_serval:
        sock_unregister(PF_SERVAL);
#endif
 fail_sock_register:
	proto_unregister(&serval_tcp_proto);     
 fail_tcp_proto:
	proto_unregister(&serval_udp_proto);     
 fail_udp_proto:
        packet_fini();
 fail_packet:
        serval_sock_tables_fini();
 fail_sock:
        service_fini();
 fail_service:
        goto out;      
}

#if defined(OS_LINUX_KERNEL)
#include <net/ip.h>
#endif

void serval_fini(void)
{
#if defined(OS_LINUX_KERNEL)
        inet_to_serval_fini();
#endif
     	sock_unregister(PF_SERVAL);
	proto_unregister(&serval_udp_proto);
	proto_unregister(&serval_tcp_proto);
        serval_sock_tables_fini();
        packet_fini();
        service_fini();
        delay_queue_fini();
}

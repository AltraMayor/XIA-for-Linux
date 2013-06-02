/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Serval UDP/Datagram sockets. Can be both connected and unconnected.
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
#include <debug.h>
#include <netdevice.h>
#include <netinet_serval.h>
#include <serval_sock.h>
#include <serval_request_sock.h>
#include <serval_ipv4.h>
#include <serval_sal.h>
#include <serval_udp.h>
#include <af_serval.h>

#define EXTRA_HDR (20)
/* payload + LL + IP + extra */
#define MAX_SERVAL_UDP_HDR (MAX_SAL_HDR + sizeof(struct udphdr)) 

static int serval_udp_connection_request(struct sock *sk,
                                         struct request_sock *rsk,
                                         struct sk_buff *skb);

static int serval_udp_connection_respond_sock(struct sock *sk, 
                                              struct sk_buff *skb,
                                              struct request_sock *rsk,
                                              struct sock *child,
                                              struct dst_entry *dst);

static int serval_udp_rcv(struct sock *sk, struct sk_buff *skb);
static void serval_udp_v4_send_check(struct sock *sk, struct sk_buff *skb);

/*
  For connected UDP we do nothing more for the SYN than adding an
  empty header. This is needed for checksumming to work 
*/
static int serval_udp_build_syn(struct sock *sk, struct sk_buff *skb)
{
        struct udphdr *uh;

        uh = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));

        if (!uh)
                return -1;
        
        skb_reset_transport_header(skb);
        uh->source = 0;
        uh->dest = 0;
        uh->len = htons(skb->len);
        uh->check = 0;
        skb->ip_summed = CHECKSUM_NONE;
        skb->protocol = IPPROTO_UDP;
        
        return 0;
}

static int serval_udp_build_synack(struct sock *sk,
                                   struct dst_entry *dst,
                                   struct request_sock *req, 
                                   struct sk_buff *skb)
{
        return serval_udp_build_syn(sk, skb);
}

static int serval_udp_build_ack(struct sock *sk,
                                struct sk_buff *skb)
{
        return serval_udp_build_syn(sk, skb);
}

static struct serval_sock_af_ops serval_udp_af_ops = {
        .rebuild_header = serval_sock_rebuild_header,
#if defined(OS_LINUX_KERNEL)
        .setsockopt = ip_setsockopt,
        .getsockopt = ip_getsockopt,
#endif
        .conn_build_syn = serval_udp_build_syn,
        .conn_build_synack = serval_udp_build_synack,
        .conn_build_ack = serval_udp_build_ack,
        .send_check = serval_udp_v4_send_check,
        .queue_xmit = serval_ipv4_xmit,
        .receive = serval_udp_rcv,
        .net_header_len = SAL_NET_HEADER_LEN,
        .conn_request = serval_udp_connection_request,
        .conn_child_sock = serval_udp_connection_respond_sock,
};

static void __serval_udp_v4_send_check(struct sk_buff *skb,
                                __be32 saddr, __be32 daddr)
{
	struct udphdr *uh = udp_hdr(skb);
        unsigned long len = skb_tail_pointer(skb) - skb_transport_header(skb);

        skb->ip_summed = CHECKSUM_NONE;
        uh->check = 0;
        uh->check = csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP,
                                      csum_partial(uh, len, 0));
}

void serval_udp_v4_send_check(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);
        __serval_udp_v4_send_check(skb, inet->inet_saddr, inet->inet_daddr);
}

static int serval_udp_transmit_skb(struct sock *sk, 
                                   struct sk_buff *skb)
{
        int err;
        struct udphdr *uh;

        /* Push back to make space for transport header */
        uh = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);

        /* Build UDP header */
        uh->source = 0;
        uh->dest = 0;
        uh->len = htons(skb->len);
        uh->check = 0;
        skb->ip_summed = CHECKSUM_NONE;
        skb->protocol = IPPROTO_UDP;
        /*
          Note, for packets resolved through the service table, this
          checksum calculated here will be recalculated once the
          resolution is performed and the src/dst IP addresses are
          known. This could be inefficient, since we are calculating
          the checksum twice for such packets.
         */
        serval_udp_v4_send_check(sk, skb);

        LOG_PKT("UDP pkt [s=%u d=%u len=%u]\n",
                ntohs(uh->source),
                ntohs(uh->dest),
                ntohs(uh->len));

        err = serval_sal_xmit_skb(skb);
        
        if (err < 0) {
                LOG_ERR("xmit failed err=%d\n", err);
        }

        return err;
}

static int serval_udp_init_sock(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
	ssk->af_ops = &serval_udp_af_ops;
        LOG_DBG("\n");
        return 0;
}

static void serval_udp_destroy_sock(struct sock *sk)
{
        /* struct serval_udp_sock *usk = serval_udp_sk(sk); */
}

static int serval_udp_disconnect(struct sock *sk, int flags)
{
        LOG_DBG("\n");
        return 0;
}

static void serval_udp_shutdown(struct sock *sk, int how)
{
        LOG_DBG("\n");
}

int serval_udp_connection_request(struct sock *sk, 
                                  struct request_sock *rsk,
                                  struct sk_buff *skb)
{
        return 0;
}

int serval_udp_connection_respond_sock(struct sock *sk, 
                                       struct sk_buff *skb,
                                       struct request_sock *rsk,
                                       struct sock *child,
                                       struct dst_entry *dst)
{
	serval_sk(sk)->af_ops = &serval_udp_af_ops;
	return 0;
}

static int serval_udp_do_rcv(struct sock *sk, struct sk_buff *skb)
{
        int err = 0;
        
        LOG_DBG("data len=%u skb->len=%u\n",
                ntohs(udp_hdr(skb)->len) - sizeof(struct udphdr), skb->len); 

        if (serval_udp_checksum_complete(skb)) {
                LOG_DBG("Checksum error, dropping.\n");
                kfree_skb(skb);
                return 0;
        }

        /* Strip UDP header before queueing */
	skb_dst_drop(skb);
	__skb_pull(skb, sizeof(struct udphdr));

        /* 
           sock_queue_rcv_skb() will increase readable memory (i.e.,
           decrease free receive buffer memory), do socket filtering
           and wake user process.
        */
        err = sock_queue_rcv_skb(sk, skb);

        if (err < 0) {
                /* Increase error statistics. These are standard
                 * macros defined for standard UDP. */
                if (err == -ENOMEM) {
                        /* TODO: statistics */
                }
                kfree_skb(skb);
        }

        return err;
}

/* 
   Receive from network.
*/
int serval_udp_rcv(struct sock *sk, struct sk_buff *skb)
{
        struct udphdr *uh = udp_hdr(skb);
        int ret = 0;

   	/*
	 *  Validate the packet.
	 */

        if (!(SAL_SKB_CB(skb)->flags & SVH_FIN)) { 
                unsigned short datalen = ntohs(uh->len) - sizeof(*uh);
                
                if (!pskb_may_pull(skb, sizeof(struct udphdr)))
                        goto drop;		
                
                /* Only ignore this message in case it has zero length and is
                      * not a FIN */
                if (datalen == 0) 
                        goto drop;
        }
        
        if (serval_udp_csum_init(skb, uh, IPPROTO_UDP))
                goto drop;

        /* Drop if receive queue is full. Dropping due to full queue
         * is done below in sock_queue_rcv for those kernel versions
         * that do not define this sk_rcvqueues_full().  */
   
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0))
        if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf)) {
                goto drop;
        }
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
        if (sk_rcvqueues_full(sk, skb)) {
                goto drop;
        }
#endif
        if (!sock_owned_by_user(sk)) {
                ret = serval_udp_do_rcv(sk, skb);
        } else {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0))
                if (sk_add_backlog(sk, skb, sk->sk_rcvbuf))
                        goto drop;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
                if (sk_add_backlog(sk, skb)) {
                        goto drop;
                }
#else
                sk_add_backlog(sk, skb);
#endif
        }
        return ret;
 drop:
        kfree_skb(skb);
        return -1;
}

static int serval_udp_sendmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg, size_t len)
{
        int err;
        struct sk_buff *skb;
        struct service_id *srvid = NULL;
        struct net_addr *netaddr = NULL;
        int nonblock = msg->msg_flags & MSG_DONTWAIT;
        long timeo;

	if (len > 0xFFFF)
		return -EMSGSIZE;

        if (len == 0)
                return -EINVAL;

	if (msg->msg_flags & MSG_OOB) 
		return -EOPNOTSUPP;

	if (msg->msg_name) {
		struct sockaddr_sv *svaddr = (struct sockaddr_sv *)msg->msg_name;
                struct sockaddr_in *inaddr = (struct sockaddr_in *)(svaddr + 1);

		if ((unsigned)msg->msg_namelen < sizeof(*svaddr))
			return -EINVAL;

		if (svaddr->sv_family != AF_SERVAL) {
			if (svaddr->sv_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}
                
                srvid = &svaddr->sv_srvid;

                /* Check for advisory IP address */
                LOG_DBG("dest sid: %s, sock addr len: %i\n",
                        service_id_to_str(&svaddr->sv_srvid), 
                        msg->msg_namelen);

                if ((unsigned)msg->msg_namelen >=
                    (sizeof(*svaddr) + sizeof(*inaddr))) {

                        if (inaddr->sin_family != AF_INET)
                                return -EAFNOSUPPORT;
#if defined(ENABLE_DEBUG)
                        {
                                char buf[20];
                                LOG_DBG("Advisory IP %s\n",
                                        inet_ntop(inaddr->sin_family,
                                                  &inaddr->sin_addr,
                                                  buf, sizeof(buf)));
                        }
#endif
                        netaddr = (struct net_addr *)&inaddr->sin_addr;
                }
        } else if (sk->sk_state != SAL_CONNECTED) {
                return -EDESTADDRREQ;
        }

        lock_sock(sk);

	timeo = sock_sndtimeo(sk, nonblock);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & SALF_REQUEST)
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
                        goto out;

        skb = sock_alloc_send_skb(sk, sk->sk_prot->max_header + len, 
                                  nonblock, &err);

        if (!skb)
                goto out;
        
        skb_reserve(skb, sk->sk_prot->max_header);

        if (srvid) {
                memcpy(&serval_sk(sk)->peer_srvid, srvid, sizeof(*srvid));
        }
        if (netaddr) {
                memcpy(&inet_sk(sk)->inet_daddr, netaddr, sizeof(*netaddr));
        }

        err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
     
        if (err < 0) {
                LOG_ERR("could not copy user data to skb\n");
                kfree_skb(skb);
                goto out;
        }

        err = serval_udp_transmit_skb(sk, skb);
        
        if (err < 0) {
                LOG_ERR("xmit failed err=%d\n", err);
        } else 
                err = len;
 out:
        release_sock(sk);

        return err;
}

static int serval_udp_recvmsg(struct kiocb *iocb, struct sock *sk, 
                              struct msghdr *msg, size_t len, int nonblock, 
                              int flags, int *addr_len)
{
        struct sockaddr_sv *svaddr = (struct sockaddr_sv *)msg->msg_name;
        int retval = -ENOMEM;
	long timeo;
        
        lock_sock(sk);

        if (sk->sk_state == SAL_CLOSED) {
                /* SAL_CLOSED is a valid state here because recvmsg
                 * should return 0 and not an error */
		retval = -ENOTCONN;
		goto out;
	}

        if ((unsigned)msg->msg_namelen < sizeof(struct sockaddr_sv)) {
                retval = -EINVAL;
                LOG_DBG("address length is incorrect\n");
                goto out;
        }

	timeo = sock_rcvtimeo(sk, nonblock);

	do {                
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

		if (skb)
			goto found_ok_skb;
	
                if (sk->sk_err) {
                        retval = sock_error(sk);
                        LOG_ERR("sk=%p error=%d\n",
                                sk, retval);
                        break;
                }

                if (sk->sk_shutdown & RCV_SHUTDOWN) {
                        retval = 0;
                        break;
                }

		if (sk->sk_state == SAL_CLOSED) {
			if (!sock_flag(sk, SOCK_DONE)) {
				retval = -ENOTCONN;
				break;
			}
                        
                        retval = 0;
			break;
		}
                
		if (!timeo) {
			retval = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			retval = sock_intr_errno(timeo);
			LOG_DBG("signal pending failed here\n");
			break;
		}

                sk_wait_data(sk, &timeo);
		continue;
	found_ok_skb:
                if (SAL_SKB_CB(skb)->flags & SVH_FIN) {
                        retval = 0;
                        goto found_fin_ok;
                }

		if (len >= skb->len) {
			retval = skb->len;
                        len = skb->len;
                } else if (len < skb->len) {
			msg->msg_flags |= MSG_TRUNC;
                        retval = len;
                }
                
                /* Copy service id */
                if (svaddr) {
                        size_t addrlen = msg->msg_namelen;

                        memset(svaddr, 0, addrlen);
                        svaddr->sv_family = AF_SERVAL;
                        *addr_len = sizeof(*svaddr);
                        
                        if (SAL_SKB_CB(skb)->srvid) {
                                memcpy(&svaddr->sv_srvid, 
                                       SAL_SKB_CB(skb)->srvid,
                                       sizeof(svaddr->sv_srvid));
                        }
                        /* Copy also IP address if possible */
                        if (addrlen >= (sizeof(*svaddr) +
                                        sizeof(struct sockaddr_in))) {
                                struct sockaddr_in *inaddr =
                                        (struct sockaddr_in *)(svaddr + 1);
                                inaddr->sin_family = AF_INET;
                                memcpy(&inaddr->sin_addr, &ip_hdr(skb)->saddr,
                                       sizeof(ip_hdr(skb)->saddr));
                                *addr_len += sizeof(*inaddr);
                        }
                }
                                
		if (skb_copy_datagram_iovec(skb, 0, msg->msg_iov, len)) {
			/* Exception. Bailout! */
			retval = -EFAULT;
                        LOG_DBG("could not copy data, len=%zu\n", len);
			break;
		}
        found_fin_ok:
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, 0);
                        /*
                          Only for stream-based memory accounting? 
                        sk_mem_reclaim_partial(sk);
                        */
                }
		break;
	} while (1);
 out:
        release_sock(sk);
        return retval;
}

#if defined(OS_LINUX_KERNEL) && defined(ENABLE_SPLICE)
/*
 * UDP splice context
 */
struct udp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *,
                               unsigned int, size_t);

static int serval_udp_splice_data_recv(read_descriptor_t *rd_desc, 
                                       struct sk_buff *skb,
                                       unsigned int offset, size_t len)
{
	struct udp_splice_state *tss = rd_desc->arg.data;
	int ret;

	ret = skb_splice_bits(skb, offset, tss->pipe,
                              min(rd_desc->count, len), tss->flags);
	if (ret > 0)
		rd_desc->count -= ret;
	return ret;
}

/*
 * This routine provides an alternative to serval_udp_recvmsg() for
 * routines that would like to handle copying from skbuffs directly in
 * 'sendfile' fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int serval_udp_read_sock(struct sock *sk, read_descriptor_t *desc,
                         sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	int retval = 0;

	if (sk->sk_state == SAL_LISTEN)
		return -ENOTCONN;

        skb = skb_peek(&sk->sk_receive_queue);
        
        if (!skb)
                return 0;
        
        if (SAL_SKB_CB(skb)->flags & SVH_FIN) {
                retval = 0;
        } else {
                retval = recv_actor(desc, skb, 0, skb->len);
                
                //skb = skb_peek(&sk->sk_receive_queue);
                /*
                 * If recv_actor drops the lock (e.g. TCP splice
                 * receive) the skb pointer might be invalid when
                 * getting here: tcp_collapse might have deleted it
                 * while aggregating skbs from the socket queue.
                 */
        }
        sk_eat_skb(sk, skb, 0);

	return retval;
}

static int __serval_udp_splice_read(struct sock *sk,
                                    struct udp_splice_state *tss)
{
	/* Store TCP splice context information in read_descriptor_t. */
	read_descriptor_t rd_desc = {
		.arg.data = tss,
		.count	  = tss->len,
	};

	return serval_udp_read_sock(sk, &rd_desc, serval_udp_splice_data_recv);
}

/**
 *  serval_udp_splice_read - splice data from DGRAM socket to a pipe
 * @sock:	socket to splice from
 * @ppos:	position (not valid)
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given socket and fill them into a pipe.
 *
 **/
ssize_t serval_udp_splice_read(struct socket *sock, loff_t *ppos,
                               struct pipe_inode_info *pipe, size_t len,
                               unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct udp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	long timeo;
	ssize_t spliced;
	int ret;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
	sock_rps_record_flow(sk);
#endif
	/*
	 * We can't seek on a socket input
	 */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, sock->file->f_flags & O_NONBLOCK);

	while (tss.len) {
		ret = __serval_udp_splice_read(sk, &tss);
		if (ret < 0)
			break;
		else if (!ret) {
			if (spliced)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == SAL_CLOSED) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				if (!sock_flag(sk, SOCK_DONE))
					ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;

		if (!timeo)
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == SAL_CLOSED ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);
        /*
          LOG_DBG("spliced=%zu ret=%d\n", spliced, ret);
        */
	if (spliced)
		return spliced;

	return ret;
}

static ssize_t serval_udp_do_sendpages(struct sock *sk, struct page **pages, 
                                       int poffset, size_t psize, int flags)
{
	int err;
	ssize_t copied = 0;
        int nonblock = flags & MSG_DONTWAIT;
	long timeo = sock_sndtimeo(sk, nonblock);

        if (sk->sk_state == SAL_INIT) {
                err = -ENOTCONN;
                goto out_err;
        }

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & (SALF_REQUEST))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

        if (psize > 0xffff) {
                LOG_ERR("Too much data\n");
                err = -ENOMEM;
                goto out_err;
        }
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	err = -EPIPE;

	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

        /*
          This code is adapted from do_tcp_sendpages and is currently
          very much experimental. This needs some serious cleanups
          before ready.
        */
	while (psize > 0) {
		struct sk_buff *skb;
		struct page *page = pages[poffset / PAGE_SIZE];
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

                skb = alloc_skb_fclone(sk->sk_prot->max_header, GFP_ATOMIC);

                if (!skb) {
                        goto out_err;
                }

                skb_reserve(skb, sk->sk_prot->max_header);
                
                /* Make sure we zero this address to signal it is unset */
                get_page(page);
                skb_fill_page_desc(skb, 0, page, offset, size);
                skb->len += size;
                skb->data_len += size;
                skb->truesize += size;
		skb->ip_summed = CHECKSUM_NONE;
		skb_shinfo(skb)->gso_segs = 0;
                skb_set_owner_w(skb, sk);
                copied += size;
		poffset += size;
                
                /* FIXME: we only handle one page at this time... Must
                 * really clean up this code. */

                err = serval_udp_transmit_skb(sk, skb);
                
                if (err < 0) {
                        LOG_ERR("xmit failed err=%d\n", err);
                }
                break;
	}

        return copied;
 out_err:
        LOG_ERR("Error\n");
	return sk_stream_error(sk, flags, err);
}

int serval_udp_sendpage(struct sock *sk, struct page *page, int offset,
                            size_t size, int flags)
{
	ssize_t res;

	if (!(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & NETIF_F_ALL_CSUM))
		return sock_no_sendpage(sk->sk_socket, page, 
                                        offset, size, flags);

	lock_sock(sk);
	res = serval_udp_do_sendpages(sk, &page, offset, size, flags);
	release_sock(sk);
        
	return res;
}
#endif /* ENABLE_SPLICE */

static void serval_udp_request_sock_destructor(struct request_sock *rsk)
{
}

static int serval_udp_setsockopt(struct sock *sk, int level, int optname, 
                                 char __user *optval, unsigned int optlen)
{
#if defined(OS_LINUX_KERNEL)
        struct serval_sock *ssk = serval_sk(sk);
        
	if (level != IPPROTO_UDP)
		return ssk->af_ops->setsockopt(sk, level, optname,
                                               optval, optlen);
#endif
        return -EOPNOTSUPP;
}

static int serval_udp_getsockopt(struct sock *sk, int level, 
                                 int optname, char __user *optval,
                                 int __user *optlen)
{
#if defined(OS_LINUX_KERNEL)
        struct serval_sock *ssk = serval_sk(sk);

	if (level != IPPROTO_UDP)
		return ssk->af_ops->getsockopt(sk, level, optname,
                                               optval, optlen);
#endif
        return -EOPNOTSUPP;
}


struct request_sock_ops udp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct serval_request_sock),
        .destructor     =       serval_udp_request_sock_destructor,
};

struct proto serval_udp_proto = {
	.name			= "SERVAL_UDP",
	.owner			= THIS_MODULE,
        .init                   = serval_udp_init_sock,
        .destroy                = serval_udp_destroy_sock,
	.close  		= serval_sal_close,   
        .connect                = serval_sal_connect,
	.disconnect 		= serval_udp_disconnect,
	.shutdown		= serval_udp_shutdown,
#if defined(OS_LINUX_KERNEL) && defined(ENABLE_SPLICE)
        .sendpage               = serval_udp_sendpage,
#endif
        .sendmsg                = serval_udp_sendmsg,
        .recvmsg                = serval_udp_recvmsg,
        .getsockopt             = serval_udp_getsockopt,
        .setsockopt             = serval_udp_setsockopt,
	.backlog_rcv		= serval_udp_do_rcv,
        .hash                   = serval_sock_hash,
        .unhash                 = serval_sock_unhash,
	.max_header		= MAX_SERVAL_UDP_HDR,
	.obj_size		= sizeof(struct serval_udp_sock),
	.rsk_prot		= &udp_request_sock_ops,
};

/*
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
#include "serval_sal.h"
#include "af_serval.h"
#include "serval_udp.h"

/* payload + LL + IP + UDP */
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

static void serval_udp_v4_send_check(struct sock *sk, struct sk_buff *skb)
{
	/* These addresses don't make sense in XIA. */
	const __be32 saddr = 0;
	const __be32 daddr = 0;

	struct udphdr *uh = udp_hdr(skb);
	unsigned long len = skb_tail_pointer(skb) - skb_transport_header(skb);

	skb->ip_summed = CHECKSUM_NONE;
	uh->check = 0;
	uh->check = csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP,
				      csum_partial(uh, len, 0));
}

/* For connected UDP we do nothing more for the SYN than adding an
 * empty header. This is needed for checksumming to work.
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

static int serval_udp_build_synack(struct sock *sk, struct dst_entry *dst,
	struct request_sock *req, struct sk_buff *skb)
{
	return serval_udp_build_syn(sk, skb);
}

static int serval_udp_build_ack(struct sock *sk, struct sk_buff *skb)
{
	return serval_udp_build_syn(sk, skb);
}

static struct serval_sock_af_ops serval_udp_af_ops = {
	.setsockopt = ip_setsockopt,
	.getsockopt = ip_getsockopt,
	.conn_build_syn = serval_udp_build_syn,
	.conn_build_synack = serval_udp_build_synack,
	.conn_build_ack = serval_udp_build_ack,
	.send_check = serval_udp_v4_send_check,
	.receive = serval_udp_rcv,
	.net_header_len = SAL_NET_HEADER_LEN,
	.conn_request = serval_udp_connection_request,
	.conn_child_sock = serval_udp_connection_respond_sock,
};

static int serval_udp_transmit_skb(struct sock *sk, struct sk_buff *skb)
{
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

	return serval_sal_xmit_skb(skb);
}

static int serval_udp_init_sock(struct sock *sk)
{
	struct serval_sock *ssk = sk_ssk(sk);

	/* Initialize serval sock part of socket. */
	serval_sock_init(ssk);
	serval_sock_init_seeds(ssk);

	ssk->af_ops = &serval_udp_af_ops;
	return 0;
}

static void serval_udp_destroy_sock(struct sock *sk)
{
	/* struct serval_udp_sock *usk = serval_udp_sk(sk); */
}

static int serval_udp_disconnect(struct sock *sk, int flags)
{
	return 0;
}

static int serval_udp_connection_request(struct sock *sk,
	struct request_sock *rsk, struct sk_buff *skb)
{
	return 0;
}

static int serval_udp_connection_respond_sock(struct sock *sk,
	struct sk_buff *skb, struct request_sock *rsk, struct sock *child,
	struct dst_entry *dst)
{
	sk_ssk(child)->af_ops = &serval_udp_af_ops;
	return 0;
}

static int serval_udp_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	int err = 0;

	if (serval_udp_checksum_complete(skb)) {
		/* Checksum error, dropping. */
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
			/* XXX: statistics */
		}
		kfree_skb(skb);
	}

	return err;
}

/*
   Receive from network.
*/
static int serval_udp_rcv(struct sock *sk, struct sk_buff *skb)
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

	/* Drop if receive queue is full. */
	if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf))
		goto drop;

	if (!sock_owned_by_user(sk))
		ret = serval_udp_do_rcv(sk, skb);
	else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf))
			goto drop;
	return ret;

drop:
	kfree_skb(skb);
	return -1;
}

static int serval_udp_sendmsg(struct kiocb *iocb, struct sock *sk,
			      struct msghdr *msg, size_t len)
{
	struct sk_buff *skb;
	struct xia_row *dest;
	struct xip_dst *xdst = NULL;
	struct xia_sock *xia = NULL;
	int nonblock = msg->msg_flags & MSG_DONTWAIT;
	int rc, dest_n;
	u8 dest_last_node;

	if (len > 0xFFFF)
		return -EMSGSIZE;

	if (len == 0)
		return -EINVAL;

	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_xia *, addr, msg->msg_name);
		rc = check_sockaddr_xia((struct sockaddr *)addr,
			msg->msg_namelen);
		if (rc)
			return rc;
		rc = check_type_of_all_sinks(addr, XIDTYPE_SRVCID);
		if (rc < 0)
			return rc;
		dest_n = rc;
		dest = addr->sxia_addr.s_row;
		dest_last_node = XIA_ENTRY_NODE_INDEX;

		xdst = xip_mark_addr_and_get_dst(sock_net(sk), dest, dest_n,
			&dest_last_node, 0);
		if (IS_ERR(xdst))
			return PTR_ERR(xdst);
	} else if (sk->sk_state != SAL_CONNECTED) {
		return -EDESTADDRREQ;
	}

	lock_sock(sk);

	if ((1 << sk->sk_state) & SALF_REQUEST) {
		long timeo = sock_sndtimeo(sk, nonblock);
		/* Wait for a connection to finish. */
		if ((rc = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto xdst;
	}

	skb = sock_alloc_send_skb(sk, sk->sk_prot->max_header + len,
		nonblock, &rc);
	if (!skb)
		goto xdst;
	skb_reserve(skb, sk->sk_prot->max_header);
	rc = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if (rc < 0) {
		/* Could not copy user data to skb. */
		goto skb;
	}

	if (xdst) {
		/* XXX This is so ugly! The socket isn't connected and
		 * now it's locked just to pass information to compose
		 * the packet.
		 * Not to mention that we're using field @ssk->xia_sk.xia_daddr
		 * that is expect to have a FlowID instead of a ServiceID.
		 */
		xia = xia_sk(sk);
		__xia_set_dest(xia, dest, dest_n, dest_last_node, xdst);
	}

	rc = serval_udp_transmit_skb(sk, skb);
	if (xdst)
		xia_reset_dest(xia);
	if (rc >= 0)
		rc = len;
	goto out;

skb:
	kfree_skb(skb);
xdst:
	if (xdst)
		xdst_put(xdst);
out:
	release_sock(sk);
	return rc;
}

static int serval_udp_recvmsg(struct kiocb *iocb, struct sock *sk,
			      struct msghdr *msg, size_t len, int nonblock,
			      int flags, int *addr_len)
{
	DECLARE_SOCKADDR(struct sockaddr_xia *, sxia, msg->msg_name);
	int retval = -ENOMEM;
	long timeo;

	if (addr_len)
		*addr_len = sizeof(*sxia);

	if ((unsigned)msg->msg_namelen < sizeof(*sxia)) {
		/* Address length is incorrect. */
		return -EINVAL;
	}

	lock_sock(sk);

	if (sk->sk_state == SAL_CLOSED) {
		/* SAL_CLOSED is a valid state here because recvmsg
		 * should return 0 and not an error.
		 */
		retval = -ENOTCONN;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, nonblock);

	do {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

		if (skb)
			goto found_ok_skb;

		if (sk->sk_err) {
			retval = sock_error(sk);
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

		/* Return source address. */
		if (sxia) {
			const struct xiphdr *xiph = xip_hdr(skb);
			copy_n_and_shade_sockaddr_xia(sxia,
				&xiph->dst_addr[xiph->num_dst], xiph->num_src);
		}

		if (skb_copy_datagram_iovec(skb, 0, msg->msg_iov, len)) {
			/* Exception. Bailout! */
			retval = -EFAULT;
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

#if defined(ENABLE_SPLICE)
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
static int serval_udp_read_sock(struct sock *sk, read_descriptor_t *desc,
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

		/* skb = skb_peek(&sk->sk_receive_queue); */
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

	sock_rps_record_flow(sk);

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

	return spliced ? spliced : ret;
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
		/* Too much data. */
		err = -ENOMEM;
		goto out_err;
	}
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	err = -EPIPE;

	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	/* XXX This code is adapted from do_tcp_sendpages and is currently
	 * very much experimental. This needs some serious cleanups
	 * before ready.
	 */
	while (psize > 0) {
		struct sk_buff *skb;
		struct page *page = pages[poffset / PAGE_SIZE];
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

		skb = alloc_skb_fclone(sk->sk_prot->max_header, GFP_ATOMIC);

		if (!skb)
			goto out_err;

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

		/* XXX We only handle one page at this time.
		 * Must really clean up this code.
		 */

		err = serval_udp_transmit_skb(sk, skb);
		break;
	}

	return copied;

out_err:
	return sk_stream_error(sk, flags, err);
}

static int serval_udp_sendpage(struct sock *sk, struct page *page, int offset,
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
	struct serval_sock *ssk = sk_ssk(sk);

	if (level != IPPROTO_UDP)
		return ssk->af_ops->setsockopt(sk, level, optname,
					       optval, optlen);
	return -EOPNOTSUPP;
}

static int serval_udp_getsockopt(struct sock *sk, int level,
				 int optname, char __user *optval,
				 int __user *optlen)
{
	struct serval_sock *ssk = sk_ssk(sk);

	if (level != IPPROTO_UDP)
		return ssk->af_ops->getsockopt(sk, level, optname,
					       optval, optlen);
	return -EOPNOTSUPP;
}

static struct request_sock_ops udp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct serval_request_sock),
	.destructor     =       serval_udp_request_sock_destructor,
};

struct proto serval_udp_proto = {
	.name			= "Serval/UDP",
	.owner			= THIS_MODULE,
	.init			= serval_udp_init_sock,
	.destroy		= serval_udp_destroy_sock,
	.close			= serval_sal_close,
	.connect		= serval_sal_connect,
	.disconnect		= serval_udp_disconnect,
#if defined(ENABLE_SPLICE)
	.sendpage		= serval_udp_sendpage,
#endif
	.sendmsg		= serval_udp_sendmsg,
	.recvmsg		= serval_udp_recvmsg,
	.getsockopt	     = serval_udp_getsockopt,
	.setsockopt	     = serval_udp_setsockopt,
	.bind			= serval_sock_bind,
	.backlog_rcv		= serval_udp_do_rcv,
	.unhash		 = serval_sock_unhash,
	.max_header		= MAX_SERVAL_UDP_HDR,
	.obj_size		= sizeof(struct serval_udp_sock),
	.rsk_prot		= &udp_request_sock_ops,
};

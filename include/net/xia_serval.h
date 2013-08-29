#ifndef _NET_XIA_SERVAL_H
#define _NET_XIA_SERVAL_H

#include <net/xia.h>

/* Serval's principal types */
#define XIDTYPE_SRVCID (__cpu_to_be32(0x18))
#define XIDTYPE_FLOWID (__cpu_to_be32(0x19))

/* XXX This struct should go away and become just an XID. */
struct service_id {
	__u8 s_sid[XIA_XID_MAX];
};

/* XXX This struct should go away and become just an XID. */
struct flow_id {
	__u8 s_id[XIA_XID_MAX];
};

#define SAL_NONCE_SIZE 8

/* TCP states from net/tcp_states.h, should be as compatible as possible.
 *
 *	TCP_ESTABLISHED = 1,
 *	TCP_SYN_SENT,
 *	TCP_SYN_RECV,
 *	TCP_FIN_WAIT1,
 *	TCP_FIN_WAIT2,
 *	TCP_TIME_WAIT,
 *	TCP_CLOSE,
 *	TCP_CLOSE_WAIT,
 *	TCP_LAST_ACK,
 *	TCP_LISTEN,
 *	TCP_CLOSING,
 *	TCP_MAX_STATES	
 */
enum {
	__SAL_MIN_STATE = 0,
	SAL_INIT = __SAL_MIN_STATE,
	SAL_CONNECTED,
	SAL_REQUEST,
	SAL_RESPOND,
	SAL_FINWAIT1,
	SAL_FINWAIT2,
	SAL_TIMEWAIT,
	SAL_CLOSED,
	SAL_CLOSEWAIT,
	SAL_LASTACK,
	SAL_LISTEN,
	SAL_CLOSING,
	__SAL_MAX_STATE
};

enum {
	SALF_CONNECTED = (1 << 1),
	SALF_REQUEST   = (1 << 2),
	SALF_RESPOND   = (1 << 3),
	SALF_FINWAIT1  = (1 << 4),
	SALF_FINWAIT2  = (1 << 5),
	SALF_TIMEWAIT  = (1 << 6),
	SALF_CLOSED    = (1 << 7),
	SALF_CLOSEWAIT = (1 << 8),
	SALF_LASTACK   = (1 << 9),
	SALF_LISTEN    = (1 << 10),
	SALF_CLOSING   = (1 << 11),
};

#ifdef __KERNEL__

#include <linux/string.h>
#include <net/request_sock.h>
#include <net/xia_socket.h>
#include <net/xia_fib.h>

#define SOCK_TYPE		0
#define REQUEST_SOCK_TYPE	1

/* Connection handshake:
 *
 * Client	  SYN		Server	Src: ServiceID_Client
 *		------>			Dst: ServiceID_Server
 * WHY: 
 *	ServiceID_Client is going to be the signature the client will use
 *	for future control operations. It also lets the server know
 *	ServiceID_Client that otherwise wouldn't be known.
 *	ServiceID_Server is the listening, late binding identifier.
 *
 * Client	SYN+ACK		Server	Src: FlowID_Server
 *		<------			Dst: ServiceID_Client
 * WHY:
 *	FlowID_Server lets the client know the chosen instance of
 *	ServiceID_Server.
 *	ServiceID_Client is what we know about the client.
 *
 * Client	  ACK		Server	Src: FlowID_Client
 *		------>			Dst: FlowID_Server
 * WHY:
 *	FlowID_Client lets the server know the chosen instance of
 *	ServiceID_Client.
 *	FlowID_Server is used to choose the correct request socket sitting at
 *	the SYN queue connects, and to bind the FlowID of the new socket that
 *	is going to be created.
 */
struct serval_sock {
	/* struct xia_sock must be the first member to work with sk_alloc(). */
	struct xia_sock		xia_sk;

	/* FIB XID related fields for ServiceID. */
	struct fib_xid		srvc_fxid;
	struct xip_dst_anchor   srvc_anchor;

	/* FIB XID related fields for FlowID.
	 *
	 * The local FlowID is in field @flow_fxid.fx_xid when
	 * @local_flowid_set is true.
	 *
	 * In other to obtain the full address, one has to replace
	 * the single sink in @xia_sk.xia_saddr with the local FlowID.
	 */
	struct fib_xid		flow_fxid;
	struct xip_dst_anchor   flow_anchor;

	/* Hold the full address to the peer's ServiceID.
	 *
	 * This address is not always derivable from the peer's FlowID one,
	 * and vice versa. The latter has a FlowID as its sink to
	 * a given service instance, whereas @peer_srvc_addr is the address to
	 * bind/chose an instance.
	 */
	struct xia_addr		peer_srvc_addr;
	/* If @peer_srvc_set is true, fields @peer_srvc_* have valid values. */
	u8			peer_srvc_set;
	/* Number of nodes in @peer_srvc_addr. */
	u8			peer_srvc_num;
	/* Index of the last node of @peer_srvc_addr. */
	u8			peer_srvc_last_node;
	/* 1 free byte. */
	/* The XIP DST that fowards toward @peer_srvc_addr. */
	struct xip_dst		*peer_srvc_xdst;

        int                     mig_dev_if;
        u32                     mig_daddr;

	/* 1 free byte. */
        /* SAL state, used for, e.g., migration */
	u8			sal_state;
	/* If @local_srvcid_hashed is true, @srvc_fxid is hashed. */
	u8			local_srvcid_hashed;
	/* If @local_flowid_hashed is true, @flow_fxid is hashed. */
	u8			local_flowid_hashed;

        struct serval_sock_af_ops *af_ops;
 	struct timer_list	retransmit_timer;        
	struct timer_list	tw_timer;
	/* XXX There must be a timer to clean up this queue, otherwise
	 * malicious SYN packets can clog a listening socket.
	 */
        struct list_head        syn_queue;
        struct list_head        accept_queue;
	struct sk_buff          *ctrl_queue;
	struct sk_buff		*ctrl_send_head;
        u8                      local_nonce[SAL_NONCE_SIZE];
        u8                      peer_nonce[SAL_NONCE_SIZE];
        struct {
                u32        una;
                u32        nxt;
                u32        wnd;
                u32        iss;
        } snd_seq;	/* SeND SEQuence. */
        struct {
                u32        nxt;
                u32        wnd;
                u32        iss;
        } rcv_seq;	/* ReCeiVe SEQuence. */
	/* timestamp of last received packet */
        u32	                last_rcv_tstamp;
        u8                      retransmits;
        u8                      backoff;
        /* 2 bytes free. */
        u32                     rto; /* Retransmission timeout in jiffies. */
        u32                     srtt;
	u32                     mdev;  /* medium deviation */
	/* maximal mdev for the last rtt period */
	u32                     mdev_max;
	u32                     rttvar;	/* smoothed mdev_max */
	u32                     rtt_seq; /* sequence number to update rttvar */
};

static inline struct serval_sock *xiask_ssk(struct xia_sock *xia)
{
	return likely(xia)
		? container_of(xia, struct serval_sock, xia_sk)
		: NULL;
}

static inline struct serval_sock *srvc_fxid_ssk(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct serval_sock, srvc_fxid)
		: NULL;
}

static inline struct serval_sock *flow_fxid_ssk(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct serval_sock, flow_fxid)
		: NULL;
}

/* XXX Drop `const' given it's not real here due to the casts.
 * It'll require code change to avoid warnings.
 */
static inline struct serval_sock *sk_ssk(const struct sock *sk)
{
	return xiask_ssk(xia_sk(sk));
}

struct serval_request_sock {
	struct request_sock	req;

	/* Reference counting is important to avoid flushing @flow_anchor
	 * before an RCU cycle has passed.
	 */
	atomic_t		refcnt;

	/* Fields for local FlowID.
	 *
	 * The local FlowID is in field @srsk->flow_fxid.fx_xid
	 */
	struct fib_xid		flow_fxid;
	struct xip_dst_anchor   flow_anchor;

	/* XXX We should have the whole peer's address whose sink is a ServiceID
	 * because this address is the one that one would know that can be
	 * reached given that it's used in the SYN+ACK packet.
	 */
	struct service_id	peer_srvcid;

	u32 rcv_seq;
	u32 iss_seq;
	u8 local_nonce[SAL_NONCE_SIZE];
	u8 peer_nonce[SAL_NONCE_SIZE];

	struct serval_sock	*parent_ssk;
	struct list_head lh;
};

static inline struct serval_request_sock *serval_rsk(struct request_sock *rsk)
{
	return likely(rsk)
		? container_of(rsk, struct serval_request_sock, req)
		: NULL;
}

static inline struct serval_request_sock *flow_fxid_srsk(struct fib_xid *fxid)
{
	return likely(fxid)
		? container_of(fxid, struct serval_request_sock, flow_fxid)
		: NULL;
}

static inline void srsk_hold(struct serval_request_sock *srsk)
{
	atomic_inc(&srsk->refcnt);
}

void srsk_put(struct serval_request_sock *srsk);

/*
 *	Serval context
 */

struct xip_serval_ctx {
	struct xip_ppal_ctx	srvc;
	struct xip_ppal_ctx	flow;

	struct serval_tcpm_hash_bucket	*tcp_metrics_hash;
	int				tcp_metrics_hash_log;
};

static inline struct xip_serval_ctx *srvc_serval(struct xip_ppal_ctx *srvc)
{
	return likely(srvc)
		? container_of(srvc, struct xip_serval_ctx, srvc)
		: NULL;
}

static inline struct xip_serval_ctx *flow_serval(struct xip_ppal_ctx *flow)
{
	return likely(flow)
		? container_of(flow, struct xip_serval_ctx, flow)
		: NULL;
}

extern int srvc_vxt;
extern int flow_vxt;

/*
 *	Serval headers
 */

struct sal_hdr {
	/* SAL Header Length plus lenght of all extension headers present
	 * in number of 32-bit words.
	 */
        uint8_t  shl;

	/* XXX This field is not necessary, it can/should be inferred from
	 * the destination ServiceID or FlowID.
	 * The problem to remove is the call of
	 * serval_sal_update_transport_csum() in
	 * serval_sal.c:serval_sal_resolve_service().
	 */
        uint8_t  protocol;

        uint16_t check;
};

/* Generic extension header */
struct sal_ext {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	res:4,
		type:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	type:4,
                res:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        uint8_t length;
};

/* These defines can be used for convenient access to the fields in
 * the base extension in extensions below.
 */
#define ext_type	exthdr.type
#define ext_length	exthdr.length
#define ext_res		exthdr.res

#define SAL_EXT_FIRST(sh) ((struct sal_ext *) \
	((char *)sh + sizeof(struct sal_hdr)))

#define SAL_EXT_NEXT(ext) ((struct sal_ext *)((char *)ext + ext->length))

enum sal_ext_type {
	SAL_CONTROL_EXT = 0,
	__SAL_EXT_TYPE_MAX,
};

struct sal_control_ext {
        struct sal_ext exthdr;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	res1:2,
                fin:1,
                rst:1,
                nack:1,
                ack:1,
                rsyn:1,
		syn:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	syn:1,
                rsyn:1,
  		ack:1,
                nack:1,
                rst:1,
                fin:1,
                res1:2;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        uint8_t  res2;
        uint32_t verno; /* Version number of control information. */
        uint32_t ackno; /* Acknowledgement number of control information. */
        uint8_t  nonce[SAL_NONCE_SIZE];
};

/* XXX Does one need this function? */
static inline void serval_sock_set_mig_dev(struct sock *sk, int ifindex)
{
	sk_ssk(sk)->mig_dev_if = ifindex;
}

/* Functions to be used to set up an struct proto. */
int serval_sock_bind(struct sock *sk, struct sockaddr *uaddr, int node_n);
void serval_sock_unhash(struct sock *sk);

/*
 * Functions to write specific functions to set up an struct proto.
 */

void serval_sock_init(struct serval_sock *ssk);
void serval_sock_init_seeds(struct serval_sock *ssk);
void serval_sock_get_flowid(u8 *flowid);

/* This function is only meant to be used by non struct serval_sock that
 * need to be hashed like struct serval_request_sock.
 */
int __serval_sock_hash_flowid(struct net *net, struct fib_xid *fxid);

int serval_swap_srsk_ssk_flowid(struct fib_xid *cur_fxid,
	struct serval_sock *new_ssk);

void serval_sock_destroy(struct sock *sk);
void serval_sock_done(struct sock *sk);
int serval_listen_stop(struct sock *sk);

static inline void serval_sock_set_state(struct sock *sk, int new_state)
{
	if (__builtin_constant_p(new_state))
		BUILD_BUG_ON(new_state <= __SAL_MIN_STATE ||
			new_state >= __SAL_MAX_STATE);
	else
		BUG_ON(new_state <= __SAL_MIN_STATE ||
			new_state >= __SAL_MAX_STATE);
	sk->sk_state = new_state;
}

static inline void serval_sock_clear_xmit_timer(struct sock *sk)
{
	struct serval_sock *ssk = sk_ssk(sk);
	sk_stop_timer(sk, &ssk->retransmit_timer);
}

static inline void serval_sock_reset_xmit_timer(struct sock *sk,
	unsigned long when, const unsigned long max_when)
{
	struct serval_sock *ssk = sk_ssk(sk);

	if (when > max_when)
		when = max_when;
	sk_reset_timer(sk, &ssk->retransmit_timer, jiffies + when);
}

#endif /* __KERNEL__ */
#endif /* _NET_XIA_FIB_H */

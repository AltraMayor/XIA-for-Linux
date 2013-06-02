/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * The Service Access Layer (SAL).
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *          David Shue <dshue@cs.princeton.edu>
 *          Rob Kiefer <rkiefer@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <platform.h>
#include <debug.h>
#include <serval_sock.h>
#include <netdevice.h>
#include <serval_sal.h>
#include <serval_ipv4.h>
#include <netinet_serval.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_ipv4.h>
#include <net/route.h>
#include <net/ip.h>
#include <serval_request_sock.h>
#include <service.h>
#include <delay_queue.h>
#include <af_serval.h>

extern atomic_t serval_nr_socks;

int sysctl_sal_fin_timeout __read_mostly = SAL_FIN_TIMEOUT;
int sysctl_sal_keepalive_time __read_mostly = SAL_KEEPALIVE_TIME;
int sysctl_sal_keepalive_probes __read_mostly = SAL_KEEPALIVE_PROBES;
int sysctl_sal_keepalive_intvl __read_mostly = SAL_KEEPALIVE_INTVL;

static struct net_addr local_addr = {
        .net_raw = { 0x7F, 0x00, 0x00, 0x01 }
};

static struct net_addr zero_addr = {
        .net_raw = { 0x00, 0x00, 0x00, 0x00 }
};

#define MAX_NUM_SAL_EXTENSIONS 10 /* Includes padding */

/*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 * Taken from linux/net/tcp.h.
 */
static inline int before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}

#define after(seq2, seq1) 	before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

/* 
   Context for parsed Serval headers 
*/   
struct sal_context {
        struct sk_buff *skb;
        struct sal_hdr *hdr;
        unsigned short length; /* Total length of all headers */
        unsigned short flags;
        uint32_t verno; /* Version number of control information */
        uint32_t ackno; /* Acknowledgement number of control information */
        struct sal_ext *ext[MAX_NUM_SAL_EXTENSIONS];
        struct sal_control_ext *ctrl_ext;
        struct sal_address_ext *addr_ext;
        struct sal_service_ext *srv_ext[2];
        struct sal_source_ext *src_ext;
};

static int serval_sal_state_process(struct sock *sk,
                                    struct sk_buff *skb,
                                    struct sal_context *ctx);

static int serval_sal_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                                   int use_copy, gfp_t gfp_mask);

static size_t min_ext_length[] = {
        [SAL_PAD_EXT] = sizeof(struct sal_pad_ext),
        [SAL_CONTROL_EXT] = sizeof(struct sal_control_ext),
        [SAL_SERVICE_EXT] = sizeof(struct sal_service_ext),
        [SAL_ADDRESS_EXT] = sizeof(struct sal_address_ext),
        [SAL_SOURCE_EXT] = sizeof(struct sal_source_ext),
};

static size_t max_ext_length[] = {
        [SAL_PAD_EXT] = sizeof(struct sal_pad_ext),
        [SAL_CONTROL_EXT] = sizeof(struct sal_control_ext),
        [SAL_SERVICE_EXT] = sizeof(struct sal_service_ext),
        [SAL_ADDRESS_EXT] = sizeof(struct sal_address_ext),
        [SAL_SOURCE_EXT] = SAL_SOURCE_EXT_MAX_LEN,
};

#if defined(ENABLE_DEBUG)

static char* sal_ext_name[] = {
        [SAL_PAD_EXT] =     "PAD",
        [SAL_CONTROL_EXT] = "CONTROL",
        [SAL_SERVICE_EXT] = "SERVICE",
        [SAL_ADDRESS_EXT] = "ADDRESS",
        [SAL_SOURCE_EXT] =  "SOURCE",
};

static int print_base_hdr(struct sal_hdr *sh, char *buf, int buflen)
{
        return snprintf(buf, buflen,
                        "len=%u proto=%u src_fl=%s dst_fl=%s",
                        sh->shl << 2, sh->protocol,
                        flow_id_to_str(&sh->src_flowid), 
                        flow_id_to_str(&sh->dst_flowid));
}

static int print_base_ext(struct sal_ext *xt, char *buf, int buflen)
{
        return snprintf(buf, buflen, "%s length=%zu",
                        sal_ext_name[xt->type],
                        SAL_EXT_LEN(xt));
}

static int print_pad_ext(struct sal_ext *xt, char *buf, int buflen)
{
        return 0;
}

static int print_control_ext(struct sal_ext *xt, char *buf, int buflen)
{
        struct sal_control_ext *cxt = 
                (struct sal_control_ext *)xt;
        
        return snprintf(buf, buflen,
                        "SYN=%u RSYN=%u ACK=%u "
                        "NACK=%u FIN=%u RST=%u "
                        "verno=%u ackno=%u",
                        cxt->syn, cxt->rsyn, cxt->ack, 
                        cxt->nack, cxt->fin, cxt->rst, 
                        ntohl(cxt->verno),
                        ntohl(cxt->ackno));
}

static int print_service_ext(struct sal_ext *xt, char *buf, int buflen)
{
        struct sal_service_ext *sxt = 
                (struct sal_service_ext *)xt;
        
        return snprintf(buf, buflen,
                        "srvid=%s",
                        service_id_to_str(&sxt->srvid));
}

static int print_address_ext(struct sal_ext *xt, char *buf, int buflen)
{
        /* struct sal_address_ext *dxt = 
           (struct sal_address_ext *)xt; */
                
        return 0;
}

static int print_source_ext(struct sal_ext *xt, char *buf, int buflen)
{
        struct sal_source_ext *sxt = 
                (struct sal_source_ext *)xt;
        unsigned char *a = sxt->source;
        int n = SAL_SOURCE_EXT_NUM_ADDRS(sxt);
        char addr[18];
        int len = 0;

        while (n > 0) {
                len += snprintf(buf + len, buflen - len, "%s ",
                                inet_ntop(AF_INET, a, addr, 18));
                a += 4;
                n--;
        }
        if (len) {
                /* Remove trailing white space */
                buf[--len] = '\0';
        }
        return len;
}

typedef int (*print_ext_func_t)(struct sal_ext *, char *, int);

static print_ext_func_t print_ext_func[] = {
        [SAL_PAD_EXT] = &print_pad_ext,
        [SAL_CONTROL_EXT] = &print_control_ext,
        [SAL_SERVICE_EXT] = &print_service_ext,
        [SAL_ADDRESS_EXT] = &print_address_ext,
        [SAL_SOURCE_EXT] = &print_source_ext,
};

static int print_ext(struct sal_ext *xt, char *buf, int buflen)
{
        int len;
        
        len = snprintf(buf, buflen, "{");
        len += print_base_ext(xt, buf + len, buflen - len);
        len += snprintf(buf + len, buflen - len, " ");
        len += print_ext_func[xt->type](xt, buf + len, buflen - len);
        return snprintf(buf + len, buflen - len, "}") + len;
}

static const char *sal_hdr_to_str(struct sal_hdr *sh) 
{
#define HDR_BUFLEN 512
        static char buf[HDR_BUFLEN];
        int hdr_len = sh->shl << 2;
        struct sal_ext *ext;
        int len = 0;
        
        buf[len++] = '[';
        
        len += print_base_hdr(sh, buf + len, HDR_BUFLEN - len);
        
        if (len < (HDR_BUFLEN - 1)) {
                buf[len++] = ']';
                buf[len] = '\0';
        }
        
        hdr_len -= SAL_HEADER_LEN;
        ext = SAL_EXT_FIRST(sh);
                
        while (hdr_len > 0) {
                uint16_t ext_len = SAL_EXT_LEN(ext);

                if (ext->type >= __SAL_EXT_TYPE_MAX) {
                        LOG_DBG("Bad extension type (=%u)\n",
                                ext->type);
                        return buf;
                }
                
                if (ext_len < min_ext_length[ext->type] ||
                    ext_len > max_ext_length[ext->type]) {
                        LOG_DBG("Bad extension \'%s\' hdr_len=%d "
                                "ext->length=%u\n",
                                sal_ext_name[ext->type], 
                                hdr_len,
                                ext_len);
                        return buf;
                }

                len += print_ext(ext, buf + len, 
                                 HDR_BUFLEN - len);

                hdr_len -= ext_len;
                ext = SAL_EXT_NEXT(ext);
        }       

#if defined(ENABLE_DEBUG)
        if (hdr_len) {
                LOG_DBG("hdr_len=%d is not 0, bad header?\n",
                        hdr_len);
        }
#endif
        len += snprintf(buf + len, HDR_BUFLEN - len, "]");

        return buf;
}

#endif /* ENABLE_DEBUG */

static int parse_pad_ext(struct sal_ext *ext, 
                         uint16_t ext_len,
                         struct sk_buff *skb,
                         struct sal_context *ctx)
{
        return 1;
}


static int parse_control_ext(struct sal_ext *ext, 
                             uint16_t ext_len,
                             struct sk_buff *skb,
                             struct sal_context *ctx)
{
        if (ctx->ctrl_ext)
                return -1;
        
        ctx->ctrl_ext = (struct sal_control_ext *)ext;
        ctx->verno = ntohl(ctx->ctrl_ext->verno);
        ctx->ackno = ntohl(ctx->ctrl_ext->ackno);

        /* Parse flags */
        if (ctx->ctrl_ext->syn)
                ctx->flags |= SVH_SYN; 
        if (ctx->ctrl_ext->rsyn)
                ctx->flags |= SVH_RSYN;
        if (ctx->ctrl_ext->ack)
                ctx->flags |= SVH_ACK;
        if (ctx->ctrl_ext->nack)
                ctx->flags |= SVH_NACK;
        if (ctx->ctrl_ext->fin)
                ctx->flags |= SVH_FIN;
        if (ctx->ctrl_ext->rst)
                ctx->flags |= SVH_RST;

        return ext_len;
}

static int parse_service_ext(struct sal_ext *ext, 
                             uint16_t ext_len,
                             struct sk_buff *skb,
                             struct sal_context *ctx)
{
        if (ctx->srv_ext[0] && ctx->srv_ext[1])
                return -1;

        if (!ctx->srv_ext[0])
                ctx->srv_ext[0] = (struct sal_service_ext *)ext;
        else if (!ctx->srv_ext[1])
                ctx->srv_ext[1] = (struct sal_service_ext *)ext;
        else
                return -1;

        return ext_len;
}

static int parse_address_ext(struct sal_ext *ext, 
                             uint16_t ext_len,
                             struct sk_buff *skb,
                             struct sal_context *ctx)
{
        LOG_INF("Address extension support not implemented\n");
        return ext_len;
}


static int parse_source_ext(struct sal_ext *ext, 
                            uint16_t ext_len,
                            struct sk_buff *skb,
                            struct sal_context *ctx)
{
        /*
        int i;
        __u32 addr;
        */      
        if (ctx->src_ext)
                return -1;
        
        ctx->src_ext = (struct sal_source_ext *)ext;

        /* Should be two addresses minimum */
        if (SAL_SOURCE_EXT_NUM_ADDRS(ctx->src_ext) < 2) {
                LOG_ERR("less than two addresses\n");
                return -1;
        }

        /*
        dev_get_ipv4_addr(skb->dev, IFADDR_LOCAL, &addr);

        for (i = 0; i < SAL_SOURCE_EXT_NUM_ADDRS(ctx->src_ext); i++) {
                if (memcmp(SAL_SOURCE_EXT_GET_ADDR(ctx->src_ext, i),
                           &addr, sizeof(addr)) == 0) {
                        LOG_DBG("Our address already in SOURCE ext. Possible loop!\n");
                        return -1;
                }
        }
        */                  
        return ext_len;
}

typedef int (*parse_ext_func_t)(struct sal_ext *, 
                                uint16_t ext_len,
                                struct sk_buff *, 
                                struct sal_context *ctx);

static parse_ext_func_t parse_ext_func[] = {
        [SAL_PAD_EXT] = &parse_pad_ext,
        [SAL_CONTROL_EXT] = &parse_control_ext,
        [SAL_SERVICE_EXT] = &parse_service_ext,
        [SAL_ADDRESS_EXT] = &parse_address_ext,
        [SAL_SOURCE_EXT] = &parse_source_ext,
};

static inline int parse_ext(struct sal_ext *ext, struct sk_buff *skb,
                            struct sal_context *ctx)
{
        unsigned short ext_len = SAL_EXT_LEN(ext);

        if (ext->type >= __SAL_EXT_TYPE_MAX) {
                LOG_DBG("Bad extension type (=%u)\n",
                        ext->type);
                return -1;
        }
        if (ext_len < min_ext_length[ext->type]) {
                LOG_DBG("Bad extension \'%s\' length (=%u)\n",
                        sal_ext_name[ext->type], ext_len);
                return -1;
        }
        
        LOG_DBG("EXT %s length=%u\n",
                sal_ext_name[ext->type], 
                ext->type == SAL_PAD_EXT ? 1 : ext_len);

        return parse_ext_func[ext->type](ext, ext_len, skb, ctx);
}

enum sal_parse_mode {
        SAL_PARSE_BASE,
        SAL_PARSE_ALL,
};

/**
   Parse Serval header and all extension, doing basic sanity checks.

   Returns: 0 on success.
*/
static int serval_sal_parse_hdr(struct sk_buff *skb, 
                                struct sal_context *ctx,
                                enum sal_parse_mode mode)
{
        struct sal_ext *ext;
        unsigned int i = 0;
        int hdr_len;

        memset(ctx, 0, sizeof(struct sal_context));
        ctx->skb = skb;
        ctx->hdr = sal_hdr(skb);
        ctx->length = ctx->hdr->shl << 2;
        ext = SAL_EXT_FIRST(ctx->hdr);

        /* Sanity checks */
        if (ctx->length < SAL_HEADER_LEN) {
                LOG_ERR("Header length(=%u) too small\n", ctx->length);
                return -1;
        }

        /* Only base header parse, return */
        if (mode == SAL_PARSE_BASE)
                return 0;

        /* Parse extensions */
        hdr_len = ctx->length - SAL_HEADER_LEN;

        while (hdr_len > 0 && i < MAX_NUM_SAL_EXTENSIONS) {
                int ext_len = parse_ext(ext, skb, ctx);
                
                if (ext_len <= 0) {
                        LOG_ERR("Bad extension length=%d\n", ext_len);
                        return -1;
                }

                ctx->ext[i++] = ext;
                hdr_len -= ext_len;
                ext = SAL_EXT_NEXT(ext);
        }

        if (hdr_len != 0) {
                LOG_ERR("hdr_len=%d (should be 0)\n", hdr_len);
        }

        /* hdr_len should be zero if everything was OK */
        return hdr_len;
}

static inline int has_verno(struct sal_context *ctx)
{
        /* Real control packets are those with sequence numbers */
        if (ctx->ctrl_ext)
                return 1;
        return 0;
}

static inline int is_pure_data(struct sal_context *ctx)
{
        return ctx->flags == 0;
}

static inline int is_pure_ack(struct sal_context *ctx)
{
        if (!ctx->ctrl_ext)
                return 0;

        return ctx->ctrl_ext->ack && !ctx->ctrl_ext->fin && 
                !ctx->ctrl_ext->syn && !ctx->ctrl_ext->rsyn && 
                !ctx->ctrl_ext->rst;
}

static inline int has_service_extension(struct sal_context *ctx,
                                        int index)
{
        struct sal_service_ext *srv_ext = ctx->srv_ext[index];

        if (!srv_ext)
                return 0;
        
        if (ctx->length < 
            (sizeof(*ctx->hdr) + min_ext_length[SAL_SERVICE_EXT])) {
                LOG_PKT("No service extension, hdr_len=%u\n", 
                        ctx->length);
                return 0;
        }
        
        if (srv_ext->exthdr.type != SAL_SERVICE_EXT || 
            srv_ext->exthdr.length < 
            min_ext_length[SAL_SERVICE_EXT] ||
            srv_ext->exthdr.length > 
            max_ext_length[SAL_SERVICE_EXT]) {
                LOG_DBG("No service extension, bad extension type\n");
                return 0;
        }

        return 1;
}

static inline int has_service_extension_src(struct sal_context *ctx)
{
        return has_service_extension(ctx, 0);
}

static inline int has_service_extension_dst(struct sal_context *ctx)
{
        return has_service_extension(ctx, 1);
}

static inline int has_valid_verno(uint32_t seg_seq, struct sock *sk)
{        
        struct serval_sock *ssk = serval_sk(sk);
        int ret = 0;

        if (sk->sk_state == SAL_LISTEN ||
            sk->sk_state == SAL_REQUEST)
                return 1;

        if (!before(seg_seq, ssk->rcv_seq.nxt)) 
                ret = 1;

        if (ret == 0) {
                LOG_DBG("Invalid version number received=%u next=%u."
                        " Could be ACK though...\n",
                        seg_seq, ssk->rcv_seq.nxt);
        }
        return ret;
}

static inline int packet_has_transport_hdr(struct sk_buff *skb, 
                                           struct sal_hdr *sh)
{
        /* We might have pulled the serval header already. */
        if (sh && ((unsigned char *)sh == skb_transport_header(skb))) {
                LOG_DBG("skb->len=%u sal_length=%u\n", 
                        skb->len, sh->shl << 2);
                return skb->len > (sh->shl << 2);
        }
            
        LOG_DBG("skb->len=%u\n", skb->len);
        return skb->len > 0;
}

static inline int has_valid_control_extension(struct sock *sk, 
                                              struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);

        if (!ctx->ctrl_ext)
                return 0;

        /* Check for control extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (ctx->length < 
            (sizeof(*ctx->hdr) + min_ext_length[SAL_CONTROL_EXT])) {
                LOG_PKT("No control extension, hdr_len=%u\n", 
                        ctx->length);
                return 0;
        }
        
        if (ctx->ctrl_ext->ext_type != SAL_CONTROL_EXT ||
            ctx->ctrl_ext->ext_length != 
            min_ext_length[SAL_CONTROL_EXT]) {
                LOG_PKT("No control extension, bad extension type\n");
                return 0;
        }

        /* Check nonce for all control extensions except SYNs, since
           those are actually establishing nonces. */
        if (!ctx->ctrl_ext->syn &&
            memcmp(ctx->ctrl_ext->nonce, ssk->peer_nonce, 
                   SAL_NONCE_SIZE) != 0) {
                LOG_PKT("Control extension has bad nonce\n");
                return 0;
        }

        return 1;
}

static inline int has_valid_address_extension(struct sock *sk,
                                              struct sal_hdr *sfh)
{
        LOG_DBG("Address extensions not supported yet\n");

        return 1;
}

static inline __sum16 serval_sal_csum(struct sal_hdr *sh, int len)
{
        return ip_compute_csum(sh, len);
}

static inline void serval_sal_send_check(struct sal_hdr *sh)
{
        sh->check = 0;
        sh->check = serval_sal_csum(sh, sh->shl << 2);
}

/* Compute the actual rto_min value */
static inline u32 serval_sal_rto_min(struct sock *sk)
{
	u32 rto_min = SAL_RTO_MIN;
#if defined(OS_LINUX_KERNEL)
	struct dst_entry *dst = __sk_dst_get(sk);
	if (dst && dst_metric_locked(dst, RTAX_RTO_MIN))
		rto_min = dst_metric_rtt(dst, RTAX_RTO_MIN);
#endif
	return rto_min;
}

/* The RTO estimation for the SAL is taken directly from the Linux
   kernel TCP code. */
/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
static void serval_sal_rtt_estimator(struct sock *sk, const __u32 mrtt)
{
	struct serval_sock *ssk = serval_sk(sk);
	long m = mrtt; /* RTT */

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be increased quickly, decrease too quickly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	if (m == 0)
		m = 1;
	if (ssk->srtt != 0) {
		m -= (ssk->srtt >> 3);	/* m is now error in rtt est */
		ssk->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
		if (m < 0) {
			m = -m;		/* m is now abs(error) */
			m -= (ssk->mdev >> 2);   /* similar update on mdev */
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
			if (m > 0)
				m >>= 3;
		} else {
			m -= (ssk->mdev >> 2);   /* similar update on mdev */
		}
		ssk->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
		if (ssk->mdev > ssk->mdev_max) {
			ssk->mdev_max = ssk->mdev;
			if (ssk->mdev_max > ssk->rttvar)
				ssk->rttvar = ssk->mdev_max;
		}
		if (after(ssk->snd_seq.una, ssk->rtt_seq)) {
			if (ssk->mdev_max < ssk->rttvar)
				ssk->rttvar -= (ssk->rttvar - ssk->mdev_max) >> 2;
			ssk->rtt_seq = ssk->snd_seq.nxt;
			ssk->mdev_max = serval_sal_rto_min(sk);
		}
	} else {
		/* no previous measure. */
		ssk->srtt = m << 3;	/* take the measured time to be rtt */
		ssk->mdev = m << 1;	/* make sure rto = 3*rtt */
		ssk->mdev_max = ssk->rttvar = max(ssk->mdev, 
                                                  serval_sal_rto_min(sk));
		ssk->rtt_seq = ssk->snd_seq.nxt;
	}
}

static inline void serval_sal_bound_rto(const struct sock *sk)
{
	if (serval_sk(sk)->rto > SAL_RTO_MAX)
		serval_sk(sk)->rto = SAL_RTO_MAX;
}

static inline u32 __serval_sal_set_rto(const struct serval_sock *ssk)
{
	return (ssk->srtt >> 3) + ssk->rttvar;
}

/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
static inline void serval_sal_set_rto(struct sock *sk)
{
	struct serval_sock *ssk = serval_sk(sk);
	/* Old crap is replaced with new one. 8)
	 *
	 * More seriously:
	 * 1. If rtt variance happened to be less 50msec, it is hallucination.
	 *    It cannot be less due to utterly erratic ACK generation made
	 *    at least by solaris and freebsd. "Erratic ACKs" has _nothing_
	 *    to do with delayed acks, because at cwnd>2 true delack timeout
	 *    is invisible. Actually, Linux-2.4 also generates erratic
	 *    ACKs in some circumstances.
	 */
	ssk->rto = __serval_sal_set_rto(ssk);

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exactly, which we pretend to do.
	 */

	/* NOTE: clamping at SAL_RTO_MIN is not required, current algo
	 * guarantees that rto is higher.
	 */
	serval_sal_bound_rto(sk);
}

static void serval_sal_rearm_rto(struct sock *sk)
{
	struct serval_sock *ssk = serval_sk(sk);

	if (!serval_sal_ctrl_queue_head(sk)) {
		serval_sock_clear_xmit_timer(sk);
	} else {
		serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);
	}
}

void serval_sal_update_rtt(struct sock *sk, const s32 seq_rtt)
{
        serval_sal_rtt_estimator(sk, seq_rtt);
	serval_sal_set_rto(sk);
        serval_sk(sk)->backoff = 0;

        LOG_SSK(sk, "Updated RTO HZ=%u seq_rtt=%d rto_msecs=%u\n",
                HZ, seq_rtt, jiffies_to_msecs(serval_sk(sk)->rto));
}

/*
  Given an ACK, clean all packets from the control queue that this ACK
  acknowledges. Or, alternatively, clean all packets if indicated by
  the 'all' argument.

  Reschedule retransmission timer as neccessary, i.e., if there are
  still unacked packets in the queue and we removed the first packet
  in the queue.
*/
static int serval_sal_clean_rtx_queue(struct sock *sk, uint32_t ackno, int all, 
                                      struct sal_skb_cb *cb_out)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb, *fskb = serval_sal_ctrl_queue_head(sk);
        unsigned int num = 0;
        u32 now = sal_time_stamp;
        s32 seq_rtt = -1;
        int err = 0;
       
        while ((skb = serval_sal_ctrl_queue_head(sk))) {
                if (after(ackno, SAL_SKB_CB(skb)->verno) || all) {
                        serval_sal_unlink_ctrl_queue(skb, sk);

                        if (cb_out) {
                                /* merge the state */
                                cb_out->flags |= SAL_SKB_CB(skb)->flags;
                        }

                        if (SAL_SKB_CB(skb)->flags & SVH_RETRANS) {
                                seq_rtt = -1;
                        } else if (!all) {
                                seq_rtt = now - SAL_SKB_CB(skb)->when;
                                serval_sal_update_rtt(sk, seq_rtt);
                                serval_sal_rearm_rto(sk);
                        }

                        LOG_PKT("cleaned rtxQ verno=%u HZ=%u seq_rtt=%d\n", 
                                SAL_SKB_CB(skb)->verno, 
                                HZ, seq_rtt);

                        if (skb == serval_sal_send_head(sk)) {
                                serval_sal_advance_send_head(sk, skb);
                        }

                        kfree_skb(skb);
                        skb = serval_sal_ctrl_queue_head(sk);
                        if (skb)
                                ssk->snd_seq.una = SAL_SKB_CB(skb)->verno;
                        num++;                        
                } else {
                        break;
                }
        }

        LOG_PKT("cleaned up %u packets from rtx queue, queue len=%u\n", 
                num, serval_sal_ctrl_queue_len(sk));
        
        /* If we removed the first packet in the queue, we should also
         * clear the retransmit timer since it is no longer valid.  */
        if (serval_sal_ctrl_queue_head(sk) != fskb) {
                serval_sock_clear_xmit_timer(sk);
                ssk->retransmits = 0;
        }

        if (serval_sal_ctrl_queue_head(sk)) {
                LOG_PKT("Setting retrans timer, queue len=%u rto=%u (ms)\n",
                        serval_sal_ctrl_queue_len(sk), 
                        jiffies_to_msecs(ssk->rto));
                serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);
        }

        return err;
}

static void serval_sal_queue_ctrl_skb(struct sock *sk, struct sk_buff *skb)
{
        /* Cannot release header here in case this is an unresolved
           packet. We need the skb_transport_header() pointer to
           calculate checksum */

	serval_sal_add_ctrl_queue_tail(sk, skb);
        
        LOG_PKT("queue packet verno=%u\n", SAL_SKB_CB(skb)->verno);

        /* Check if the skb became first in queue, in that case update
         * unacknowledged verno. */
        if (skb == serval_sal_ctrl_queue_head(sk)) {
                serval_sk(sk)->snd_seq.una = SAL_SKB_CB(skb)->verno;
                LOG_PKT("setting snd_una=%u\n",
                        serval_sk(sk)->snd_seq.una);
        }
}

/* 
   This function writes packets in the control queue to the
   network. It will write up to the current send window or the limit
   given as argument.  
*/
static int serval_sal_write_xmit(struct sock *sk, unsigned int limit,
                                 gfp_t gfp)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        unsigned int num = 0;
        int err = 0;
        
        LOG_PKT("writing from queue snd_una=%u snd_nxt=%u snd_wnd=%u\n",
                ssk->snd_seq.una, ssk->snd_seq.nxt, ssk->snd_seq.wnd);
        
        LOG_SSK(sk, "RTO HZ=%u rto=%u rto_msec=%u\n",
                HZ, ssk->rto, jiffies_to_msecs(ssk->rto));

	while ((skb = serval_sal_send_head(sk)) && 
               (ssk->snd_seq.nxt - ssk->snd_seq.una) <= ssk->snd_seq.wnd) {
                
                if (limit && num == limit)
                        break;

                SAL_SKB_CB(skb)->when = sal_time_stamp;
                                
                err = serval_sal_transmit_skb(sk, skb, 1, gfp);
                
                if (err < 0) {
                        LOG_ERR("xmit failed err=%d\n", err);
                        break;
                }
                serval_sal_advance_send_head(sk, skb);
                num++;
        }

        LOG_PKT("sent %u packets\n", num);

        return err;
}

/* 
   Queue SAL control packets for the purpose of doing retransmissions
   and socket buffer accounting. The TCP SYN is piggy-backed on the
   SAL control SYN and should take one byte send buffer
   space. Therefore, we need to keep the SYN until it is ACKed or
   freed due to reaching max retransmissions. 
*/
static int serval_sal_queue_and_push(struct sock *sk, struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sal_skb_cb cb;
        int err;
        
        memset(&cb, 0, sizeof(cb));

        /* Remove previously queued control packet(s). We currently
           only queue one control packet at a time, allowing control
           packets to override each other (necessary for, e.g.,
           (re)migration). It is not strictly necessary to use a queue
           for this, but we use it anyway for convenience and future
           proofness (in case we want to implement a send window). */
        serval_sal_clean_rtx_queue(sk, 0, 1, &cb);

        /* We need to merge the state in unacknowledged packets with
         * the our new state when we are overriding (currently
         * previous flags) */
        SAL_SKB_CB(skb)->flags |= cb.flags;

        /* Queue the new packet */
        serval_sal_queue_ctrl_skb(sk, skb);

        /* 
           Set retransmission timer.
        */
        if (skb == serval_sal_ctrl_queue_head(sk))
                serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);
        
        /* 
           Write packets in queue to network.
        */
        err = serval_sal_write_xmit(sk, 1, GFP_ATOMIC);

        if (err != 0) {
                LOG_ERR("xmit failed err=%d\n", err);
        }

        return err;
}

static struct sk_buff *sk_sal_alloc_skb(struct sock *sk, int size, gfp_t gfp)
{
        struct sk_buff *skb;

        skb = alloc_skb(sk->sk_prot->max_header, GFP_ATOMIC);

        if (!skb)
                return NULL;

        LOG_DBG("Alloc'd %d bytes (%d len). Proto max: %d\n", 
                size, skb->len, sk->sk_prot->max_header);        
        skb_reserve(skb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(skb, sk);
        skb->protocol = IPPROTO_SERVAL;
        skb->ip_summed = CHECKSUM_NONE;

        return skb;
}

static int serval_sal_send_syn(struct sock *sk, u32 verno)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err;

        skb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, GFP_ATOMIC);

        if (!skb)
                return -ENOMEM;

        /* Ask transport to fill in */
        if (ssk->af_ops->conn_build_syn) {
                err = ssk->af_ops->conn_build_syn(sk, skb);

                if (err) {
                        LOG_SSK(sk, "Transport protocol returned error\n");
                        __kfree_skb(skb);
                        return err;
                }
        }

        SAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
        SAL_SKB_CB(skb)->flags = SVH_SYN;
        SAL_SKB_CB(skb)->verno = verno;
        ssk->snd_seq.nxt = verno + 1;

        LOG_SSK(sk, "Sending REQUEST verno=%u local_flowid=%s srvid=%s\n",
                SAL_SKB_CB(skb)->verno,
                flow_id_to_str(&ssk->local_flowid),
                service_id_to_str(&ssk->peer_srvid));

        err = serval_sal_queue_and_push(sk, skb);
        
        if (err < 0) {
                LOG_ERR("queuing failed\n");
        }
        
        return err;
}

int serval_sal_connect(struct sock *sk, struct sockaddr *uaddr, 
                       int addr_len)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct service_id *srvid = &((struct sockaddr_sv *)uaddr)->sv_srvid;
        
	if ((size_t)addr_len < sizeof(struct sockaddr_sv))
		return -EINVAL;

        /* Set the peer serviceID in the socket */
        service_id_copy(&ssk->peer_srvid, srvid);
        
        /* Check for extra IP address */
        if ((size_t)addr_len >= sizeof(struct sockaddr_sv) +
            sizeof(struct sockaddr_in)) {
                struct sockaddr_in *saddr =
                        (struct sockaddr_in *)(((struct sockaddr_sv *)uaddr) + 1);
                
                if (saddr->sin_family == AF_INET) {
                        memcpy(&inet_sk(sk)->inet_daddr,
                               &saddr->sin_addr,
                               sizeof(saddr->sin_addr));
                }
        }

        /* Disable segmentation offload */
        sk->sk_gso_type = 0;
        
        return serval_sal_send_syn(sk, ssk->snd_seq.iss);
}

static void serval_sal_timewait(struct sock *sk, int state, int timeo)
{
        unsigned long timeout = jiffies + timeo;
        struct serval_sock *ssk = serval_sk(sk);
        const int rto = (ssk->rto << 2) - (ssk->rto >> 1);

        serval_sock_set_state(sk, state);
        
        if (timeo < rto)
                timeout = jiffies + rto;

        sk_reset_timer(sk, &ssk->tw_timer, timeout); 
}

void serval_sal_done(struct sock *sk)
{
        LOG_SSK(sk, "socket DONE!\n");

        if (serval_sk(sk)->af_ops->done)
                serval_sk(sk)->af_ops->done(sk);
        
        serval_sock_done(sk);
}

static int serval_sal_send_rsyn(struct sock *sk, u32 verno)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err;

        if (sk->sk_state == SAL_REQUEST ||
            sk->sk_state == SAL_LISTEN ||
            sk->sk_state == SAL_CLOSED) {
                LOG_SSK(sk, "Cannot send RSYN in state %s\n",
                        serval_sock_state_str(sk));
                return 0;
        }

        switch (ssk->sal_state) {
        case SAL_RSYN_INITIAL:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT);
                break;
        case SAL_RSYN_RECV:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT_RECV);
                break;
        case SAL_RSYN_SENT:
        case SAL_RSYN_SENT_RECV:
                /* Here we just move to the same state again, so
                   nothing to do. */
                break;
        }

        for (;;) {
                skb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header,
                                       GFP_ATOMIC);
                if (skb)
                        break;
                yield();
        }

        /* Use same sequence number as previous packet for migration
           requests */
        LOG_SSK(sk, "Sending RSYN verno=%u\n", verno);
        SAL_SKB_CB(skb)->flags = SVH_RSYN;
        SAL_SKB_CB(skb)->verno = verno;

        if (sk->sk_state == SAL_FINWAIT1 ||
            sk->sk_state == SAL_CLOSING ||
            sk->sk_state == SAL_LASTACK) {
                /* We have sent our FIN, but not received the ACK. We
                   need to add the FIN bit. */
                SAL_SKB_CB(skb)->flags |= SVH_FIN;
        }

        err = serval_sal_queue_and_push(sk, skb);
 
        if (err < 0) {
                LOG_ERR("queuing failed\n");
        }

        return err;
}

int serval_sal_migrate(struct sock *sk)
{
        LOG_SSK(sk, "Sending RSYN\n");
        return serval_sal_send_rsyn(sk, serval_sk(sk)->snd_seq.nxt++);
}

int serval_sal_send_fin(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err;

        /* We are under lock, so allocation must be atomic */
        /* Socket is locked, keep trying until memory is available. */
        for (;;) {
                skb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, 
                                       GFP_ATOMIC);
                
                if (skb)
                        break;
                yield();
        }
        
        LOG_SSK(sk, "Sending SAL FIN\n");
        SAL_SKB_CB(skb)->flags = SVH_FIN;
        SAL_SKB_CB(skb)->verno = ssk->snd_seq.nxt++;
        
        /* If we are in the process of migrating, then we should
           probably add also the RSYN flag. Otherwise, if the previous
           RSYN was lost, this FIN packet will "override" the RSYN and
           the migration will never happen. TODO: verify that this is
           really the way to handle this situation. */
        if (ssk->sal_state == SAL_RSYN_SENT) {
                LOG_SSK(sk, "RSYN was in progress, adding RSYN flag\n");
                SAL_SKB_CB(skb)->flags |= SVH_RSYN;
        } else if (serval_sk(sk)->sal_state == SAL_RSYN_RECV) {
                SAL_SKB_CB(skb)->flags |= SVH_RSYN | SVH_ACK;
        }
        
        serval_sock_set_flag(ssk, SSK_FLAG_FIN_SENT);

        err = serval_sal_queue_and_push(sk, skb);
        
        if (err < 0) {
                LOG_ERR("queuing failed\n");
        }

        return err;
}

/* Called as a result of user app close() */
void serval_sal_close(struct sock *sk, long timeout)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        LOG_SSK(sk, "Closing socket\n");

        switch (sk->sk_state) {
        case SAL_CLOSEWAIT:
                serval_sock_set_state(sk, SAL_LASTACK);
                break;
        case SAL_CONNECTED:
        case SAL_RESPOND:
                serval_sock_set_state(sk, SAL_FINWAIT1);
                break;
        case SAL_FINWAIT1:
        case SAL_FINWAIT2:
        case SAL_CLOSING:
        case SAL_TIMEWAIT:
                LOG_ERR("Close called in post close() state %s\n",
                        serval_sock_state_str(sk));
                return;
        default:
                LOG_SSK(sk, "Calling serval_sal_done on socket in state %s\n",
                        serval_sock_state_str(sk));
                serval_sal_done(sk);
                return;
        }
        
        if (ssk->af_ops->conn_close) {
                /* Tell transport to, e.g., schedule
                   end-of-stream (i.e., put FIN in the last
                   queued transport segment). This will defer
                   the call to serval_sal_send_shutdown()
                   until transport is done. */
                err = ssk->af_ops->conn_close(sk);
                
                if (err < 0) {
                        LOG_ERR("Transport error %d\n", err);
                } else if (err > 0) {
                        /* Data was unread, we need to send RESET */
                        serval_sock_set_state(sk, SAL_CLOSED);
                        serval_sal_send_active_reset(sk, sk->sk_allocation);
                }
        } else {
                err = serval_sal_send_fin(sk);
        }

        sk_stream_wait_close(sk, timeout);
}

static int serval_sal_send_ack(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err = 0;

        skb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, GFP_ATOMIC);
                        
        if (!skb)
                return -ENOMEM;

        SAL_SKB_CB(skb)->flags = SVH_ACK;
        /* Do not increment sequence numbers for pure ACKs */
        SAL_SKB_CB(skb)->verno = ssk->snd_seq.nxt;

        LOG_SSK(sk, "Sending ACK verno=%u\n", ssk->rcv_seq.nxt);

        if (err == 0) {
                /* Do not queue pure ACKs */
                err = serval_sal_transmit_skb(sk, skb, 0, GFP_ATOMIC);
        }
               
        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }
   
        return err;
}

enum source_ext_res {
        SOURCE_EXT_IP_EXISTS,
        SOURCE_EXT_IP_NONE,
        SOURCE_EXT_NONE,
};

static 
enum source_ext_res serval_sal_source_ext_check(struct sk_buff *skb,
                                                struct sal_context *ctx,
                                                __u32 ipaddr)
{
        int i;
        
        if (!ctx->src_ext)
                return SOURCE_EXT_NONE;
        
        for (i = 0; i < SAL_SOURCE_EXT_NUM_ADDRS(ctx->src_ext); i++) {
                if (memcmp(SAL_SOURCE_EXT_GET_ADDR(ctx->src_ext, i),
                           &ipaddr, 
                           sizeof(ipaddr)) == 0) {
                        return SOURCE_EXT_IP_EXISTS;
                }
        }
        return SOURCE_EXT_IP_NONE;
}

/**
   Add source extension to SAL header. If one already exists, append
   the source IP address of the packet to the existing header.

   @in_skb the skb to add the extension to.  

   @ctx the serval header context for the incoming packet (note that
   this context may not point to the headers in in_skb as in_skb may
   be a clone or copy.
*/
static int serval_sal_add_source_ext(struct sk_buff **in_skb,
                                     struct sal_context *ctx)
{
        struct sk_buff *skb = *in_skb;
        struct iphdr *iph;
        struct sal_hdr *sh;
        struct sal_source_ext *sxt = ctx ? ctx->src_ext : NULL;
        unsigned int size, extra_len = 0, sal_len = 0, ext_len = 0;
        unsigned char *ptr;

        iph = ip_hdr(skb);
        sh = sal_hdr(skb);

        if (!ctx) {
                LOG_ERR("No header context\n");
                return -EINVAL;
        }

        switch (serval_sal_source_ext_check(skb, ctx, iph->daddr)) {
        case SOURCE_EXT_IP_NONE:
                /* We just add another IP address. */
                LOG_DBG("Appending address to SOURCE extension\n");
                extra_len = 4;
                ext_len = ctx->src_ext->ext_length + extra_len;
                break;
        case SOURCE_EXT_NONE:
                LOG_DBG("Adding new SOURCE extension\n");
                extra_len = SAL_SOURCE_EXT_LEN + 4;
                ext_len = extra_len;
                break;
        case SOURCE_EXT_IP_EXISTS:
                LOG_ERR("IP dst address already in "
                        "SOURCE ext. Possible loop!\n");
                return -1;
        }
        
        sal_len = ctx->length + extra_len;
        size = (char *)sh - (char *)iph;

        /* Push back to IP header */
        skb_push(skb, size);

        if (skb_headroom(skb) < (extra_len + size + 
                                 skb->dev->hard_header_len)) {
                LOG_DBG("Expanding SKB headroom\n");
                skb = skb_copy_expand(skb, skb_headroom(skb) + 
                                      extra_len,
                                      skb_tailroom(skb),
                                      GFP_ATOMIC);

                if (!skb) {
                        LOG_ERR("Could not expand skb!\n");
                        return -ENOMEM;
                }

                kfree_skb(*in_skb);
                *in_skb = skb;
        }
        
        skb_reset_network_header(skb);
        iph = ip_hdr(skb);
        skb_set_transport_header(skb, size);
        sh = sal_hdr(skb);

        if (ctx->src_ext) {
                /* Point to just after source extension in the new skb */
                unsigned int off = (SAL_SOURCE_EXT_GET_LAST_ADDR(ctx->src_ext) - 
                                    (unsigned char *)ctx->hdr) + 4;
                ptr = ((unsigned char *)sh + off);
        } else {
                /* No previous source extension. Append new header. */
                ptr = ((unsigned char *)sh + ctx->length);
        }

        /* Check if we need to linearize */
        if (skb_is_nonlinear(skb)) {
                if (skb_linearize(skb)) {
                        LOG_ERR("Could not linearize skb\n");
                        return -ENOMEM;
                }
        }

        /* Move back everything from the point of insertion, making
           room for extra_len bytes */
        memmove(skb_push(skb, extra_len), iph,
                ptr - (unsigned char *)iph);
        
        /* Update header pointers */
        skb_set_mac_header(skb, -skb->dev->hard_header_len);
        skb_reset_network_header(skb);
        iph = ip_hdr(skb);
        pskb_pull(skb, size);
        skb_reset_transport_header(skb);
        sh = sal_hdr(skb);

        if (ctx->src_ext) {
                sxt = (struct sal_source_ext *)
                        ((char *)sh + ((char *)ctx->src_ext - 
                                       (char *)ctx->hdr));
        } else {
                sxt = (struct sal_source_ext *)
                        ((unsigned char *)sh + ctx->length);
        }

        sxt->ext_type = SAL_SOURCE_EXT;
        sxt->ext_length = ext_len;

        if (ctx->src_ext) {
                memcpy(SAL_SOURCE_EXT_GET_LAST_ADDR(sxt), 
                       &iph->daddr, sizeof(iph->daddr));
        } else {
                memcpy(SAL_SOURCE_EXT_GET_ADDR(sxt, 0), 
                       &iph->saddr, sizeof(iph->saddr));
                memcpy(SAL_SOURCE_EXT_GET_ADDR(sxt, 1), 
                       &iph->daddr, sizeof(iph->daddr));
        }
        
        sh->check = 0;
        sh->shl = sal_len >> 2;

        LOG_DBG("New SAL hdr (old_len=%u new_len=%u): skb->len=%u %s\n",
                ctx->length,
                sal_len,
                skb->len,
                sal_hdr_to_str(sh));

        return extra_len;
}

/* Kill this socket if we receive a reset. */
void serval_sal_rcv_reset(struct sock *sk)
{
	/* We want the right error as BSD sees it (and indeed as we do). */
	switch (sk->sk_state) {
	case SAL_REQUEST:
		sk->sk_err = ECONNREFUSED;
		break;
	case SAL_CLOSEWAIT:
		sk->sk_err = EPIPE;
		break;
	case SAL_CLOSED:
		return;
	default:
		sk->sk_err = ECONNRESET;
	}

        LOG_SSK(sk, "RESET received\n");

	/* This barrier is coupled with smp_rmb() in serval_tcp_poll() */
	smp_wmb();

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_error_report(sk);

	serval_sal_done(sk);
}

static void serval_sal_send_reset(struct sock *sk, struct sk_buff *skb, 
                                  struct sal_context *ctx)
{
        struct sk_buff *rskb;
        struct dst_entry *dst = NULL;
        struct sal_hdr *rsh;
        struct sal_control_ext *ctrl_ext;
        unsigned int sal_len = 0;
        int err = 0;

        if (ctx->ctrl_ext && ctx->ctrl_ext->rst)
                return;

        /* Allocate RESPONSE reply */
        rskb = alloc_skb(MAX_SAL_HDR, GFP_ATOMIC);

        if (!rskb)
                return;

        skb_reserve(rskb, MAX_SAL_HDR);
        rskb->protocol = IPPROTO_SERVAL;
        rskb->ip_summed = CHECKSUM_NONE;

        if (sk)
                skb_serval_set_owner_w(rskb, sk);

#if defined(OS_LINUX_KERNEL)
        /*
          For kernel, we need to route this packet and
          associate a dst_entry with the skb for it to be
          accepted by the kernel IP stack.
        */
        {
                struct rtable *rt;
                struct net *net = &init_net;
                int ifindex = skb->dev ? skb->dev->ifindex : 0;
                
                if (sk) {
                        net = sock_net(sk);
                        ifindex = sk->sk_bound_dev_if;
                }
#if defined(ENABLE_DEBUG)
                {
                        char daddr[18], saddr[18];
                        LOG_DBG("routing reset saddr=%s daddr=%s ifindex=%d\n",
                                inet_ntop(AF_INET, &ip_hdr(skb)->saddr, 
                                          saddr, 18),
                                inet_ntop(AF_INET, &ip_hdr(skb)->daddr, 
                                          daddr, 18), ifindex);
                }
#endif
                rt = serval_ip_route_output(net,
                                            ip_hdr(skb)->saddr,
                                            ip_hdr(skb)->daddr,
                                            0, ifindex);
                
                if (!rt) {
                        LOG_DBG("RESET not routable\n");
                        goto drop_response;
                }
                
                dst = route_dst(rt);
        }
#endif /* OS_LINUX_KERNEL */

        skb_dst_set(rskb, dst);
        rskb->dev = skb->dev;
        
        skb_reset_transport_header(rskb);

        /* Add control extension */
        ctrl_ext = (struct sal_control_ext *)
                skb_push(rskb, SAL_CONTROL_EXT_LEN);
        memset(ctrl_ext, 0, SAL_CONTROL_EXT_LEN);
        ctrl_ext->ext_type = SAL_CONTROL_EXT;
        ctrl_ext->ext_length = SAL_CONTROL_EXT_LEN;
        ctrl_ext->rst = 1;
        
	if (ctx->flags & SVH_ACK) {
		ctrl_ext->verno = htonl(ctx->ackno);
	} else {
		ctrl_ext->ack = 1;
		ctrl_ext->ackno = htonl(ctx->verno + 
                                        (ctx->flags & SVH_SYN) + 
                                        (ctx->flags & SVH_FIN));
	}

        /* Copy our nonce to control extension */
        if (ctx->ctrl_ext) {
                memcpy(ctrl_ext->nonce, 
                       ctx->ctrl_ext->nonce, SAL_NONCE_SIZE);
        }

        sal_len += SAL_CONTROL_EXT_LEN;
 
        /* Add Serval header */
        rsh = (struct sal_hdr *)skb_push(rskb, sizeof(*rsh));
        memcpy(&rsh->dst_flowid, &ctx->hdr->src_flowid, 
               sizeof(rsh->dst_flowid));
        memcpy(&rsh->src_flowid, &ctx->hdr->dst_flowid, 
               sizeof(rsh->src_flowid));
        rsh->protocol = ctx->hdr->protocol;
        rsh->shl = (SAL_HEADER_LEN + sal_len) >> 2;

        LOG_PKT("Serval XMIT RESPONSE %s skb->len=%u\n",
                sal_hdr_to_str(rsh), rskb->len);
        
        skb_reset_transport_header(skb);

        /* Calculate SAL header checksum. */
        serval_sal_send_check(rsh);
        
        /* 
           Cannot use serval_sal_transmit_skb here since we do not yet
           have a full accepted socket (sk is the listening sock). 
        */
        err = serval_ipv4_build_and_send_pkt(rskb, sk, 
                                             ip_hdr(skb)->daddr,
                                             ip_hdr(skb)->saddr, NULL);
        
        if (err) {
                LOG_ERR("Could not send RST packet\n");
        }
        return;

drop_response:
        __kfree_skb(rskb);
        return;
}

void serval_sal_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;
        struct serval_sock *ssk = serval_sk(sk);

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_SAL_HDR, priority);

	if (!skb)
		return;

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_SAL_HDR);
        skb_serval_set_owner_w(skb, sk);
        skb->protocol = IPPROTO_SERVAL;
        skb->ip_summed = CHECKSUM_NONE;
        SAL_SKB_CB(skb)->flags = SVH_RST | SVH_ACK;
	SAL_SKB_CB(skb)->when = sal_time_stamp;
        SAL_SKB_CB(skb)->verno = ssk->snd_seq.nxt;

	serval_sal_transmit_skb(sk, skb, 0, priority);
}

static int serval_sal_send_synack(struct sock *sk,
                                  struct request_sock *rsk,
                                  struct sk_buff *skb,
                                  struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *srsk = serval_rsk(rsk);
        struct sk_buff *rskb;
        struct dst_entry *dst = NULL;
        struct sal_hdr *rsh;
        struct sal_control_ext *ctrl_ext;
        /* struct sal_service_ext *srv_ext; */
        unsigned int sal_len = 0;
        uint16_t ext_len;
        int err = 0;

        /* Allocate RESPONSE reply */
        rskb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, GFP_ATOMIC);

        if (!rskb)
                return -ENOMEM;

#if defined(OS_LINUX_KERNEL)
        /*
          For kernel, we need to route this packet and
          associate a dst_entry with the skb for it to be
          accepted by the kernel IP stack.
        */
        {
                struct inet_request_sock *ireq = inet_rsk(rsk);
                struct rtable *rt;
                
                rt = serval_ip_route_output(sock_net(sk),
                                            ireq->rmt_addr,
                                            ireq->loc_addr,
                                            0, sk->sk_bound_dev_if);
                
                if (!rt) {
                        LOG_ERR("RESPONSE not routable\n");
                        goto drop_response;
                }
                
                dst = route_dst(rt);
        }
#endif /* OS_LINUX_KERNEL */

        /* Let transport chip in */
        if (ssk->af_ops->conn_build_synack) {
                err = ssk->af_ops->conn_build_synack(sk, dst, rsk, rskb);
                
                if (err) {
                        goto drop_and_release;
                }
        } else {
                LOG_DBG("Transport has no SYNACK callback\n");
        }

        rskb->protocol = IPPROTO_SERVAL;
        skb_dst_set(rskb, dst);
        rskb->dev = skb->dev;
        
        skb_reset_transport_header(rskb);

        /* Add source extension, if necessary */
        if (ctx->src_ext) {
                struct sal_source_ext *sxt;
                ext_len = ctx->src_ext->ext_length;

                LOG_DBG("Adding SOURCE ext to response\n");

                /*
                  The SYN had a source extension, which means we were
                  not the first hop in this resolution and we must
                  therefore also append our source address. Then send
                  back the reply with the initial destination address
                  as source to comply with ingress filtering (e.g.,
                  for clients behind NATs).
                */
                sxt = (struct sal_source_ext *)
                        skb_push(rskb, ext_len + 4);

                if (!sxt) {
                        LOG_DBG("Could not add source extensions\n");
                        goto drop_and_release;
                }
                memcpy(sxt, ctx->src_ext, ext_len);
                sxt->ext_type = SAL_SOURCE_EXT;
                sxt->ext_length = ext_len + 4;
                memcpy(SAL_SOURCE_EXT_GET_LAST_ADDR(sxt), 
                       &inet_rsk(rsk)->loc_addr,
                       sizeof(inet_rsk(rsk)->loc_addr));
                sal_len += ext_len + 4;
        } 

        /* Add control extensions */
        ext_len = SAL_CONTROL_EXT_LEN;
        ctrl_ext = (struct sal_control_ext *)
                skb_push(rskb, ext_len);

        if (!ctrl_ext)
                goto drop_and_release;

        memset(ctrl_ext, 0, ext_len);
        ctrl_ext->ext_type = SAL_CONTROL_EXT;
        ctrl_ext->ext_length = ext_len;
        ctrl_ext->verno = htonl(srsk->iss_seq);
        ctrl_ext->ackno = htonl(srsk->rcv_seq + 1);
        ctrl_ext->syn = 1;
        ctrl_ext->ack = 1;
        memcpy(ctrl_ext->nonce, srsk->local_nonce, SAL_NONCE_SIZE);
        sal_len += ext_len;
        
        /* Add Serval header */
        rsh = (struct sal_hdr *)skb_push(rskb, SAL_HEADER_LEN);
        memcpy(&rsh->dst_flowid, &srsk->peer_flowid, 
               sizeof(rsh->dst_flowid));
        memcpy(&rsh->src_flowid, &srsk->local_flowid, 
               sizeof(srsk->local_flowid));
        rsh->protocol = ctx->hdr->protocol;
        rsh->shl = (SAL_HEADER_LEN + sal_len) >> 2;

        LOG_PKT("Serval XMIT RESPONSE %s skb->len=%u\n",
                sal_hdr_to_str(rsh), rskb->len);
        
        skb_reset_transport_header(skb);

        /* Calculate SAL header checksum. */
        serval_sal_send_check(rsh);

        /* 
           Cannot use serval_sal_transmit_skb here since we do not yet
           have a full accepted socket (sk is the listening sock). 
        */
        err = serval_ipv4_build_and_send_pkt(rskb, sk, 
                                             srsk->reply_saddr,
                                             inet_rsk(rsk)->rmt_addr, NULL);
        return 0;
drop_and_release:
        dst_release(dst);
#if defined(OS_LINUX_KERNEL)
drop_response:
#endif
        __kfree_skb(rskb);
        return 0;
}

static int serval_sal_rcv_syn(struct sock *sk, 
                              struct sk_buff *skb,
                              struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sal_control_ext *ctrl_ext = ctx->ctrl_ext;
        struct request_sock *rsk;
        struct serval_request_sock *srsk;
        struct net_addr myaddr;
        int err = 0;

        if (!has_valid_control_extension(sk, ctx) ||
            !has_service_extension_src(ctx))
                goto drop;

        /* Make compiler be quiet */
        memset(&myaddr, 0, sizeof(myaddr));

        LOG_SSK(sk, "REQUEST verno=%u\n", ctx->verno);

        if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) 
                goto drop;

        /* Try to figure out the source address for the incoming
         * interface so that we can use it in our reply.  
         *
         * FIXME:
         * should probably route the reply here somehow in case we
         * want to reply on another interface than the incoming one.
         */
        if (!dev_get_ipv4_addr(skb->dev, IFADDR_LOCAL, &myaddr)) {
                LOG_SSK(sk, "No source address for interface %s\n",
                        skb->dev);
                goto drop;
        }

        rsk = serval_reqsk_alloc(sk->sk_prot->rsk_prot);

        if (!rsk)
                goto drop;

        srsk = serval_rsk(rsk);

        /* Copy fields in request packet into request sock */
        memcpy(&srsk->peer_flowid, &ctx->hdr->src_flowid, 
               sizeof(ctx->hdr->src_flowid));
        memcpy(&srsk->target_srvid, &ctx->srv_ext[0]->srvid,
               sizeof(ctx->srv_ext[0]->srvid));
        memcpy(srsk->peer_nonce, ctrl_ext->nonce, SAL_NONCE_SIZE);
        srsk->rcv_seq = ctx->verno;

        /* Save our local address that we grabbed from the incoming
         * interface. This address should in most cases be the same
         * address as the IP header destination of the incoming
         * packet, unless the SYN was broadcast. */
        memcpy(&inet_rsk(rsk)->loc_addr, &myaddr,
               sizeof(inet_rsk(rsk)->loc_addr));

        /* 
           Here we need to figure out which addresses to save in our
           sockets, and which ones to use in our reply.
           
           This decision may vary depending on whether we are dealing
           with a client behind a NAT or not. For a NAT'd client we
           need to spoof the source address in the reply to ensure it
           carries the source expected by the NAT (i.e., the
           destination address that the client initially
           targeted---this would be the first SAL forwarder/hop).

           Further, if the request carried a source extension it means
           that the packet was forwarded in the SAL. Then we will find
           the true source address in the extension and otherwise in
           the IP header.

           A source extension should always carry at least two
           addresses: the original source, and the first forwarder.
        */
        if (ctx->src_ext) {
                /* Get the original source and save in our request
                 * socket */
                memcpy(&inet_rsk(rsk)->rmt_addr,
                       SAL_SOURCE_EXT_GET_ADDR(ctx->src_ext, 0),
                       sizeof(inet_rsk(rsk)->rmt_addr));
                
                /* No NAT, use our own address in the reply. */
                memcpy(&srsk->reply_saddr, &myaddr, sizeof(srsk->reply_saddr));
        } else {
                /* There was no source extension, so we will find the
                 * addresses in the IP header. */
                memcpy(&inet_rsk(rsk)->rmt_addr, &ip_hdr(skb)->saddr,
                       sizeof(inet_rsk(rsk)->rmt_addr));
                
                /* Packet was broadcasted, so we cannot use the
                 * incoming destination address to figure out which
                 * interface address to use. */
                if (skb->pkt_type == PACKET_BROADCAST)
                        memcpy(&srsk->reply_saddr,
                               &myaddr,
                               sizeof(srsk->reply_saddr));
                else 
                        memcpy(&srsk->reply_saddr,
                               &ip_hdr(skb)->daddr,
                               sizeof(srsk->reply_saddr));
        }
        
#if defined(ENABLE_DEBUG)
        {
                char rmtstr[18], locstr[18], replystr[18];
                LOG_SSK(sk, "rmt_addr=%s loc_addr=%s reply_saddr=%s\n",
                        inet_ntop(AF_INET, &inet_rsk(rsk)->rmt_addr, 
                                  rmtstr, 18),
                        inet_ntop(AF_INET, &inet_rsk(rsk)->loc_addr, 
                                  locstr, 18),
                        inet_ntop(AF_INET, &srsk->reply_saddr, 
                                  replystr, 18));
        }
#endif
 
        /* Call upper transport protocol handler */
        if (ssk->af_ops->conn_request) {
                err = ssk->af_ops->conn_request(sk, rsk, skb);

                if (err) {
                        /* Transport will free the skb on error */
                        reqsk_free(rsk);
                        goto done;
                }
        }
        
        /* Add the new request socket to the SYN queue. */
        list_add(&srsk->lh, &ssk->syn_queue);
        sk->sk_ack_backlog++;
       
        err = serval_sal_send_synack(sk, rsk, skb, ctx);
 drop:
        /* Free the SYN request */
        kfree_skb(skb);
 done:
        return err;
}

/*
  Create new child socket in RESPOND state. This happens as a result
  of a LISTEN:ing socket receiving an ACK in response to a SYNACK
  response.  */
static struct sock *
serval_sal_create_respond_sock(struct sock *sk, 
                               struct sk_buff *skb,
                               struct request_sock *req,
                               struct dst_entry *dst)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sock *nsk;

        nsk = sk_clone_lock(sk, GFP_ATOMIC);

        if (nsk) {
                struct serval_sock *nssk = serval_sk(nsk);
                int ret;
                
                atomic_inc(&serval_nr_socks);
                serval_sock_init(nsk);
                /* Indicate that this is a child socket. Necessary to
                 * know that this socket should not unregister its
                 * serviceID. */
                serval_sock_set_flag(nssk, SSK_FLAG_CHILD);
                
                /* Transport protocol specific init. */                
                ret = ssk->af_ops->conn_child_sock(sk, skb, 
                                                   req, nsk, dst);

                if (ret < 0) {
                        LOG_ERR("Transport child sock init failed\n");
                        sock_set_flag(nsk, SOCK_DEAD);
                        sk_free(nsk);
                        nsk = NULL;
                }
        }        
        
        return nsk;
}

/*
  Check if a request sock has previously been created by a SYN, in
  case of receiving retransmitted/duplicate SYNs.  */  
static struct request_sock *serval_sal_find_rsk(struct sock *sk,
                                                struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *srsk;
        
        list_for_each_entry(srsk, &ssk->syn_queue, lh) {
                if (memcmp(&srsk->peer_flowid, &ctx->hdr->src_flowid, 
                           sizeof(srsk->peer_flowid)) == 0) {
                        return &srsk->rsk.req;
                }
        }

        list_for_each_entry(srsk, &ssk->accept_queue, lh) {
                if (memcmp(&srsk->peer_flowid, &ctx->hdr->src_flowid, 
                           sizeof(srsk->peer_flowid)) == 0) {
                        return &srsk->rsk.req;
                }
        }

        return NULL;
}
/*
  This function is called as a result of receiving a ACK in response
  to a SYNACK that was sent by a "parent" sock in LISTEN state (the sk
  argument). 
   
  The objective is to find a serval_request_sock that corresponds to
  the ACK just received and initiate processing on that request
  sock. Such processing includes transforming the request sock into a
  regular sock and putting it on the parent sock's accept queue.

*/
static struct sock * serval_sal_request_sock_handle(struct sock *sk,
                                                    struct sk_buff *skb,
                                                    struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *srsk;

        list_for_each_entry(srsk, &ssk->syn_queue, lh) {
                if (memcmp(&srsk->local_flowid, &ctx->hdr->dst_flowid, 
                           sizeof(srsk->local_flowid)) == 0) {
                        struct sock *nsk;
                        struct serval_sock *nssk;
                        struct request_sock *rsk = &srsk->rsk.req;
                        struct inet_request_sock *irsk = &srsk->rsk;
                        struct inet_sock *newinet;
                        
                        if (memcmp(srsk->peer_nonce, 
                                   ctx->ctrl_ext->nonce, 
                                   SAL_NONCE_SIZE) != 0) {
                                LOG_ERR("Bad nonce\n");
                                return NULL;
                        }

                        if (ctx->verno != srsk->rcv_seq + 1) {
                                LOG_ERR("Bad verno received=%u expected=%u\n",
                                        ctx->verno, 
                                        srsk->rcv_seq + 1);
                                return NULL;
                        }
                        if (ctx->ackno != srsk->iss_seq + 1) {
                                LOG_ERR("Bad ackno received=%u expected=%u\n",
                                        ctx->ackno, 
                                        srsk->iss_seq + 1);
                                return NULL;
                        }
                        
                        nsk = serval_sal_create_respond_sock(sk, skb, 
                                                             rsk, NULL);
                        
                        if (!nsk)
                                return NULL;

                        /* Move request sock to accept queue */
                        list_move_tail(&srsk->lh, &ssk->accept_queue);
                        nsk->sk_ack_backlog = 0;

                        newinet = inet_sk(nsk);
                        nssk = serval_sk(nsk);

                        serval_sock_set_state(nsk, SAL_RESPOND);

                        memcpy(&nssk->local_flowid, &srsk->local_flowid, 
                               sizeof(srsk->local_flowid));
                        memcpy(&nssk->peer_flowid, &srsk->peer_flowid, 
                               sizeof(srsk->peer_flowid));
                        service_id_copy(&nssk->peer_srvid, &srsk->peer_srvid);
                        service_id_copy(&nssk->local_srvid, &srsk->target_srvid);
                        memcpy(&newinet->inet_daddr, &irsk->rmt_addr,
                               sizeof(newinet->inet_daddr));
                        memcpy(&newinet->inet_saddr, &irsk->loc_addr,
                               sizeof(newinet->inet_saddr));      

                        memcpy(nssk->local_nonce, srsk->local_nonce, 
                               SAL_NONCE_SIZE);
                        memcpy(nssk->peer_nonce, srsk->peer_nonce, 
                               SAL_NONCE_SIZE);
                        nssk->snd_seq.iss = srsk->iss_seq;
                        nssk->snd_seq.una = srsk->iss_seq;
                        nssk->snd_seq.nxt = srsk->iss_seq + 1;
                        nssk->rcv_seq.iss = srsk->rcv_seq;
                        nssk->rcv_seq.nxt = srsk->rcv_seq + 1;
                        rsk->sk = nsk;
                        
                        /* Hash the sock to make it demuxable */
                        nsk->sk_prot->hash(nsk);

                        return nsk;
                }
        }
        
        return sk;
}

static int serval_sal_ack_process(struct sock *sk,
                                  struct sk_buff *skb,
                                  struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        
        if (!(ctx->flags & SVH_ACK))
                return -1;

	/* If the ack is older than previous acks
	 * then we can probably ignore it.
	 */
	if (before(ctx->ackno, ssk->snd_seq.una))
		goto old_ack;

	/* If the ack corresponds to something we haven't sent yet,
           ignore.
	 */
	if (after(ctx->ackno, ssk->snd_seq.nxt))
		goto invalid_ack;

        serval_sal_clean_rtx_queue(sk, ctx->ackno, 0, NULL);
        ssk->snd_seq.una = ctx->ackno;
        ssk->ack_rcv_tstamp = sal_time_stamp;

        LOG_PKT("received valid ACK ackno=%u\n", 
                ctx->ackno);

        /* Check for migration handshake ACK */
        switch (ssk->sal_state) {
        case SAL_RSYN_RECV:
                if (!(ctx->flags & SVH_RSYN))
                        serval_sock_set_sal_state(sk, SAL_RSYN_INITIAL);
                break;
        case SAL_RSYN_SENT_RECV:
                if (!(ctx->flags & SVH_RSYN))
                        serval_sock_set_sal_state(sk, SAL_RSYN_SENT);
                break;
        default:
                return 0;
        }
        
        if (!(ctx->flags & SVH_RSYN)) {
                LOG_SSK(sk, "Migration complete for flow %s\n",
                        flow_id_to_str(&ssk->local_flowid));
                memcpy(&inet_sk(sk)->inet_daddr, &ssk->mig_daddr, 4);
                memset(&ssk->mig_daddr, 0, 4);
                sk_dst_reset(sk);
                
                if (ssk->af_ops->migration_completed)
                        ssk->af_ops->migration_completed(sk);
        }

        return 0;
 invalid_ack:
        LOG_SSK(sk, "invalid ackno %u out of sequence, expected %u\n",
                ctx->ackno, ssk->snd_seq.una + 1);
        return -1;
 old_ack:
        LOG_SSK(sk, "old ackno %u, expected %u\n",
                ctx->ackno, ssk->snd_seq.una + 1);
        return -1;
}

static int serval_sal_rcv_rsynack(struct sock *sk,
                                  struct sk_buff *skb,
                                  struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct net_device *mig_dev = dev_get_by_index(sock_net(sk), 
                                                      ssk->mig_dev_if);
        int err = 0;

        LOG_SSK(sk, "received RSYN-ACK\n");

        if (!mig_dev) {
                LOG_ERR("No migration device set\n");
                return -1;
        }

        switch (ssk->sal_state) {
        case SAL_RSYN_SENT:
                LOG_SSK(sk, "Migration complete for flow %s!\n",
                        flow_id_to_str(&ssk->local_flowid));
                serval_sock_set_sal_state(sk, SAL_RSYN_INITIAL);
                
                dev_get_ipv4_addr(mig_dev, IFADDR_LOCAL, 
                                  &inet_sk(sk)->inet_saddr);
                serval_sock_set_dev(sk, mig_dev->ifindex);
                serval_sock_set_mig_dev(sk, 0);
                sk_dst_reset(sk);

                if (ssk->af_ops->migration_completed)
                        ssk->af_ops->migration_completed(sk);
                break;
        case SAL_RSYN_SENT_RECV:
                serval_sock_set_sal_state(sk, SAL_RSYN_RECV);
                memcpy(&ssk->mig_daddr, &ip_hdr(skb)->saddr, 4);
                sk_dst_reset(sk);
                break;
        default:
                goto out;
        }
        
        ssk->rcv_seq.nxt = ctx->verno + 1;

        err = serval_sal_send_ack(sk);
out:        
        dev_put(mig_dev);

        return err;
}

/*
  This function handles the case when we received an RSYN (without
  ACK). */
static int serval_sal_rcv_rsyn(struct sock *sk,
                               struct sk_buff *skb,
                               struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *rskb = NULL;
        
#if defined(ENABLE_DEBUG)
        {
                char buf[18];
                LOG_SSK(sk, "RSYN from address %s\n",
                        inet_ntop(AF_INET, &ip_hdr(skb)->saddr, buf, 18));
        }
#endif
        if (!has_valid_control_extension(sk, ctx)) {
                LOG_ERR("Bad migration control packet\n");
                return -1;
        }
       
        /* We ignore migrations in these states */
        if (sk->sk_state == SAL_CLOSED ||
            sk->sk_state == SAL_LISTEN ||
            sk->sk_state == SAL_REQUEST)
                return -1;
                
        switch(ssk->sal_state) {
        case SAL_RSYN_INITIAL:
                serval_sock_set_sal_state(sk, SAL_RSYN_RECV);
                break;
        case SAL_RSYN_SENT:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT_RECV);
                break;
        case SAL_RSYN_RECV:
        case SAL_RSYN_SENT_RECV:
                /* Just send another RSYN+ACK to acknowledge the new
                   address change */
                break;
        default:
                LOG_SSK(sk, "RSYN in SAL state %s\n", 
                        serval_sock_sal_state_str(sk));
                return 0;
        }
        
        if (ssk->af_ops->freeze_flow)
                ssk->af_ops->freeze_flow(sk);
        
        ssk->rcv_seq.nxt = ctx->verno + 1;        
        memcpy(&ssk->mig_daddr, &ip_hdr(skb)->saddr, 4);
        rskb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header,
                                GFP_ATOMIC);
        if (!rskb)
                return -ENOMEM;
        
        SAL_SKB_CB(rskb)->flags = SVH_RSYN | SVH_ACK;
        SAL_SKB_CB(rskb)->verno = ssk->snd_seq.nxt++;
        SAL_SKB_CB(rskb)->when = sal_time_stamp;

        return serval_sal_queue_and_push(sk, rskb);
}

static int serval_sal_rcv_fin(struct sock *sk, 
                              struct sk_buff *skb,
                              struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        LOG_SSK(sk, "received SAL FIN\n");
        
        if (!has_valid_control_extension(sk, ctx)) {
                LOG_ERR("Bad control extension\n");
                return -1;
        }
        
        sk->sk_shutdown |= RCV_SHUTDOWN;
        sock_set_flag(sk, SOCK_DONE);

        ssk->rcv_seq.nxt = ctx->verno + 1;
        
        /* If there is still an application attached to the
           sock, then wake it up. */
        if (!sock_flag(sk, SOCK_DEAD)) {
                LOG_SSK(sk, "Wake user\n");
                sk->sk_state_change(sk);
                
                /* Do not send POLL_HUP for half
                   duplex close. */
                if (sk->sk_shutdown == SHUTDOWN_MASK ||
                    sk->sk_state == SAL_CLOSED)
                        sk_wake_async(sk, SOCK_WAKE_WAITD, 
                                      POLL_HUP);
                else
                        sk_wake_async(sk, SOCK_WAKE_WAITD, 
                                      POLL_IN);
        }

        err = serval_sal_send_ack(sk);
        
        return err;
}

static int serval_sal_connected_state_process(struct sock *sk,
                                              struct sk_buff *skb,
                                              struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        char should_drop = 0, should_close = 0;

        err = serval_sal_ack_process(sk, skb, ctx);

        if (ctx->flags & SVH_FIN) {
                err = serval_sal_rcv_fin(sk, skb, ctx);
                
                if (err == 0)
                        should_close = 1;
        }

        /* Should pass FINs to transport and ultimately the user, as
         * it needs to pick it off its receive queue to notice EOF. */
        if (packet_has_transport_hdr(skb, ctx->hdr) || 
            (ctx->flags & SVH_FIN)) {
                /* Set the received service id.

                   NOTE: The transport protocol is free to overwrite
                   the control block with its own information. TCP
                   does this, for sure.
                 */
                SAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                ssk->last_rcv_tstamp = sal_time_stamp;
                err = ssk->af_ops->receive(sk, skb);
        } else {
                /* No transport header, so we just drop the packet
                 * since there is nothing more to do with it. */
                err = 0;
                should_drop = 1;
        }

        if (should_close)
                serval_sock_set_state(sk, SAL_CLOSEWAIT);

        if (should_drop)
                kfree_skb(skb);

        return err;
}

static int serval_sal_closewait_state_process(struct sock *sk, 
                                              struct sk_buff *skb,
                                              struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        if (ctx->flags & SVH_FIN)
                serval_sal_send_ack(sk);

        serval_sal_ack_process(sk, skb, ctx);

        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                /* Set the received service id.

                   NOTE: The transport protocol is free to overwrite
                   the control block with its own information. TCP
                   does this, for sure.
                 */
                SAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;

                err = ssk->af_ops->receive(sk, skb);
        } else {
                goto drop;
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

/*
  This function works as the initial receive function for a child
  socket that has just been created by a parent (as a result of
  successful connection handshake).

  The processing resembles that which happened for the parent socket
  when this packet was first received by the parent.

*/
static int serval_sal_child_process(struct sock *parent, 
                                    struct sock *child,
                                    struct sk_buff *skb,
                                    struct sal_context *ctx)
{
        int ret = 0;
        int state = child->sk_state;

        /* child sock is already locked here */

        /* Check lock on child socket, similarly to how we handled the
           parent sock for the incoming skb. */
        if (!sock_owned_by_user(child)) {

                ret = serval_sal_state_process(child, skb, ctx);

                if (ret == 0 && 
                    state == SAL_RESPOND && 
                    child->sk_state != state) {
                        LOG_SSK(parent, "waking up parent (listening) sock\n");
                        parent->sk_data_ready(parent, 0);
                }
        } else {
                /* 
                   User got lock, add skb to backlog so that it will
                   be processed in user context when the lock is
                   released.
                */
                __sk_add_backlog(child, skb);
        }

        bh_unlock_sock(child);
        sock_put(child);
        LOG_SSK(child, "child refcnt=%d\n", atomic_read(&child->sk_refcnt));
        return ret;
}

static int serval_sal_listen_state_process(struct sock *sk,
                                           struct sk_buff *skb,
                                           struct sal_context *ctx)
{
        /* Is this a SYN? */
        if ((ctx->flags & SVH_SYN) && !(ctx->flags & SVH_ACK)) {
                struct request_sock *rsk = serval_sal_find_rsk(sk, ctx);
                
                if (rsk) {
                        LOG_SSK(sk, "SYN already received, dropping!\n");
                        serval_sal_send_synack(sk, rsk, skb, ctx);
                        goto drop;
                }
                return serval_sal_rcv_syn(sk, skb, ctx);
        } else if (ctx->flags & SVH_ACK) {
                        struct sock *nsk;
                        /* Processing for socket that has received SYN
                           already */

                        LOG_SSK(sk, "received ACK\n");
                        
                        nsk = serval_sal_request_sock_handle(sk, skb, ctx);
                        
                        /* The new sock is already locked here */

                        if (nsk && nsk != sk) {
                                return serval_sal_child_process(sk, nsk,
                                                                skb, ctx);
                        }
                        kfree_skb(skb);
        } else {
                serval_sal_send_reset(sk, skb, ctx);
                goto drop;
        }

        return 0;

 drop:
        kfree_skb(skb);
        return 0;
}

static int serval_sal_request_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sal_hdr *sh = ctx->hdr;
        struct sk_buff *rskb;
        int err = 0;
                
        if (!has_valid_control_extension(sk, ctx))
                goto drop;
        
        if (!((ctx->flags & SVH_SYN) && (ctx->flags & SVH_ACK))) {
                LOG_ERR("packet is not a SYN-ACK response\n");
                goto drop;
        }

        /* Process ACK */
        if (serval_sal_ack_process(sk, skb, ctx) != 0) {
                LOG_SSK(sk, "ACK is invalid\n");
                goto drop;
        }
        
        LOG_SSK(sk, "Got RESPONSE verno=%u ackno=%u TCP off=%u hdrlen=%u\n",
                ctx->verno, ctx->ackno,
                skb_transport_header(skb) - (unsigned char *)sh,
                ctx->hdr->shl << 2);

        /* Save device and peer flow id */
        serval_sock_set_dev(sk, skb->dev->ifindex);

        /* Save IP addresses. These are important for checksumming in
           transport protocols */
        if (ctx->src_ext) {
                /* The previous source address is our true destination. */
                memcpy(&inet_sk(sk)->inet_daddr, 
                       SAL_SOURCE_EXT_GET_LAST_ADDR(ctx->src_ext), 
                       sizeof(inet_sk(sk)->inet_daddr));
#if defined(ENABLE_DEBUG)
                {
                        char dststr[18];
                        LOG_SSK(sk, "Response had source extension, using %s as service IP\n",
                                inet_ntop(AF_INET, &inet_sk(sk)->inet_daddr,
                                          dststr, 18)); 
                }
#endif
        } else {
                memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
                       sizeof(inet_sk(sk)->inet_daddr));
        }

        /* This should be our own address of the incoming interface */
        memcpy(&inet_sk(sk)->inet_saddr, &ip_hdr(skb)->daddr, 
               sizeof(inet_sk(sk)->inet_saddr));

        /* Save nonce */
        memcpy(ssk->peer_nonce, ctx->ctrl_ext->nonce, SAL_NONCE_SIZE);

        /* Update socket ids */
        memcpy(&ssk->peer_flowid, &sh->src_flowid, 
               sizeof(sh->src_flowid));
      
        /* Update expected rcv sequence number */
        ssk->rcv_seq.nxt = ctx->verno + 1;
        
        /* Let transport know about the response */
        if (ssk->af_ops->request_state_process) {
                err = ssk->af_ops->request_state_process(sk, skb);

                if (err) {
                        LOG_ERR("Transport drops packet\n");
                        goto error;
                }
        }

        /* Move to connected state */
        serval_sock_set_state(sk, SAL_CONNECTED);
        
        /* Let application know we are connected. */
	if (!sock_flag(sk, SOCK_DEAD)) {
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        }

        /* Allocate ACK */
        rskb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, GFP_ATOMIC);

        if (!rskb) {
                err = -ENOMEM;
                goto error;
        }
        
        /* Ask transport to fill in*/
        if (ssk->af_ops->conn_build_ack) {
                err = ssk->af_ops->conn_build_ack(sk, rskb);

                if (err) {
                        LOG_ERR("Transport drops packet on building ACK\n");
                        goto error;
                }
        }
        
        /* Update control block */
        SAL_SKB_CB(rskb)->flags = SVH_ACK | SVH_CONN_ACK;

        /* Do not increase sequence number for pure ACK */
        SAL_SKB_CB(rskb)->verno = ssk->snd_seq.nxt;
        rskb->protocol = IPPROTO_SERVAL;

        /* Xmit, do not queue ACK */
        err = serval_sal_transmit_skb(sk, rskb, 0, GFP_ATOMIC);

drop: 
        kfree_skb(skb);

        return 0;
error:
        return err;
}

static int serval_sal_respond_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        if (!has_valid_control_extension(sk, ctx))
                goto drop;

        /* Process ACK */
        if (serval_sal_ack_process(sk, skb, ctx) == 0) {
                LOG_SSK(sk, "\n");

                /* Save device */
                serval_sock_set_dev(sk, skb->dev->ifindex);

                memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
                       sizeof(inet_sk(sk)->inet_daddr));

                if (ssk->af_ops->respond_state_process) {
                        err = ssk->af_ops->respond_state_process(sk, skb);

                        if (err) {
                                LOG_WARN("Transport drops ACK\n");
                                goto error;
                        }
                }

                /* Valid ACK */
                serval_sock_set_state(sk, SAL_CONNECTED);

                /* Let user know */
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        }
drop:
        kfree_skb(skb);
error:
        return 0;
}

static int serval_sal_finwait1_state_process(struct sock *sk, 
                                             struct sk_buff *skb,
                                             struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        int ack_ok = 0;

        if (ctx->flags & SVH_ACK && 
            serval_sal_ack_process(sk, skb, ctx) == 0)
                ack_ok = 1;

        if (ctx->flags & SVH_FIN) {
                if (serval_sal_rcv_fin(sk, skb, ctx) == 0) {
                        if (ack_ok)
                                serval_sal_timewait(sk, SAL_TIMEWAIT, 
                                                    SAL_TIMEWAIT_LEN);
                        else
                                serval_sock_set_state(sk, SAL_CLOSING);
                }
        } else if (ack_ok) {
                serval_sal_timewait(sk, SAL_FINWAIT2, SAL_FIN_TIMEOUT);
        }
        
        if (packet_has_transport_hdr(skb, ctx->hdr) || 
            ctx->flags & SVH_FIN) {
                /* Set the received service id */
                SAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                err = 0;
                goto drop;
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

static int serval_sal_finwait2_state_process(struct sock *sk, 
                                             struct sk_buff *skb,
                                             struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        
        /* We've received our FIN-ACK already */
        if (ctx->flags & SVH_FIN) {
                err = serval_sal_rcv_fin(sk, skb, ctx);

                if (err == 0) {
                        serval_sal_timewait(sk, SAL_TIMEWAIT, 
                                            SAL_TIMEWAIT_LEN);
                }
        }

        if (packet_has_transport_hdr(skb, ctx->hdr) ||
            ctx->flags & SVH_FIN) {
                /* Set the received service id */
                SAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                err = 0;
                goto drop;
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

static int serval_sal_closing_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
                
        if ((ctx->flags & SVH_ACK) && 
            serval_sal_ack_process(sk, skb, ctx) == 0) {
                /* ACK was valid */
                serval_sal_timewait(sk, SAL_TIMEWAIT, SAL_TIMEWAIT_LEN);
        }

        if (ctx->flags & SVH_FIN) {
                serval_sal_send_ack(sk);
        }

        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                /* Set the received service id */
                SAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                goto drop;
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

static int serval_sal_lastack_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0, ack_ok;
        
        LOG_SSK(sk, "SAL pkt %s\n", sal_hdr_to_str(ctx->hdr));

        if (ctx->flags & SVH_FIN)
                serval_sal_send_ack(sk);

        ack_ok = serval_sal_ack_process(sk, skb, ctx) == 0;
                
        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                /* Set the received service id */
                SAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                err = 0;
                kfree_skb(skb);
        }

        if (ack_ok) {
                /* ACK was valid */
                LOG_SSK(sk, "Valid ACK, closing socket\n");
                serval_sal_done(sk);
        } else {
                LOG_SSK(sk, "Packet not a valid ACK\n");
        }

        return err;
}

/*
  Receive for datagram sockets that are not connected.
*/
static int serval_sal_init_state_process(struct sock *sk, 
                                         struct sk_buff *skb,
                                         struct sal_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        if (ssk->hash_key && ctx->srv_ext[0] && ctx->srv_ext[1]) {
                LOG_SSK(sk, "Receiving unconnected datagram for service %s\n", 
                        service_id_to_str((struct service_id*) ssk->hash_key));
        } else {
                LOG_SSK(sk, "Non-matching datagram\n");
                return -1;
        }

        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                /* Set source serviceID */
                SAL_SKB_CB(skb)->srvid = &ctx->srv_ext[1]->srvid; 
                err = ssk->af_ops->receive(sk, skb);
        } else {
                kfree_skb(skb);
                err = 0;
        }

        return err;
}

int serval_sal_state_process(struct sock *sk, 
                             struct sk_buff *skb,
                             struct sal_context *ctx)
{
        int err = 0;

#if defined(ENABLE_DEBUG)
        {
                char buf[512];
                LOG_SSK(sk, "SAL %s\n",
                        serval_sock_print_state(sk, buf, 512));
        }
#endif
        if (ctx->ctrl_ext) {                
                if (!has_valid_verno(ctx->verno, sk))
                        goto drop;

                /* Is this a reset packet */
                if (ctx->ctrl_ext->rst) {
                        serval_sal_rcv_reset(sk);
                        goto drop;
                }
                
                /* Check for migration */
                if (ctx->ctrl_ext->rsyn) {
                        if (ctx->ctrl_ext->ack)
                                err = serval_sal_rcv_rsynack(sk, skb, ctx);
                        else
                                err = serval_sal_rcv_rsyn(sk, skb, ctx);
                }
        }
        serval_sk(sk)->tot_pkts_recv++;
        serval_sk(sk)->tot_bytes_recv += skb->len;

        switch (sk->sk_state) {
        case SAL_INIT:
                if (sk->sk_type == SOCK_DGRAM) 
                        err = serval_sal_init_state_process(sk, skb, ctx);
                else
                        goto drop;
                break;
        case SAL_CONNECTED:
                err = serval_sal_connected_state_process(sk, skb, ctx);
                break;
        case SAL_REQUEST:
                err = serval_sal_request_state_process(sk, skb, ctx);
                break;
        case SAL_RESPOND:
                err = serval_sal_respond_state_process(sk, skb, ctx);
                break;
        case SAL_LISTEN:
                err = serval_sal_listen_state_process(sk, skb, ctx);
                break;
        case SAL_FINWAIT1:
                err = serval_sal_finwait1_state_process(sk, skb, ctx);
                break;
        case SAL_FINWAIT2:
                err = serval_sal_finwait2_state_process(sk, skb, ctx);
                break;
        case SAL_CLOSING:
                err = serval_sal_closing_state_process(sk, skb, ctx);
                break;
        case SAL_LASTACK:
                err = serval_sal_lastack_state_process(sk, skb, ctx);
                break;
        case SAL_TIMEWAIT:
                /* Resend ACK of FIN in case our previous one got lost */
                if (ctx->ctrl_ext && ctx->ctrl_ext->fin)
                        serval_sal_send_ack(sk);
                goto drop;
        case SAL_CLOSEWAIT:
                err = serval_sal_closewait_state_process(sk, skb, ctx);
                break;
        case SAL_CLOSED:
                serval_sal_send_reset(sk, skb, ctx);
                goto drop;
        default:
                LOG_ERR("bad socket state %s %u\n", 
                        serval_sock_state_str(sk), sk->sk_state);
                goto drop;
        }
                
        if (err) {
                LOG_ERR("Error on receive: %d\n", err);
        }

        return 0;
drop:
        kfree_skb(skb);

        return 0;
}

static int serval_sal_do_rcv_ctx(struct sock *sk, struct sk_buff *skb, 
                                 struct sal_context *ctx)
{
        /* We can safely use __skb_pull here, because we have already
         * linearized the SAL header part of the skb */
        __skb_pull(skb, ctx->length);

        /* Repoint to the transport header pointer to the actual
         * transport layer header */
        skb_reset_transport_header(skb);
        
        SAL_SKB_CB(skb)->flags = ctx->flags;
        SAL_SKB_CB(skb)->srvid = NULL;
        
        return serval_sal_state_process(sk, skb, ctx);
}

/* 
   This function is called when processing the backlog, and must
   conform to that interface. We have to reparse the Serval headers.
 */
int serval_sal_do_rcv(struct sock *sk, struct sk_buff *skb)
{
        struct sal_context ctx;

        if (serval_sal_parse_hdr(skb, &ctx, SAL_PARSE_ALL)) {
                LOG_ERR("Could not parse Serval header\n");
                kfree_skb(skb);
                return -1;
        }

        return serval_sal_do_rcv_ctx(sk, skb, &ctx);
}

void serval_sal_error_rcv(struct sk_buff *skb, u32 info)
{
        LOG_WARN("ICMP error handling not implemented!\n");
        
        /* TODO: deal with ICMP errors, e.g., wake user and report. */
}

/* Resolution return values. */
enum {
        SAL_RESOLVE_ERROR = -1,
        SAL_RESOLVE_NO_MATCH,
        SAL_RESOLVE_DEMUX,
        SAL_RESOLVE_FORWARD,
        SAL_RESOLVE_DELAY,
        SAL_RESOLVE_DROP,
};

static int serval_sal_update_transport_csum(struct sk_buff *skb,
                                            int protocol)
{
        struct iphdr *iph = ip_hdr(skb);

        skb->ip_summed = CHECKSUM_NONE;
        
        switch (protocol) {
        case SERVAL_PROTO_TCP:
                tcp_hdr(skb)->check = 0;
                skb->csum = csum_partial(tcp_hdr(skb),
                                         skb->len, 0);
                tcp_hdr(skb)->check = 
                        csum_tcpudp_magic(iph->saddr, 
                                          iph->daddr, 
                                          skb->len, 
                                          IPPROTO_TCP, 
                                          skb->csum);
                break;
        case SERVAL_PROTO_UDP:
                udp_hdr(skb)->check = 0;
                skb->csum = csum_partial(udp_hdr(skb),
                                         skb->len, 0);
                udp_hdr(skb)->check = 
                        csum_tcpudp_magic(iph->saddr, 
                                          iph->daddr, 
                                          skb->len, 
                                          IPPROTO_UDP, 
                                          skb->csum);
                break;
        default:
                LOG_INF("Unknown transport protocol %u, "
                        "forgoing checksum calculation\n",
                        protocol);
                break;
        }
        
        return 0;
}

static int serval_sal_resolve_service(struct sk_buff *skb, 
                                      struct sal_context *ctx,
                                      struct service_id *srvid,
                                      struct sock **sk)
{
        struct service_entry* se = NULL;
        struct service_iter iter;
        struct target *target = NULL;
        unsigned int hdr_len = ctx->length;
        unsigned int num_forward = 0;
        unsigned int data_len = skb->len - hdr_len;
        int err = SAL_RESOLVE_NO_MATCH;

        *sk = NULL;

        LOG_DBG("Resolve or demux inbound packet on serviceID %s\n", 
                service_id_to_str(srvid));

        /* Match on the highest priority srvid rule, even if it's not
         * the sock TODO - use flags/prefix in resolution This should
         * probably be in a separate function call
         * serval_sal_transit_rcv or resolve something
         */
        se = service_find(srvid, SERVICE_ID_MAX_PREFIX_BITS);

        if (!se) {
                LOG_INF("No matching service entry for serviceID %s\n",
                        service_id_to_str(srvid));
                return SAL_RESOLVE_NO_MATCH;
        }
        
	if (service_iter_init(&iter, se, SERVICE_ITER_ANYCAST) < 0)
                return SAL_RESOLVE_ERROR;
        
        /*
          Send to all targets listed for this service.
        */
        target = service_iter_next(&iter);

        if (!target) {
                LOG_INF("No target to forward on!\n");
                service_iter_inc_stats(&iter, -1, data_len);
                service_iter_destroy(&iter);
                service_entry_put(se);
                return SAL_RESOLVE_NO_MATCH;
        }

        service_iter_inc_stats(&iter, 1, data_len);
                
        while (target) {
                struct target *next_target;
                struct sk_buff *cskb = NULL;
                struct iphdr *iph;
                unsigned int iph_len;
                unsigned int protocol = sal_hdr(skb)->protocol;
                int ret = 0;
                
                next_target = service_iter_next(&iter);
                
                if (target->type == SERVICE_RULE_DEMUX) {
                        /* local resolution */
                        *sk = target->out.sk;
                        sock_hold(*sk);
                        err = SAL_RESOLVE_DEMUX;
                        num_forward++;
                        break;
                } else if (target->type == SERVICE_RULE_DELAY) {
                        delay_queue_skb(cskb, srvid);
                        err = SAL_RESOLVE_DELAY;
                        num_forward++;
                        break;
                } else if (target->type == SERVICE_RULE_DROP) {
                        err = SAL_RESOLVE_DROP;
                        num_forward++;
                        break;
                }

                /* We only get here if we resolved on a FORWARD RULE */
                err = SAL_RESOLVE_FORWARD;

                if (skb->pkt_type != PACKET_HOST &&
                    skb->pkt_type != PACKET_OTHERHOST) {
                        /* Do not forward, e.g., broadcast
                           packets as they may cause
                           resolution loops. */
                        LOG_DBG("Broadcast packet. Not forwarding\n");
                        err = SAL_RESOLVE_DROP;
                        break;
                }
                
                if (!next_target && !(*sk)) {
                        /* Only consume this skb if there are no more
                           targets and we didn't resolve to a local
                           socket (in which case we must continue
                           processing the packet after this function
                           returns). */
                        cskb = skb;
                } else {
                        cskb = skb_copy(skb, GFP_ATOMIC);
                        
                        if (!cskb) {
                                LOG_ERR("Skb allocation failed\n");
                                err = SAL_RESOLVE_DROP;
                                break;
                        }
                }

                iph = ip_hdr(cskb);
                iph_len = iph->ihl << 2;
#if defined(OS_USER)
                /* Set the output device - ip_forward uses the
                 * out device specified in the dst_entry route
                 * and assumes that skb->dev is the input
                 * interface*/
                if (target->out.dev)
                        cskb->dev = target->out.dev;
#endif /* OS_LINUX_KERNEL */
                
                /* Set the true overlay source address if the
                 * packet may be ingress-filtered user-level
                 * raw socket forwarding may drop the packet
                 * if the source address is invalid */
                ret = serval_sal_add_source_ext(&cskb, ctx);
                
                if (ret < 0) {
                        LOG_ERR("Failed to add source extension, err=%d\n", 
                                ret);
                        
                        /* Need to free the skb if it's a copy */
                        if (cskb != skb) {
                                LOG_ERR("Freeing skb copy\n");
                                kfree_skb(cskb);
                        }
                        /* Try next target */
                } else {
                        iph = ip_hdr(cskb);
                        hdr_len += ret;
                        
                        /* Update destination address */
                        memcpy(&iph->daddr, target->dst, sizeof(iph->daddr));
                        
                        /* Must recalculate transport checksum. Pull
                           to reveal transport header */
                        pskb_pull(cskb, hdr_len);
                        skb_reset_transport_header(cskb);
                        
                        serval_sal_update_transport_csum(cskb,
                                                         protocol);
                        
                        /* Push back to Serval header */
                        skb_push(cskb, hdr_len);
                        skb_reset_transport_header(cskb);
                        
                        /* Recalculate SAL checksum */
                        serval_sal_send_check(sal_hdr(cskb));

                        /* Push back to IP header */
                        skb_push(cskb, iph_len);
                                                
                        ret = serval_ipv4_forward_out(cskb);
                        
                        if (ret) {
                                /* serval_ipv4_forward_out has taken
                                   custody of packet, no need to
                                   free. */
                                LOG_ERR("Forwarding failed\n");
                        } else 
                                num_forward++;
                }
                target = next_target;
        }
        
        if (num_forward == 0)
                service_iter_inc_stats(&iter, -1, -data_len);
        
        service_iter_destroy(&iter);
        service_entry_put(se);

        return err;
}

static struct sock *serval_sal_demux_service(struct sk_buff *skb, 
                                             struct service_id *srvid,
                                             int protocol)
{
        struct sock *sk;

        LOG_DBG("Demux on serviceID %s\n", service_id_to_str(srvid));

        /* only allow listening socket demux */
        sk = serval_sock_lookup_service(srvid, protocol);
        
        if (!sk) {
                LOG_INF("No matching sock for serviceID %s\n",
                        service_id_to_str(srvid));
        } else {
                LOG_DBG("Socket is %p\n", sk);
        }
        
        return sk;
}

static struct sock *serval_sal_demux_flow(struct sk_buff *skb, 
                                          struct sal_context *ctx)
{
        struct sock *sk = NULL;
        
        /* If this is a SYN, then we know that we must demux on
           service */
        if (ctx->ctrl_ext && 
            ctx->ctrl_ext->syn && 
            !ctx->ctrl_ext->ack)
                return NULL;

        /* Ok, try to demux on flowID */
        sk = serval_sock_lookup_flow(&ctx->hdr->dst_flowid);
                
        if (!sk) {
                LOG_INF("No matching sock for flowid %s\n",
                        flow_id_to_str(&ctx->hdr->dst_flowid));
        }

        return sk;
}

static int serval_sal_resolve(struct sk_buff *skb, 
                              struct sal_context *ctx,
                              struct sock **sk)
{
        int ret = SAL_RESOLVE_NO_MATCH;
        struct service_id *srvid = NULL;
        
        if (ctx->length <= SAL_HEADER_LEN)
                return SAL_RESOLVE_ERROR;
        
        if (!ctx->srv_ext[0])
                return SAL_RESOLVE_ERROR;

        srvid = &ctx->srv_ext[0]->srvid;

        if (net_serval.sysctl_sal_forward) {
                ret = serval_sal_resolve_service(skb, ctx, srvid, sk);
        } else {
                *sk = serval_sal_demux_service(skb, srvid, ctx->hdr->protocol);
                
                if (*sk)
                        ret = SAL_RESOLVE_DEMUX;
        }
        
        return ret;
}

static int serval_sal_rcv_finish(struct sock *sk, 
                                 struct sk_buff *skb, 
                                 struct sal_context *ctx)
{
        int err = 0;

        bh_lock_sock_nested(sk);

        LOG_SSK(sk, "SAL %s\n", sal_hdr_to_str(ctx->hdr));

        /* We only reach this point if a valid local socket destination
         * has been found */
        
        err = serval_sal_do_rcv_ctx(sk, skb, ctx);

        bh_unlock_sock(sk);
        sock_put(sk);

        if (err != 0) {
                service_inc_stats(-1, -(skb->len - ctx->length));
        }

	return err;
}

int serval_sal_reresolve(struct sk_buff *skb)
{
        struct sal_context ctx;
        struct sock *sk;
        int err = 0;

        LOG_DBG("Reresolving packet\n");

        if (serval_sal_parse_hdr(skb, &ctx, SAL_PARSE_ALL)) {
                LOG_DBG("Bad Serval header %s\n",
                        ctx.hdr ? sal_hdr_to_str(ctx.hdr) : "NULL");
                kfree_skb(skb);
                return -1;
        }

        err = serval_sal_resolve(skb, &ctx, &sk);

        switch (err) {
        case SAL_RESOLVE_DEMUX:
                return serval_sal_rcv_finish(sk, skb, &ctx);
        case SAL_RESOLVE_FORWARD:                
                return 0;
        case SAL_RESOLVE_DELAY:
                return err;
        case SAL_RESOLVE_NO_MATCH:
        case SAL_RESOLVE_DROP:
                LOG_DBG("RESOLVE NO_MATCH or DROP\n");
                err = -EHOSTUNREACH;
                break;
        case SAL_RESOLVE_ERROR:
                LOG_ERR("RESOLVE ERROR\n");
                err = -EHOSTUNREACH;
        default:
                if (sk)
                        sock_put(sk);
        }

        kfree_skb(skb);
        
        return err;
}

int serval_sal_rcv(struct sk_buff *skb)
{
        struct sock *sk = NULL;
        struct sal_context ctx;
        unsigned int sal_length;
        int err = 0;
        
#if defined(ENABLE_DEBUG)
        {
                struct iphdr *iph = ip_hdr(skb);
                char src[18], dst[18];

                LOG_PKT("skb->len=%u : %s -> %s\n",
                        skb->len, 
                        inet_ntop(AF_INET, &iph->saddr, src, 18),
                        inet_ntop(AF_INET, &iph->daddr, dst, 18));
        }
#endif

        if (skb->len < SAL_HEADER_LEN) {
                LOG_DBG("skb length too short (%u bytes)\n", 
                        skb->len);
                goto drop;
        }
        
        /* First see if we can pull the base header, because we know
         * the packet should have at least that size SAL header. Note,
         * we cannot simply look into the packet and check the real
         * SAL header length (including extensions), because the skb
         * migth be paged. This function call will also linearize the
         * requested length. */
        if (!pskb_may_pull(skb, SAL_HEADER_LEN)) {
                LOG_DBG("Cannot pull base SAL header\n",
                        SAL_HEADER_LEN);
                goto drop;
        }
        
        /* Now we can actually look into the base header */
        sal_length = sal_hdr(skb)->shl << 2;

        if (sal_length > SAL_HEADER_LEN) {
                /* There are extensions, so we need to check that we
                 * can pull more than the base header */
                if (!pskb_may_pull(skb, sal_length)) {
                        LOG_DBG("Cannot pull %u bytes SAL header\n",
                                sal_length);
                        goto drop;
                }
        }

        /* Ok, we are ready to parse the full header. */       
        if (serval_sal_parse_hdr(skb, &ctx, SAL_PARSE_ALL)) {
                LOG_DBG("Bad Serval header %s\n",
                        ctx.hdr ? sal_hdr_to_str(ctx.hdr) : "NULL");
                goto drop;
        }
        
        if (unlikely(serval_sal_csum(ctx.hdr, ctx.length))) {
                LOG_DBG("SAL checksum error!\n");
                goto drop;
        }       

        sk = serval_sal_demux_flow(skb, &ctx);
        
        if (!sk) {
                /* Resolve on serviceID */
                err = serval_sal_resolve(skb, &ctx, &sk);
                
                switch (err) {
                case SAL_RESOLVE_DEMUX:
                        break;
                case SAL_RESOLVE_FORWARD:
                        /* Packet forwarded on out device */
                        LOG_PKT("SAL FORWARD\n");
                        return NET_RX_SUCCESS;
                case SAL_RESOLVE_DELAY:
                        LOG_PKT("SAL DELAY\n");
                        /* Packet in delay queue */
                        return NET_RX_SUCCESS;
                case SAL_RESOLVE_NO_MATCH:
                        if (!(ctx.flags & SVH_SYN && 
                              !(ctx.flags & SVH_ACK)))
                                serval_sal_send_reset(NULL, skb, &ctx);
                case SAL_RESOLVE_DROP:
                case SAL_RESOLVE_ERROR:
                default:
                        LOG_PKT("SAL DROPPING %s\n", sal_hdr_to_str(ctx.hdr));
                        goto drop;
                }
        }

        /* We could potentially call sk_receive_skb() here, which does
           pretty much the same thing as
           serval_sal_rcv_finish(). However, sk_receive_skb() sets
           skb->dev to NULL, so that later processing won't be able to
           learn the incoming interface. */
        err = serval_sal_rcv_finish(sk, skb, &ctx);
        
        if (err < 0)
                return NET_RX_DROP;
      
        return NET_RX_SUCCESS;
 drop:
        if (sk)
                sock_put(sk);

        service_inc_stats(-1, -(skb->len - ctx.length));
        kfree_skb(skb);

        /* We always return zero here, since function processes an
           inbound packet and the IP layer that passed us this packet
           expects a zero return value. */
        return NET_RX_DROP;
}

#ifdef __DISABLED__
static int serval_sal_xmit_probe_skb(struct sock *sk, int urgent)
{
	struct serval_sock *ssk = serval_sk(sk);
	struct sk_buff *skb;

	skb = alloc_skb(MAX_SAL_HDR, GFP_ATOMIC);

	if (!skb)
		return -1;

	skb_reserve(skb, MAX_SAL_HDR);
        skb_serval_set_owner_w(skb, sk);
        skb->protocol = IPPROTO_SERVAL;
        skb->ip_summed = CHECKSUM_NONE;
        SAL_SKB_CB(skb)->flags = SVH_ACK;
	SAL_SKB_CB(skb)->when = sal_time_stamp;
        SAL_SKB_CB(skb)->verno = ssk->snd_seq.nxt;

	return serval_sal_transmit_skb(sk, skb, 0, GFP_ATOMIC);
}

#endif /* __DISABLED__ */

/* FIXME: Keepalive currently not completely implemented. */
int serval_sal_send_keepalive_probe(struct sock *sk)
{
	if (sk->sk_state == SAL_CLOSED)
		return -1;

        return 0; /* serval_sal_xmit_probe_skb(sk, 0); */
}

static int serval_sal_rexmit(struct sock *sk)
{        
        struct sk_buff *skb;
        int err = 0;

        skb = serval_sal_ctrl_queue_head(sk);
        
        if (!skb) {
                LOG_ERR("No packet to retransmit!\n");
                return -1;
        }

        SAL_SKB_CB(skb)->flags |= SVH_RETRANS;

        /* Always clone retransmitted packets */
        err = serval_sal_transmit_skb(sk, skb, 1, GFP_ATOMIC);
        
        if (err < 0) {
                LOG_ERR("Retransmit failed\n");
        }

        return err;
}

static void serval_sal_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

        LOG_SSK(sk, "Write ERROR, socket DONE\n");
	serval_sal_done(sk);
}

void serval_sal_rexmit_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        struct serval_sock *ssk = serval_sk(sk);

        LOG_SSK(sk, "Retransmit timeout\n");

        bh_lock_sock(sk);

        LOG_SSK(sk, "Transmit timeout sock=%p rto_msecs=%u backoff=%u\n", 
                sk, jiffies_to_msecs(ssk->rto), ssk->backoff);

        if (ssk->retransmits == net_serval.sysctl_sal_max_retransmits) {
                /* TODO: check error values here */
                LOG_SSK(sk, "max retransmits=%u reached. NOT rescheduling timer! Closing socket\n",
                        net_serval.sysctl_sal_max_retransmits);
                serval_sal_write_err(sk);
        } else {
                LOG_SSK(sk, "ReXmit and rescheduling timer (attempt %d)\n",
                        ssk->retransmits);
                serval_sal_rexmit(sk);

                ssk->backoff++;
                ssk->retransmits++;
                
                serval_sock_reset_xmit_timer(sk, min(ssk->rto << ssk->backoff, 
                                                     SAL_RTO_MAX),
                                             SAL_RTO_MAX);
        }
        bh_unlock_sock(sk);
        sock_put(sk);
}

/* This timeout is used for TIMEWAIT and FINWAIT2 */
void serval_sal_timewait_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        bh_lock_sock(sk);
        LOG_SSK(sk, "Timeout in state %s\n", serval_sock_state_str(sk));
        serval_sal_done(sk);
        bh_unlock_sock(sk);
        /* put for the timer. */
        sock_put(sk);
}

static void serval_sal_synack_timeout(struct sock *sk)
{
	/* serval_sock_reqsk_queue_prune(sk, TCP_SYNQ_INTERVAL,
           TCP_TIMEOUT_INIT, TCP_RTO_MAX); */
}

void serval_sal_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (SALF_CLOSED | SALF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		serval_sock_reset_keepalive_timer(sk, serval_sal_keepalive_time_when(serval_sk(sk)));
	else if (!val)
		serval_sock_delete_keepalive_timer(sk);
}

static inline int serval_sal_fin_time(const struct sock *sk)
{
	int fin_timeout = sysctl_sal_fin_timeout;
	const int rto = serval_sk(sk)->rto;

	if (fin_timeout < (rto << 2) - (rto >> 1))
		fin_timeout = (rto << 2) - (rto >> 1);

	return fin_timeout;
}

void serval_sal_keepalive_timeout(unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct serval_sock *ssk = serval_sk(sk);
	u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);

	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		serval_sock_reset_keepalive_timer(sk, HZ/20);
		goto out;
	}

	if (sk->sk_state == SAL_LISTEN) {
		serval_sal_synack_timeout(sk);
		goto out;
	}

	if (sk->sk_state == SAL_FINWAIT2 && 
            sock_flag(sk, SOCK_DEAD)) {
                /*
		if (tp->linger2 >= 0) {
			const int tmo = serval_sal_fin_time(sk) - SAL_TIMEWAIT_LEN;

			if (tmo > 0) {
				serval_sal_timewait(sk, SAL_FINWAIT2, tmo);
				goto out;
			}
		}
                */
		//serval_sal_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

	if (!sock_flag(sk, SOCK_KEEPOPEN) || 
            sk->sk_state == SAL_CLOSED)
		goto out;

	//elapsed = serval_sal_keepalive_time_when(ssk);

	/* It is alive without keepalive 8) */
	//if (ssk->packets_out || tcp_send_head(sk))
	//	goto resched;

	elapsed = serval_sal_keepalive_time_elapsed(ssk);

	if (elapsed >= serval_sal_keepalive_time_when(ssk)) {
		if (serval_sal_send_keepalive_probe(sk) <= 0) {
			ssk->probes_out++;
			elapsed = serval_sal_keepalive_intvl_when(ssk);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = SAL_RESOURCE_PROBE_INTERVAL;
		}
	} else {
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		elapsed = serval_sal_keepalive_time_when(ssk) - elapsed;
	}

	sk_mem_reclaim(sk);

        //resched:
	serval_sock_reset_keepalive_timer(sk, elapsed);
	goto out;

death:
	serval_sal_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static int serval_sal_do_xmit(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        struct serval_sock *ssk = serval_sk(sk);
      	uint32_t temp_daddr = 0;
        u8 skb_flags = SAL_SKB_CB(skb)->flags;
        struct net_device *mig_dev = NULL; 
        int err = 0;

        if (skb_flags & SVH_RSYN) {
                mig_dev = dev_get_by_index(sock_net(sk), 
                                           ssk->mig_dev_if);

                if (mig_dev) {
                        dev_get_ipv4_addr(mig_dev,
                                          IFADDR_LOCAL,
                                          &inet_sk(sk)->inet_saddr);
#if defined(ENABLE_DEBUG)
                        {
                                char src[18];
                                LOG_SSK(sk, "Sending on mig_dev %s src=%s\n",
                                        mig_dev->name, 
                                        inet_ntop(AF_INET, 
                                                  &inet_sk(sk)->inet_saddr, 
                                                  src, 18));
                        }
#endif
                        skb->dev = mig_dev;
                } else {
                        LOG_SSK(sk, "No migration device %d\n",
                                ssk->mig_dev_if);
                }
                
                if (ssk->sal_state == SAL_RSYN_RECV) {
#if defined(ENABLE_DEBUG)
                        char dst[18];
                        LOG_SSK(sk, "Sending to migration addr %s\n",
                                inet_ntop(AF_INET, 
                                          &ssk->mig_daddr, 
                                          dst, 18));
#endif
                        memcpy(&temp_daddr, &inet_sk(sk)->inet_daddr, 4);
        	            memcpy(&inet_sk(sk)->inet_daddr, 
                                   &ssk->mig_daddr, 4);
                }
                
                /* Must remove any cached route */
                sk_dst_reset(sk);
        }

        /*
          FIXME: we kind of hard code the outgoing device here based
          on what has been bound to the socket in the connection
          setup phase. Instead, the device should be resolved based
          on, e.g., dst IP (if it exists at this point).

          However, we currently do not implement an IP routing table
          for userlevel, which would otherwise be used for this
          resolution. Kernel space should work, because it routes
          packet according to the kernel's routing table, thus
          figuring out the device along the way.

          Packets that are sent using an advisory IP may fail in
          queue_xmit for userlevel unless the socket has had its
          interface set by a previous send event.
        */
        err = ssk->af_ops->queue_xmit(skb);
        
        if (skb_flags & SVH_RSYN) {
                /* Restore inet_sk(sk)->daddr */
                if (mig_dev) {
                        struct net_device *dev = 
                                dev_get_by_index(sock_net(sk), 
                                                 sk->sk_bound_dev_if);
                                
                        if (dev) {
                                dev_get_ipv4_addr(dev,
                                                  IFADDR_LOCAL,
                                                  &inet_sk(sk)->inet_saddr);
                                dev_put(dev);
                        }
                }
                
                if (ssk->sal_state == SAL_RSYN_RECV) {
                        memcpy(&inet_sk(sk)->inet_daddr, &temp_daddr, 4);
                }
                /* Reset cached route again */
                sk_dst_reset(sk);
        }

        if (err < 0) {
                LOG_ERR("xmit failed err=%d\n", err);
        }
        else {
            ssk->tot_pkts_sent++;
            LOG_SSK(sk, "SKB things: %d %d\n", skb->len, skb->data_len);
            ssk->tot_bytes_sent += skb->len;
        }

        if (mig_dev)
                dev_put(mig_dev);

        return err;
}

static inline int serval_sal_add_ctrl_ext(struct sock *sk, 
                                          struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sal_control_ext *ctrl_ext;

        ctrl_ext = (struct sal_control_ext *)
                skb_push(skb, SAL_CONTROL_EXT_LEN);

        ctrl_ext->ext_type = SAL_CONTROL_EXT;
        ctrl_ext->ext_length = SAL_CONTROL_EXT_LEN;
        ctrl_ext->verno = htonl(SAL_SKB_CB(skb)->verno);
        ctrl_ext->ackno = htonl(ssk->rcv_seq.nxt);
        memcpy(ctrl_ext->nonce, ssk->local_nonce, SAL_NONCE_SIZE);
        ctrl_ext->syn = SAL_SKB_CB(skb)->flags & SVH_SYN ? 1 : 0;
        ctrl_ext->rsyn = SAL_SKB_CB(skb)->flags & SVH_RSYN ? 1 : 0;
        ctrl_ext->ack = SAL_SKB_CB(skb)->flags & SVH_ACK ? 1 : 0;
        ctrl_ext->nack = SAL_SKB_CB(skb)->flags & SVH_NACK ? 1 : 0;
        ctrl_ext->fin = SAL_SKB_CB(skb)->flags & SVH_FIN ? 1 : 0;
        ctrl_ext->rst = SAL_SKB_CB(skb)->flags & SVH_RST ? 1 : 0;

        return SAL_CONTROL_EXT_LEN;
}

static inline int serval_sal_add_service_ext(struct sock *sk, 
                                             struct sk_buff *skb,
                                             struct service_id *srvid)
{
        struct sal_service_ext *srv_ext;

        srv_ext = (struct sal_service_ext *)
                skb_push(skb, SAL_SERVICE_EXT_LEN);
        srv_ext->ext_type = SAL_SERVICE_EXT;
        srv_ext->ext_length = SAL_SERVICE_EXT_LEN;
        service_id_copy(&srv_ext->srvid, srvid);

        return SAL_SERVICE_EXT_LEN;
}

/*
  We currently have no use for PAD extension, because all SAL headers
  are 32-bit aligned.

static inline int serval_sal_add_pad_ext(struct sock *sk, 
                                         struct sk_buff *skb,
                                         unsigned short pad_bytes)
{
        struct sal_pad_ext *pad_ext;

        if (pad_bytes == 0)
                return 0;

        pad_ext = (struct sal_pad_ext *)skb_push(skb, pad_bytes);
        memset(pad_ext, 0, pad_bytes);
        
        return pad_bytes;
}
*/

static struct sal_hdr *serval_sal_build_header(struct sock *sk, 
                                               struct sk_buff *skb)
{
        struct sal_hdr *sh;
        struct serval_sock *ssk = serval_sk(sk);
        unsigned short hdr_len = 0;

        /* Add appropriate extension headers */
        if (SAL_SKB_CB(skb)->flags & SVH_SYN || 
            SAL_SKB_CB(skb)->flags & SVH_RSYN ||
            SAL_SKB_CB(skb)->flags & SVH_FIN ||
            SAL_SKB_CB(skb)->flags & SVH_RST ||
            SAL_SKB_CB(skb)->flags & SVH_ACK) {
                /* The ACK for a SYN-ACK must carry a
                   serviceID. */
                if (SAL_SKB_CB(skb)->flags & SVH_SYN ||
                    SAL_SKB_CB(skb)->flags & SVH_CONN_ACK) {
                        hdr_len += serval_sal_add_service_ext(sk, skb, 
                                                              &ssk->peer_srvid);
                }

                hdr_len += serval_sal_add_ctrl_ext(sk, skb);                
        } else {
                /* Unconnected datagram, add service extensions */
                if (sk->sk_state == SAL_INIT && 
                    sk->sk_type == SOCK_DGRAM) {
                        hdr_len += serval_sal_add_service_ext(sk, skb, &ssk->local_srvid);
                        hdr_len += serval_sal_add_service_ext(sk, skb, &ssk->peer_srvid);
                }
        }

        /* Add SAL base header */
        
        sh = (struct sal_hdr *)skb_push(skb, SAL_HEADER_LEN);
        hdr_len += SAL_HEADER_LEN;
        memcpy(&sh->src_flowid, &ssk->local_flowid, 
               sizeof(ssk->local_flowid));
        memcpy(&sh->dst_flowid, &ssk->peer_flowid, 
               sizeof(ssk->peer_flowid));
        sh->protocol = sk->sk_protocol;
        sh->shl = (hdr_len >> 2);

        skb->protocol = IPPROTO_SERVAL;

#if defined(ENABLE_DEBUG)
        BUG_ON(hdr_len % 4 != 0);
#endif
        return sh;
}

int serval_sal_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                            int use_copy, gfp_t gfp_mask)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct inet_sock *inet = inet_sk(sk);
	struct service_entry *se;
	struct target *target;
        struct sal_hdr *sh;
	int err = -1;
        struct service_iter iter;
        struct sk_buff *cskb = NULL;
        int dlen = skb->len - 8; /* KLUDGE?! TODO not sure where the
                                    extra 8 bytes are coming from at
                                    this point */

    LOG_SSK(sk, "SKB in transmit: %p\n", skb);
	if (likely(use_copy)) {
                /* pskb_copy will make a copy of header and
                   non-fragmented data. Making a copy is necessary
                   since we are changing the TCP header checksum for
                   every copy we send (retransmission or copies for
                   packets matching multiple rules). */
                skb = pskb_copy(skb, gfp_mask);


		if (unlikely(!skb)) {
                        /* Shouldn't free the passed skb here, since
                         * we were asked to use a copy. That probably
                         * means the original skb sits in a queue
                         * somewhere, and freeing it would be bad. */
                        return -ENOBUFS;
                }

                skb_serval_set_owner_w(skb, sk);
	}

        /* NOTE:
         *
         * Do not use skb_set_owner_w(skb, sk) here as that will
         * reserve write space for the socket on the transport

         * packets as they might then fill up the write queue/buffer
         * for the socket. However, skb_set_owner_w(skb, sk) also
         * guarantees that the socket is not released until skb is
         * free'd, which is good. I guess we could implement our own
         * version of skb_set_owner_w() and grab a socket refcount
         * instead, which is released in the skb's destructor.
         */

        /* If we are connected, transmit immediately */
        if ((1 << sk->sk_state) & (SALF_CONNECTED | 
                                   SALF_FINWAIT1 | 
                                   SALF_FINWAIT2 | 
                                   SALF_CLOSING | 
                                   SALF_CLOSEWAIT)) {
                sh = serval_sal_build_header(sk, skb);
                serval_sal_send_check(sh);

                LOG_SSK(sk, "Serval XMIT %s skb->len=%u\n",
                        sal_hdr_to_str(sh), skb->len);

                return serval_sal_do_xmit(skb);
        }
        
	/* Use service id to resolve IP, unless IP is already set. */
        if (memcmp(&zero_addr, 
                   &inet_sk(sk)->inet_daddr, 
                   sizeof(zero_addr)) != 0) {

                skb_reset_transport_header(skb);
                /*
                char ip[18];
                LOG_SSK(sk, "Sending packet to user-specified "
                        "advisory address: %s\n", 
                        inet_ntop(AF_INET, &SAL_SKB_CB(skb)->addr, 
                                  ip, 17));
                */
                /* for user-space, need to specify a device - the
                 * kernel will route */
                sh = serval_sal_build_header(sk, skb);

                serval_sal_send_check(sh);
                
                LOG_SSK(sk, "Serval XMIT %s skb->len=%u\n",
                        sal_hdr_to_str(sh), skb->len);
                
                /* note that the service resolution stats
                 * (packets/bytes) will not be incremented here In the
                 * future, the stats should be defined as SNMP
                 * counters in include/net/snmp.h and incremented with
                 * the appropriate per-cpu atomic inc macros TODO
                 */
                return serval_sal_do_xmit(skb);
        }

        LOG_SSK(sk, "Resolving service %s\n",
                service_id_to_str(&ssk->peer_srvid));

        se = service_find(&ssk->peer_srvid, SERVICE_ID_MAX_PREFIX_BITS);

	if (!se) {
		LOG_SSK(sk, "service lookup failed for [%s]\n",
                        service_id_to_str(&ssk->peer_srvid));
                service_inc_stats(-1, -dlen);
                kfree_skb(skb);
		return -EADDRNOTAVAIL;
	}

	if (service_iter_init(&iter, se, 
                              net_serval.sysctl_resolution_mode) < 0) {
                kfree_skb(skb);
                LOG_ERR("Could not initialize service iterator\n");
                return -1;
        }

        /*
          Send to all destinations resolved for this service.
        */
	target = service_iter_next(&iter);

        if (!target) {
                LOG_SSK(sk, "No device to transmit on!\n");
                service_iter_inc_stats(&iter, -1, -dlen);
                kfree_skb(skb);
                service_iter_destroy(&iter);
                service_entry_put(se);
                return -EHOSTUNREACH;
        }

	while (target) {
		struct target *next_target;
                struct net_device *dev = NULL;
                int local_err = 0;
                
                if (cskb == NULL) {
                        service_iter_inc_stats(&iter, 1, dlen);
                }
                
                next_target = service_iter_next(&iter);
		
                if (next_target == NULL) {
			cskb = skb;
		} else {
                        /* Always be atomic here since we are holding
                         * socket lock */
                        LOG_SSK(sk, "SKB copy 2: %p\n", skb);
                        cskb = pskb_copy(skb, GFP_ATOMIC);
                        
			if (!cskb) {
				LOG_ERR("Allocation failed\n");
                                kfree_skb(skb);
                                err = -ENOBUFS;
				break;
			}
                        /* skb copy will have no socket set. */
                        skb_serval_set_owner_w(cskb, sk);
		}

                if (target->type == SERVICE_RULE_DELAY) {
                        err = delay_queue_skb(cskb, 
                                              &serval_sk(sk)->peer_srvid);
                        target = next_target;
                        continue;
                } else if (target->type == SERVICE_RULE_DROP) {
                        kfree_skb(cskb);
                        err = -EHOSTUNREACH;
                        target = next_target;
                        continue;
                }

                /* Remember the flow destination */
		if (is_sock_target(target)) {
                        /* use a localhost address and bounce it off
                         * the IP layer*/
                        memcpy(&inet->inet_daddr,
                               &local_addr, sizeof(inet->inet_daddr));

                        /* kludgey but sets the output device for
                         * reaching a local socket destination to the
                         * default device TODO - make sure this is
                         * appropriate for kernel operation as well
                         */
#if defined(OS_BSD)
                        dev = __dev_get_by_name(sock_net(sk), "lo0");
#else
                        dev = __dev_get_by_name(sock_net(sk), "lo");
#endif

                        if (!dev) {
                                target = next_target;
                                err = -ENODEV;
                                continue;
                        }
		} else {
                        memcpy(&inet->inet_daddr,
                               target->dst,
                               sizeof(inet->inet_daddr) < target->dstlen ? 
                               sizeof(inet->inet_daddr) : target->dstlen);
                       
                        dev = target->out.dev;
                }
                
                cskb->dev = dev;

                /* Need also to set the source address for
                   checksum calculation */
                if (!dev_get_ipv4_addr(dev, IFADDR_LOCAL,
                                       &inet->inet_saddr)) {
                        LOG_ERR("No source IPv4 address for interface %s\n",
                                dev->name);
                        target = next_target;
                        continue;
                }

#if defined(ENABLE_DEBUG)
                {
                        char src[18], dst[18];
                        LOG_SSK(sk, "Resolved service %s with IP %s->%s " 
                                "on device=%s\n",
                                service_id_to_str(&ssk->peer_srvid),
                                inet_ntop(AF_INET, &inet->inet_saddr, 
                                          src, sizeof(src)), 
                                inet_ntop(AF_INET, &inet->inet_daddr, 
                                          dst, sizeof(dst)), 
                                cskb->dev ? cskb->dev->name : "Undefined");
                }
#endif
                /* Make sure no route is associated with the
                   socket. When IP routes a packet which is associated
                   with a socket, it will stick to that route in the
                   future. This will inhibit a re-resolution, which is
                   not what we want here. */
                
                if (__sk_dst_get(sk))
                        sk_dst_reset(sk);
                
                /*
                  We have to calculate the checksum for resolution
                  packets at this point as it is not until here that
                  we know the destination IP to put in the
                  packet. Normally, the checksum is calculated by the
                  transport protocol before being passed to SAL.
                */
                if (ssk->af_ops->send_check &&
                    packet_has_transport_hdr(cskb, NULL)) {
                        LOG_SSK(sk, "Calculating transport checksum\n");
                        ssk->af_ops->send_check(sk, cskb);
                }

                /* Add SAL header */
                sh = serval_sal_build_header(sk, cskb);

                /* Compute SAL header checksum */
                serval_sal_send_check(sh);

                /* Cannot reset transport header until after checksum
                   calculation since transport send_check requires
                   access to transport header */
                skb_reset_transport_header(cskb);

		local_err = ssk->af_ops->queue_xmit(cskb);

		if (local_err < 0) {
			LOG_ERR("xmit failed on queue_xmit err=%d\n", 
                                local_err);
                        /* Only set error in case we haven't succeeded
                           in transmitting any packet. See comment
                           below. */
                        if (err != 0)
                                err = local_err;
		} else {
                        /* Since we may send a SYN on multiple
                           interfaces, we only want to return an error
                           message in case transmission failed on all
                           interfaces. Once we succeed on any
                           interface, we set return value to
                           success. */
                        err = 0;
                }
                
		target = next_target;
	}
        
        /* Reset dst cache since we don't want to potantially cache a
           broadcast destination */
        if (__sk_dst_get(sk))
                sk_dst_reset(sk);

        /* Zero the address again so that we do not confuse the
           resolution in case of retransmission. */
        memset(&inet_sk(sk)->inet_daddr, 0, 
               sizeof(inet_sk(sk)->inet_daddr));
                   
        service_iter_destroy(&iter);
	service_entry_put(se);
        LOG_DBG("Returning %d\n", err);

	return err;
}

/* This function is typically called by transport to send data */
int serval_sal_xmit_skb(struct sk_buff *skb) 
{
        return serval_sal_transmit_skb(skb->sk, skb, 0, GFP_ATOMIC);
}

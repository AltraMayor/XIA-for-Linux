/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _DST_H_
#define _DST_H_

#include <platform.h>
#include <atomic.h>
#include <skbuff.h>

#if defined(OS_LINUX_KERNEL)
#include <net/dst.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
static inline void dst_metric_set(struct dst_entry *dst, int metric, u32 val)
{
        dst->metrics[metric-1] = val;
}
#endif
#endif
#if defined(OS_USER)
#include <sys/types.h>

#if defined(OS_LINUX)
#include <linux/rtnetlink.h>
#else

enum {
        RTAX_UNSPEC,
#define RTAX_UNSPEC RTAX_UNSPEC
        RTAX_LOCK,
#define RTAX_LOCK RTAX_LOCK
        RTAX_MTU,
#define RTAX_MTU RTAX_MTU
        RTAX_WINDOW,
#define RTAX_WINDOW RTAX_WINDOW
        RTAX_RTT,
#define RTAX_RTT RTAX_RTT
        RTAX_RTTVAR,
#define RTAX_RTTVAR RTAX_RTTVAR
        RTAX_SSTHRESH,
#define RTAX_SSTHRESH RTAX_SSTHRESH
        RTAX_CWND,
#define RTAX_CWND RTAX_CWND
        RTAX_ADVMSS,
#define RTAX_ADVMSS RTAX_ADVMSS
        RTAX_REORDERING,
#define RTAX_REORDERING RTAX_REORDERING
        RTAX_HOPLIMIT,
#define RTAX_HOPLIMIT RTAX_HOPLIMIT
        RTAX_INITCWND,
#define RTAX_INITCWND RTAX_INITCWND
        RTAX_FEATURES,
#define RTAX_FEATURES RTAX_FEATURES
        RTAX_RTO_MIN,
#define RTAX_RTO_MIN RTAX_RTO_MIN
        RTAX_INITRWND,
#define RTAX_INITRWND RTAX_INITRWND
        __RTAX_MAX
};

#define RTAX_MAX (__RTAX_MAX - 1)
#endif

struct service_entry;
struct sk_buff;

struct kmem_cache {
        unsigned long size;
};

struct dst_ops {
	unsigned short		family;
	uint16_t		protocol;
	unsigned		gc_thresh;
	int			(*gc)(struct dst_ops *ops);
	struct dst_entry *	(*check)(struct dst_entry *, uint32_t cookie);
	void			(*destroy)(struct dst_entry *);
	void			(*ifdown)(struct dst_entry *,
					  struct net_device *dev, int how);
	struct dst_entry *	(*negative_advice)(struct dst_entry *);
	void			(*link_failure)(struct sk_buff *);
	void			(*update_pmtu)(struct dst_entry *dst, uint32_t mtu);
	int			(*local_out)(struct sk_buff *skb);

	atomic_t		entries;
	struct kmem_cache	*kmem_cachep;
};

struct dst_entry {
	struct dst_entry	*child;
	struct net_device       *dev;
	short			error;
	short			obsolete;
	int			flags;
	unsigned long		expires;

	unsigned short		header_len;	/* more space at head required */
	unsigned short		trailer_len;	/* space to reserve at tail */

	struct dst_entry	*path;

	int			(*input)(struct sk_buff*);
	int			(*output)(struct sk_buff*);

	struct  dst_ops	        *ops;

	u32			metrics[RTAX_MAX];

	atomic_t		__refcnt;	/* client references	*/
	int			__use;
	unsigned long		lastuse;
	union {
		struct dst_entry *next;
		struct service_entry *srv_next;
	};
};

static inline u32
dst_metric(const struct dst_entry *dst, int metric)
{
	return dst->metrics[metric-1];
}

static inline u32 dst_mtu(const struct dst_entry *dst)
{
	u32 mtu = dst_metric(dst, RTAX_MTU);
	return mtu;
}

static inline void dst_hold(struct dst_entry * dst)
{
	atomic_inc(&dst->__refcnt);
}

static inline void dst_use(struct dst_entry *dst, unsigned long time)
{
	dst_hold(dst);
	dst->__use++;
	dst->lastuse = time;
}

static inline void dst_use_noref(struct dst_entry *dst, unsigned long time)
{
	dst->__use++;
	dst->lastuse = time;
}

static inline
struct dst_entry * dst_clone(struct dst_entry * dst)
{
	if (dst)
		atomic_inc(&dst->__refcnt);
	return dst;
}

extern void dst_release(struct dst_entry *dst);

static inline void refdst_drop(unsigned long refdst)
{
	if (!(refdst & SKB_DST_NOREF))
		dst_release((struct dst_entry *)(refdst & SKB_DST_PTRMASK));
}

/**
 * skb_dst_drop - drops skb dst
 * @skb: buffer
 *
 * Drops dst reference count if a reference was taken.
 */
static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->_skb_refdst) {
		refdst_drop(skb->_skb_refdst);
		skb->_skb_refdst = 0UL;
	}
}

static inline void skb_dst_copy(struct sk_buff *nskb, const struct sk_buff *oskb)
{
	nskb->_skb_refdst = oskb->_skb_refdst;
	if (!(nskb->_skb_refdst & SKB_DST_NOREF))
		dst_clone(skb_dst(nskb));
}

/**
 * skb_dst_force - makes sure skb dst is refcounted
 * @skb: buffer
 *
 * If dst is not yet refcounted, let's do it
 */
static inline void skb_dst_force(struct sk_buff *skb)
{
	if (skb_dst_is_noref(skb)) {
		skb->_skb_refdst &= ~SKB_DST_NOREF;
		dst_clone(skb_dst(skb));
	}
}

/* Children define the path of the packet through the
 * Linux networking.  Thus, destinations are stackable.
 */

static inline struct dst_entry *skb_dst_pop(struct sk_buff *skb)
{
	struct dst_entry *child = skb_dst(skb)->child;

	skb_dst_drop(skb);
	return child;
}

extern int dst_discard(struct sk_buff *skb);
extern void * dst_alloc(struct dst_ops * ops);
extern void __dst_free(struct dst_entry * dst);
extern struct dst_entry *dst_destroy(struct dst_entry * dst);

static inline void dst_free(struct dst_entry * dst)
{
	if (dst->obsolete > 1)
		return;
	if (!atomic_read(&dst->__refcnt)) {
		dst = dst_destroy(dst);
		if (!dst)
			return;
	}
	__dst_free(dst);
}

static inline void dst_link_failure(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	if (dst && dst->ops && dst->ops->link_failure)
		dst->ops->link_failure(skb);
}
/*
static inline void dst_set_expires(struct dst_entry *dst, int timeout)
{
	unsigned long expires = jiffies + timeout;

	if (expires == 0)
		expires = 1;

	if (dst->expires == 0 || time_before(expires, dst->expires))
		dst->expires = expires;
}
*/
/* Output packet to network from transport.  */
static inline int dst_output(struct sk_buff *skb)
{
	return skb_dst(skb)->output(skb);
}

/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
	return skb_dst(skb)->input(skb);
}

static inline struct dst_entry *dst_check(struct dst_entry *dst, uint32_t cookie)
{
	if (dst->obsolete)
		dst = dst->ops->check(dst, cookie);
	return dst;
}

extern void dst_init(void);

#endif /* OS_USER */

#endif /* _DST_H */

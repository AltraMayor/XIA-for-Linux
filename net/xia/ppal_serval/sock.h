/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SOCK_H_
#define _SOCK_H_

#include <platform.h>

#if defined(OS_LINUX_KERNEL)
#include <net/sock.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
#define sk_clone_lock(x,y) sk_clone(x,y)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
        return sk->sk_sleep;
}
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
static inline struct net *sock_net(struct sock *sk)
{
        return sk->sk_net;
}
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define __sk_add_backlog sk_add_backlog
#endif

static inline unsigned long get_socket_inode(struct socket *socket)
{
        if (socket) {
                struct address_space *faddr;
                struct inode *inode;
                if (!socket->file) {
                        goto out;
                }

                faddr = socket->file->f_mapping;
                if (!faddr) {
                        goto out;
                }
        
                inode = faddr->host;
                if (inode) {
                        return inode->i_ino;
                }
        }
out:
        return 0;
}

#endif
#if defined(OS_USER)
#include <serval/atomic.h>
#include <serval/lock.h>
#include <serval/dst.h>
#include <serval/list.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "skbuff.h"
#include "net.h"
#include "wait.h"
#include "timer.h"

struct sk_buff;
struct proto;
struct request_sock_ops;

/* From linux asm-generic/poll.h. Seems to be non-standardized */
#ifndef POLLRDNORM 
#define POLLRDNORM      0x0040
#endif
#ifndef POLLRDBAND
#define POLLRDBAND      0x0080
#endif
#ifndef POLLWRNORM
#define POLLWRNORM      0x0100
#endif
#ifndef POLLWRBAND
#define POLLWRBAND      0x0200
#endif
#ifndef POLLMSG
#define POLLMSG         0x0400
#endif
#ifndef POLLREMOVE
#define POLLREMOVE      0x1000
#endif
#ifndef POLLRDHUP
#define POLLRDHUP       0x2000
#endif

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

/* #define SOCK_REFCNT_DEBUG 1 */

typedef struct {
        pthread_mutex_t slock;
        int owned;
} socket_lock_t;

struct sock_common {
        struct hlist_node	skc_node;
	atomic_t		skc_refcnt;
        int     	        skc_tx_queue_mapping;
        union  {
                unsigned int skc_hash;
                uint16_t skc_u16hashes[2];
        };
        unsigned short          skc_family;
        unsigned char	        skc_state;
        unsigned char	        skc_reuse;
        int     	        skc_bound_dev_if;
        struct proto            *skc_prot;
        struct net              *skc_net;
};

struct sock {
        struct sock_common      __sk_common;
#define sk_node __sk_common.skc_node
#define sk_refcnt __sk_common.skc_refcnt
#define sk_tx_queue_mapping __sk_common.skc_tx_queue_mapping
#define sk_copy_start __sk_common.skc_hash
#define sk_hash __sk_common.skc_hash
#define sk_family __sk_common.skc_family
#define sk_state __sk_common.skc_state
#define sk_reuse __sk_common.skc_reuse
#define sk_bound_dev_if __sk_common.skc_bound_dev_if
#define sk_prot __sk_common.skc_prot
#define sk_net __sk_common.skc_net
        unsigned int		sk_shutdown  : 2,
				sk_no_check  : 2,
				sk_userlocks : 4,
				sk_protocol  : 8,
				sk_type      : 16;
        struct socket_wq  	*sk_wq;
	struct dst_entry	*sk_dst_cache;
	int			sk_rcvbuf;
        socket_lock_t           sk_lock;
        struct {
                struct sk_buff *head;
                struct sk_buff *tail;
                int len;
        } sk_backlog;
	spinlock_t		sk_dst_lock;
	atomic_t		sk_rmem_alloc;
	atomic_t		sk_wmem_alloc;
	atomic_t		sk_omem_alloc;
	atomic_t		sk_drops;
	unsigned short		sk_ack_backlog;
	unsigned short		sk_max_ack_backlog;
	int			sk_sndbuf;
	struct sk_buff_head	sk_receive_queue;
	struct sk_buff_head	sk_write_queue;
        int			sk_wmem_queued;
	int			sk_forward_alloc;
	gfp_t			sk_allocation;
	int			sk_route_caps;
	int			sk_route_nocaps;
	int			sk_gso_type;
	unsigned int		sk_gso_max_size;
	int			sk_rcvlowat;
	int			sk_write_pending;
	unsigned long 		sk_flags;
	unsigned long	        sk_lingertime;
        struct sk_buff_head	sk_error_queue;
	rwlock_t		sk_callback_lock;
        int                     sk_err,
                                sk_err_soft;
        __u32                   sk_priority;
	long			sk_rcvtimeo;
	long			sk_sndtimeo;
	struct timer_list	sk_timer;
	struct socket		*sk_socket;
	struct sk_buff		*sk_send_head;
	__u32   		sk_mark;
        void (*sk_destruct)(struct sock *sk);
	void (*sk_state_change)(struct sock *sk);
	void (*sk_data_ready)(struct sock *sk, int bytes);
	void (*sk_write_space)(struct sock *sk);
	void (*sk_error_report)(struct sock *sk);
  	int (*sk_backlog_rcv)(struct sock *sk,
                              struct sk_buff *skb);  
};

struct kiocb;
#define __user 

struct proto {
        struct module           *owner;
	void			(*close)(struct sock *sk, 
					long timeout);
	int			(*connect)(struct sock *sk,
				        struct sockaddr *uaddr, 
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept) (struct sock *sk, int flags, int *err);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	int			(*init)(struct sock *sk);
	void			(*destroy)(struct sock *sk);
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*getsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval, 
					int __user *option);  	 
	int			(*sendmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg, size_t len);
	int			(*recvmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg,
					size_t len, int noblock, int flags, 
					int *addr_len);
	int			(*sendpage)(struct sock *sk, struct page *page,
					int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk, 
					struct sockaddr *uaddr, int addr_len);

	int			(*backlog_rcv) (struct sock *sk, 
						struct sk_buff *skb);

	/* Keeping track of sk's, looking them up, and port selection methods. */
	void			(*hash)(struct sock *sk);
	void			(*unhash)(struct sock *sk);
	int			(*get_port)(struct sock *sk, unsigned short snum);

	int			max_header;
	unsigned int		obj_size;

	struct request_sock_ops	*rsk_prot;

	char			name[32];
	void			(*enter_memory_pressure)(struct sock *sk);
	atomic_t		*memory_allocated;	/* Current allocated memory. */
	struct percpu_counter	*sockets_allocated;	/* Current number of sockets. */
	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the __sk_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	int			*memory_pressure;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
	int			*sysctl_mem;
#else
        long			*sysctl_mem;
#endif
	int			*sysctl_wmem;
	int			*sysctl_rmem;
	struct list_head	node;
};

/* TODO find some way to do this in userspace? */
static inline unsigned long get_socket_inode(struct socket *socket)
{
        return 0;
}

static inline int wq_has_sleeper(struct socket_wq *wq)
{
        return wq && waitqueue_active(&wq->wait);
}

static inline int sock_no_getsockopt(struct socket *s, int a, 
                                     int b, char __user *c, int __user *d)
{
        return -EOPNOTSUPP;
}

static inline int sock_no_setsockopt(struct socket *s, int a, int b, 
                                     char __user *c, unsigned int d)
{
        return -EOPNOTSUPP;
}

static inline ssize_t sock_no_sendpage(struct socket *sock,
                                       struct page *page,
                                       int offset, size_t size, 
                                       int flags)
{
        return -EOPNOTSUPP;
}

int sock_common_getsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen);

int sock_common_setsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, unsigned int optlen);

extern int proto_register(struct proto *prot, int);
extern void proto_unregister(struct proto *prot);

enum sock_flags {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
        SOCK_FASYNC,
        SOCK_QUEUE_SHRUNK,
};

#define sock_net(s) ((s)->sk_net)


static inline void sk_node_init(struct hlist_node *node)
{
        node->pprev = NULL;
}

static inline void sk_tx_queue_set(struct sock *sk, int tx_queue)
{
	sk->sk_tx_queue_mapping = tx_queue;
}

static inline void sk_tx_queue_clear(struct sock *sk)
{
	sk->sk_tx_queue_mapping = -1;
}

static inline int sk_tx_queue_get(const struct sock *sk)
{
	return sk ? sk->sk_tx_queue_mapping : -1;
}

static inline void sk_set_socket(struct sock *sk, struct socket *sock)
{
	sk_tx_queue_clear(sk);
	sk->sk_socket = sock;
}

#define sk_wait_event(__sk, __timeo, __condition)                       \
        ({ int __rc;                                                    \
                release_sock(__sk);                                     \
                __rc = __condition;                                     \
                if (!__rc) {                                            \
                        *(__timeo) = schedule_timeout(*(__timeo));      \
                }                                                       \
                lock_sock(__sk);                                        \
                __rc = __condition;                                     \
                __rc;                                                   \
        })

int sk_wait_data(struct sock *sk, long *timeo);

#define SOCK_MIN_SNDBUF 2048
#define SOCK_MIN_RCVBUF 256

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK)) {
		sk->sk_sndbuf = min(sk->sk_sndbuf, sk->sk_wmem_queued >> 1);
		sk->sk_sndbuf = max(sk->sk_sndbuf, SOCK_MIN_SNDBUF);
	}
}

struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp);

static inline int sock_writeable(const struct sock *sk) 
{
	return atomic_read(&sk->sk_wmem_alloc) < (sk->sk_sndbuf >> 1);
}

static inline long sock_rcvtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	return (waitall ? len : min_t(int, sk->sk_rcvlowat, len)) ? : 1;
}

void sk_reset_timer(struct sock *sk, struct timer_list* timer,
                    unsigned long expires);
void sk_stop_timer(struct sock *sk, struct timer_list* timer);
int sk_receive_skb(struct sock *sk, struct sk_buff *skb, const int nested);
int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);
int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb);

static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb, int copied_early)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
        sk->sk_flags |= (0x1 << flag);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
        sk->sk_flags &= ((0x1 << flag) ^ -1UL);
}

static inline int sock_flag(struct sock *sk, enum sock_flags flag)
{
	return sk->sk_flags & (0x1 << flag);
}

static inline void sk_acceptq_removed(struct sock *sk)
{
	sk->sk_ack_backlog--;
}

static inline void sk_acceptq_added(struct sock *sk)
{
	sk->sk_ack_backlog++;
}

static inline int sk_acceptq_is_full(struct sock *sk)
{
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
}

static inline void sock_rps_record_flow(const struct sock *sk)
{
}

static inline void sock_rps_reset_flow(const struct sock *sk)
{
}

static inline void sock_rps_save_rxhash(struct sock *sk, uint32_t rxhash)
{
}

static inline int sock_error(struct sock *sk)
{
        int err;
	if (likely(!sk->sk_err))
		return 0;
	err = sk->sk_err;
        sk->sk_err = 0;
	return -err;
}

static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

void sock_wfree(struct sk_buff *skb);
void sock_rfree(struct sk_buff *skb);

static inline void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_wfree;
	/*
	 * We used to take a refcount on sk, but following operation
	 * is enough to guarantee sk_free() wont free this sock until
	 * all in-flight packets are completed
	 */
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);
}

static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	/* sk_mem_charge(sk, skb->truesize); */
}

static inline unsigned long sock_wspace(struct sock *sk)
{
        int amt = 0;

        if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
                amt = sk->sk_sndbuf - atomic_read(&sk->sk_wmem_alloc);
                if (amt < 0) 
                        amt = 0;
        }
        return amt;
}

static inline void sk_wake_async(struct sock *sk, int how, int band)
{
        /* Check if async notification is required on this socket. */
        if (sock_flag(sk, SOCK_FASYNC))
                sock_wake_async(sk->sk_socket, how, band);
}

void sock_init_data(struct socket *sock, struct sock *sk);

#define sk_clone_lock(x,y) sk_clone(x,y)
struct sock *sk_clone(const struct sock *sk, const gfp_t priority);
struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot);
void sk_free(struct sock *sk);

static inline void sock_hold_real(struct sock *sk)
{
        atomic_inc(&sk->sk_refcnt);
}

#if defined(SOCK_REFCNT_DEBUG)
#define sock_hold(sk) do {                                              \
                sock_hold_real(sk);                                     \
                printf("%s:%d/%s() sock_hold: %p refcnt=%u\n",          \
                       __FILE__, __LINE__, __func__,                    \
                       (sk), atomic_read(&(sk)->sk_refcnt));            \
        } while (0)                                            
#else
#define sock_hold(sk) sock_hold_real(sk)
#endif

/* 
   Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static inline void __sock_put_real(struct sock *sk)
{
	atomic_dec(&sk->sk_refcnt);
}

static inline void sock_put_real(struct sock *sk)
{
        if (atomic_dec_and_test(&sk->sk_refcnt))
                sk_free(sk);
}

#if defined(SOCK_REFCNT_DEBUG)
#define __sock_put(sk) do {                                     \
                printf("%s:%d/%s() __sock_put %p refcnt=%u\n",  \
                       __FILE__, __LINE__, __func__,            \
                       sk, atomic_read(&sk->sk_refcnt) - 1);    \
                __sock_put_real(sk);                            \
        } while (0)

#define sock_put(sk) do {                                       \
                printf("%s:%d/%s() %p sock_put refcnt=%u\n",    \
                       __FILE__, __LINE__, __func__,            \
                       sk, atomic_read(&sk->sk_refcnt) - 1);    \
                sock_put_real(sk);                              \
        } while (0)
#else
#define __sock_put(sk) __sock_put_real(sk)
#define sock_put(sk) sock_put_real(sk)
#endif

void lock_sock(struct sock *sk);

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk) spin_lock(&((__sk)->sk_lock.slock))
/* #define bh_lock_sock_nested(__sk)                \
        spin_lock_nested(&((__sk)->sk_lock.slock), \
        SINGLE_DEPTH_NESTING) */
#define bh_lock_sock_nested(__sk) bh_lock_sock(__sk)

#define bh_unlock_sock(__sk) spin_unlock(&((__sk)->sk_lock.slock))

void release_sock(struct sock *sk);

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
        return sk->sk_wq ? &sk->sk_wq->wait : NULL;
}

static inline void sock_orphan(struct sock *sk)
{
	write_lock(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk_set_socket(sk, NULL);
	sk->sk_wq  = NULL;
	write_unlock(&sk->sk_callback_lock);
}

static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	write_lock(&sk->sk_callback_lock);
        sk->sk_wq = parent->wq;
	parent->sk = sk;
	sk_set_socket(sk, parent);
	write_unlock(&sk->sk_callback_lock);
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */
#define sock_owned_by_user(sk)((sk)->sk_lock.owned)

static inline struct dst_entry *__sk_dst_get(struct sock *sk)
{
        return sk->sk_dst_cache;
}

static inline struct dst_entry *sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst = sk->sk_dst_cache;

	if (dst)
		dst_hold(dst);

	return dst;
}

extern void sk_reset_txq(struct sock *sk);

static inline void dst_negative_advice(struct sock *sk)
{
	struct dst_entry *ndst, *dst = __sk_dst_get(sk);

	if (dst && dst->ops->negative_advice) {
		ndst = dst->ops->negative_advice(dst);

		if (ndst != dst) {
			sk->sk_dst_cache = ndst;
			sk_reset_txq(sk);
		}
	}
}


static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	/*
	 * This can be called while sk is owned by the caller only,
	 * with no state that can be checked in a rcu_dereference_check() cond
	 */
	old_dst = sk->sk_dst_cache;
        sk->sk_dst_cache = dst;
	dst_release(old_dst);
}

static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	spin_lock(&sk->sk_dst_lock);
	__sk_dst_set(sk, dst);
	spin_unlock(&sk->sk_dst_lock);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	__sk_dst_set(sk, NULL);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	spin_lock(&sk->sk_dst_lock);
	__sk_dst_reset(sk);
	spin_unlock(&sk->sk_dst_lock);
}

struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie);

struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie);

static inline int sk_can_gso(const struct sock *sk)
{
	return 0; //net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);
}

extern void sk_setup_caps(struct sock *sk, struct dst_entry *dst);

static inline void sk_nocaps_add(struct sock *sk, int flags)
{
	sk->sk_route_nocaps |= flags;
	sk->sk_route_caps &= ~flags;
}
void sk_common_release(struct sock *sk);

/*
 * Functions for memory accounting
 */
int __sk_mem_schedule(struct sock *sk, int size, int kind);
void __sk_mem_reclaim(struct sock *sk);

#define SK_MEM_QUANTUM ((int)PAGE_SIZE)
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SK_MEM_SEND	0
#define SK_MEM_RECV	1

static inline int sk_mem_pages(int amt)
{
	return (amt + SK_MEM_QUANTUM - 1) >> SK_MEM_QUANTUM_SHIFT;
}

static inline int sk_has_account(struct sock *sk)
{
	/* return true if protocol supports memory accounting */
	return !!sk->sk_prot->memory_allocated;
}

static inline int sk_wmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return 1;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_SEND);
}

static inline int sk_rmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return 1;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_RECV);
}

static inline void sk_mem_reclaim(struct sock *sk)
{
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc >= SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk);
}

static inline void sk_mem_reclaim_partial(struct sock *sk)
{
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc > SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk);
}

static inline void sk_mem_charge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc -= size;
}

static inline void sk_mem_uncharge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc += size;
}

static inline void sk_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk->sk_wmem_queued -= skb->truesize;
	sk_mem_uncharge(sk, skb->truesize);
	__kfree_skb(skb);
}

static inline void __sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
        /* dont let skb dst not refcounted, we are going to leave rcu lock */
        //skb_dst_force(skb);

        if (!sk->sk_backlog.tail)
                sk->sk_backlog.head = skb;
        else
                sk->sk_backlog.tail->next = skb;

        sk->sk_backlog.tail = skb;
        skb->next = NULL;
}

static inline int sk_rcvqueues_full(const struct sock *sk, 
                                    const struct sk_buff *skb)
{
        unsigned int qsize = sk->sk_backlog.len + atomic_read(&sk->sk_rmem_alloc);
        return qsize + skb->truesize > (unsigned int)sk->sk_rcvbuf;
}

/* The per-socket spinlock must be held here. */
static inline int sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
        if (sk_rcvqueues_full(sk, skb))
                return -ENOBUFS;

        __sk_add_backlog(sk, skb);
        sk->sk_backlog.len += skb->truesize;
        return 0;
}

static inline int sk_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
        return sk->sk_backlog_rcv(sk, skb);
}

int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
void sk_stream_wait_close(struct sock *sk, long timeo_p);
int sk_stream_error(struct sock *sk, int flags, int err);
void sk_stream_kill_queues(struct sock *sk);

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(struct sock *sk)
{
	return sk->sk_wmem_queued >> 1;
}

static inline int sk_stream_wspace(struct sock *sk)
{
	return sk->sk_sndbuf - sk->sk_wmem_queued;
}

extern void sk_stream_write_space(struct sock *sk);

static inline int sk_stream_memory_free(struct sock *sk)
{
	return sk->sk_wmem_queued < sk->sk_sndbuf;
}

extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;


extern int sysctl_optmem_max;

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

#endif /* OS_USER */

#endif /* _SOCK_H_ */

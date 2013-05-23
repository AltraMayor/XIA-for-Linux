/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _NET_H_
#define _NET_H_

#include <platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/net.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
/* SOCK_WAKE types are not explicitly enumerated in older kernels. */
enum {
        SOCK_WAKE_IO,
        SOCK_WAKE_WAITD,
        SOCK_WAKE_SPACE,
        SOCK_WAKE_URG,
};
#endif

#else
#include <sys/socket.h>

#if defined(OS_LINUX)
#include <linux/net.h>
#else

/* Grabbed from linux/net.h */
typedef enum {
        SS_FREE = 0,
        SS_UNCONNECTED,
        SS_CONNECTING,
        SS_CONNECTED,
        SS_DISCONNECTING
} socket_state;

#endif /* OS_LINUX */

#include "wait.h"

#define SOCK_ASYNC_NOSPACE 0
#define SOCK_ASYNC_WAITDATA 1
#define SOCK_NOSPACE 2
#define SOCK_PASSCRED 3
#define SOCK_PASSSEC 4

struct sock;
struct net;

struct fasync_struct {
	pthread_mutex_t lock;
        int pipefd[2];
};

struct socket_wq {
	wait_queue_head_t	wait;
	struct fasync_struct	*fasync_list;
};

struct socket {
        struct client           *client;
        unsigned long           flags;
        socket_state            state;
        struct socket_wq        *wq;
        short                   type;
        struct sock             *sk;
        const struct proto_ops  *ops;
};

/* Dummy module struct for kernel compatibility */
#define THIS_MODULE (NULL)

struct module {
        char name[1];
};

#define __user 

struct kiocb;
struct sockaddr;
struct msghdr;
struct file;
struct poll_table_struct;

struct proto_ops {
	int		family;
        struct module   *owner;
	int		(*release)   (struct socket *sock);
	int		(*bind)	     (struct socket *sock,
				      struct sockaddr *myaddr,
				      int sockaddr_len);
	int		(*connect)   (struct socket *sock,
				      struct sockaddr *vaddr,
				      int sockaddr_len, int flags);
	int		(*accept)    (struct socket *sock,
				      struct socket *newsock, int flags);
	int		(*getname)   (struct socket *sock,
				      struct sockaddr *addr,
				      int *sockaddr_len, int peer);
	unsigned int	(*poll)	     (struct file *file, struct socket *sock,
				      struct poll_table_struct *wait);
	int		(*ioctl)     (struct socket *sock, unsigned int cmd,
				      unsigned long arg);
	int		(*listen)    (struct socket *sock, int len);
	int		(*shutdown)  (struct socket *sock, int flags);
	int		(*setsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, unsigned int optlen);
	int		(*getsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, int __user *optlen);
	int		(*sendmsg)   (struct kiocb *iocb, struct socket *sock,
				      struct msghdr *m, size_t total_len);
	int		(*recvmsg)   (struct kiocb *iocb, struct socket *sock,
				      struct msghdr *m, size_t total_len,
				      int flags);
};

struct net_proto_family {
	int		family;
        struct module   *owner;
	int		(*create)(struct net *net, struct socket *sock,
				  int protocol, int kern);
};

enum {
        SOCK_WAKE_IO,
        SOCK_WAKE_WAITD,
        SOCK_WAKE_SPACE,
        SOCK_WAKE_URG,
};

extern int sock_wake_async(struct socket *sk, int how, int band);

int sock_register(const struct net_proto_family *fam);
void sock_unregister(int family);
int sock_create(int family, int type, int proto,
                struct socket **res);
void sock_release(struct socket *sock);

/* 
   The struct net implements network namespaces in the kernel. We just
   use a dummy net here for compatibility with the kernel API.
 */
struct net {
	unsigned int dummy;
};

extern struct net init_net;

#define net_ratelimit() 0

#endif /* OS_LINUX_KERNEL */

#endif /* _NET_H_ */

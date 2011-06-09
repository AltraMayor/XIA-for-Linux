/*
 * XIA in net namespaces
 */

#ifndef __NETNS_XIA_H__
#define __NETNS_XIA_H__

#include <net/inet_frag.h>

struct xia_devconf;
struct hlist_head;
struct sock;

/* FIXME This struct is just a placeholder for now. */
struct netns_xia {
	struct xia_devconf	*devconf_all;
	struct xia_devconf	*devconf_dflt;
	struct hlist_head	*fib_table_hash;
	struct sock		*fibnl;

	struct sock		**icmp_sk;
	struct sock		*tcp_sock;

	struct netns_frags	frags;

	atomic_t rt_genid;
	atomic_t dev_addr_genid;
};

#endif /* __NETNS_XIA_H__ */

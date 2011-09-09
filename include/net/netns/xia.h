/*
 * XIA's net namespace
 */

#ifndef __NETNS_XIA_H__
#define __NETNS_XIA_H__

struct netns_xia {
	struct fib_xia_rtable *main_rtbl;
	struct fib_xia_rtable *local_rtbl;
};

#endif /* __NETNS_XIA_H__ */

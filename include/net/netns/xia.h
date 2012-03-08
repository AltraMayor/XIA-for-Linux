/*
 * XIA's net namespace
 */

#ifndef __NETNS_XIA_H__
#define __NETNS_XIA_H__

#include <net/dst_ops.h>
#include <net/xia_dst_table.h>

struct netns_xia {
	struct fib_xia_rtable	*local_rtbl;
	struct fib_xia_rtable	*main_rtbl;
#if defined(CONFIG_XIA_PPAL_HID) || defined(CONFIG_XIA_PPAL_HID_MODULE)
	struct xia_hid_state	*hid_state;
#endif

	/* Route cache. */
	struct dst_ops		xip_dst_ops;
	struct xip_dst_table	xip_dst_table;
};

#endif /* __NETNS_XIA_H__ */

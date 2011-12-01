/*
 * XIA's net namespace
 */

#ifndef __NETNS_XIA_H__
#define __NETNS_XIA_H__

struct netns_xia {
	struct fib_xia_rtable *local_rtbl;
	struct fib_xia_rtable *main_rtbl;
#if defined(CONFIG_XIA_PPAL_HID) || defined(CONFIG_XIA_PPAL_HID_MODULE)
	struct xia_hid_state *hid_state;
#endif
};

#endif /* __NETNS_XIA_H__ */

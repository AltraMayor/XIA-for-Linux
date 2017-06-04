#ifndef _NET_XIA_ETHER_H
#define _NET_XIA_ETHER_H
/* prevents double declarations */

#include <linux/netdevice.h>
#include <net/xia_list_fib.h>

/* Local ETHERs */

struct fib_xid_ether_local {
	struct xip_dst_anchor	xhl_anchor;

	/* WARNING: @xhl_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xhl_common;
};

/* Main ETHERs */

struct fib_xid_ether_main {

	/* WARNING: @xhl_common is of variable size, and
	 * MUST be the last member of the struct.
	 */
	struct fib_xid		xhl_common;
};

#endif		/* _NET_XIA_ETHER_H */
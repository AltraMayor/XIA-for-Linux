#ifndef _NET_XIA_HID_H
#define _NET_XIA_HID_H

#include <linux/netdevice.h>
#include <linux/netlink.h>

struct rtnl_xia_hid_hdw_addrs {
	__u16		hha_len;
	__u8		hha_addr_len;
	__u8		hha_ha[MAX_ADDR_LEN];
	int		hha_ifindex;
};

static inline int RTHA_OK(struct rtnl_xia_hid_hdw_addrs *rtha, int len)
{
	return len >= 0 && (unsigned)len >= sizeof(*rtha) &&
		rtha->hha_len <= (unsigned)len;
}

static inline struct rtnl_xia_hid_hdw_addrs *RTHA_NEXT(
	struct rtnl_xia_hid_hdw_addrs *rtha)
{
	return	(struct rtnl_xia_hid_hdw_addrs*)
		(((char*)rtha) + NLMSG_ALIGN(rtha->hha_len));
}

#endif /* _NET_XIA_HID_H */

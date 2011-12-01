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

#ifdef __KERNEL__

#include <linux/timer.h>

/* TODO Rename it to xia_hid_net. */
struct xia_hid_state {
	/* TODO Use attomic here! */
	u8	new_hids_to_announce;

	/* 3 bytes free. */

	struct timer_list announce_timer;
};

/* Exported by nwp.c */

int hid_nwp_init(void);
void hid_nwp_exit(void);

int hid_new_hid_state(struct net *net);
void hid_free_hid_state(struct net *net);

void announce_myself(struct net *net);
void stop_announcements(struct net *net);

#endif /* __KERNEL__ */

#endif /* _NET_XIA_HID_H */

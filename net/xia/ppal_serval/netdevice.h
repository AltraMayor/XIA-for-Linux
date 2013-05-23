/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _NETDEVICE_H_
#define _NETDEVICE_H_

#include <platform.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

enum addr_type {
        IFADDR_LOCAL,
        IFADDR_ADDRESS,
        IFADDR_BROADCAST,
        IFADDR_NETMASK,
};

static inline int dev_get_ipv4_addr(struct net_device *dev, 
                                    enum addr_type type, void *addr)
{
        struct in_device *in_dev;
        int ret = 0;
        
	rcu_read_lock();

	in_dev = __in_dev_get_rcu(dev);

        if (in_dev) {
                for_primary_ifa(in_dev) {
                        switch (type) {
                        case IFADDR_LOCAL:
                                memcpy(addr, &ifa->ifa_local, 4);
                                break;
                        case IFADDR_ADDRESS:
                                memcpy(addr, &ifa->ifa_address, 4);
                                break;
                        case IFADDR_BROADCAST:
                                memcpy(addr, &ifa->ifa_broadcast, 4);
                                break;
                        case IFADDR_NETMASK:
                                memcpy(addr, &ifa->ifa_mask, 4);
                                break;
                        }
                        ret = 1;
                        break;
                }
                endfor_ifa(indev);
        }
	rcu_read_unlock();

        return ret;
}

#endif /* _NETDEVICE_H_ */

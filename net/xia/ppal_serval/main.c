/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/route.h>
#include <af_serval.h>
#include <debug.h>
#include <netdevice.h>
#include <linux/inetdevice.h>
#include <ctrlmsg.h>
#include <af_serval.h>
#include <ctrl.h>
#include <service.h>
#include <serval_ipv4.h>
#include <serval_sock.h>

MODULE_AUTHOR("Erik Nordström");
MODULE_DESCRIPTION("Serval stack for Linux");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

/*
  Module parameters
  -----------------
  Permissions (affect visibility in sysfs): 
  0 = not visible in sysfs
  S_IRUGO = world readable
  S_IRUGO|S_IWUSR = root can change
*/

/* The debug parameter is defined in debug.c */
unsigned int debug = 0;
module_param(debug, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(debug, "Set debug level 0-6 (0=off).");

unsigned int checksum_mode = 0;
module_param(checksum_mode, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(debug, "Set checksum mode (0=software, 1=hardware)");

static char *ifname = NULL;
module_param(ifname, charp, S_IRUGO);
MODULE_PARM_DESC(ifname, "Resolve only on this device");

extern int proc_init(void);
extern void proc_fini(void);
extern int serval_sysctl_register(struct net *net);
extern void serval_sysctl_unregister(struct net *net);
extern int udp_encap_init(void);
extern void udp_encap_fini(void);

struct net_device *resolve_dev_impl(const struct in_addr *addr,
                                    int ifindex)
{
        struct net_device *dev;
        struct rtable *rt;
        
        if (ifindex < 0)
                ifindex = 0;

        rt = serval_ip_route_output(&init_net, 
                                    addr->s_addr,
                                    0, 0, ifindex);
        
        if (!rt) {
#if defined(ENABLE_DEBUG)
                char buf[18];
                
                LOG_DBG("Service address %s is not routable.\n",
                        inet_ntop(AF_INET, addr, buf, 18));
#endif
                return NULL;
        }
        
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
        dev = rt->dst.dev;
#else
        dev = rt->u.dst.dev;
#endif
        dev_hold(dev);
        ip_rt_put(rt);
        
        return dev;
}

static int dev_configuration(struct net_device *dev)
{
        struct net_addr dst;
        struct service_id default_service;
        int ret;

        memset(&default_service, 0, sizeof(default_service));

        if (ifname && strcmp(dev->name, ifname) != 0)
                return 0;

        if (dev->flags & IFF_POINTOPOINT)
                ret = dev_get_ipv4_addr(dev, IFADDR_ADDRESS, &dst);
        else
                ret = dev_get_ipv4_addr(dev, IFADDR_BROADCAST, &dst);

        if (ret == 1) {
#if defined(ENABLE_DEBUG)
                {
                        char buf[16];
                        LOG_DBG("dev %s bc=%s\n", 
                                dev->name, 
                                inet_ntop(AF_INET, &dst, buf, 16));
                }
#endif
                service_add(&default_service, 0, SERVICE_RULE_FORWARD, 0, 
                            BROADCAST_SERVICE_DEFAULT_PRIORITY,
                            BROADCAST_SERVICE_DEFAULT_WEIGHT, 
                            &dst, sizeof(dst), make_target(dev), 
                            GFP_ATOMIC);
        } 
        return ret;
}

static int serval_netdev_event(struct notifier_block *this,
                               unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;

        if (dev_net(dev) != &init_net)
                return NOTIFY_DONE;
        
        if (strncmp(dev->name, "lo", 2) == 0)
                return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
        {
                LOG_DBG("netdev UP %s\n", dev->name);
                dev_configuration(dev);
                break;
        }
	case NETDEV_GOING_DOWN:
        {           
                LOG_DBG("netdev GOING DOWN %s\n", dev->name);
                service_del_dev_all(dev->name);
		break;
        }
	case NETDEV_DOWN:
                LOG_DBG("netdev DOWN %s\n",
                        dev->name);
                break;
	default:
		break;
	};

	return NOTIFY_DONE;
}

static int serval_inetaddr_event(struct notifier_block *this,
                                 unsigned long event, void *ptr)
{

        struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
        struct net_device *dev = ifa->ifa_dev->dev;
                
        if (dev_net(dev) != &init_net)
                return NOTIFY_DONE;
        
        if (strncmp(dev->name, "lo", 2) == 0)
                return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
        {
                LOG_DBG("inetdev UP %s - migrating\n", dev->name);
                dev_configuration(dev);
                if (net_serval.sysctl_auto_migrate)
                        serval_sock_migrate_iface(0, dev->ifindex);
                break;
        }
	case NETDEV_GOING_DOWN:
        {
                LOG_DBG("inetdev GOING DOWN %s\n",
                        dev->name);
		break;
        }
	case NETDEV_DOWN:
                LOG_DBG("inetdev DOWN %s - Freezing all flows\n", 
                        dev->name);
                serval_sock_freeze_flows(dev);
                service_del_dev_all(dev->name);
                if (net_serval.sysctl_auto_migrate)
                        serval_sock_migrate_iface(dev->ifindex, 0);
                break;
	default:
		break;
	};

	return NOTIFY_DONE;
}

static struct notifier_block netdev_notifier = {
	.notifier_call = serval_netdev_event,
};

static struct notifier_block inetaddr_notifier = {
	.notifier_call = serval_inetaddr_event,
};

int __init serval_module_init(void)
{
	int err = 0;

        pr_alert("Loaded Serval protocol module\n");

        err = proc_init();
        
        if (err < 0) {
                LOG_CRIT("Cannot create proc entries\n");
                pr_alert("ERROR: Cannot create proc entries\n");
                goto fail_proc;
        }

        err = ctrl_init();
        
	if (err < 0) {
                LOG_CRIT("Cannot create netlink control socket\n");
                pr_alert("ERROR: Cannot create netlink control socket\n");
                goto fail_ctrl;
        }

	err = serval_init();

	if (err < 0) {
		 LOG_CRIT("Cannot initialize serval protocol\n");
         pr_alert("ERROR: Cannot initialize serval protocol\n");
		 goto fail_serval;
	}

	err = register_netdevice_notifier(&netdev_notifier);

	if (err < 0) {
                LOG_CRIT("Cannot register netdevice notifier\n");
                pr_alert("ERROR: Cannot register netdevice notifier\n");
                goto fail_netdev_notifier;
        }

	err = register_inetaddr_notifier(&inetaddr_notifier);

	if (err < 0) {
                LOG_CRIT("Cannot register inetaddr notifier\n");
                pr_alert("ERROR: Cannot register inetaddr notifier\n");
                goto fail_inetaddr_notifier;
        }

        net_serval.sysctl_debug = debug;

        err = serval_sysctl_register(&init_net);

        if (err < 0) {
                LOG_CRIT("Cannot register Serval sysctl interface\n");
                pr_alert("ERROR: Cannot register Serval sysctl interface\n");
                goto fail_sysctl;

        }

        err = udp_encap_init();
        
        if (err != 0) {
                LOG_CRIT("UDP encapsulation init failed\n");
                pr_alert("ERROR: UDP encapsulation init failed\n");
                goto fail_udp_encap;
        }
        
 out:
	return err;
 fail_udp_encap:
        serval_sysctl_unregister(&init_net);
 fail_sysctl:
        unregister_inetaddr_notifier(&inetaddr_notifier);
 fail_inetaddr_notifier:
        unregister_netdevice_notifier(&netdev_notifier);
 fail_netdev_notifier:
        serval_fini();
 fail_serval:
        ctrl_fini();
 fail_ctrl:
        proc_fini();
 fail_proc:
	goto out;
}

void __exit serval_module_fini(void)
{
        udp_encap_fini();
        serval_sysctl_unregister(&init_net);
        unregister_inetaddr_notifier(&inetaddr_notifier);
        unregister_netdevice_notifier(&netdev_notifier);
	serval_fini();
        ctrl_fini();
        proc_fini();
        pr_alert("Unloaded Serval protocol module\n");
}

module_init(serval_module_init)
module_exit(serval_module_fini)

MODULE_ALIAS_NETPROTO(PF_SERVAL);

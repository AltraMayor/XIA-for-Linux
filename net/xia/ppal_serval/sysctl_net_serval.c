/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * NET4:Sysctl interface to net af_serval subsystem.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <af_serval.h>
#include <debug.h>

extern struct netns_serval net_serval;
static unsigned int encap_port_max = 65535;
static unsigned int zero = 0;
static unsigned int one = 1;
static unsigned int ten = 10;
static unsigned int cent = 1000;
static unsigned int three = 3;

extern int udp_encap_client_init(unsigned short);
extern int udp_encap_server_init(unsigned short);
extern void udp_encap_client_fini(void);
extern void udp_encap_server_fini(void);
extern int inet_to_serval_enable(void);
extern void inet_to_serval_disable(void);

static int proc_inet_to_serval(struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
        unsigned int old_val = *((unsigned int *)table->data);
        int err;

        err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

        if (write && err == 0) {
                unsigned int val = *((unsigned int *)table->data);
                
                if (old_val != 0 && val == 0) {
                        inet_to_serval_disable();
                } else if (old_val == 0 && val != 0) {
                        err = inet_to_serval_enable();
                        
                        if (err) {
                                LOG_ERR("Could not enable INET to SERVAL support!\n");
                                *((unsigned int *)table->data) = 0;
                        } else 
                                *((unsigned int *)table->data) = 1;
                }
        }
        
        return err;
}

static int proc_udp_encap_port(struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	int err;
	unsigned short old_port = *((unsigned short *)table->data);
	int (*init_func)(unsigned short);
	void (*fini_func)(void);

	if (table->data == &net_serval.sysctl_udp_encap_client_port) {
		init_func = udp_encap_client_init;
		fini_func = udp_encap_client_fini;
	} else {
		init_func = udp_encap_server_init;
		fini_func = udp_encap_server_fini;
	}

	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && err == 0) {
		fini_func();

		err = init_func(*((unsigned short *)table->data));
		
		if (err) {
			*((unsigned short *)table->data) = old_port;
			init_func(old_port);
			/* If we fail to reinitialize UDP
			 * encapsulation here, there isn't much we can
			 * do */
		}
	} 

	return err;
}

static ctl_table serval_table[] = {
    {   
        .procname = "auto_migrate",
        .data = &net_serval.sysctl_auto_migrate,
        .maxlen = sizeof(unsigned int),
        .mode = 0644,
        .proc_handler = proc_dointvec_minmax,
                .extra1 = &zero,
                .extra2 = &one,
    },
    {
        .procname = "debug",
		.data = &net_serval.sysctl_debug,
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
                .extra1 = &zero,
                .extra2 = &ten,
	},
    {
        .procname = "inet_to_serval",
		.data = &net_serval.sysctl_inet_to_serval,
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_inet_to_serval,
                .extra1 = &zero,
                .extra2 = &one,
	},
	{
		.procname= "sal_forward",
		.data= &net_serval.sysctl_sal_forward,
		.maxlen= sizeof(unsigned int),
		.mode= 0644,
		.proc_handler = proc_dointvec_minmax,
                .extra1 = &zero,
                .extra2 = &one,
	},
	{
		.procname = "sal_max_retransmits",
		.data = &net_serval.sysctl_sal_max_retransmits,
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
                .extra1 = &zero,
                .extra2 = &cent,
	},
        {
		.procname = "service_resolution_mode",
		.data = &net_serval.sysctl_resolution_mode,
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 = &zero,
		.extra2 = &three,
	},
    {
        .procname = "udp_encap",
        .data = &net_serval.sysctl_udp_encap,
        .maxlen = sizeof(unsigned int),
        .mode = 0644,
        .proc_handler = proc_dointvec_minmax,
                .extra1 = &zero,
                .extra2 = &one,
    },
	{
		.procname = "udp_encap_client_port",
		.data = &net_serval.sysctl_udp_encap_client_port,
		.maxlen = sizeof(unsigned short),
		.mode = 0644,
		.proc_handler = proc_udp_encap_port,
		.extra1 = &one,
		.extra2 = &encap_port_max,
	},
	{
		.procname = "udp_encap_server_port",
		.data = &net_serval.sysctl_udp_encap_server_port,
		.maxlen = sizeof(unsigned short),
		.mode = 0644,
		.proc_handler = proc_udp_encap_port,
		.extra1 = &one,
		.extra2 = &encap_port_max,
	},
	{ }
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
static struct ctl_path serval_path[] = {
	{ .procname = "net", },
	{ .procname = "serval", },
	{ },
};
#endif

int serval_sysctl_register(struct net *net)
{
	struct ctl_table *table;

	table = kmemdup(serval_table, sizeof(serval_table), GFP_KERNEL);
	if (table == NULL)
		goto err_alloc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	net_serval.ctl = register_net_sysctl(net, "net/serval", table);
#else
	net_serval.ctl = register_net_sysctl_table(net, serval_path, table);
#endif
	if (net_serval.ctl == NULL)
		goto err_reg;

	return 0;

err_reg:
	kfree(table);
err_alloc:
	return -ENOMEM;
}

void serval_sysctl_unregister(struct net *net)
{
	struct ctl_table *table;

	table = net_serval.ctl->ctl_table_arg;
	unregister_sysctl_table(net_serval.ctl);
	kfree(table);
}

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
static unsigned int zero = 0;
static unsigned int one = 1;
static unsigned int ten = 10;
static unsigned int cent = 1000;
static unsigned int three = 3;

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

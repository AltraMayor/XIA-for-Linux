/*
 * NET4:Sysctl interface to net af_serval subsystem.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */
#include <net/net_namespace.h>
#include "af_serval.h"

static unsigned int zero = 0;
static unsigned int cent = 1000;

static struct ctl_table serval_table[] = {
	{
		.procname = "sal_max_retransmits",
		.data = &net_serval.sysctl_sal_max_retransmits,
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 = &zero,
		.extra2 = &cent,
	},
	{ }
};

int serval_sysctl_register(struct net *net)
{
	struct ctl_table *table;

	table = kmemdup(serval_table, sizeof(serval_table), GFP_KERNEL);
	if (table == NULL)
		goto err_alloc;

	net_serval.ctl = register_net_sysctl(net, "net/serval", table);
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

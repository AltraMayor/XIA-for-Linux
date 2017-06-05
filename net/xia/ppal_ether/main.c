#include <linux/module.h>
#include <net/xia_dag.h>
#include <net/xia_output.h>
#include <net/xia_vxidty.h>
#include <net/xia_ether.h>

/* xia_ether_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_ether_init(void)
{
	int rc;

	rc = vxt_register_xidty(XIDTYPE_ETHER);
	if (rc < 0) {
		pr_err("Can't obtain a virtual XID type for ETHER\n");
		goto out;
	}
	ether_vxt = rc;

	rc = xia_register_pernet_subsys(&ether_net_ops);
	if (rc)
		goto vxt;

	rc = xip_add_router(&ether_rt_proc);
	if (rc)
		goto net;

	rc = ppal_add_map("ether", XIDTYPE_ETHER);
	if (rc)
		goto route;

	pr_alert("XIA Principal ETHER loaded\n");
	goto out;

route:
	xip_del_router(&ether_rt_proc);
net:
	xia_unregister_pernet_subsys(&ether_net_ops);
vxt:
	BUG_ON(vxt_unregister_xidty(XIDTYPE_ETHER));
out:
	return rc;
}

/* xia_ether_exit - this function is called when the module is removed. */
static void __exit xia_ether_exit(void)
{
	ppal_del_map(XIDTYPE_ETHER);
	xip_del_router(&ether_rt_proc);
	xia_unregister_pernet_subsys(&ether_net_ops);

	rcu_barrier();
	/* flush_scheduled_work(); */

	BUG_ON(vxt_unregister_xidty(XIDTYPE_ETHER));
	pr_alert("XIA Principal ETHER UNloaded\n");
}


module_init(xia_ether_init);
module_exit(xia_ether_exit);
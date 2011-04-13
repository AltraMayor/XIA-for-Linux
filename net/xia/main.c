/*
 * XIA		An implementation of the XIA protocol suite for the LINUX
 *		operating system.  XIA is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_XIA protocol family socket handler.
 *
 * Author:	Michel Machado, <michel@digirati.com.br>
 */

#include <linux/module.h>
#include <net/xia_dag.h>

/* Initialization functions
 *
 * These functions are defined in other files, but they are only used here.
 */

int init_main_lock_table(int *size_byte, int *n);
void destroy_main_lock_table(void);

int xia_fib_init(void);
void xia_fib_exit(void);

int xip_route_init(void);
void xip_route_exit(void);

int xia_socket_init(void);
void xia_socket_exit(void);

/* Main */

/* xia_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init xia_init(void)
{
	int rc, size, n;

	rc = init_main_lock_table(&size, &n);
	if (rc)
		goto out;

	/* Add Not A Type principal. */
	rc = ppal_add_map("nat", XIDTYPE_NAT);
	if (rc)
		goto locks;

	rc = xia_fib_init();
	if (rc)
		goto nat;

	rc = xip_route_init();
	if (rc)
		goto fib;

	rc = xia_socket_init();
	if (rc)
		goto route;

	pr_info("XIA lock table entries: %i = 2^%i (%i bytes)\n",
		n, ilog2(n), size);
	pr_alert("XIA loaded\n");
	goto out;

/*
socket:
	xia_socket_exit();
*/
route:
	xip_route_exit();
fib:
	xia_fib_exit();
nat:
	ppal_del_map(XIDTYPE_NAT);
locks:
	destroy_main_lock_table();
out:
	return rc;
}

/* xia_exit - this function is called when the modlule is removed. */
static void __exit xia_exit(void)
{
	xia_socket_exit();
	xip_route_exit();
	xia_fib_exit();
	ppal_del_map(XIDTYPE_NAT);

	/* The order of the following two calls is critical to properly
	 * release structures that use call_rcu, or work queues.
	 */
	rcu_barrier();
	flush_scheduled_work();

	destroy_main_lock_table();
	pr_alert("XIA UNloaded\n");
}

module_init(xia_init);
module_exit(xia_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Network Stack");
MODULE_ALIAS_NETPROTO(PF_XIA);

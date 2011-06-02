#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

/*
 * xia_init - this function is called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int xia_init(void)
{
	printk(KERN_ALERT "XIA loaded\n");
	return 0;
}

/*
 * xia_exit - this function is called when the modlule is removed.
 */
static void xia_exit(void)
{
	printk(KERN_ALERT "XIA UNloaded\n");
}

module_init(xia_init);
module_exit(xia_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Machado <michel@digirati.com.br>");
MODULE_DESCRIPTION("XIA Network Protocol Suite");

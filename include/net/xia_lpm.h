#ifndef _NET_XIA_LPM_H
#define _NET_XIA_LPM_H

#ifdef __KERNEL__

#include <net/xia_fib.h>

#define XIA_LPM_PREFIX_TYPE_SIZE	sizeof(u8)
#define XIA_LPM_MAX_PREFIX_LEN		(8 * XIA_XID_MAX)

/* Ensure the application has passed a pointer to a u8
 * that represents a prefix len of a valid size.
 */
static inline bool valid_prefix(struct xia_fib_config *cfg)
{
	return cfg->xfc_protoinfo &&
	       cfg->xfc_protoinfo_len == XIA_LPM_PREFIX_TYPE_SIZE &&
	       *(u8 *)cfg->xfc_protoinfo <= XIA_LPM_MAX_PREFIX_LEN;
}

/*
 *	Exported by tree_fib.c
 */

extern const struct xia_ppal_rt_iops xia_ppal_tree_rt_iops;

/* Find the first predecessor node above @fxid that also has an fxid.
 *
 * WARNING
 *	This function will return the closest predecessor
 *	regardless of the table it is in.
 */
struct fib_xid *tree_fib_get_pred_locked(struct fib_xid *fxid);

int tree_fib_newroute_lock(struct fib_xid *new_fxid,
	struct fib_xid_table *xtbl, struct xia_fib_config *cfg,
	int *padded);

int tree_fib_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
	struct xia_fib_config *cfg);

int tree_fib_mrd_dump(struct fib_xid *fxid, struct fib_xid_table *xtbl,
	struct xip_ppal_ctx *ctx, struct sk_buff *skb,
	struct netlink_callback *cb);

#endif /* __KERNEL__ */
#endif /* _NET_XIA_LPM_H */

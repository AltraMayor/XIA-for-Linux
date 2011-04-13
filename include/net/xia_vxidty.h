#ifndef _NET_XIA_VXIDTY
#define _NET_XIA_VXIDTY

/*
 * XID types are 32 bits long, so one cannot just map them to something else
 * using an array like IPv4/IPv6 can do with its protocol/next-header field.
 * Nevertheless, having an efficient way to map XID types to other
 * data structures is important for an XIA stack.
 *
 * Given that an XIA stack is expected to support only a small number of
 * principals at the same time, a hardware solution would be to use
 * a small Content-Addressable Memory (CAM) to map XID types to
 * sequential integers, which, in turn, allows direct maps with arrays.
 *
 * The code in this file emulates that hardware solution using perfect hashing.
 */

#include <net/xia.h>	/* xid_type_t */

/* It must be a power of 2. */
#define XIP_VXT_TABLE_SIZE	64

/* Virtual XID Type */
struct xip_vxt_entry {
	xid_type_t	xid_type;
	int		index;
};

extern const struct xip_vxt_entry *xip_virtual_xid_types;

/* Convert XID type to its Virtual XID Type.
 *
 * IMPORTANT
 *	Only call this function holding an RCU reading lock;
 *	otherwise call xt_to_vxt().
 *
 * RETURN
 *	The index allocated to @ty, a number greater or equal to zero,
 *		if @ty is mapped.
 *	Otherwise -1.
 */
static inline int xt_to_vxt_rcu(xid_type_t ty)
{
	if (likely(ty > 0)) {
		const struct xip_vxt_entry *entry =
			&(
				rcu_dereference(xip_virtual_xid_types)
				[__be32_to_cpu(ty) & (XIP_VXT_TABLE_SIZE - 1)]
			);
		if (likely(entry->xid_type == ty))
			return entry->index;
	}
	return -1;
}

/* NOTE: if RCU reading lock is held, consider calling xt_to_vxt_rcu(). */
static inline int xt_to_vxt(xid_type_t ty)
{
	int ret;

	rcu_read_lock();
	ret = xt_to_vxt_rcu(ty);
	rcu_read_unlock();
	return ret;
}

/* Register @ty among virtual XID types.
 *
 * IMPORTANT
 *	This function may sleep.
 *
 * RETURN
 *	-EEXIST if @ty is already registered.
 *	-EINVAL if @ty can't be allocated at this time due to the mapping
 *		mechanism's limitations.
 *	-ENOSPC if the mapping is full.
 *	The index allocated to @ty, that is, a number greater or equal to zero.
 */
int vxt_register_xidty(xid_type_t ty);

/* Unregister @ty among virtual XID types.
 *
 * IMPORTANT
 *	This function may sleep.
 *
 * RETURN
 *	-EINVAL if @ty is not registered.
 *	Zero on success.
 */
int vxt_unregister_xidty(xid_type_t ty);

#endif	/* _NET_XIA_VXIDTY */

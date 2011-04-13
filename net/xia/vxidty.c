#include <net/xia_vxidty.h>

/* XXX The current perfect hashing mechanism used here is quite simple and
 * limiting, many sets of XID types are not supported.
 * A better mechanism must be developed.
 */

#define ULONG_SIZE_IN_BIT	(sizeof(unsigned long) * 8)

static DEFINE_MUTEX(vxt_mutex);
static unsigned long allocated_vxt[(XIP_MAX_XID_TYPES + ULONG_SIZE_IN_BIT - 1)
	/ ULONG_SIZE_IN_BIT];
static struct xip_vxt_entry map1[XIP_VXT_TABLE_SIZE] __read_mostly;
static struct xip_vxt_entry map2[XIP_VXT_TABLE_SIZE] __read_mostly;
const struct xip_vxt_entry *xip_virtual_xid_types __read_mostly = map1;

#define MAP_SIZE_IN_BYTE	(sizeof(map1))

static inline struct xip_vxt_entry *writable_current_map(void)
{
	return (struct xip_vxt_entry *)xip_virtual_xid_types;
}

static inline struct xip_vxt_entry *get_entry_locked(struct xip_vxt_entry *map,
						     xid_type_t ty)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(XIP_VXT_TABLE_SIZE);
	BUILD_BUG_ON(XIP_VXT_TABLE_SIZE < XIP_MAX_XID_TYPES);
	return &map[__be32_to_cpu(ty) & (XIP_VXT_TABLE_SIZE - 1)];
}

static inline struct xip_vxt_entry *next_map(void)
{
	return xip_virtual_xid_types == map1 ? map2 : map1;
}

int vxt_register_xidty(xid_type_t ty)
{
	struct xip_vxt_entry *entry, *old_map, *new_map;
	int ret;

	mutex_lock(&vxt_mutex);

	/* Check that everything is ready. */
	old_map = writable_current_map(); /* get_entry_locked() requires it. */
	entry = get_entry_locked(old_map, ty);
	if (entry->xid_type == ty) {
		ret = -EEXIST;
		goto out;
	} else if (entry->xid_type) {
		ret = -EINVAL;
		goto out;
	}
	ret = find_first_zero_bit(allocated_vxt, XIP_MAX_XID_TYPES);
	if (ret >= XIP_MAX_XID_TYPES) {
		ret = -ENOSPC;
		goto out;
	}

	/* Cook a new map. */
	__set_bit(ret, allocated_vxt);
	new_map = next_map();
	memmove(new_map, old_map, MAP_SIZE_IN_BYTE);
	entry = get_entry_locked(new_map, ty);
	entry->xid_type = ty;
	entry->index = ret;

	/* Publish the new map. */
	rcu_assign_pointer(xip_virtual_xid_types, new_map);
	synchronize_rcu();

out:
	mutex_unlock(&vxt_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(vxt_register_xidty);

int vxt_unregister_xidty(xid_type_t ty)
{
	struct xip_vxt_entry *entry, *old_map, *new_map;
	int ret;

	mutex_lock(&vxt_mutex);

	/* Check that everything is ready. */
	old_map = writable_current_map(); /* get_entry_locked() requires it. */
	entry = get_entry_locked(old_map, ty);
	if (entry->xid_type != ty) {
		ret = -EINVAL;
		goto out;
	}
	ret = 0;

	/* Cook a new map. */
	BUG_ON(!__test_and_clear_bit(entry->index, allocated_vxt));
	new_map = next_map();
	memmove(new_map, old_map, MAP_SIZE_IN_BYTE);
	entry = get_entry_locked(new_map, ty);
	memset(entry, 0, sizeof(*entry));

	/* Publish the new map. */
	rcu_assign_pointer(xip_virtual_xid_types, new_map);
	synchronize_rcu();

out:
	mutex_unlock(&vxt_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(vxt_unregister_xidty);

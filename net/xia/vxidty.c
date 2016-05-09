#include <net/xia_vxidty.h>

/* The current perfect hashing mechanism used here is hopscotch hashing
 */

#define ULONG_SIZE_IN_BIT	(sizeof(unsigned long) * 8)

atomic_t tot_element = ATOMIC_INIT(0);

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

static inline void find_closer_bucket(struct xip_vxt_entry **free_bucket, int * free_distance) {

	int free_dist;
	struct xip_vxt_entry *move_bucket = *free_bucket - (HOP_RANGE -1);
	
	for(free_dist = (HOP_RANGE -1); free_dist > 0; --free_dist) {
		unsigned start_hop_info = move_bucket->hop_info;
		int move_free_distance = -1;
		unsigned int mask = 1;
		int i;
		for(i = 0; i < free_dist; ++i, mask <<= 1) {
			if (mask & start_hop_info) {
				move_free_distance = i;
				break;
			}
		}

		if (-1 != move_free_distance) {
			if (start_hop_info ==  move_bucket->hop_info) {
				struct xip_vxt_entry * new_free_bucket = move_bucket + move_free_distance;
				move_bucket->hop_info |= (1 << free_dist);
				(*free_bucket)->xid_type = new_free_bucket->xid_type;
				(*free_bucket)->index = new_free_bucket->index;
				
				new_free_bucket->xid_type = 0;
				new_free_bucket->index = 0;
				move_bucket->hop_info &= ~(1 << move_free_distance);

				*free_bucket = new_free_bucket;
				*free_distance -=free_dist;

				return;
			}
		}

		move_bucket++;
	}

	*free_bucket = NULL; 
	*free_distance = 0;
}

static inline struct xip_vxt_entry *get_entry_locked(struct xip_vxt_entry *map,
						     xid_type_t ty)
{
	__u32 hash_index = __be32_to_cpu(ty) & (XIP_VXT_TABLE_SIZE - 1);
	
	__u32 free_distance =0;
	struct xip_vxt_entry * free_bucket;
	
	struct xip_vxt_entry * start_bucket = &(rcu_dereference(map)[hash_index]);

	struct xip_vxt_entry *target = lookup(map, ty);

	if (target) return target;

	BUILD_BUG_ON_NOT_POWER_OF_2(XIP_VXT_TABLE_SIZE);
	BUILD_BUG_ON(XIP_VXT_TABLE_SIZE < XIP_MAX_XID_TYPES);

	rcu_assign_pointer(free_bucket, start_bucket);

	/* find the first empty entry */
	for (free_distance = 0; free_distance < ADD_RANGE; ++free_distance) {
		if (0 == free_bucket->xid_type)
			break;

		hash_index = (hash_index + 1) & (XIP_VXT_TABLE_SIZE - 1);
		
		free_bucket = &(rcu_dereference(map)[hash_index]);
	}

	if (free_distance < ADD_RANGE) {
		do{
			if (free_distance < HOP_RANGE) {
				start_bucket->hop_info |= (1 << free_distance);
				//free_bucket->xid_type = ty;
				//free_bucket->index = current_idx++;

				return free_bucket;
			}

			find_closer_bucket(&free_bucket, &free_distance);
		} while( NULL!= free_bucket);
	}

	pr_info("There is no empty space left, need to resize!!!\n");
	
	return get_entry_locked(map, ty);
}

static inline struct xip_vxt_entry *next_map(void)
{
	return xip_virtual_xid_types == map1 ? map2 : map1;
}

int vxt_register_xidty(xid_type_t ty) {
	struct xip_vxt_entry *entry, *old_map, *new_map;
	int ret;

	mutex_lock(&vxt_mutex);
	
	ret = 0;

	if (likely(XIP_VXT_TABLE_SIZE == atomic_read(&tot_element))) {
		ret = -ENOSPC;
		pr_info("Can't perform Registration..Hash Table is full!!\n");
		goto out;
	}

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

	/* Stat for the total entries */
	atomic_inc(&tot_element);

	/* Publish the new map. */
	rcu_assign_pointer(xip_virtual_xid_types, new_map);
	synchronize_rcu();
	
out:
	mutex_unlock(&vxt_mutex);
	return ret;

	/*
	   return vxt_register_xidty(ty,0);
	 */
}
EXPORT_SYMBOL_GPL(vxt_register_xidty);

int vxt_unregister_xidty(xid_type_t ty)
{
	struct xip_vxt_entry *entry, *old_map, *new_map;
	int ret;

	mutex_lock(&vxt_mutex);

	ret = 0;

	if (likely(0 == atomic_read(&tot_element))) {
		ret = -EINVAL;
		pr_info("Can't perform Deletion..Hash Table is empty!!\n");
		goto out;
	}

	/* Check that everything is ready. */
	old_map = writable_current_map(); /* get_entry_locked() requires it. */
	entry = lookup(old_map, ty);
	if (!entry || (entry->xid_type != ty)) {
		ret = -EINVAL;
		goto out;
	}

	/* Cook a new map. */
	BUG_ON(!__test_and_clear_bit(entry->index, allocated_vxt));
	new_map = next_map();
	memmove(new_map, old_map, MAP_SIZE_IN_BYTE);

	entry = lookup(new_map, ty);

	if (!entry) {
		pr_info("Unregister XIDTYPE %u failed: NULL entry!\n", __be32_to_cpu(ty));
		ret = -EINVAL;
		goto out;
	}

	memset(entry, 0, sizeof(*entry));

	/* Stat for the total entries */
	atomic_dec(&tot_element);

	/* Publish the new map. */
	rcu_assign_pointer(xip_virtual_xid_types, new_map);
	synchronize_rcu();

out:
	mutex_unlock(&vxt_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(vxt_unregister_xidty);

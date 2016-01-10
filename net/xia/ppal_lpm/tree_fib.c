#include <linux/slab.h>
#include <net/xia_dag.h>
#include <net/xia_lpm.h>
#include <linux/rwlock.h>

/* Each struct tree_fib_xid represents a node in a tree. */
struct tree_fib_xid {
	struct tree_fib_xid 	*parent;
	struct tree_fib_xid 	*left;
	struct tree_fib_xid 	*right;
	bool			has_fxid;
};

struct tree_fib_xid_table {
	/* Root of tree data structure that holds struct fib_xids. */
	struct tree_fib_xid 	*root;
	/* RCU is currently not used on the tree, so we use a rwlock. */
	rwlock_t		writers_lock;
};

static inline struct fib_xid *tfxid_fxid(struct tree_fib_xid *tfxid)
{
	return likely(tfxid)
		? container_of((void *)tfxid, struct fib_xid, fx_data)
		: NULL;
}

static inline struct tree_fib_xid *fxid_tfxid(struct fib_xid *fxid)
{
	return (struct tree_fib_xid *)fxid->fx_data;
}

static inline struct fib_xid_table *txtbl_xtbl(struct tree_fib_xid_table *txtbl)
{
	return likely(txtbl)
		? container_of((void *)txtbl, struct fib_xid_table, fxt_data)
		: NULL;
}

static inline struct tree_fib_xid_table *xtbl_txtbl(struct fib_xid_table *xtbl)
{
	return (struct tree_fib_xid_table *)xtbl->fxt_data;
}

static void tree_xtbl_death_work(struct work_struct *work);

static int tree_xtbl_init(struct xip_ppal_ctx *ctx, struct net *net,
			  struct xia_lock_table *locktbl,
			  const xia_ppal_all_rt_eops_t all_eops,
			  const struct xia_ppal_rt_iops *all_iops)
{
	struct fib_xid_table *new_xtbl;
	struct tree_fib_xid_table *txtbl;

	if (ctx->xpc_xtbl)
		return -EEXIST; /* Duplicate. */

	new_xtbl = kzalloc(sizeof(*new_xtbl) + sizeof(*txtbl), GFP_KERNEL);
	if (!new_xtbl)
		return -ENOMEM;
	txtbl = xtbl_txtbl(new_xtbl);

	/* Since a node for the root will be added for *any* entry
	 * (even prefix length 0), and since it makes the tree algorithms
	 * simpler, we setup the root node here. The root node will remain
	 * allocated throughout the life of the FIB, even if it changes
	 * between being part of an fxid and just a node.
	 */
	txtbl->root = kmalloc(sizeof(*txtbl->root), GFP_KERNEL);
	if (!txtbl->root) {
		kfree(new_xtbl);
		return -ENOMEM;
	}
	/* Make sure the root's outgoing pointers are NULL. */
	memset(txtbl->root, 0, sizeof(*txtbl->root));

	new_xtbl->fxt_ppal_type = ctx->xpc_ppal_type;
	new_xtbl->fxt_net = net;
	hold_net(net);
	rwlock_init(&txtbl->writers_lock);
	new_xtbl->all_eops = all_eops;
	new_xtbl->all_iops = all_iops;

	atomic_set(&new_xtbl->refcnt, 1);
	INIT_WORK(&new_xtbl->fxt_death_work, tree_xtbl_death_work);
	ctx->xpc_xtbl = new_xtbl;

	return 0;
}

static void *tree_fxid_ppal_alloc(size_t ppal_entry_size, gfp_t flags)
{
	return kmalloc(ppal_entry_size + sizeof(struct tree_fib_xid), flags);
}

static void tree_fxid_init(struct fib_xid *fxid, int table_id, int entry_type)
{
	struct tree_fib_xid *tfxid = fxid_tfxid(fxid);
	/* Make sure @tfxid's outgoing pointers are NULL. */
	memset(tfxid, 0, sizeof(*tfxid));

	BUILD_BUG_ON(XRTABLE_MAX_INDEX >= 0x100);
	BUG_ON(table_id >= XRTABLE_MAX_INDEX);
	fxid->fx_table_id = table_id;

	BUILD_BUG_ON(XIA_LPM_MAX_PREFIX_LEN >= 0x100);
	BUG_ON(entry_type > XIA_LPM_MAX_PREFIX_LEN);
	fxid->fx_entry_type = entry_type;

	fxid->dead.xtbl = NULL;
}

static inline void disconnect_from_parent(struct tree_fib_xid *node)
{
	if (node && node->parent) {
		if (node == node->parent->left)
			node->parent->left = NULL;
		else
			node->parent->right = NULL;
	}
}

/* Destroy the subtree whose root is @node.
 * This function assumes the tree has been locked.
 */
static int destroy_subtree(struct fib_xid_table *xtbl,
			   struct tree_fib_xid *node)
{
	int rm_count = 0;
	while (node) {
		if (node->left) {
			node = node->left;
		} else if (node->right) {
			node = node->right;
		} else {
			struct tree_fib_xid *parent = node->parent;
			disconnect_from_parent(node);
			if (node->has_fxid) {
				/* @node has an fxid. */
				fxid_free_norcu(xtbl, tfxid_fxid(node));
				atomic_dec(&xtbl->fxt_count);
				rm_count++;
			} else {
				/* @node is just a node without an fxid. */
				kfree(node);
			}
			node = parent;
		}
	}
	return rm_count;
}

static void tree_xtbl_death_work(struct work_struct *work)
{
	struct fib_xid_table *xtbl = container_of(work, struct fib_xid_table,
		fxt_death_work);
	struct tree_fib_xid_table *txtbl = xtbl_txtbl(xtbl);

	int c = atomic_read(&xtbl->fxt_count);
	int rm_count = destroy_subtree(xtbl, txtbl->root);

	/* It doesn't return an error here because there's nothing
	 * the caller can do about this error/bug.
	*/
	if (c != rm_count) {
		pr_err("While freeing XID table of principal %x, %i entries were found, whereas %i are counted! Ignoring it, but it's a serious bug!\n",
		       __be32_to_cpu(xtbl->fxt_ppal_type), rm_count, c);
		       dump_stack();
	}

	release_net(xtbl->fxt_net);
	kfree(xtbl);
}

/* Find the ith bit in the XID.
 *
 * Returns zero if the actual next bit is 0,
 * and non-zero is the actual next bit is 1.
 */
static inline u8 xid_next_bit(const u8 *xid, int i)
{
	/* Be overly cautious to ensure logical right shift. */
	return xid[i >> 0x3] & (0x80U >> (i & 0x7));
}

/* If @exact_match is non-zero, then this function returns the
 * struct fib_xid that matches @xid at exactly @prefix_len bytes.
 * If @exact_match is zero, then this function returns the entry whose
 * prefix has the longest match, and @prefix_len is ignored.
 */
static struct fib_xid *__tree_fxid_find(struct fib_xid_table *xtbl,
					const u8 *xid, u8 prefix_len,
					int exact_match)
{
	struct tree_fib_xid_table *txtbl = xtbl_txtbl(xtbl);
	struct tree_fib_xid *cur;
	struct fib_xid *fxid_to_ret = NULL;
	u8 bits_seen = 0;

	int i;
	write_lock(&txtbl->writers_lock);
	cur = txtbl->root;

	if (cur->has_fxid)
		fxid_to_ret = tfxid_fxid(cur);

	/* An exact match should stop here. */
	if (exact_match && bits_seen == prefix_len)
		goto out;

	for (i = 0; i < XIA_LPM_MAX_PREFIX_LEN; i++) {
		u8 next_bit = xid_next_bit(xid, i);
		if (cur->left && next_bit == 0)
			cur = cur->left;
		else if (cur->right && next_bit != 0)
			cur = cur->right;
		else
			goto out;

		bits_seen++;

		/* Not all nodes in the tree have an fxid
		 * associated with them. If the current node
		 * does, then save it to potentially return.
		 */
		if (cur->has_fxid)
			fxid_to_ret = tfxid_fxid(cur);

		/* An exact match should stop here. */
		if (exact_match && bits_seen == prefix_len)
			goto out;
	}

out:
	/* If we're doing exact matching and we didn't see all the bits,
	 * or if the exact prefix doesn't have an @fxid, return NULL.
	 */
	if (exact_match && (bits_seen != prefix_len || !cur->has_fxid))
		return NULL;
	return fxid_to_ret;
}

/* No extra information is needed, so @parg is empty. */
static void tree_fib_unlock(struct fib_xid_table *xtbl, void *parg)
{
	write_unlock(&xtbl_txtbl(xtbl)->writers_lock);
}

static struct fib_xid *tree_fxid_find_rcu(struct fib_xid_table *xtbl,
					  const u8 *xid)
{
	/* Do longest prefix matching matching. */
	return __tree_fxid_find(xtbl, xid, 0, 0);
}

/* No extra information is needed, so @parg is empty. */
static struct fib_xid *tree_fxid_find_lock(void *parg,
	struct fib_xid_table *xtbl, const u8 *xid)
{
	/* Do longest prefix matching matching. */
	return __tree_fxid_find(xtbl, xid, 0, 0);
}

static struct tree_fib_xid *get_leftmost_node(struct tree_fib_xid *node) {
	while (node->left)
		node = node->left;
	return node;
}

static struct tree_fib_xid *get_next_node(struct tree_fib_xid *node) {
	if (node->right) {
		return get_leftmost_node(node->right);
	} else {
		while (node->parent && node == node->parent->right) {
			node = node->parent;
		}
		return node->parent;
	}
}

static int tree_iterate_xids(struct fib_xid_table *xtbl,
			     int (*locked_callback)(struct fib_xid_table *xtbl,
						    struct fib_xid *fxid,
						    const void *arg),
			     const void *arg)
{
	struct tree_fib_xid_table *txtbl = xtbl_txtbl(xtbl);
	struct tree_fib_xid *cur;
	int rc = 0;

	read_lock(&txtbl->writers_lock);
	cur = get_leftmost_node(txtbl->root);
	while (cur) {
		if (cur->has_fxid) {
			rc = locked_callback(xtbl, tfxid_fxid(cur), arg);
			if (rc)
				goto out;
		}
		cur = get_next_node(cur);
	}
out:
	read_unlock(&txtbl->writers_lock);
	return rc;
}

static inline void replace_node(struct tree_fib_xid *old,
				struct tree_fib_xid *new)
{
	/* Set new node's outgoing pointers. */
	new->parent = old->parent;
	new->left = old->left;
	new->right = old->right;

	/* Set new node's incoming pointers. */
	if (old->parent) {
		if (old == old->parent->left)
			old->parent->left = new;
		else
			old->parent->right = new;
	}
	if (old->left)
		old->left->parent = new;
	if (old->right)
		old->right->parent = new;
}

/* No extra information is needed, so @parg is empty. */
static int tree_fxid_add_locked(void *parg, struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
{
	struct tree_fib_xid_table *txtbl = xtbl_txtbl(xtbl);
	struct tree_fib_xid *cur, *new_node;
	int i;

	cur = txtbl->root;
	for (i = 0; i < fxid->fx_entry_type; i++) {
		u8 next_bit = xid_next_bit(fxid->fx_xid, i);
		if (cur->left && next_bit == 0) {
			cur = cur->left;
			continue;
		} else if (cur->right && next_bit != 0) {
			cur = cur->right;
			continue;
		}

		/* Need to construct next node in path. */
		new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
		if (!new_node)
			return -ENOMEM;
		new_node->parent = cur;
		new_node->left = NULL;
		new_node->right = NULL;
		new_node->has_fxid = false;

		if (next_bit == 0)
			cur->left = new_node;
		else
			cur->right = new_node;
		cur = new_node;
	}

	/* If the node found already has an fxid, then return that
	 * is already exists. Otherwise, add a pointer to this
	 * node to the new @fxid.
	 */
	if (cur->has_fxid)
		return -EEXIST;

	new_node = fxid_tfxid(fxid);
	replace_node(cur, new_node);
	new_node->has_fxid = true;

	/* Update root node to go from a "normal" node to
	 * a node with an @fxid associated it it.
	 */
	if (cur == txtbl->root)
		txtbl->root = new_node;

	/* @cur was previously allocated as a node without
	 * an fxid. Since @to_add takes its place, @cur is
	 * no longer needed.
	 */
	kfree(cur);

	atomic_inc(&xtbl->fxt_count);
	return 0;
}

static int tree_fxid_add(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	int rc;
	write_lock(&xtbl_txtbl(xtbl)->writers_lock);
	rc = tree_fxid_add_locked(NULL, xtbl, fxid);
	write_unlock(&xtbl_txtbl(xtbl)->writers_lock);
	return rc;
}

/* No extra information is needed, so @parg is empty. */
static void tree_fxid_rm_locked(void *parg, struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
{
	struct tree_fib_xid_table *txtbl = xtbl_txtbl(xtbl);
	struct tree_fib_xid *new_tfxid, *cur;

	/* Get the node associated with this @fxid. */
	cur = fxid_tfxid(fxid);

	/* Replace the node allocated as a part of the @fxid with
	 * a node that does not have an fxid associated it, so
	 * that the tree remains intact.
	 */
	new_tfxid = kmalloc(sizeof(*new_tfxid), GFP_KERNEL);
	if (unlikely(!new_tfxid)) {
		char xid_str[XIA_MAX_STRXID_SIZE];
		struct xia_xid xid;
		xid.xid_type = __be32_to_cpu(xtbl->fxt_ppal_type);
		memmove(xid.xid_id, fxid->fx_xid, XIA_XID_MAX);
		BUG_ON(xia_xidtop(&xid, xid_str, XIA_MAX_STRXID_SIZE) < 0);

		pr_err("While deleting entry %s/%hhu, no more memory was available to maintain the tree. Therefore, the entire subtree rooted at this entry must be deleted\n",
		       xid_str, fxid->fx_entry_type);
		dump_stack();

		/* The memory for the fxid that the user asked to deleted
		 * will be freed later -- we just need to remove it from
		 * the tree.
		 */
		disconnect_from_parent(cur);

		/* For every other node in this subtree, we need to remove
		 * the nodes and free the memory.
		 */
		disconnect_from_parent(cur->left);
		destroy_subtree(xtbl, cur->left);
		disconnect_from_parent(cur->right);
		destroy_subtree(xtbl, cur->right);

		return;
	}
	new_tfxid->has_fxid = false;
	replace_node(cur, new_tfxid);
	atomic_dec(&xtbl->fxt_count);

	/* Update the tree's root to be this new, "downgraded"
	 * node if necessary.
	 */
	if (cur == txtbl->root)
		txtbl->root = new_tfxid;

	/* The loop below is an optimization to prune the tree
	 * of "zombie" nodes. If we added a new, long prefix that
	 * created a long path in the tree, and are now removing
	 * that prefix, the entire path is useless, so we can
	 * remove it.
	 *
	 * While we're not at the root, at a leaf node, and don't
	 * have an fxid, delete the node and move up.
	 */
	cur = new_tfxid;
	while ((cur != txtbl->root) &&
	       (!cur->left && !cur->right) &&
	       (!cur->has_fxid)) {
		struct tree_fib_xid *parent = cur->parent;
		disconnect_from_parent(cur);
		kfree(cur);
		cur = parent;
	}
}

static void tree_fxid_rm(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	write_lock(&xtbl_txtbl(xtbl)->writers_lock);
	tree_fxid_rm_locked(NULL, xtbl, fxid);
	write_unlock(&xtbl_txtbl(xtbl)->writers_lock);
}

/* tree_xid_rm() removes the entry with the longest matching prefix,
 * since we have no prefix information for @xid.
 */
static struct fib_xid *tree_xid_rm(struct fib_xid_table *xtbl, const u8 *xid)
{
	struct fib_xid *fxid = __tree_fxid_find(xtbl, xid, 0, 0);
	if (!fxid) {
		tree_fib_unlock(xtbl, NULL);
		return NULL;
	}
	tree_fxid_rm_locked(NULL, xtbl, fxid);
	tree_fib_unlock(xtbl, NULL);
	return fxid;
}

static void tree_fxid_replace_locked(struct fib_xid_table *xtbl,
				     struct fib_xid *old_fxid,
				     struct fib_xid *new_fxid)
{
	replace_node(fxid_tfxid(old_fxid), fxid_tfxid(new_fxid));
}

int tree_fib_newroute_lock(struct fib_xid *new_fxid,
			   struct fib_xid_table *xtbl,
			   struct xia_fib_config *cfg, int *padded)
{
	struct fib_xid *cur_fxid;
	const u8 *id;

	if (padded)
		*padded = 0;

	/* Acquire lock and do exact matching to find @cur_fxid. */
	id = cfg->xfc_dst->xid_id;
	cur_fxid = __tree_fxid_find(xtbl, id, new_fxid->fx_entry_type, 1);

	if (cur_fxid) {
		if ((cfg->xfc_nlflags & NLM_F_EXCL) ||
		    !(cfg->xfc_nlflags & NLM_F_REPLACE))
			return -EEXIST;

		if (cur_fxid->fx_table_id != new_fxid->fx_table_id)
			return -EINVAL;

		/* Replace entry.
		 * Notice that @cur_fxid and @new_fxid may be of different
		 * types
		 */
		tree_fxid_replace_locked(xtbl, cur_fxid, new_fxid);
		fxid_free(xtbl, cur_fxid);
		return 0;
	}

	if (!(cfg->xfc_nlflags & NLM_F_CREATE))
		return -ENOENT;

	/* Add new entry. */
	BUG_ON(tree_fxid_add_locked(NULL, xtbl, new_fxid));

	if (padded)
		*padded = 1;
	return 0;
}

/* tree_fib_newroute() differs from all_fib_newroute() because its lookup
 * function has the option of doing longest prefix or exact matching, and
 * all_fib_newroute() is not flexible enough to do that.
 *
 * This simple version of newroute simply adds the entry, without
 * flushing any anchors.
 */
static int tree_fib_newroute(struct fib_xid *new_fxid,
			     struct fib_xid_table *xtbl,
			     struct xia_fib_config *cfg, int *padded)
{
	int rc = tree_fib_newroute_lock(new_fxid, xtbl, cfg, padded);
	tree_fib_unlock(xtbl, NULL);
	return rc;
}

/* tree_fib_delroute() differs from all_fib_delroute() because its lookup
 * function has the option of doing longest prefix or exact matching, and
 * all_fib_delroute() is not flexible enough to do that.
 */
int tree_fib_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
		      struct xia_fib_config *cfg)
{
	struct fib_xid *fxid;
	int rc;

	if (!valid_prefix(cfg))
		return -EINVAL;

	/* Do exact matching to find @fxid. */
	fxid = __tree_fxid_find(xtbl, cfg->xfc_dst->xid_id,
				*(u8 *)cfg->xfc_protoinfo, 1);
	if (!fxid) {
		rc = -ENOENT;
		goto unlock;
	}
	if (fxid->fx_table_id != cfg->xfc_table) {
		rc = -EINVAL;
		goto unlock;
	}

	tree_fxid_rm_locked(NULL, xtbl, fxid);
	tree_fib_unlock(xtbl, NULL);
	fxid_free(xtbl, fxid);
	return 0;

unlock:
	tree_fib_unlock(xtbl, NULL);
	return rc;
}

/* Dump all entries in tree. */
static int tree_xtbl_dump_rcu(struct fib_xid_table *xtbl,
			      struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			      struct netlink_callback *cb)
{
	struct tree_fib_xid_table *txtbl = xtbl_txtbl(xtbl);
	struct tree_fib_xid *cur;
	int rc = 0;

	read_lock(&txtbl->writers_lock);
	cur = get_leftmost_node(txtbl->root);
	while (cur) {
		if (cur->has_fxid) {
			struct fib_xid *fxid = tfxid_fxid(cur);
			rc = xtbl->all_eops[fxid->fx_table_id].
				dump_fxid(fxid, xtbl, ctx, skb, cb);
			if (rc < 0)
				goto out;
		}
		cur = get_next_node(cur);
	}
out:
	read_unlock(&txtbl->writers_lock);
	return rc;
}

struct fib_xid *tree_fib_get_pred_locked(struct fib_xid *fxid)
{
	struct tree_fib_xid *par = fxid_tfxid(fxid)->parent;
	while (par) {
		if (par->has_fxid)
			return tfxid_fxid(par);
		par = par->parent;
	}
	return NULL;
}

/* Main entries for LPM need to display the prefix length when dumped,
 * so tree_fib_mrd_dump() differs from fib_mrd_dump().
 */
int tree_fib_mrd_dump(struct fib_xid *fxid, struct fib_xid_table *xtbl,
		      struct xip_ppal_ctx *ctx, struct sk_buff *skb,
		      struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_redirect_main *mrd = fxid_mrd(fxid);
	struct xia_xid dst;

	nlh = nlmsg_put(skb, portid, seq, RTM_NEWROUTE, sizeof(*rtm),
			NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = XRTABLE_MAIN_INDEX;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl_ppalty(xtbl);
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);

	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst) ||
		     nla_put(skb, RTA_GATEWAY, sizeof(mrd->gw), &mrd->gw)))
		goto nla_put_failure;

	/* Add prefix length to packet. */
	if (unlikely(nla_put(skb, RTA_PROTOINFO, sizeof(fxid->fx_entry_type),
			     &(fxid->fx_entry_type))))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

const struct xia_ppal_rt_iops xia_ppal_tree_rt_iops = {
	.xtbl_init = tree_xtbl_init,
	.xtbl_death_work = tree_xtbl_death_work,

	.fxid_ppal_alloc = tree_fxid_ppal_alloc,
	.fxid_init = tree_fxid_init,

	/* Note that there is no RCU-specific version. */
	.fxid_find_rcu = tree_fxid_find_rcu,
	.fxid_find_lock = tree_fxid_find_lock,
	.iterate_xids = tree_iterate_xids,
	/* Note that there is no RCU-specific version. */
	.iterate_xids_rcu = tree_iterate_xids,

	.fxid_add = tree_fxid_add,
	.fxid_add_locked = tree_fxid_add_locked,

	.fxid_rm = tree_fxid_rm,
	.fxid_rm_locked = tree_fxid_rm_locked,
	.xid_rm = tree_xid_rm,

	.fxid_replace_locked = tree_fxid_replace_locked,

	.fib_unlock = tree_fib_unlock,

	.fib_newroute = tree_fib_newroute,
	.fib_delroute = tree_fib_delroute,

	.xtbl_dump_rcu = tree_xtbl_dump_rcu,
};

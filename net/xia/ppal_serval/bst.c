/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * This is an implementation of a binary search trie (bst), also
 * called a bitwise trie. It works well for LPM lookups of arbitrary
 * length bit strings. Do not confuse with binary search trees.
 * 
 * The code is not particularly optimized at this point.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <platform.h>
#include <debug.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "bst.h"

#define PREFIX_BYTE(bits) ((bits) / 8)
#define PREFIX_SIZE(bits) (PREFIX_BYTE(bits) + (((bits) % 8) ? 1 : 0))
#define CHECK_BIT(prefix, bitoffset) (((char *)prefix)[PREFIX_BYTE(bitoffset)] \
				      & (0x1 << (7 - ((bitoffset) % 8))))

/*
  struct bst_node:

  A node in a bitwise trie.

  A non-NULL private pointer indicates that the node is "active",
  i.e., there is data associated with this node. A node can be freed
  when private is NULL and there are no children.  
*/
struct bst_node {       
        struct bst *tree;
	struct bst_node *parent, *left, *right;
        struct bst_node_ops *ops;
        struct list_head lh; /* Used for printing trees non-recursively */
	unsigned char flags;
        void *private;
	unsigned int prefix_bits;
        unsigned int prefix_size;
	unsigned char prefix[0];
};

const unsigned char *bst_node_get_prefix(const struct bst_node *n)
{
        return n->prefix;
}

unsigned int bst_node_get_prefix_size(const struct bst_node *n)
{
        return PREFIX_SIZE(n->prefix_bits);
}

unsigned long bst_node_get_prefix_bits(const struct bst_node *n)
{
        return n->prefix_bits;
}

void *bst_node_get_private(struct bst_node *n)
{
        return n->private;
}

int bst_node_print_prefix(struct bst_node *n, char *buf, size_t buflen)
{
        unsigned int i;
        int len = 0, totlen = 0;
        
        if (n == NULL || buflen <= 0)
                return 0;

        if (n->prefix_bits == 0) {
                len = snprintf(buf, buflen, "0");
                totlen += len;
        } else {
                for (i = 0; i < PREFIX_SIZE(n->prefix_bits); i++) {
                        len = snprintf(&buf[i*2], buflen, "%02x",
                                       n->prefix[i] & 0xff);
                        
                        if (len > buflen)
                                buflen = 0;
                        else
                                buflen -= len;
                        totlen += len;
                }
        }
        return len;
}

static void stack_push(struct list_head *stack, struct bst_node *n)
{
        list_add(&n->lh, stack);
}

static struct bst_node *stack_pop(struct list_head *stack)
{
        struct bst_node *n;

        if (list_empty(stack))
                return NULL;

        n = list_first_entry(stack, struct bst_node, lh);
        list_del(&n->lh);

        return n;
}

void bst_iterator_init(struct bst *tree, struct bst_iterator *iter)
{
        INIT_LIST_HEAD(&iter->stack);
        iter->curr = tree->root;
        if (iter->curr)
                stack_push(&iter->stack, iter->curr);
}

struct bst_node *bst_iterator_node(struct bst_iterator *iter)
{
        return iter->curr;
}

struct bst_node *bst_iterator_next(struct bst_iterator *iter)
{
        struct bst_node *n = NULL;

        /* Skip over entries without private pointer set (i.e., those
           nodes without data) */
        while (!list_empty(&iter->stack)) {
                n = stack_pop(&iter->stack);
                
                if (n->left)
                        stack_push(&iter->stack, n->left);
                
                if (n->right)
                        stack_push(&iter->stack, n->right);

                if (n->private)
                        break;
        }

        iter->curr = n;

        return n;
}

int bst_node_print(struct bst_node *n, char *buf, size_t buflen)
{
        int len = 0;

        buf[0] = '\0';

        if (n->private && n->ops && n->ops->print)
                len = n->ops->print(n, buf, buflen);

        return len;
}

int bst_node_print_nonrecursive(struct bst_node *n, char *buf, size_t buflen)
{
        struct list_head stack;
        int len = 0, tot_len = 0;

        INIT_LIST_HEAD(&stack);
        
        stack_push(&stack, n);
        
        while (!list_empty(&stack)) {
                n = stack_pop(&stack);
                if (n) {
                        if (n->private) {
                                if (n->ops && n->ops->print) {
                                        len = n->ops->print(n, buf + tot_len, 
                                                            buflen);

                                        tot_len += len;

                                        if (len > buflen)
                                                buflen = 0;
                                        else
                                                buflen -= len;
                                }
                        }
                        if (n->right)
                                stack_push(&stack, n->right);
                        
                        if (n->left)
                                stack_push(&stack, n->left);
                }
        }
        return tot_len;
}

/*
  Print using recursion. Cannot use this in kernel due to limited
  stack space. Must instead use the non-recursive version above that
  implements its own heap-based stack.
 */
int bst_node_print_recursive(struct bst_node *n, char *buf, size_t buflen)
{
        int len = 0, tot_len = 0;

	if (n) {
		if (n->private) {
                        if (n->ops && n->ops->print) {
                                len = n->ops->print(n, buf + tot_len, 
                                                    buflen);

                                tot_len += len;

                                if (len > buflen)
                                        buflen = 0;
                                else
                                        buflen -= len;
                        }
                }

		len = bst_node_print_recursive(n->left, buf + tot_len, 
                                               buflen);
                
                tot_len += len;
                
                if (len > buflen)
                        buflen = 0;
                else
                        buflen -= len;

		len = bst_node_print_recursive(n->right, buf + tot_len, 
                                               buflen);
                
                tot_len += len;
                
                if (len > buflen)
                        buflen = 0;
                else
                        buflen -= len;
	}

        return tot_len;
}

static
struct bst_node *bst_node_find_longest_prefix(struct bst_node *n,
                                              struct bst_node **prev,
                                              void *prefix,
                                              unsigned int prefix_bits,
                                              int (*match)(struct bst_node *))
{
        if (!n)
                return NULL;

        while (1) {
                /* Keep track of the previous matching node */
                if (n->private) {
                        if (match == NULL || match(n))
                                *prev = n;
                }
                /*
                  We are matching the root node, or we hit the prefix
                  length we are matching.
                */
                if (prefix_bits == 0 || n->prefix_bits == prefix_bits)
                        break;
                
                /* check if next bit is zero or one and, based on that, go
                 * left or right */
                /*
                LOG_DBG("checking byte %u, bits=%u\n",
                        PREFIX_BYTE(n->prefix_bits), n->prefix_bits);
                */
                if (CHECK_BIT(prefix, n->prefix_bits)) {
                        if (n->right) {
                                n = n->right;
                        } else {
                                break;
                        }
                } else {
                        if (n->left) {
                                n = n->left;
                        } else {
                                break;
                        }
                }
        }
        return n;
}

struct bst_node *bst_find_longest_prefix_match(struct bst *tree, 
                                               void *prefix,
                                               unsigned int prefix_bits,
                                               int (*match)(struct bst_node *))
{
        struct bst_node *n, *prev = NULL;

        n = bst_node_find_longest_prefix(tree->root, 
                                         &prev, prefix, 
                                         prefix_bits, match);

        if (n && n->private && (!match || match(n)))
                return n;

        return prev;
}

struct bst_node *bst_find_longest_prefix(struct bst *tree, 
                                         void *prefix,
                                         unsigned int prefix_bits)
{
        return bst_find_longest_prefix_match(tree, prefix, prefix_bits, NULL);
}

/*
  Free the memory associated with a node. The node should have been
  destroyed first, and not be active 
*/
static void bst_node_free(struct bst_node *n)
{
        /* Make sure the parent knows this node is dead, unless the
         * parent is the node itself. */
        if (n->parent != n) {
                if (n->parent->right == n)
                        n->parent->right = NULL;
                else
                        n->parent->left = NULL;
        } else {
                n->tree->root = NULL;
        }
        kfree(n);
}

static void bst_node_orphan(struct bst_node *n)
{
        if (n->private) {
                if (n->tree)
                        n->tree->entries--;
                
                if (n->ops && n->ops->destroy)
                        n->ops->destroy(n);
                
                n->ops = NULL;
                n->private = NULL;
        }
}

/*
  This function will release a node and free it unless it still has
  children. It will also free any parents that are orphaned and
  childless.
 */
void bst_node_release(struct bst_node *n)
{
        struct bst_node *parent;

        bst_node_orphan(n);

        /* Node still has children, so do not free it */
        if (n->left || n->right)
                return;

        /* Go up the tree and remove all parents until hitting the
           first node which is still active or have a remaining
           child */
        parent = n->parent;
        bst_node_free(n);
        n = parent;
        
        while (n && !n->private && !n->left && 
               !n->right && n != n->parent) {
                parent = n->parent;
                bst_node_free(n);
                n = parent;
        }
}

/* Destroy a sub-tree by recursing down the children */
static void __bst_destroy_subtree(struct bst_node *n)
{
        struct bst_node *root = n;

        while (1) {                
                if (n == root && !n->left && !n->right) {
                        bst_node_orphan(n);
                        bst_node_free(n);
                        break;
                }

                if (!n->right) {
                        if (!n->left) {
                                struct bst_node *parent = n->parent;
                                bst_node_orphan(n);
                                bst_node_free(n);
                                n = parent;
                        } else {
                                n->right = n->left;
                                n->left = NULL;
                        }
                } else 
                        n = n->right;
        }
}

/* Apply function to subtree */
int bst_subtree_func(struct bst_node *n, 
                     int (*func)(struct bst_node *, void *arg),
                     void *arg)
{
        struct list_head stack;
        int ret = 0, count = 0;
        
        INIT_LIST_HEAD(&stack);
        
        stack_push(&stack, n);
        
        while (!list_empty(&stack)) {
                n = stack_pop(&stack);

                if (n) {
                        struct bst_node *left = n->left, 
                                *right = n->right;
                        
                        if (n->private) {
                                ret = func(n, arg);
                                
                                if (ret < 0)
                                        return ret;
                                
                                count += ret;
                        }
                        if (right)
                                stack_push(&stack, right);
                        
                        if (left)
                                stack_push(&stack, left);
                }
        }
        return count;
}

/* Apply function to subtree recursively */
int bst_subtree_func_recursive(struct bst_node *n, 
                               int (*func)(struct bst_node *, void *arg),
                               void *arg)
{
        int count = 0, ret;
        
        if (!n)
                return count;


        if (n->left) {
                ret = bst_subtree_func(n->left, func, arg);
                if (ret < 0)
                        return ret;
                count += ret;
        }
        
        if (n->right) {
                ret = bst_subtree_func(n->right, func, arg);
                if (ret < 0)
                        return ret;
                count += ret;
        }

        ret = func(n, arg);
        
        if (ret < 0)
                return ret;
        
        count += ret;

        return count;
}

int bst_init(struct bst *t)
{
        t->root = NULL;
        t->entries = 0;

        return 0;
}

void bst_destroy(struct bst *tree)
{
        if (tree->entries > 0 && tree->root) {
                __bst_destroy_subtree(tree->root);
                tree->root = NULL;
                tree->entries = 0;
        }
}

static int bst_node_init(struct bst_node *n,
                         struct bst_node_ops *ops, 
                         void *private)
{
        if (n->ops) {
                LOG_ERR("ops already set\n");
                return -1;
        }        
        if (n->private) {
                LOG_ERR("private already set\n");
                return -1;
        }

        n->ops = ops;
        n->private = private;
        
        if (ops && ops->init) {
                if (ops->init(n) < 0) {
                        LOG_ERR("init failed\n");
                        return -1;
                }
        }
        return 0;
}

static struct bst_node *bst_create_node(struct bst_node *parent,
                                        void *prefix, 
                                        unsigned int prefix_size,
                                        unsigned int prefix_bits,
                                        gfp_t alloc)
{
        struct bst_node *n;

	n = (struct bst_node *)kmalloc(sizeof(*n) + prefix_size, alloc);
	
	if (!n)
		return NULL;
	
	memset(n, 0, sizeof(*n) + prefix_size);

	if (CHECK_BIT(prefix, parent->prefix_bits)) {
		parent->right = n;
	} else {
		parent->left = n;
	}

        n->tree = parent->tree;
	n->left = NULL;
	n->right = NULL;
        n->ops = NULL;
        n->private = NULL;
	n->parent = parent;
	n->flags = 0;
        n->prefix_size = prefix_size;
	n->prefix_bits = parent->prefix_bits + 1;
	memcpy(n->prefix, prefix, n->prefix_size);
        INIT_LIST_HEAD(&n->lh);
        
    
	/* 
	   Compute a mask that zeros out the extra bits that we might
	   have copied in the last byte of the prefix.
	*/
	
	if (n->prefix_bits % 8) {
                unsigned char endmask = 0;
                unsigned int i;

		for (i = 0; i < n->prefix_bits % 8; i++) {
			endmask |= (0x1 << (7-i));
		}
		
		n->prefix[n->prefix_size-1] &= endmask;
	}
    
        return n;
}

/*
  Note for kernel: Recursive functions can easily exhaust the stack
  space in the kernel (which seems to be limited to 4k). Therefore,
  avoid implementing inserts by doing recursive callse to
  bst_node_new().
 */
static struct bst_node *bst_node_new(struct bst_node *parent,
                                     struct bst_node_ops *ops,
                                     void *private,
				     void *prefix, 
				     unsigned int prefix_bits,
                                     gfp_t alloc)
{

        struct bst_node *n = NULL;
        
        while (1) {
                n =  bst_create_node(parent,
                                     prefix,
                                     PREFIX_SIZE(parent->prefix_bits + 1),
                                     prefix_bits,
                                     alloc);
                
                if (!n) {
                        LOG_ERR("Memory allocation failed\n");
                        break;
                }
                
                if (CHECK_BIT(prefix, parent->prefix_bits)) {
                        parent->right = n;
                        
                        if (parent->prefix_bits + 1 != prefix_bits)
                                parent = parent->right;
                        else 
                                break;
                } else {
                        parent->left = n;
                        
                        if (parent->prefix_bits + 1 != prefix_bits)
                                parent = parent->left;
                        else
                                break;
                }
        }
        
        return n;
}

struct bst_node *bst_node_insert_prefix(struct bst_node *root, 
                                        struct bst_node_ops *ops, 
                                        void *private, void *prefix, 
                                        unsigned int prefix_bits,
                                        gfp_t alloc)
{
	struct bst_node *n, *prev = NULL;
        
	n = bst_node_find_longest_prefix(root, &prev, prefix, 
                                         prefix_bits, NULL);	
	
	/*
          printf("found %p %p %p %p %u\n", 
          n, n->parent,
          n->left, n->right,
          n->prefix_bits)
        */
        if (n->prefix_bits < prefix_bits) {
                n = bst_node_new(n, ops, private, prefix, prefix_bits, alloc);
		
		if (!n) {
                        LOG_ERR("node_new failed\n");
			return NULL;
                }
        }
        
        if (bst_node_init(n, ops, private) == -1) {
                LOG_ERR("node_init failed\n");
                /* TODO: handle init failure... cleanup tree? */
                return NULL;
        }

	return n;
}

struct bst_node *bst_insert_prefix(struct bst *tree, struct bst_node_ops *ops, 
                                   void *private, void *prefix, 
                                   unsigned int prefix_bits,
                                   gfp_t alloc)
{
        struct bst_node *n;

        if (tree->entries == 0) {
                tree->root = kmalloc(sizeof(struct bst_node), alloc);
                
                if (!tree->root)
                        return NULL;

                memset(tree->root, 0, sizeof(*tree->root));
                tree->root->left = tree->root->right = NULL;
                tree->root->parent = tree->root;
                tree->root->ops = NULL;
                tree->root->private = NULL;
                tree->root->flags = 0;
                tree->root->prefix_bits = 0;
                tree->root->tree = tree;
        }

        n = bst_node_insert_prefix(tree->root, ops, private, 
                                   prefix, prefix_bits, alloc);

        if (n) {
                tree->entries++;
        }

        return n;
}

int bst_remove_prefix(struct bst *tree, void *prefix, unsigned int prefix_bits)
{
        struct bst_node *n;

        n = bst_find_longest_prefix(tree, prefix, prefix_bits);
        
        if (n && n->prefix_bits == prefix_bits) {
                bst_node_orphan(n);
                return 1;
        }

        return 0;
}

int bst_print(struct bst *tree, char *buf, size_t buflen)
{
        if (!tree || tree->entries == 0)
                return 0;

        return bst_node_print_nonrecursive(tree->root, buf, buflen);
}

static int bst_node_init_default(struct bst_node *n)
{
        return 0;
}

static void bst_node_destroy_default(struct bst_node *n)
{

}

struct bst_node_ops default_bst_node_ops = {
        .init = bst_node_init_default,
        .destroy = bst_node_destroy_default,
};

#if defined(ENABLE_MAIN)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFLEN 2000


static int print_ip_entry(struct bst_node *n, char *buf, size_t buflen)
{
	struct in_addr addr;
        
        memset(&addr, 0, sizeof(addr));
        memcpy(&addr, n->prefix, PREFIX_SIZE(n->prefix_bits));
        
        return snprintf(buf, buflen, "\t%s", inet_ntoa(addr));
}

static struct bst_node_ops ip_ops = {
        .init = bst_node_init_default,
        .destroy = bst_node_destroy_default,
        .print = print_ip_entry
};

int main(int argc, char **argv)
{
	struct bst root;
	struct in_addr addr;
        char buf[BUFLEN];

	bst_init(&root);

	inet_aton("192.168.1.0", &addr);
	bst_insert_prefix(&root, &ip_ops, NULL, &addr, 24, 0);
	
	inet_aton("192.168.1.253", &addr);
	bst_insert_prefix(&root, &ip_ops, NULL, &addr, 26, 0);

	inet_aton("192.168.2.0", &addr);
	bst_insert_prefix(&root, &ip_ops, NULL, &addr, 25, 0);

	inet_aton("192.168.2.250", &addr);
	bst_insert_prefix(&root, &ip_ops, NULL, &addr, 27, 0);


	bst_insert_prefix(&root, &ip_ops, NULL, NULL, 0, 0);

	bst_print(&root, buf, BUFLEN);
        
        printf("%s", buf);
       
	printf("remove:\n");

	inet_aton("192.168.1.0", &addr);

        bst_remove_prefix(&root, &addr, 24, 0);

	bst_print(&root, buf, BUFLEN);

        printf("%s", buf);
       
	bst_destroy(&root);

	return 0;
}

#endif

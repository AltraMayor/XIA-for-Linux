/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _BST_H_
#define _BST_H_

#include <list.h>

struct bst_node;

struct bst {
        struct bst_node *root;
        unsigned int entries;
};

#define BST_INITIALIZER { NULL, 0 }
 
struct bst_node_ops {
        int (*init)(struct bst_node *);
        void (*destroy)(struct bst_node *);
        int (*print)(struct bst_node *, char *buf, size_t buflen);
};

struct bst_iterator {
        struct list_head stack;
        struct bst_node *curr;
};

extern struct bst_node_ops default_bst_node_ops;

int bst_init(struct bst *tree);
void bst_destroy(struct bst *tree);
struct bst_node *bst_insert_prefix(struct bst *tree, struct bst_node_ops *ops,
                                   void *private, void *prefix, 
                                   unsigned int prefix_bits,
                                   gfp_t alloc);
void bst_remove_node(struct bst *tree, struct bst_node *n);
int bst_remove_prefix(struct bst *tree, void *prefix,
                       unsigned int prefix_bits);
void bst_node_release(struct bst_node *n);

struct bst_node *bst_find_longest_prefix(struct bst *tree, 
                                         void *prefix,
                                         unsigned int prefix_bits);

struct bst_node *bst_find_longest_prefix_match(struct bst *tree, 
                                               void *prefix,
                                               unsigned int prefix_bits,
                                               int (*match)(struct bst_node *));

void bst_iterator_init(struct bst *tree, struct bst_iterator *iter);
struct bst_node *bst_iterator_node(struct bst_iterator *iter);
struct bst_node *bst_iterator_next(struct bst_iterator *iter);
int bst_node_print(struct bst_node *n, char *buf, size_t buflen);
int bst_node_print_prefix(struct bst_node *n, char *buf, size_t buflen);
int bst_print(struct bst *tree, char *buf, size_t buflen);
void *bst_node_get_private(struct bst_node *n);
const unsigned char *bst_node_get_prefix(const struct bst_node *n);
unsigned int bst_node_get_prefix_size(const struct bst_node *n);
unsigned long bst_node_get_prefix_bits(const struct bst_node *n);
int bst_subtree_func(struct bst_node *n, 
                     int (*func)(struct bst_node *, void *arg), 
                     void *arg);

#define bst_node_private(n, type) ((type *)bst_node_get_private((n)))

#endif /* _BST_H_ */

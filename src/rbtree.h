#ifndef __RBTREE_H__
#define __RBTREE_H__

enum rb_color
{
    SRB_BLACK,
    SRB_RED,
};
typedef struct node_key
{
    char *name;
    short type;
} KEY;

typedef struct rbtree_node
{
    struct rbtree_node *parent;
    struct rbtree_node *left;
    struct rbtree_node *right;
    enum rb_color color;
    KEY *key;
    void *data;
} rbtree_node;

typedef int (*rbtree_cmp_fn_t)(void *key_a, void *key_b); //比较函数模板

typedef struct rbtree
{
    struct rbtree_node *root;
    rbtree_cmp_fn_t compare;
} rbtree;

int rb_compare(KEY *key_a, KEY *key_b);
struct rbtree *rbtree_init(rbtree_cmp_fn_t fn);
int rbtree_insert(struct rbtree *tree, KEY *key, void *data);
void *rbtree_lookup(struct rbtree *tree, KEY *key);
int rbtree_remove(struct rbtree *tree, KEY *key);
#endif

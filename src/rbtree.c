#include "rbtree.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

void delete_case1(struct rbtree *tree, struct rbtree_node *node);
void delete_case2(struct rbtree *tree, struct rbtree_node *node);
void delete_case3(struct rbtree *tree, struct rbtree_node *node);
void delete_case4(struct rbtree *tree, struct rbtree_node *node);
void delete_case5(struct rbtree *tree, struct rbtree_node *node);
void delete_case6(struct rbtree *tree, struct rbtree_node *node);

static inline enum rb_color get_color(struct rbtree_node *node)
{
    return (node == NULL) ? SRB_BLACK : node->color;
}

static inline void set_color(enum rb_color color, struct rbtree_node *node)
{
    assert(node != NULL);
    node->color = color;
}

static inline struct rbtree_node *get_parent(struct rbtree_node *node)
{
    assert(node != NULL);
    return node->parent;
}

static inline void set_parent(struct rbtree_node *parent, struct rbtree_node *node)
{
    assert(node != NULL);
    node->parent = parent;
}

static int is_root(struct rbtree_node *node)
{
    assert(node != NULL);
    return (get_parent(node) == NULL);
}

static inline int is_black(struct rbtree_node *node)
{
    assert(node != NULL);
    return (get_color(node) == SRB_BLACK);
}

static inline int is_red(struct rbtree_node *node)
{
    assert(node != NULL);
    return (get_color(node) == SRB_RED);
}

struct rbtree_node *sibling(rbtree_node *node)
{
    assert(node != NULL);
    assert(node->parent != NULL); /* Root node has no sibling */
    if (node == node->parent->left)
        return node->parent->right;
    else
        return node->parent->left;
}
static inline rbtree_node *get_min(struct rbtree_node *node)
{
    assert(node != NULL);
    while (node->left)
        node = node->left;
    return node;
}

static inline rbtree_node *get_max(struct rbtree_node *node)
{
    assert(node != NULL);
    while (node->right)
        node = node->right;
    return node;
}

struct rbtree_node *rbtree_min(struct rbtree *tree)
{
    if (tree->root == NULL)
        return NULL;
    else
        return get_min(tree->root);
}

struct rbtree_node *rbtree_max(struct rbtree *tree)
{
    if (tree->root == NULL)
        return NULL;
    else
        return get_max(tree->root);
}

struct rbtree_node *rbtree_prev(struct rbtree_node *node)
{
    assert(node != NULL);
    if (node->left)
        return get_max(node->left);

    struct rbtree_node *parent;
    while ((parent = get_parent(node)) && parent->left == node)
        node = parent;
    return parent;
}

struct rbtree_node *rbtree_next(struct rbtree_node *node)
{
    assert(node != NULL);

    if (node->right)
        return get_min(node->right);

    struct rbtree_node *parent = NULL;
    while ((parent = get_parent(node)) != NULL && parent->right == node)
        node = parent;
    return parent;
}

struct rbtree_node *rbtree_createnode(KEY *key, void *data)
{
    struct rbtree_node *newnode = (struct rbtree_node *)malloc(sizeof(struct rbtree_node));
    if (newnode == NULL)
        return NULL;
    newnode->key = malloc(sizeof(KEY));
    newnode->key->name = malloc(strlen(key->name) + 1);
    newnode->key->type = key->type;
    newnode->data = data;
    memcpy(newnode->key->name, key->name, strlen(key->name) + 1);
    printf("CREATE %s %s\n", newnode->key->name, key->name);
    return newnode;
}

struct rbtree_node *do_lookup(KEY *key, struct rbtree *tree, struct rbtree_node **pparent)
{
    struct rbtree_node *current = tree->root;

    while (current)
    {
        // printf("NOW KEY %s %d\n", current->key->name, current->key->type);
        // printf("WANT KEY %s %d\n", key->name, key->type);
        int ret = tree->compare(current->key, key);
        if (ret == 0)
            return current;
        else
        {
            if (pparent != NULL)
                *pparent = current;
            if (ret < 0)
                current = current->right;
            else
                current = current->left;
        }
    }
    return NULL;
}

void *rbtree_lookup(struct rbtree *tree, KEY *key)
{
    assert(tree != NULL);
    struct rbtree_node *node;
    printf("lookup %s %d\n", key->name, key->type);
    node = do_lookup(key, tree, NULL);
    return (node == NULL) ? NULL : (node->data);
}

static void set_child(struct rbtree *tree, struct rbtree_node *node, struct rbtree_node *child)
{
    int ret = tree->compare(node->key, child->key);
    assert(ret != 0);

    if (ret > 0)
        node->left = child;
    else
        node->right = child;
}

static void rotate_left(struct rbtree_node *node, struct rbtree *tree)
{
    struct rbtree_node *p = node;
    struct rbtree_node *q = node->right;
    struct rbtree_node *parent = node->parent;
    if (parent == NULL)
        tree->root = q;
    else
    {
        if (parent->left == p)
            parent->left = q;
        else
            parent->right = q;
    }
    set_parent(parent, q);
    set_parent(q, p);

    p->right = q->left;
    if (q->left)
        set_parent(p, q->left);
    q->left = p;
}

static void rotate_right(struct rbtree_node *node, struct rbtree *tree)
{
    struct rbtree_node *p = node;
    struct rbtree_node *q = node->left; /* can't be NULL */
    struct rbtree_node *parent = get_parent(p);

    if (!is_root(p))
    {
        if (parent->left == p)
            parent->left = q;
        else
            parent->right = q;
    }
    else
        tree->root = q;
    set_parent(parent, q);
    set_parent(q, p);

    p->left = q->right;
    if (p->left)
        set_parent(p, p->left);
    q->right = p;
}
struct rbtree *rbtree_init(rbtree_cmp_fn_t compare)
{
    struct rbtree *tree = malloc(sizeof(struct rbtree));
    if (tree == NULL)
        return NULL;

    tree->root = NULL;
    tree->compare = compare;
    return tree;
}

/*原版本
struct rbtree* rbtree_init(rbtree_cmp_fn_t compare)
{
    struct rbtree* tree = malloc(sizeof(struct rbtree));
    if(tree == NULL)
        return NULL;
    else
    {
        tree->root = NULL;
        tree->compare = compare;
    }
    return tree;
}
*/

struct rbtree_node *__rbtree_insert(struct rbtree_node *node, struct rbtree *tree)
{
    struct rbtree_node *samenode = NULL;
    struct rbtree_node *parent = NULL;

    samenode = do_lookup(node->key, tree, &parent);
    if (samenode != NULL)
        return samenode;

    node->left = node->right = NULL;

    set_color(SRB_RED, node);
    set_parent(parent, node);

    if (parent == NULL)
        tree->root = node;
    else
        set_child(tree, parent, node);

    while ((parent = get_parent(node)) != NULL && parent->color == SRB_RED)
    {
        struct rbtree_node *grandpa = get_parent(parent); //grandpa must be existed
        //because root is black ,and parent is red,
        //parent can not be root of tree. and parent is red,so grandpa must be black
        if (parent == grandpa->left)
        {
            struct rbtree_node *uncle = grandpa->right;
            if (uncle && get_color(uncle) == SRB_RED)
            {
                set_color(SRB_RED, grandpa);
                set_color(SRB_BLACK, parent);
                set_color(SRB_BLACK, uncle);
                node = grandpa;
            }
            else
            {
                if (node == parent->right)
                {
                    rotate_left(parent, tree);
                    node = parent;
                    parent = get_parent(parent);
                }
                set_color(SRB_BLACK, parent);
                set_color(SRB_RED, grandpa);
                rotate_right(grandpa, tree);
            }
        }
        else
        {
            struct rbtree_node *uncle = grandpa->left;
            if (uncle && uncle->color == SRB_RED)
            {
                set_color(SRB_RED, grandpa);
                set_color(SRB_BLACK, parent);
                set_color(SRB_BLACK, uncle);
                node = grandpa;
            }
            else
            {
                if (node == parent->left)
                {
                    rotate_right(parent, tree);
                    node = parent;
                    parent = get_parent(node);
                }
                set_color(SRB_BLACK, parent);
                set_color(SRB_RED, grandpa);
                rotate_left(grandpa, tree);
            }
        }
    }

    set_color(SRB_BLACK, tree->root);
    return NULL;
}

int rbtree_insert(struct rbtree *tree, KEY *key, void *data)
{
    struct rbtree_node *node = rbtree_createnode(key, data);
    struct rbtree_node *samenode = NULL;
    if (node == NULL)
        return -1;
    else
        samenode = __rbtree_insert(node, tree);
    if (samenode != NULL)
        return -2;
    return 0;
}
int rb_compare(KEY *key_a, KEY *key_b)
{
    printf("Comapre %s %d %s %d\n%d %d\n", key_a->name, strlen(key_a->name), key_b->name, strlen(key_b->name), key_a->type, key_b->type);
    if (strcmp(key_a->name, key_b->name) > 0)
        return 1;
    else if (strcmp(key_a->name, key_b->name) < 0)
        return -1;
    else
    {
        if (key_a->type > key_b->type)
            return 1;
        else if (key_a->type < key_b->type)
            return -1;
        else
            return 0;
    }
}

void replace_node(struct rbtree *t, rbtree_node *oldn, rbtree_node *newn)
{
    if (oldn->parent == NULL)
        t->root = newn;
    else
    {
        if (oldn == oldn->parent->left)
            oldn->parent->left = newn;
        else
            oldn->parent->right = newn;
    }
    if (newn != NULL)
        newn->parent = oldn->parent;
}

void delete_case1(struct rbtree *tree, struct rbtree_node *node)
{
    if (node->parent == NULL)
        return;
    else
        delete_case2(tree, node);
}

void delete_case2(struct rbtree *tree, struct rbtree_node *node)
{
    if (get_color(sibling(node)) == SRB_RED)
    {
        node->parent->color = SRB_RED;
        sibling(node)->color = SRB_BLACK;
        if (node == node->parent->left)
            rotate_left(node->parent, tree);
        else
            rotate_right(node->parent, tree);
    }
    delete_case3(tree, node);
}

void delete_case3(struct rbtree *tree, struct rbtree_node *node)
{
    if (node->parent->color == SRB_BLACK && get_color(sibling(node)) == SRB_BLACK &&
        get_color(sibling(node)->right) == SRB_BLACK && get_color(sibling(node)->left) == SRB_BLACK)
    {
        sibling(node)->color = SRB_RED;
        delete_case1(tree, node->parent);
    }
    else
        delete_case4(tree, node);
}

void delete_case4(struct rbtree *t, struct rbtree_node *n)
{
    if (get_color(n->parent) == SRB_RED && get_color(sibling(n)) == SRB_BLACK &&
        get_color(sibling(n)->left) == SRB_BLACK && get_color(sibling(n)->right) == SRB_BLACK)
    {
        sibling(n)->color = SRB_RED; //sibling's two son is black ,so it can changed to red
        n->parent->color = SRB_BLACK;
    }
    else
        delete_case5(t, n);
}

void delete_case5(struct rbtree *t, rbtree_node *n)
{
    if (n == n->parent->left && get_color(sibling(n)) == SRB_BLACK &&
        get_color(sibling(n)->left) == SRB_RED && get_color(sibling(n)->right) == SRB_BLACK)
    {
        sibling(n)->color = SRB_RED;
        sibling(n)->left->color = SRB_BLACK;
        rotate_right(sibling(n), t);
    }
    else if (n == n->parent->right && get_color(sibling(n)) == SRB_BLACK &&
             get_color(sibling(n)->right) == SRB_RED && get_color(sibling(n)->left) == SRB_BLACK)
    {
        sibling(n)->color = SRB_RED;
        sibling(n)->right->color = SRB_BLACK;
        rotate_left(sibling(n), t);
    }
    delete_case6(t, n);
}

void delete_case6(struct rbtree *t, rbtree_node *n)
{
    sibling(n)->color = get_color(n->parent);
    n->parent->color = SRB_BLACK;
    if (n == n->parent->left)
    {
        assert(get_color(sibling(n)->right) == SRB_RED);
        sibling(n)->right->color = SRB_BLACK;
        rotate_left(n->parent, t);
    }
    else
    {
        assert(get_color(sibling(n)->left) == SRB_RED);
        sibling(n)->left->color = SRB_BLACK;
        rotate_right(n->parent, t);
    }
}
void __rbtree_remove(struct rbtree_node *node, struct rbtree *tree)
{
    struct rbtree_node *left = node->left;
    struct rbtree_node *right = node->right;
    struct rbtree_node *child = NULL;
    if (left != NULL && right != NULL)
    {
        struct rbtree_node *next = get_min(right);
        node->key = next->key;
        node->data = next->data;
        node = next;
    }

    assert(node->left == NULL || node->right == NULL);
    child = (node->right == NULL ? node->left : node->right);
    if (get_color(node) == SRB_BLACK)
    {
        set_color(get_color(child), node);
        delete_case1(tree, node);
    }
    replace_node(tree, node, child);
    if (node->parent == NULL && child != NULL) //node is root,root should be black
        set_color(SRB_BLACK, child);

    free(node->key->name);
    free(node->key);
    free(node);
}

int rbtree_remove(struct rbtree *tree, KEY *key)
{
    struct rbtree_node *node = do_lookup(key, tree, NULL);
    if (node == NULL)
        return -1;
    else
        __rbtree_remove(node, tree);
    return 0;
}

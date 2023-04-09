#include <limits.h>
#include "netinet/in.h"

#include "lib.h"
#include "trie.h"

struct trie_node* create_node()
{
    struct trie_node* new_node = malloc(sizeof(struct trie_node));
    new_node->left = NULL;
    new_node->right = NULL;
    new_node->route = NULL;

    return new_node;
}

void insert_in_trie(struct route_table_entry *route, struct trie_node *route_trie)
{
    int level = CHAR_BIT * IP_LEN;

    uint32_t mask = ntohl(route->mask);
    uint32_t prefix = ntohl(route->prefix);
    while((mask & 1) == 0)
        mask >>= 1;

    struct trie_node *node = route_trie;

    while (mask) {
        if (prefix >> (level - 1) & 1) {
            if (!node->right)
                node->right = create_node();
            node = node->right;
        } else {
            if (!node->left)
                node->left = create_node();
            node = node->left;
        }

        level--;
        mask >>= 1;
    }

    node->route = route;
}

struct route_table_entry *lpm(uint32_t ip_dest, struct trie_node *route_trie)
{
    int level = CHAR_BIT * IP_LEN;
    ip_dest = ntohl(ip_dest);
    struct trie_node* node = route_trie;
    struct route_table_entry* best_route = NULL;

    while (node) {
        if (node->route) {
            best_route = node->route;
        }

        if (ip_dest >> (level - 1) & 1) {
            node = node->right;
        } else {
            node = node->left;
        }

        level--;
    }
    return best_route;
}

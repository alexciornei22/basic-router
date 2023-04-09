#ifndef HOMEWORK1_PUBLIC_TRIE_H
#define HOMEWORK1_PUBLIC_TRIE_H

#include <stdint.h>

/* trie node for efficient LPM algorithm */
struct trie_node {
    struct trie_node* left;
    struct trie_node* right;
    struct route_table_entry* route;
};

/**
 * allocates memory for new trie node
 */
struct trie_node* create_node();

/**
 * Insert a routing table entry in trie for efficient
 * LPM algorithm
 * @param route new route to be added
 * @param route_trie route trie
 */
void insert_in_trie(struct route_table_entry *route, struct trie_node *route_trie);

/**
 * Searches the best route for given IP destination address
 * @param ip_dest IP destination address
 * @param route_trie route trie
 * @return routing table entry or NULL if no route
 * is found
 */
struct route_table_entry *lpm(uint32_t ip_dest, struct trie_node *route_trie);

#endif //HOMEWORK1_PUBLIC_TRIE_H

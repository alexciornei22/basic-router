#include <arpa/inet.h>
#include <string.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

struct arp_entry* arp_table;
int arp_len;

queue q;

struct arp_entry *get_mac_entry(uint32_t given_ip) {
    for (int i = 0; i < arp_len; i++)
    {
        if (given_ip == arp_table[i].ip) {
            return &arp_table[i];
        }
    }

    return NULL;
}

void add_to_arp_table(struct arp_header* arp_hdr)
{
    arp_table[arp_len].ip = arp_hdr->spa;
    memcpy(arp_table[arp_len].mac, arp_hdr->sha, MAC_LEN);
    arp_len++;
}

int handle_ip(char *buf, size_t len, int interface, struct trie_node *route_trie)
{
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

    uint16_t old_checksum = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    uint16_t new_checksum = checksum((uint16_t*) ip_hdr, sizeof(struct iphdr));
    if (old_checksum != new_checksum) {
        printf("Incorrect checksum\n");
        return -1;
    }

    if (ip_hdr->ttl <= 1) {
        printf("TTL exceeded\n");
        send_icmp_error(buf, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, route_trie);

        return -1;
    }
    ip_hdr->ttl--;

    // update checksum
    ip_hdr->check = htons(checksum((uint16_t*) ip_hdr, sizeof(struct iphdr)));

    if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
        send_icmp_reply(ip_hdr->saddr, buf, len, route_trie);
        return 0;
    }

    struct route_table_entry *best_route = lpm(ip_hdr->daddr, route_trie);
    if (!best_route) {
        printf("Route not found\n");
        send_icmp_error(buf, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, route_trie);

        return -1;
    }

    struct arp_entry *entry = get_mac_entry(best_route->next_hop);
    if (!entry) {
        queue_enq(q, make_packet(buf, best_route, len));
        send_arp_request(best_route);

        printf("MAC Address not found\n");
        return 1;
    }

    memcpy(eth_hdr->ether_dhost, entry->mac, MAC_LEN);

    get_interface_mac(best_route->interface, eth_hdr->ether_shost);
    send_to_link(best_route->interface, buf, len);

    printf("Sent!\n");
    return 0;
}

int handle_arp(char *buf, int interface)
{
    struct arp_header* arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));

    if (arp_hdr->op == htons(ARP_OPCODE_REQ)) {
        printf("Sent Reply!\n");
        return send_arp_reply(arp_hdr, interface);
    }

    if (arp_hdr->op == htons(ARP_OPCODE_REP)) {
        add_to_arp_table(arp_hdr);

        queue aux = queue_create();

        while (!queue_empty(q)) {
            struct packet* pack = (struct packet*) queue_deq(q);

            struct arp_entry* entry = get_mac_entry(pack->best_route->next_hop);

            if (entry) {
                struct ether_header* pack_eth_hdr = (struct ether_header*) pack->buf;

                memcpy(pack_eth_hdr->ether_dhost, entry->mac, MAC_LEN);
                get_interface_mac(pack->best_route->interface, pack_eth_hdr->ether_shost);
                send_to_link(pack->best_route->interface, pack->buf, pack->len);
            } else {
                queue_enq(aux, pack);
            }
        }

        while (!queue_empty(aux)) {
            struct packet* pack = (struct packet*) queue_deq(aux);
            queue_enq(q, pack);
        }

        free(aux);
    }

    return 0;
}

struct packet *make_packet(char *buf, struct route_table_entry* best_route, size_t len)
{
    struct packet* new_packet = malloc(sizeof(struct packet));
    new_packet->buf = calloc(MAX_PACKET_LEN, sizeof(char));
    memcpy(new_packet->buf, buf, len);
    new_packet->best_route = best_route;
    new_packet->len = len;

    return new_packet;
}

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
        if (node->route != NULL) {
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

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
    q = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

    struct trie_node* route_trie = create_node();
    read_rtable(argv[1], route_trie);


    arp_table = calloc(100, sizeof(struct arp_entry));
    arp_len = 0;

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

        if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
            handle_ip(buf, len, interface, route_trie);
            continue;
        }

        if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
            handle_arp(buf, interface);
            continue;
        }
    }
}

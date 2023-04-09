#include <arpa/inet.h>
#include <string.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"

struct arp_entry *get_mac_entry(uint32_t given_ip, struct arp_table *arp_table) {
    for (int i = 0; i < arp_table->len; i++)
    {
        if (given_ip == arp_table->arp_entries[i].ip) {
            return &arp_table->arp_entries[i];
        }
    }

    return NULL;
}

void add_to_arp_table(struct arp_header *arp_hdr, struct arp_table *arp_table)
{
    arp_table->arp_entries[arp_table->len].ip = arp_hdr->spa;
    memcpy(arp_table->arp_entries[arp_table->len].mac, arp_hdr->sha, MAC_LEN);
    arp_table->len++;
}

int handle_ip(char *buf, size_t len, int interface, struct trie_node *route_trie, struct arp_table *arp_table)
{
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

    // Validate checksum
    uint16_t old_checksum = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    uint16_t new_checksum = checksum((uint16_t*) ip_hdr, sizeof(struct iphdr));
    if (old_checksum != new_checksum) {
        printf("Incorrect checksum\n");
        return -1;
    }

    if (ip_hdr->ttl <= 1) {
        printf("TTL exceeded\n");
        send_icmp_error(buf, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, route_trie, arp_table);

        return -1;
    }
    ip_hdr->ttl--;

    // update checksum
    ip_hdr->check = htons(checksum((uint16_t*) ip_hdr, sizeof(struct iphdr)));

    // Check if the router is the destination, if it is send icmp reply
    if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
        send_icmp_reply(ip_hdr->saddr, buf, len, route_trie, arp_table);
        return 0;
    }

    struct route_table_entry *best_route = lpm(ip_hdr->daddr, route_trie);
    if (!best_route) {
        printf("Route not found\n");
        send_icmp_error(buf, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, route_trie, arp_table);

        return -1;
    }

    struct arp_entry *entry = get_mac_entry(best_route->next_hop, arp_table);
    if (!entry) {
        queue_enq(arp_table->q, make_packet(buf, best_route, len));
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

int handle_arp(char *buf, int interface, struct arp_table *arp_table)
{
    struct arp_header* arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));

    if (arp_hdr->op == htons(ARP_OPCODE_REQ)) {
        printf("Sent Reply!\n");
        return send_arp_reply(arp_hdr, interface);
    }

    if (arp_hdr->op == htons(ARP_OPCODE_REP)) {
        add_to_arp_table(arp_hdr, arp_table);

        queue aux = queue_create();

        while (!queue_empty(arp_table->q)) {
            struct packet* pack = (struct packet*) queue_deq(arp_table->q);

            struct arp_entry* entry = get_mac_entry(pack->best_route->next_hop, arp_table);

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
            queue_enq(arp_table->q, pack);
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

int check_dest_mac(uint8_t dest_mac[MAC_LEN], int interface)
{
    uint8_t broadcast[MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t router_mac[MAC_LEN];
    get_interface_mac(interface, router_mac);

    if (memcmp(dest_mac, broadcast, MAC_LEN) == 0)
        return 0;
    return memcmp(dest_mac, router_mac, MAC_LEN);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

    struct trie_node* route_trie = create_node();
    read_rtable(argv[1], route_trie);

    struct arp_table* arp_table = malloc(sizeof(struct arp_table));
    arp_table->arp_entries = calloc(MAX_HOSTS, sizeof(struct arp_entry));
    arp_table->len = 0;
    arp_table->q = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

        // Validate L2 destination
        if (check_dest_mac(eth_hdr->ether_dhost, interface) != 0) {
            continue;
        }

        // Handle IPv4 Packet
        if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
            handle_ip(buf, len, interface, route_trie, arp_table);
            continue;
        }

        // Handle ARP Packet
        if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
            handle_arp(buf, interface, arp_table);
            continue;
        }

        printf("Unknown Protocol\n");
    }
}

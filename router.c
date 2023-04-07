#include <arpa/inet.h>
#include <string.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

struct route_table_entry* rtable;
int rtable_len;

struct arp_entry* arp_table;
int arp_len;

queue q;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
    uint32_t max_mask = 0;
    struct route_table_entry* best_route = NULL;

    for (int i = 0; i < rtable_len; i++) {
        if ((ip_dest & rtable[i].mask) == rtable[i].prefix && max_mask < rtable[i].mask) {
            max_mask = rtable[i].mask;
            best_route = &rtable[i];
        }
    }

    return best_route;
}

struct arp_entry *get_mac_entry(uint32_t given_ip) {
    for (int i = 0; i < arp_len; i++)
    {
        if (given_ip == arp_table[i].ip) {
            return &arp_table[i];
        }
    }

    return NULL;
}

int handle_ip(char *buf, size_t len, struct ether_header* eth_hdr, int interface)
{
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

    uint16_t old_checksum = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    uint16_t new_checksum = checksum((uint16_t*) ip_hdr, sizeof(struct iphdr));
    if (old_checksum != new_checksum) {
        printf("Incorrect checksum\n");
        return -1;
    }

    ip_hdr->ttl--;
    if (ip_hdr->ttl < 1) {
        printf("TTL exceeded\n");
        send_icmp_error(buf, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);

        return -1;
    }
    // update checksum
    ip_hdr->check = htons(checksum((uint16_t*) ip_hdr, sizeof(struct iphdr)));

    if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
        send_icmp_reply(ip_hdr->saddr, buf + sizeof(struct ether_header) + sizeof(struct iphdr) + 8);
        return 0;
    }

    struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
    if (!best_route) {
        printf("Route not found\n");
        send_icmp_error(buf, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);

        return -1;
    }

    struct arp_entry *entry = get_mac_entry(best_route->next_hop);
    if (!entry) {
        queue_enq(q, make_packet(buf, best_route, len, interface));
        send_arp_request(best_route);

        printf("MAC Address not found\n");
        return 1;
    }

    memcpy(eth_hdr->ether_dhost, entry->mac, 6);
    // Call send_to_link(best_router->interface, packet, packet_len);

    get_interface_mac(best_route->interface, eth_hdr->ether_shost);
    send_to_link(best_route->interface, buf, len);
    printf("Sent!\n");
    return 0;
}

int handle_arp(char *buf, size_t len, struct ether_header* eth_hdr, int interface)
{
    struct arp_header* arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));

    if (arp_hdr->op == htons(ARP_OPCODE_REQ)) {
        printf("Sent Reply!\n");
        return send_arp_reply(arp_hdr, interface);
    }

    if (arp_hdr->op == htons(ARP_OPCODE_REP)) {
        arp_table[arp_len].ip = arp_hdr->spa;
        memcpy(arp_table[arp_len].mac, arp_hdr->sha, MAC_LEN);
        arp_len++;

        queue aux = queue_create();

        while (!queue_empty(q)) {
            struct packet* pack = (struct packet*) queue_deq(q);

            struct arp_entry* entry = get_mac_entry(pack->best_route->next_hop);

            if (entry) {
                struct ether_header* pack_eth_hdr = (struct ether_header*) pack->buf;

                memcpy(pack_eth_hdr->ether_dhost, entry->mac, 6);
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

struct packet *make_packet(char *buf, struct route_table_entry* best_route, size_t len, int interface)
{
    struct packet* new_packet = malloc(sizeof(struct packet));
    new_packet->buf = calloc(MAX_PACKET_LEN, sizeof(char));
    memcpy(new_packet->buf, buf, len);
    new_packet->best_route = best_route;
    new_packet->len = len;
    new_packet->interface = interface;

    return new_packet;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
    q = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

    rtable = calloc(100000, sizeof(struct route_table_entry));
    rtable_len = read_rtable(argv[1], rtable);

    arp_table = calloc(100, sizeof(struct arp_entry));
    arp_len = 0;

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

        if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
            handle_ip(buf, len, eth_hdr, interface);
            continue;
        }

        if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
            handle_arp(buf, len, eth_hdr, interface);
            continue;
        }
    }
}

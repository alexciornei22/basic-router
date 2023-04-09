#include "lib.h"
#include "protocols.h"
#include "queue.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>


int interfaces[ROUTER_NUM_INTERFACES];

extern queue q;

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s, (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

int send_to_link(int intidx, char *frame_data, size_t len)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 */
	int ret;
	ret = write(interfaces[intidx], frame_data, len);
	DIE(ret == -1, "write");
	return ret;
}

ssize_t receive_from_link(int intidx, char *frame_data)
{
	ssize_t ret;
	ret = read(interfaces[intidx], frame_data, MAX_PACKET_LEN);
	return ret;
}

int socket_receive_message(int sockfd, char *frame_data, size_t *len)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the
	 * interface, eg 1500 bytes
	 * */
	int ret = read(sockfd, frame_data, MAX_PACKET_LEN);
	DIE(ret < 0, "read");
	*len = ret;
	return 0;
}

int recv_from_any_link(char *frame_data, size_t *length) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				ssize_t ret = receive_from_link(i, frame_data);
				DIE(ret < 0, "receive_from_link");
				*length = ret;
				return i;
			}
		}
	}

	return -1;
}

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	int ret;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ret = ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	DIE(ret == -1, "ioctl SIOCGIFADDR");
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	int ret;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ret = ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	DIE(ret == -1, "ioctl SIOCGIFHWADDR");
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
}

void init(int argc, char *argv[])
{
	for (int i = 0; i < argc; ++i) {
		printf("Setting up interface: %s\n", argv[i]);
		interfaces[i] = get_sock(argv[i]);
	}
}


uint16_t checksum(uint16_t *data, size_t len)
{
	unsigned long checksum = 0;
	uint16_t extra_byte;
	while (len > 1) {
		checksum += ntohs(*data++);
		len -= 2;
	}
	if (len) {
		*(uint8_t *)&extra_byte = *(uint8_t *)data;
		checksum += extra_byte;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >>16);
	return (uint16_t)(~checksum);
}

int read_rtable(const char *path, struct trie_node *route_trie)
{
	FILE *fp = fopen(path, "r");
	int i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL) {
        struct route_table_entry* new_route = malloc(sizeof(struct route_table_entry));

		p = strtok(line, " .");
		i = 0;
		while (p != NULL) {
			if (i < 4)
				*(((unsigned char *)&new_route->prefix)  + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *)&new_route->next_hop)  + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *)&new_route->mask)  + i % 4) = atoi(p);

			if (i == 12)
                new_route->interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}

        insert_in_trie(new_route, route_trie);
	}
    return 0;
}

int send_arp_request(struct route_table_entry* route)
{
    char *buf = malloc(MAX_PACKET_LEN);
    size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);

    struct ether_header* eth_hdr = (struct ether_header*) buf;
    struct arp_header* arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));

    get_interface_mac(route->interface, eth_hdr->ether_shost);
    memset(eth_hdr->ether_dhost, 0xff, MAC_LEN);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    arp_hdr->htype = htons(ARP_HTYPE_ETH);
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->hlen = MAC_LEN;
    arp_hdr->plen = IP_LEN;
    arp_hdr->op = htons(ARP_OPCODE_REQ);
    get_interface_mac(route->interface, arp_hdr->sha);
    arp_hdr->spa = inet_addr(get_interface_ip(route->interface));
    memset(arp_hdr->tha, 0x0, MAC_LEN);
    arp_hdr->tpa = route->next_hop;

    send_to_link(route->interface, buf, len);

    return 0;
}

int send_arp_reply(struct arp_header* arp_req, int interface)
{
    char *buf = malloc(MAX_PACKET_LEN);
    size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);

    struct ether_header* eth_hdr = (struct ether_header*) buf;
    struct arp_header* arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));

    get_interface_mac(interface, eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_dhost, arp_req->sha, MAC_LEN);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    arp_hdr->htype = htons(ARP_HTYPE_ETH);
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->hlen = MAC_LEN;
    arp_hdr->plen = IP_LEN;
    arp_hdr->op = htons(ARP_OPCODE_REP);
    get_interface_mac(interface, arp_hdr->sha);
    arp_hdr->spa = inet_addr(get_interface_ip(interface));
    memcpy(arp_hdr->tha, arp_req->sha, MAC_LEN);
    arp_hdr->tpa = arp_req->spa;

    send_to_link(interface, buf, len);

    return 0;
}

int send_icmp_error(char *buf, size_t len, int error, int code, struct trie_node *route_trie)
{
    struct iphdr* ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));

    char error_msg[MAX_PACKET_LEN];
    memset(error_msg, 0, MAX_PACKET_LEN);

    size_t error_len = len + sizeof(struct iphdr) + sizeof(struct icmphdr);
    size_t icmp_len = error_len - (sizeof(struct ether_header) + sizeof(struct iphdr));

    struct ether_header* error_eth = (struct ether_header*) error_msg;
    struct iphdr* error_ip = (struct iphdr*) (error_msg + sizeof(struct ether_header));
    struct icmphdr* error_icmp = (struct icmphdr*) (error_msg + sizeof(struct ether_header) + sizeof(struct iphdr));
    char *data = (error_msg + sizeof(struct ether_header) + sizeof(struct iphdr) + 8);

    error_eth->ether_type = htons(ETHERTYPE_IP);

    error_ip->version = 4;
    error_ip->ihl = 5;
    error_ip->tos = 0;
    error_ip->tot_len = htons(error_len - sizeof(struct ether_header));
    error_ip->id = htons(1);
    error_ip->frag_off = 0;
    error_ip->ttl = 64;
    error_ip->check = 0;
    error_ip->protocol = 1;

    error_icmp->type = error;
    error_icmp->code = code;
    error_icmp->checksum = 0;
    memcpy(data, ip_hdr, len - sizeof(struct ether_header));

    struct route_table_entry* route = lpm(ip_hdr->saddr, route_trie);
    error_ip->saddr = inet_addr(get_interface_ip(route->interface));
    error_ip->daddr = ip_hdr->saddr;

    error_ip->check = htons(checksum((uint16_t*) error_ip, sizeof(struct iphdr)));
    error_icmp->checksum = htons(checksum((uint16_t*) error_icmp, icmp_len));

    get_interface_mac(route->interface, error_eth->ether_dhost);
    struct arp_entry* arp_entry = get_mac_entry(route->next_hop);
    if (!arp_entry) {
        struct packet* new_pack = make_packet(error_msg, route, error_len);
        queue_enq(q, new_pack);
        send_arp_request(route);

        return -1;
    }
    memcpy(error_eth->ether_dhost, arp_entry->mac, MAC_LEN);

    send_to_link(route->interface, error_msg, error_len);

    return 0;
}

int send_icmp_reply(uint32_t ip, char *original_buf, size_t len, struct trie_node *route_trie)
{
    char reply_msg[MAX_PACKET_LEN];
    memset(reply_msg, 0, MAX_PACKET_LEN);

    size_t reply_len = len;
    size_t icmp_len = len - sizeof(struct ether_header) - sizeof(struct iphdr);

    struct ether_header* reply_eth = (struct ether_header*) reply_msg;
    struct iphdr* reply_ip = (struct iphdr*) (reply_msg + sizeof(struct ether_header));

    struct icmphdr* reply_icmp = (struct icmphdr*) (reply_msg + sizeof(struct ether_header) + sizeof(struct iphdr));
    struct icmphdr* echo_icmp = (struct icmphdr*) (original_buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    reply_eth->ether_type = htons(ETHERTYPE_IP);

    reply_ip->version = 4;
    reply_ip->ihl = 5;
    reply_ip->tos = 0;
    reply_ip->tot_len = htons(len - sizeof(struct ether_header));
    reply_ip->id = htons(1);
    reply_ip->frag_off = 0;
    reply_ip->ttl = 64;
    reply_ip->check = 0;
    reply_ip->protocol = 1;

    memcpy(reply_icmp, echo_icmp, icmp_len);
    reply_icmp->type = 0;
    reply_icmp->code = ICMP_ECHOREPLY;
    reply_icmp->checksum = 0;

    struct route_table_entry* route = lpm(ip, route_trie);
    reply_ip->saddr = inet_addr(get_interface_ip(route->interface));
    reply_ip->daddr = ip;

    reply_ip->check = htons(checksum((uint16_t*) reply_ip, sizeof(struct iphdr)));
    reply_icmp->checksum = htons(checksum((uint16_t*) reply_icmp, icmp_len));

    get_interface_mac(route->interface, reply_eth->ether_shost);
    struct arp_entry* arp_entry = get_mac_entry(route->next_hop);
    if (!arp_entry) {
        struct packet* new_pack = make_packet(reply_msg, route, reply_len);
        queue_enq(q, new_pack);
        send_arp_request(route);

        return -1;
    }
    memcpy(reply_eth->ether_dhost, arp_entry->mac, MAC_LEN);

    send_to_link(route->interface, reply_msg, reply_len);

    return 0;
}
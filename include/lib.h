#ifndef _SKEL_H_
#define _SKEL_H_

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "queue.h"
#include "trie.h"

#define MAX_PACKET_LEN 1600
#define MAX_HOSTS 100

#define MAC_LEN 6
#define IP_LEN 4

#define ARP_OPCODE_REQ 1
#define ARP_OPCODE_REP 2
#define ARP_HTYPE_ETH 1

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_NET_UNREACH    0        /* Network Unreachable                */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/

#define ROUTER_NUM_INTERFACES 3

int send_to_link(int interface, char *frame_data, size_t length);

/*
 * @brief Receives a packet. Blocking function, blocks if there is no packet to
 * be received.
 *
 * @param frame_data - region of memory in which the data will be copied; should
 *        have at least MAX_PACKET_LEN bytes allocated 
 * @param length - will be set to the total number of bytes received.
 * Returns: the interface it has been received from.
 */
int recv_from_any_link(char *frame_data, size_t *length);

/* Route table entry */
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

/* ARP table entry when skipping the ARP exercise */
struct arp_entry {
    uint32_t ip;
    uint8_t mac[6];
};

/* ARP table */
struct arp_table {
    struct arp_entry* arp_entries; /* ARP entries */
    size_t len; /* size of ARP table */
    queue q; /* queue of packets which wait ARP response */
};

/* packet info for use in ARP queue storage */
struct packet {
    char *buf; /* packet buffer */
    struct route_table_entry* best_route; /* best route where packet needs to be sent */
    size_t len; /* packet length */
};

char *get_interface_ip(int interface);

/**
 * @brief Get the interface mac object. The function writes
 * the MAC at the pointer mac. uint8_t *mac should be allocated.
 *
 * @param interface
 * @param mac
 */
void get_interface_mac(int interface, uint8_t *mac);

/**
 * @brief IPv4 checksum per  RFC 791. To compute the checksum
 * of an IP header we must set the checksum to 0 beforehand.
 *
 * also works as ICMP checksum per RFC 792. To compute the checksum
 * of an ICMP header we must set the checksum to 0 beforehand.

 * @param data memory area to checksum
 * @param size in bytes
 */
uint16_t checksum(uint16_t *data, size_t len);

/**
 * @brief Populates route trie from file
 * @param path route table file path
 * @param route_trie root of route trie
 */
void read_rtable(const char *path, struct trie_node *route_trie);

/**
 * @param route route to send ARP request for
 */
void send_arp_request(struct route_table_entry* route);

/**
 * Sends out ICMP error
 * @param buf original packet buffer
 * @param len original packet length
 * @param error ICMP error
 * @param code ICMP code
 * @param route_trie route trie
 * @param arp_table ARP table
 */
void send_icmp_error(char *buf, size_t len, int error, int code, struct trie_node *route_trie, struct arp_table *arp_table);

/**
 * Sends ICMP reply to given IP address
 * @param ip target IP address
 * @param original_buf original packet buffer
 * @param len original packet length
 * @param route_trie route trie
 * @param arp_table ARP table
 */
void send_icmp_reply(uint32_t ip, char *original_buf, size_t len, struct trie_node *route_trie, struct arp_table *arp_table);

/**
 * Searches for an IP in cached MAC address table
 * @param given_ip IP address to search
 * @param arp_table ARP table with MAC addresses
 * @return ARP table entry for given IP or NULL if
 * MAC address is not found
 */
struct arp_entry *get_mac_entry(uint32_t given_ip, struct arp_table *arp_table);

void init(int argc, char *argv[]);

/**
 * initialises a packet to be added in the ARP queue
 */
struct packet *make_packet(char *buf, struct route_table_entry* best_route, size_t len);

#define DIE(condition, message, ...) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[(%s:%d)]: " # message "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

#endif /* _SKEL_H_ */

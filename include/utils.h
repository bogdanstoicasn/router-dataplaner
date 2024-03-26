#ifndef UTILS_H
#define UTILS_H

#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "queue.h"
#include "list.h"
#include "protocols.h"
#include "lib.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

#define CHAR_TO_IP(char_ip, int_ip) \
    inet_pton(AF_INET, char_ip, &int_ip)


struct route_table_entry *alloc_rtable(const char *path);

struct arp_table_entry *alloc_arp_table(const char *path);

int comparator_function(const void *first, const void *second);

struct route_table_entry *get_best_rtable(uint32_t dest_ip, struct route_table_entry *rtable, int rtable_size);

struct arp_table_entry *get_best_arp(uint32_t dest_ip, struct arp_table_entry *arp_table, int arp_table_len);


void arp_request(struct ether_header *eth_hdr, struct route_table_entry *next_route, uint32_t interface);

void icmp_packet_builder(struct ether_header *eth_hdr, uint32_t interface, uint8_t type);

void ip_packet_builder(struct ether_header *eth_hdr, uint32_t interface, uint32_t len,
                       struct route_table_entry *rtable, int rtable_size,
                       struct arp_table_entry *arp_table, int arp_table_len);


#endif
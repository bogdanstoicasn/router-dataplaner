#include "utils.h"

/*
    Function that allocs the rtable from a file
*/
struct route_table_entry *alloc_rtable(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Could not open file %s\n", path);
        return NULL;
    }

    // now we get number of lines
    int lines = 0;
    char c;
    while ((c = fgetc(fp)) != EOF) {
        if (c == '\n') {
            lines++;
        }
    }

    // now we allocate the rtable
    struct route_table_entry *rtable = malloc(lines * sizeof(struct route_table_entry));
    if (!rtable) {
        fprintf(stderr, "Could not allocate rtable\n");
        exit(1);
    }
    fclose(fp);
    return rtable;

}

/*
    Function that allocs the arp table from a file

*/
struct arp_table_entry *alloc_arp_table(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Could not open file %s\n", path);
        return NULL;
    }

    // now we get number of lines
    int lines = 0;
    char c;
    while ((c = fgetc(fp)) != EOF) {
        if (c == '\n') {
            lines++;
        }
    }

    // now we allocate the rtable
    struct arp_table_entry *arp_table = malloc(lines * sizeof(struct arp_table_entry));
    if (!arp_table) {
        fprintf(stderr, "Could not allocate arp table\n");
        exit(1);
    }
    fclose(fp);
    return arp_table;
}

int comparator_function(const void *first, const void *second)
{
    struct route_table_entry *first_entry = (struct route_table_entry *)first;
    struct route_table_entry *second_entry = (struct route_table_entry *)second;

    if (ntohl(first_entry->prefix) > ntohl(second_entry->prefix)) {
        return 1;
    } else if (ntohl(first_entry->prefix) < ntohl(second_entry->prefix)) {
        return -1;
    } else {
        if (ntohl(first_entry->mask) > ntohl(second_entry->mask)) {
            return 1;
        } else if (ntohl(first_entry->mask) < ntohl(second_entry->mask)) {
            return -1;
        } else {
            return 0;
        }
    }
}

/*
    Function that searches best route in rtable using binary search
*/
struct route_table_entry *get_best_rtable(uint32_t dest_ip, struct route_table_entry *rtable, int rtable_size)
{
    int left = 0;
    int right = rtable_size - 1;
    int mid;
    struct route_table_entry *best_route = NULL;
    while (left <= right) {
        mid = left + (right - left) / 2;
        if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix && !best_route) {
            best_route = &rtable[mid];
        }

        if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix && best_route) {
            if (ntohl(rtable[mid].mask) > ntohl(best_route->mask)) {
                best_route = &rtable[mid];
            }
        }

        if ((dest_ip & rtable[mid].mask) > rtable[mid].prefix) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return best_route;
}

/*
    Function that gets the best route in arp table using linear search
*/
struct arp_table_entry *get_best_arp(uint32_t dest_ip, struct arp_table_entry *arp_table, int arp_table_len)
{
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == dest_ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

/*
    Function that builds an icmp packet
*/
void icmp_packet_builder(struct ether_header *eth_hdr, uint32_t interface, uint8_t type)
{
    struct iphdr *ip_hdr = (struct iphdr *)(eth_hdr + 1);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(ip_hdr + 1);

    icmp_hdr->type = type;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    // not sure about this
    icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));

    // prepare the ipcmp body

    //uint32_t icmp_len = sizeof(*ip_hdr) + 8;
    int8_t *icmp_body = malloc(sizeof(*ip_hdr) + 8);
    DIE(icmp_body == NULL, "malloc in icmp_packet_builder");

    memcpy(icmp_body, ip_hdr, sizeof(*ip_hdr) + 8);
    uint32_t ip_router;

    CHAR_TO_IP(get_interface_ip(interface), ip_router); 

    /*
        Swap the ip addresses
    */
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = ip_router;
    ip_hdr->ttl = htons(64);
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->tot_len = htons(sizeof(*icmp_hdr) + 2 * sizeof(*ip_hdr) + 8);
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

    /*
        Swap the mac addresses
    */
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
    get_interface_mac(interface, eth_hdr->ether_shost);

    /*
        Copy the icmp body
    */
    memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, sizeof(*ip_hdr) + 8);

    size_t leng = sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*icmp_hdr) + 8;
    send_to_link(interface, (char *)eth_hdr, leng);

    free(icmp_body);
}

/*
    Function that sends an arp request
*/
void arp_request(struct ether_header *eth_hdr, struct route_table_entry *next_route, uint32_t interface)
{
    struct arp_header *arp_hdr = (struct arp_header *)(eth_hdr + 1);
    arp_hdr->htype = htons(1);
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->op = htons(1);

    get_interface_mac(next_route->interface, arp_hdr->sha);

    uint32_t ip_router;
    CHAR_TO_IP(get_interface_ip(interface), ip_router);
    arp_hdr->spa = ip_router;

    // fill the target mac with 0
    memset(arp_hdr->tha, 0, sizeof(arp_hdr->tha));
    arp_hdr->tpa = next_route->next_hop;

    // fill with F the destination mac
    memset(eth_hdr->ether_dhost, 0xff, sizeof(eth_hdr->ether_dhost));
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    size_t len = sizeof(*eth_hdr) + sizeof(*arp_hdr);

    send_to_link(next_route->interface, (char *)eth_hdr, len);
}

/*
    Function that builds the ip packet
*/
void ip_packet_builder(struct ether_header *eth_hdr, uint32_t interface, uint32_t len,
                       struct route_table_entry *rtable, int rtable_size,
                       struct arp_table_entry *arp_table, int arp_table_len)
{
    struct iphdr *ip_hdr = (struct iphdr *)(eth_hdr + 1);
    uint32_t ip_router;
    CHAR_TO_IP(get_interface_ip(interface), ip_router);

    if (ip_hdr->daddr != ip_router) {
        uint16_t old_check = ip_hdr->check;

        ip_hdr->check = 0;
        ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

        if (old_check != ip_hdr->check) {
            fprintf(stderr, "Checksums do not match\n");
            return;
        }
        if (ip_hdr->ttl <= 1) {
            icmp_packet_builder(eth_hdr, interface, 11);
            return;
        }

        ip_hdr->ttl = ip_hdr->ttl - 1;
        ip_hdr->check = 0;
        ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

        struct route_table_entry *best_route = get_best_rtable(ip_hdr->daddr, rtable, rtable_size);
        if (!best_route) {
            icmp_packet_builder(eth_hdr, interface, 3);
            return;
        }

        struct arp_table_entry *best_arp = get_best_arp(best_route->next_hop, arp_table, arp_table_len);

        get_interface_mac(best_route->interface, eth_hdr->ether_shost);

        if (!best_arp) {
            // insert paquet in queue
            //TODO
        }
        memcpy(eth_hdr->ether_dhost, best_arp->mac, sizeof(best_arp->mac));
        size_t leng = sizeof(*eth_hdr) + len;
        send_to_link(best_route->interface, (char *)eth_hdr, leng);
        return;
    }

    struct icmphdr *icmp_hdr = (struct icmphdr *)(ip_hdr + 1);
    icmp_hdr->type = 0;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(*icmp_hdr)));

    uint32_t length = ntohs(ip_hdr->tot_len) - sizeof(*ip_hdr) - sizeof(*icmp_hdr);

    int8_t *icmp_body = malloc(length);
    DIE(icmp_body == NULL, "malloc in ip_packet_builder");
    memcpy(icmp_body, ip_hdr, length);
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = ip_router;
    ip_hdr->ttl = htons(64);
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->tot_len = htons((uint16_t)length + sizeof(*icmp_hdr) + sizeof(*ip_hdr));
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
    get_interface_mac(interface, eth_hdr->ether_shost);
    memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, length);

    send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*icmp_hdr) + length);

    free(icmp_body);
}


#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "list.h"

#define ETHERTYPE_IP 0x0800 // Ethernet type for IP
#define ETHERTYPE_ARP 0x0806 // Ethernet type for ARP
#define TTL_MAX 64 // Maximum value of TTL
#define MAX_ARP_TABLE_LEN 20 // Maximum number of entries in ARP table
#define BROADCAST 0xff // Broadcast MAC address
#define HTYPE_ETHERNET 1 // Ethernet hardware type
#define ARP_HWADDR_LEN_ETH 6  // Length of Ethernet MAC address
#define ARP_PROTOADDR_LEN_IPV4 4  // Length of IPv4 address
#define OFFSET_ADDR 1 // General use offset for addresses

struct waiting_element {
	char *eth_hdr;
	int len;
	struct route_table_entry *next_route;
};

// main data structures
static struct route_table_entry *rtable;
static int rtable_len;

static struct arp_table_entry *arp_table;
static int arp_table_len;

static queue packets_queue;
// end of main data structures

static struct route_table_entry *alloc_rtable(const char *path)
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
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    return rtable;

}

static int comparator_function(const void *first, const void *second)
{
    struct route_table_entry *first_entry = (struct route_table_entry *)first;
    struct route_table_entry *second_entry = (struct route_table_entry *)second;

    if (ntohl(first_entry->prefix) < ntohl(second_entry->prefix)) {
        return 1;
    } else if (ntohl(first_entry->prefix) > ntohl(second_entry->prefix)) {
        return -1;
    } else {
        if (ntohl(first_entry->mask) < ntohl(second_entry->mask)) {
            return 1;
        } else if (ntohl(first_entry->mask) > ntohl(second_entry->mask)) {
            return -1;
        } else {
            return 0;
        }
    }
}

/*
    Function that searches best route in rtable using binary search
*/
static struct route_table_entry *get_best_rtable(uint32_t ip_dest)
{
	int l = 0;
	int r = rtable_len - 1;
	struct route_table_entry *next_hop = NULL;

	while (l <= r) {
		int m = l + (r - l) / 2;

		if ((ip_dest & rtable[m].mask) == rtable[m].prefix && !next_hop)
			next_hop = &rtable[m];

		// if we have a better route
		if ((ip_dest & rtable[m].mask) == rtable[m].prefix && next_hop)
			if (ntohl(rtable[m].mask) > ntohl(next_hop->mask))
				next_hop = &rtable[m];

		if (ntohl(rtable[m].prefix) >= ntohl(ip_dest))
			l = m + 1;
		else
			r = m - 1;
	}
	return next_hop;
}

/*
    Function that gets the best route in arp table using linear search
*/
struct arp_table_entry *get_best_arp(uint32_t dest_ip)
{
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == dest_ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

/*
	Function that sends a packet to a link
	@param eth - the ethernet header
	@param next - the next hop
	@param interface - the interface
*/
static void send_arp_request(struct ether_header *eth, struct route_table_entry *next, uint32_t interface)
{
	struct arp_header *arp = (struct arp_header *)(eth + OFFSET_ADDR);

	// set the ethernet header and type of packet
	memset(eth->ether_dhost, BROADCAST, sizeof(eth->ether_dhost));
	eth->ether_type = htons(ETHERTYPE_ARP);
	// end of setting the ethernet header

	memset(arp, 0, sizeof(*arp));

	arp->htype = arp->op = htons(HTYPE_ETHERNET);

	arp->ptype = htons(ETHERTYPE_IP);
	arp->hlen = ARP_HWADDR_LEN_ETH;
	arp->plen = ARP_PROTOADDR_LEN_IPV4;

	get_interface_mac(next->interface, arp->sha);

	uint32_t router_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &router_ip);

	// set the arp header
	arp->spa = router_ip;
	arp->tpa = next->next_hop;

	send_to_link(interface, (char *)eth, sizeof(*eth) + sizeof(*arp));
}

static void send_icmp_packet(struct ether_header *eth, uint32_t interface, uint8_t type)
{
	struct iphdr *ip = (struct iphdr *)(eth + OFFSET_ADDR);
	struct icmphdr *icmp = (struct icmphdr *)(ip + OFFSET_ADDR);

	// 2 types of icmp packets: 11 and 3, 11 is for ttl exceeded, 3 is for destination unreachable

	icmp->type = type;
	icmp->code = icmp->checksum = 0;
	icmp->checksum = htons(checksum((uint16_t *)icmp, sizeof(*icmp)));

	// prepare the icmp body with ipv4 and its first 8 bytes

	uint32_t length = sizeof(*ip) + 8;
	int8_t *icmp_body = malloc(length);
	DIE(icmp_body == NULL, "malloc in icmp_packet");

	memcpy(icmp_body, ip, length);

	uint32_t router_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &router_ip);

	// set the ip header
	ip->daddr = ip->saddr;
	ip->saddr = router_ip;
	ip->ttl = htons(TTL_MAX);
	ip->protocol = IPPROTO_ICMP;
	ip->tot_len = htons(length + sizeof(*ip) + sizeof(*icmp));
	ip->check = 0;
	ip->check  = htons(checksum((uint16_t *)ip, sizeof(*ip)));

	memcpy(eth->ether_dhost, eth->ether_shost, sizeof(eth->ether_shost));
	get_interface_mac(interface, eth->ether_shost);

	memcpy((char *)icmp + sizeof(*icmp), icmp_body, length);

	send_to_link(interface, (char *)eth, sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) + length);

	free(icmp_body);
}

static void ip_packet_for_router(struct ether_header *eth, uint32_t interface, uint32_t len)
{
	struct iphdr *ip = (struct iphdr *)(eth + OFFSET_ADDR);

	uint32_t router_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &router_ip);

	struct icmphdr *icmp = (struct icmphdr *)(ip + OFFSET_ADDR);

	icmp->type = icmp->code = icmp->checksum = 0;
	icmp->checksum = htons(checksum((uint16_t *)icmp, sizeof(*icmp)));

	uint32_t length = ntohs(ip->tot_len) - sizeof(*ip) - sizeof(*icmp);

	int8_t *icmp_body = malloc(length);
	DIE(icmp_body == NULL, "malloc in ip_packet");

	memcpy(icmp_body, ip, length);

	ip->daddr = ip->saddr;
	ip->saddr = router_ip;
	ip->ttl = htons(TTL_MAX);
	ip->protocol = IPPROTO_ICMP;
	ip->tot_len = htons((uint16_t)length + sizeof(*ip) + sizeof(*icmp));

	ip->check = 0;
	ip->check = htons(checksum((uint16_t *)ip, sizeof(*ip)));

	memcpy(eth->ether_dhost, eth->ether_shost, sizeof(eth->ether_shost));

	get_interface_mac(interface, eth->ether_shost);

	memcpy((char *)icmp + sizeof(*icmp), icmp_body, length);

	send_to_link(interface, (char *)eth, sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) + length);

	free(icmp_body);
}

static void ip_packet_for_host(struct ether_header *eth, uint32_t interface, uint32_t len)
{
	struct iphdr *ip = (struct iphdr *)(eth + OFFSET_ADDR);

	uint32_t router_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &router_ip);

	uint16_t old_checksum = ip->check;
	ip->check = 0;
	ip->check = htons(checksum((uint16_t *)ip, sizeof(*ip)));

	if (old_checksum != ip->check)
		return;
	
	// ttl check
	if (ip->ttl <= 1) {
		send_icmp_packet(eth, interface, 11);
		return;
	}

	--ip->ttl;
	ip->check = 0;
	ip->check = htons(checksum((uint16_t *)ip, sizeof(*ip)));

	// get best route
	struct route_table_entry *next = get_best_rtable(ip->daddr);
	if (!next) {
		send_icmp_packet(eth, interface, 3);
		return;
	}

	// get best arp
	struct arp_table_entry *arp = get_best_arp(next->next_hop);

	get_interface_mac(next->interface, eth->ether_shost);

	if (!arp) {

		struct waiting_element *entry = malloc(sizeof(*entry));
		DIE(entry == NULL, "malloc in ip_packet");
		entry->eth_hdr = malloc(len);
		DIE(entry->eth_hdr == NULL, "malloc in ip_packet");
		memcpy(entry->eth_hdr, eth, len);
		entry->len = len;
		entry->next_route = next;
		queue_enq(packets_queue, entry);
		// send arp request
		send_arp_request(eth, next, interface);
		return;
	}

	memcpy(eth->ether_dhost, arp->mac, sizeof(arp->mac));

	send_to_link(next->interface, (char *)eth, len);
}

static void send_ip_packet(struct ether_header *eth, uint32_t interface, uint32_t len)
{
	struct iphdr *ip = (struct iphdr *)(eth + OFFSET_ADDR);

	uint32_t router_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &router_ip);

	// If the packet is for the router
	if (ip->daddr == router_ip) {
		ip_packet_for_router(eth, interface, len);
		return;
	}

	// If the packet is for a host
	ip_packet_for_host(eth, interface, len);

}

static void send_arp_packet(struct ether_header *eth, uint32_t interface, uint32_t len)
{
	struct arp_header *arp = (struct arp_header *)(eth + OFFSET_ADDR);


	if (ntohs(arp->op) != 1) {
		arp_table[arp_table_len].ip = arp->spa;
		memcpy(arp_table[arp_table_len].mac, arp->sha, sizeof(arp->sha));
		++arp_table_len;

		while (!queue_empty(packets_queue)) {
			struct waiting_element *entry = queue_deq(packets_queue);
			send_ip_packet((struct ether_header *)entry->eth_hdr, interface, entry->len);
			free(entry->eth_hdr);
			free(entry);
		}
		return;
	}

	uint32_t router_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &router_ip);
	if (arp->tpa != router_ip)
		return;
	
	arp->op = htons(2);
	arp->tpa = arp->spa;
	arp->spa = router_ip;

	memcpy(arp->tha, arp->sha, sizeof(arp->sha));
	get_interface_mac(interface, arp->sha);

	memcpy(eth->ether_dhost, arp->tha, sizeof(arp->tha));
	get_interface_mac(interface, eth->ether_shost);

	send_to_link(interface, (char *)eth, len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = alloc_rtable(argv[1]);
	rtable_len = read_rtable(argv[1], rtable);

	arp_table = malloc(MAX_ARP_TABLE_LEN * sizeof(*arp_table));
	if (!arp_table) {
		fprintf(stderr, "Could not allocate arp table\n");
		exit(EXIT_FAILURE);
	}

	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	packets_queue = queue_create();
	if (!packets_queue) {
		fprintf(stderr, "Could not allocate packets queue\n");
		exit(EXIT_FAILURE);
	}

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), comparator_function);

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
		switch(ntohs(eth_hdr->ether_type)) {
			case ETHERTYPE_IP:
				send_ip_packet(eth_hdr, interface, len);
				break;
			case ETHERTYPE_ARP:
				send_arp_packet(eth_hdr, interface, len);
				break;
			default:
				break;
		}

	}

	free(rtable);
	free(arp_table);
	free(packets_queue);
	return 0;
}


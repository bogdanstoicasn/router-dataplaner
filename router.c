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
#define POW_2(x) (1 << (x)) // Power of 2


struct simple_memory_pool {
	void *memory;
	size_t size;
	size_t used; // in this project was used for debugging
};

struct waiting_element {
	void *eth_hdr;
	int len;
	struct route_table_entry *next_route;
};

// main data structures
static struct route_table_entry *rtable;
static int rtable_len;

static struct arp_table_entry *arp_table;
static int arp_table_len;

static queue packets_queue;
static struct simple_memory_pool pool;
// end of main data structures

#define ROUTER_RESOURCES_SECTION
/*
	Function that initializes the memory pool
	@param size - the size of the memory pool
*/
void init_mem_pool(size_t size)
{
	pool.memory = calloc(size, sizeof(uint8_t));
	if (!pool.memory) {
		fprintf(stderr, "Could not allocate memory pool\n");
		exit(EXIT_FAILURE);
	}

	pool.size = size;
	pool.used = 0;
}

/*
	Function that resets the memory pool data
*/
void reset_mem_pool_data()
{
	memset(pool.memory, 0, pool.size);
	pool.used = 0;
}

static struct route_table_entry *alloc_rtable(const char *path);

/*
	Function that allocs the router resources
	@param file - the file with the routing table
*/
void alloc_router_resources(const char *file)
{
	init_mem_pool(POW_2(8));

	rtable = alloc_rtable(file);
	rtable_len = read_rtable(file, rtable);

	arp_table = malloc(MAX_ARP_TABLE_LEN * sizeof(*arp_table));
	if (!arp_table) {
		fprintf(stderr, "Could not allocate arp table\n");
		exit(EXIT_FAILURE);
	}

	packets_queue = queue_create();
	if (!packets_queue) {
		fprintf(stderr, "Could not allocate packets queue\n");
		exit(EXIT_FAILURE);
	}
}

/*
	Function that frees the resources used by the router
*/
void free_router_resources()
{
	free(rtable);
	free(arp_table);
	free(packets_queue);
	free(pool.memory);
}


/*
	Function that allocs the rtable by number of lines
	@param path - the path to the file
*/
static struct route_table_entry *alloc_rtable(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Could not open file %s\n", path);
        exit(EXIT_FAILURE);
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
    struct route_table_entry *rtable = malloc(lines * sizeof(*rtable));
    if (!rtable) {
        fprintf(stderr, "Could not allocate rtable\n");
        exit(EXIT_FAILURE);
    }

    fclose(fp);
    return rtable;

}

#undef ROUTER_RESOURCES_SECTION

/*
	Function that compares two route table entries
	@param first - the first entry
	@param second - the second entry
	return the result of the comparison
*/
static int comparator_function(const void *first, const void *second)
{
    struct route_table_entry *first_entry = (struct route_table_entry *)first;
    struct route_table_entry *second_entry =
											(struct route_table_entry *)second;

    if (ntohl(first_entry->prefix) < ntohl(second_entry->prefix))
        return 1;
    else if (ntohl(first_entry->prefix) > ntohl(second_entry->prefix))
        return -1;
    else {
        if (ntohl(first_entry->mask) < ntohl(second_entry->mask))
            return 1;
        else if (ntohl(first_entry->mask) > ntohl(second_entry->mask))
            return -1;
        else
            return 0;
    }
}

/*
    Function that searches best route in rtable using binary search
*/
static struct route_table_entry *get_best_rtable(uint32_t ip_dest)
{
	int left = 0;
	int right = rtable_len - 1;
	struct route_table_entry *best_hop = NULL;

	while (left <= right) {
		int mid = left + (right - left) / 2;

		if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix
			 && ((!best_hop)
			 || (ntohl(rtable[mid].mask) > ntohl(best_hop->mask))))
    			best_hop = &rtable[mid];

		if (ntohl(rtable[mid].prefix) >= ntohl(ip_dest))
			left = mid + 1;
		else
			right = mid - 1;
	}
	return best_hop;
}

/*
    Function that gets the best route in arp table using linear search
*/
struct arp_table_entry *get_best_arp(uint32_t dest_ip)
{
    for (int i = 0; i < arp_table_len; ++i)
        if (arp_table[i].ip == dest_ip)
            return &arp_table[i];
    return NULL;
}


/*
	Function that recalculates the checksum
*/
void recalculate_checksum(struct iphdr *ip)
{
	ip->check = 0;
	ip->check = htons(checksum((uint16_t *)ip, sizeof(*ip)));
}

/*
	Function that sends a arp request
	@param eth - the ethernet header
	@param next - the next hop
	@param interface - the interface
	@param router_ip - the ip of the router
*/
static void send_arp_request(struct ether_header *eth,
							 struct route_table_entry *next,
							 uint32_t interface, uint32_t router_ip)
{
	struct arp_header *arp = (struct arp_header *)(eth + OFFSET_ADDR);

	// set the ethernet header and type of packet
	memset(eth->ether_dhost, BROADCAST, sizeof(eth->ether_dhost));
	eth->ether_type = htons(ETHERTYPE_ARP);
	// end of setting the ethernet header

	memset(arp, 0, sizeof(*arp));

	// set for arp request
	arp->htype = arp->op = htons(HTYPE_ETHERNET);

	arp->ptype = htons(ETHERTYPE_IP);
	arp->hlen = ARP_HWADDR_LEN_ETH;
	arp->plen = ARP_PROTOADDR_LEN_IPV4;

	// set the source mac and ip
	get_interface_mac(next->interface, arp->sha);

	arp->spa = router_ip;
	arp->tpa = next->next_hop;

	send_to_link(interface, (char *)eth, sizeof(*eth) + sizeof(*arp));
}

/*
	Function that sends an icmp packet
	11 - ttl exceeded
	3 - destination unreachable
	@param interface - the interface
	@param eth - the ethernet header
	@param  type - the type of icmp packet
	@param router_ip - the ip of the router
*/
static void send_icmp_packet(struct ether_header *eth,
							 uint32_t interface, uint8_t type, uint32_t router_ip)
{
	struct iphdr *ip = (struct iphdr *)(eth + OFFSET_ADDR);
	struct icmphdr *icmp = (struct icmphdr *)(ip + OFFSET_ADDR);

	// 2 types of icmp packets:
	// 11 - ttl exceeded
	// 3 - destination unreachable
	icmp->type = type;
	
	recalculate_checksum(ip);

	// prepare the icmp body with ipv4 and its first 8 bytes
	// 64 + 8 = 72
	// bassically we reconstruct the ip header in the icmp body
	// it's like a debuggin tool
	uint32_t length;
	if (type == 0) {
		// handle the reques/reply
		length = ntohs(ip->tot_len) - sizeof(*ip) - sizeof(*icmp); 
	} else {
		// handle the ntimeout and host unreach
		length = sizeof(*ip) +8;
	}

	memcpy(pool.memory, ip, length);

	// set the ip header
	// we swap the source and destination ip addresses
	// and set the rest of the fields
	ip->daddr = ip->saddr;
	ip->saddr = router_ip;
	ip->ttl = htons(TTL_MAX);
	ip->protocol = IPPROTO_ICMP; // not used but good practice
	ip->tot_len = htons(length + sizeof(*ip) + sizeof(*icmp)); 
	
	recalculate_checksum(ip);

	// swap the mac addresses as well
	memcpy(eth->ether_dhost, eth->ether_shost, sizeof(eth->ether_shost));
	get_interface_mac(interface, eth->ether_shost);

	memcpy((char *)icmp + sizeof(*icmp), pool.memory, length);

	send_to_link(interface, (char *)eth, sizeof(*eth) + sizeof(*ip)
				 + sizeof(*icmp) + length);

	// reset the mem pool for next use
	reset_mem_pool_data();
}

/*
	Function that sends a packet to a link
	The packet is intended for a host
	@param interface - the interface
	@param eth - the ethernet header
	@param len - the length
	@param router_ip - the ip of the router
*/
static void ip_packet_for_host(struct ether_header *eth,
							   uint32_t interface, uint32_t len, uint32_t router_ip)
{
	struct iphdr *ip = (struct iphdr *)(eth + OFFSET_ADDR);

	uint16_t old_checksum = ip->check;
	// recalculate the checksum
	recalculate_checksum(ip);

	if (old_checksum != ip->check)
		return;
	
	// ttl check && send icmp packet for ttl exceeded
	if (ip->ttl <= 1) {
		send_icmp_packet(eth, interface, 11, router_ip);
		return;
	}

	--ip->ttl;
	
	recalculate_checksum(ip);

	// get best route
	struct route_table_entry *next = get_best_rtable(ip->daddr);

	// if we don't have a route send icmp packet
	if (!next) {
		send_icmp_packet(eth, interface, 3, router_ip);
		return;
	}

	// get best arp
	struct arp_table_entry *arp = get_best_arp(next->next_hop);

	get_interface_mac(next->interface, eth->ether_shost);

	// if the arp entry is in the table send the packet
	if (arp) {
		memcpy(eth->ether_dhost, arp->mac, sizeof(arp->mac));
		send_to_link(next->interface, (char *)eth, len);
		return;
	}

	// put arp packet in queue if we don't have the mac
	// then send the arp request to get the mac
	struct waiting_element *entry = malloc(sizeof(*entry));
	DIE(entry == NULL, "malloc in ip_packet");

	entry->eth_hdr = malloc(len);
	DIE(entry->eth_hdr == NULL, "malloc in ip_packet");

	memcpy(entry->eth_hdr, eth, len);
	entry->len = len;
	entry->next_route = next;
	queue_enq(packets_queue, entry);

	// send arp request
	send_arp_request(eth, next, next->interface, router_ip);
}

/*
	Function that sends an IP packet
	@param interface - the interface
	@param eth - the ethernet header
	@param len - the length

*/
static void send_ip_packet(struct ether_header *eth,
						   uint32_t interface, uint32_t len, uint32_t router_ip)
{
	struct iphdr *ip = (struct iphdr *)(eth + OFFSET_ADDR);

	// transform the ip address, reduce redundanc and repetitive code
	// If the packet is for the router or for a host
	(ip->daddr == router_ip) ? send_icmp_packet(eth, interface, 0, router_ip)
							 : ip_packet_for_host(eth, interface, len, router_ip);

}

/*
	Function that sends an arp packet
	@param eth - the ethernet header
	@param interface - the interface
	@param len - the length
*/
static void send_arp_packet(struct ether_header *eth,
							uint32_t interface, uint32_t len, uint32_t router_ip)
{
	struct arp_header *arp = (struct arp_header *)(eth + OFFSET_ADDR);

	// arp reply
	if (ntohs(arp->op) != 1) {
		arp_table[arp_table_len].ip = arp->spa;
		memcpy(arp_table[arp_table_len].mac, arp->sha, sizeof(arp->sha));
		++arp_table_len;

		// send packets from queue if any
		// (the packets hold the arp reply with the addr)
		while (!queue_empty(packets_queue)) {
			struct waiting_element *entry = queue_deq(packets_queue);
			send_ip_packet((struct ether_header *)entry->eth_hdr,
						   interface, entry->len, router_ip);
			free(entry->eth_hdr);
			free(entry);
		}
		return;
	}

	// here we handle the arp request
	// 1. swap the source and destination
	// 2. set the op to 2
	// 3. set the source mac to the router mac
	// 4. set the destination mac to the source mac
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

/*
	Function that handles a packet
	@param eth - the ethernet header
	@param interface - the interface
	@param len - the length
*/
void handle_packet(struct ether_header *eth, uint32_t interface, uint32_t len)
{
	uint32_t router_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &router_ip);
	switch (ntohs(eth->ether_type)) {
		case ETHERTYPE_IP:
			send_ip_packet(eth, interface, len, router_ip);
			break;
		case ETHERTYPE_ARP:
			send_arp_packet(eth, interface, len, router_ip);
			break;
		default:
			break;
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// our heap data
	alloc_router_resources(argv[1]);

	qsort(rtable, rtable_len, sizeof(*rtable),
		  comparator_function);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type).
		The oposite is needed when sending a packet on the link, */
		handle_packet(eth_hdr, interface, len);

	}

	free_router_resources();

	return 0;
}


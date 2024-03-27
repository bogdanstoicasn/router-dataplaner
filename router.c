#include "utils.h"


static struct route_table_entry *rtable;
static int rtable_size;

static struct arp_table_entry *arp_table;
static int arp_table_len;

static struct queue *chiuwewe;

// liniar search in rtable
struct route_table_entry *get_best_rtable1(uint32_t dest_ip, struct route_table_entry *rtable, int rtable_size)
{
	for (int i = 0; i < rtable_size; ++i) {
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
			return &rtable[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Parse the routing table
	rtable = alloc_rtable(argv[1]);
	rtable_size = read_rtable(argv[1], rtable);

	// Parse the ARP table
	arp_table = malloc(sizeof(struct arp_table_entry) * 6);	
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator_function);

	chiuwewe = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* Check if we got an IPv4 packet */
		// if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
		// 	printf("Ignored non-IPv4 packet\n");
		// 	continue;
		// }

		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) */
		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
			printf("Checksum gone wrong\n");
			fflush(stdout);
			continue;
		}
		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		//struct route_table_entry *best_route = get_best_rtable(ip_hdr->daddr, rtable, rtable_size);
		struct route_table_entry *best_route = get_best_rtable(ip_hdr->daddr, rtable, rtable_size);
		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */
		if (ip_hdr->ttl < 1) {
			printf("Packet gone wrong beacuse of time\n");
			fflush(stdout);
			continue;
		}
		int old_ttl = ip_hdr->ttl;
		int old_check = ip_hdr->check;
		ip_hdr->ttl -= 1;
		//ip_hdr->check = ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
		ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;
		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */

		// update the eth address from next jump: me->next_person->...
		// and i get the mac table from next_person
		struct arp_table_entry *mac_entry = get_best_arp(best_route->next_hop, arp_table, arp_table_len);
		if (mac_entry == NULL) {
			printf("No mac entry found\n");
			fflush(stdout);
			continue;
		}
		// update the eth address
		for (int i = 0; i < 6; ++i) {
			eth_hdr->ether_dhost[i] = mac_entry->mac[i];
		}
		uint8_t mac[6];
		// get the mac address of the interface
		get_interface_mac(best_route->interface, mac);

		// update the eth address with my interface
		for (int i = 0; i < 6; ++i) {
			eth_hdr->ether_shost[i] = mac[i];
		}
		/* TODO 2.5: Forward the package to best_route->interface. */
		send_to_link(best_route->interface, buf, len);
		
		// Call send_to_link(best_router->interface, packet, packet_len);

	}

	free(rtable);
	free(arp_table);
	free(chiuwewe);
}


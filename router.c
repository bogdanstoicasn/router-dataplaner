#include "utils.h"


static struct route_table_entry *rtable;
static int rtable_size;

static struct arp_table_entry *arp_table;
static int arp_table_len;

static struct queue *chiuwewe;


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Parse the routing table
	rtable = alloc_rtable(argv[1]);
	rtable_size = read_rtable(argv[1], rtable);

	// Parse the ARP table
	arp_table = alloc_arp_table(argv[2]);
	arp_table_len = parse_arp_table(argv[2], arp_table);

	qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator_function);

	chiuwewe = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		switch (ntohs(eth_hdr->ether_type)) {
			case ETHERTYPE_IP:
				break;
			case ETHERTYPE_ARP:
				break;
			default:
				break;
		}
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}

	free(rtable);
	free(arp_table);
	free(chiuwewe);
}


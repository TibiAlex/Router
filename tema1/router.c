//Buzera Tiberiu 323CA
#include <queue.h>
#include "skel.h"

//Structura folosita pentru a face parsarea fisierului rtable
typedef struct {
	uint32_t prefix;
	uint32_t next;
	uint32_t mask;
	int interface;
} rtable;

typedef struct {
	uint32_t ip;
	uint8_t mac[6];
}arp;

//functie ce inverseaza ordinea octetilor in cazul in care ip-ul este 
//retinut in memorie invers
uint32_t reverse_octets(uint32_t n) {
	uint32_t b0,b1,b2,b3;

	b0 = (n & 0x000000ff) << 24u;
	b1 = (n & 0x0000ff00) << 8u;
	b2 = (n & 0x00ff0000) >> 8u;
	b3 = (n & 0xff000000) >> 24u;

	return b0 | b1 | b2 | b3;	
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	/*
	Parsarea tabelei de rutare
	*/
	FILE *file = fopen("rtable0.txt", "r");
	DIE(file == NULL, "ERROR OPEN FILE");
	int count = 0;
	char c;
	for (c = getc(file); c != EOF; c = getc(file)) {
		if(c == '\n') {
			count++;
		}
	}
	rtable *rtable = malloc(2 * count * sizeof(rtable));
	fseek(file, 0, SEEK_SET);
	for(int i = 0; i < count; i++) {
		char s1[20], s2[20], s3[20];
		int interface;
		fscanf(file, "%s %s %s %d", s1, s2, s3, &interface);
		int ret = inet_aton(s1, (struct in_addr *)(&rtable[i].prefix));
		rtable[i].prefix = reverse_octets(rtable[i].prefix);
		DIE(ret == 0, "ERROR INET_ATON PREFIX");
		ret = inet_aton(s2, (struct in_addr *)(&rtable[i].next));
		rtable[i].next = reverse_octets(rtable[i].next);
		DIE(ret == 0, "ERROR INET_ATON NEXT_HOP");
		ret = inet_aton(s3, (struct in_addr *)(&rtable[i].mask));
		rtable[i].mask = reverse_octets(rtable[i].mask);
		DIE(ret == 0, "ERROR INET_ATON MASK");
		rtable[i].interface = interface;
	}
	fclose(file);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */

		/*
		ARP_REQUEST
		*/
		struct arp_header *arp_hdr = parse_arp(&m.payload);
		if(arp_hdr != NULL) {
			if(arp_hdr->op == htons(ARPOP_REQUEST)) {
				struct ether_header eth_hdr;
				for(int i = 0; i < 6; i++) {
					eth_hdr.ether_dhost[i] = arp_hdr->sha[i];
				}
				get_interface_mac(m.interface, eth_hdr.ether_shost);
				eth_hdr.ether_type = htons(ETHERTYPE_ARP);

				send_arp(arp_hdr->spa, arp_hdr->tpa, &eth_hdr, m.interface, htons(ARPOP_REPLY));
				continue;
			}
		}
		/*
		ARP_REPLY
		*/
		if(arp_hdr != NULL) {
			if(arp_hdr->op == htons(ARPOP_RREPLY)) {

			}
		}
	}
}

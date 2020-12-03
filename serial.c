/* 	Compilation: gcc -g serial.c -o serial -lpcap
	Usage: ./serial <file.pcap>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

/* UDP header struct */
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;		/* datagram checksum */
};

/* Reports a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Reports the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

/* Procedure that reads a UDP packet and prints its payload content */
const unsigned char* dump_UDP_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len);
	

int main(int argc, char *argv[]) {
	pcap_t *pcap;	//pionter to the pcap file
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	char *filepath;
	if (argc == 2) {
		filepath = argv[1]; //get filename from command-line
	}
	else {
		printf("USAGE: ./serial <file.pcap>\n");
		exit(1);
	}

	pcap = pcap_open_offline(filepath, errbuf);	//opening the pcap file
	if (pcap == NULL) {	//check error in pcap file
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	int count = 1; //for keeping count of packet's number
	
	/* Loop extracting packets as long as we have something to read */
	while ((packet = pcap_next(pcap, &header)) != NULL) {
		
		printf("Packet nr: %d\n", count++);
		const unsigned char* payload = dump_UDP_packet(packet, header.ts, header.caplen); //getting the payload
		if(payload != NULL)
			printf("payload= \n%s\n", payload);
		else
			printf("The packet reading has not been completed succesfully!\n");
	}

	return 0;
}


void problem_pkt(struct timeval ts, const char *reason) {
	fprintf(stderr, "error: %s\n", reason);

}

void too_short(struct timeval ts, const char *truncated_hdr) { 
	fprintf(stderr, "packetis truncated and lacks a full %s\n", truncated_hdr); 
}

const unsigned char* dump_UDP_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len) {
	struct ip *ip; //from netinet/ip.h
	//struct UDP_hdr *udp_header;
	unsigned int IP_header_length;

	/* For simplicity, this program assumes Ethernet encapsulation. */

	if (capture_len < sizeof(struct ether_header)) { //if the capture_len is too short
		too_short(ts, "Ethernet header");
		return NULL;
	}

	packet += sizeof(struct ether_header); // Move the packet pointer after the ether_header
	
	capture_len -= sizeof(struct ether_header); // Decrease the capture len yet to be read

	if (capture_len < sizeof(struct ip)) {  //if the capture len is too short to contain the ip
		
		too_short(ts, "IP header");
		return NULL;
	}

	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	// ip_hl is in 4-byte words

	if (capture_len < IP_header_length) {
		too_short(ts, "IP header with options");
		return NULL;
	}

	// now we can check if it's a udp packet
	if (ip->ip_p != IPPROTO_UDP) {
		problem_pkt(ts, "non-UDP packet");
		return NULL;
	}

	
	packet += IP_header_length; //Move the packet pointer after the ip header
	
	capture_len -= IP_header_length; //Decrease the capture len yet to be read

	if (capture_len < sizeof(struct UDP_hdr)) {
		too_short(ts, "UDP header");
		return NULL;
	}

	
	/* Now the packet points to the upd_header, that contains:
	*  source port, destination port, packet lenght and checksum. */
	//udp_header = (struct UDP_hdr*) packet;

	//Erase comment to print the packet info
	/*
	printf("UDP src_port=%d dst_port=%d length=%d checksum=%d\n",
		ntohs(udp_header->uh_sport),
		ntohs(udp_header->uh_dport),
		ntohs(udp_header->uh_ulen),
		ntohs(udp_header->uh_sum));
	*/

	/*	According to the UDP standard the header is 32 bit lenght
	*	Adding 32 bit to the packet we have a pointer to the payload */
	const unsigned char* payload = packet + 32;
	
	//printf("payload= \n%s\n", payload);
	
	return payload;
}

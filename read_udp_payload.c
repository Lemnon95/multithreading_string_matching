/* 	Compile with gcc read_udp_payload.c  -o read_udp_payload -lpcap
	Important note: You must change the filepath declared above to the main
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

 /*
 * UDP header struct
 */
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

/*
* Procedure that read a UDP packet and print the content
*/
const char* dump_UDP_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len)
{
	struct ip *ip; //from netinet/ip.h
	struct UDP_hdr *udp_header;
	unsigned int IP_header_length;

	/* For simplicity, this program assume Ethernet encapsulation. */

	if (capture_len < sizeof(struct ether_header))
		{
		//if the capture_len is too short
		too_short(ts, "Ethernet header");
		return NULL;
		}

	// Move the packet pointer after the ether_header
	packet += sizeof(struct ether_header);
	// Decrease the capture len yet to be read
	capture_len -= sizeof(struct ether_header);

	if (capture_len < sizeof(struct ip))
		{ 
		//if the capture len is too short to contain the ip
		too_short(ts, "IP header");
		return NULL;
		}

	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	// ip_hl is in 4-byte words

	if (capture_len < IP_header_length)
		{
		too_short(ts, "IP header with options");
		return NULL;
		}

	// now we can check if is it a udp packet
	if (ip->ip_p != IPPROTO_UDP)
		{
		problem_pkt(ts, "non-UDP packet");
		return NULL;
		}

	// Move the packet pointer after the ip header
	packet += IP_header_length;
	// Decrease the capture len yet to be read
	capture_len -= IP_header_length;

	if (capture_len < sizeof(struct UDP_hdr))
		{
		too_short(ts, "UDP header");
		return NULL;
		}

	
	/*	Now the packet point to the upd_header, that contain
	*	sorce port, destination port, packet lenght, checksum
	*/
	udp_header = (struct UDP_hdr*) packet;

	//Erase comment to print the packet info
	/*
	printf("UDP src_port=%d dst_port=%d length=%d checksum=%d\n",
		ntohs(udp_header->uh_sport),
		ntohs(udp_header->uh_dport),
		ntohs(udp_header->uh_ulen),
		ntohs(udp_header->uh_sum));
	*/

	/*	According to the UDP standard the header is 32 bit lenght
	*	Adding 32 bit to the packet we have a pointer to the payload
	*/
	const char* payload = packet += 32;
	
	//printf("payload= \n%s\n", payload);
	
	return payload;
}
	
// Path of the pcap file containg ONLY udp packets
const char *filepath = "udp.pcap";

int main(int argc, char *argv[])
	{
	pcap_t *pcap;	//ponter to the pcap file
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;


	pcap = pcap_open_offline(filepath, errbuf);	//open the pcap file saved offline
	if (pcap == NULL)	//check error in pcap file
		{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
		}

	int count = 1;
	/* Loop through extracting packets as long as we have
	 * some to read.
	 */
	while ((packet = pcap_next(pcap, &header)) != NULL) {
		
		printf("Packet nr: %d\n", count++);
		
		const char* payload = dump_UDP_packet(packet, header.ts, header.caplen);
		if(payload != NULL)
			printf("payload= \n%s\n", payload);
		else
			printf("The packet reading is not complete succesfully!\n");
	}

	return 0;
	}


void problem_pkt(struct timeval ts, const char *reason)
	{
	fprintf(stderr, "error: %s\n", reason);
	}

void too_short(struct timeval ts, const char *truncated_hdr)
	{
	fprintf(stderr, "packetis truncated and lacks a full %s\n", truncated_hdr);
	}

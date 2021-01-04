/*
* Library that contain dumping function for UDP and TCP packets 
* sniffed using tcpdump and contained in a pcap file
*/

/* UDP header struct */
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;		/* datagram checksum */
};

/* TCP structs */

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;	/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;	/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* don't fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;	/* sequence number */
	tcp_seq th_ack;	/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* Print error message if we find a packet problem */
void problem_pkt(const char *reason) {
	fprintf(stderr, "error: %s\n", reason);

}

/* Print the error message if we find a packet too short */
void too_short(const char *truncated_hdr) { 
	fprintf(stderr, "packetis truncated and lacks a full %s\n", truncated_hdr); 
}

/* Function use to extract the payload from an UDP packet
* INPUT:
*	packet: The package in which we look for the payload
	payload_length: unsigned int variable passed by reference in which we save the payload length. We can use it in the calling function
	capture_len : the len of the packet
	
* OUTPUT
	payload
*/
char* dump_UDP_packet(const unsigned char *packet, unsigned int * payload_lenght, unsigned int capture_len) {

	struct ip *ip; //from netinet/ip.h
	struct udp_header *udp_h;
	unsigned int IP_header_length;


	if (capture_len < sizeof(struct ether_header)) { //if the capture_len is too short
		//too_short("Ethernet header");
		return NULL;
	}

	packet += sizeof(struct ether_header); // Move the packet pointer after the ether_header
	capture_len -= sizeof(struct ether_header); // Decrease the capture len yet to be read

	if (capture_len < sizeof(struct ip)) {  //if the capture len is too short to contain the ip
		//too_short("IP header");
		return NULL;
	}

	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	// ip_hl is in 4-byte words

	if (capture_len < IP_header_length) {
		//too_short("IP header with options");
		return NULL;
	}

	// now we can check if it's a udp packet
	if (ip->ip_p != IPPROTO_UDP) {
		//problem_pkt("non-UDP packet");
		return NULL;
	}

	
	packet += IP_header_length; //Move the packet pointer after the ip header
	capture_len -= IP_header_length; //Decrease the capture len yet to be read

	if (capture_len < sizeof(struct UDP_hdr)) {
		//too_short("UDP header");
		return NULL;
	}
	
	//get the header
	udp_h = (struct udp_header *) (packet + IP_header_length + sizeof(struct ether_header));
	
	packet += sizeof(udp_h); //Move the packet pointer after the header
	capture_len -= sizeof(udp_h); //Decrease the capture len yet to be read
	
	(*payload_lenght) = capture_len; // Now capture_len is equal to the payload len. We can use it in the calling function
	
	return (char*) packet; //packet now point to payload
}

/* Function use to extract the payload from a TCP packet
* INPUT:
*	packet: The package in which we look for the payload
	payload_length: unsigned int variable passed by reference in which we save the payload length. We can use it in the calling function
	capture_len : the len of the packet
	
* OUTPUT
	payload
*/
char* dump_TCP_packet(const unsigned char *packet, unsigned int * payload_lenght, unsigned int capture_len) {

	// ethernet headers are always exactly 14 bytes 
	#define SIZE_ETHERNET 14
	
	const struct sniff_ip *ip; // The IP header 
	const struct sniff_tcp *tcp; // The TCP header 

	u_int size_ip;
	u_int size_tcp;

	packet += SIZE_ETHERNET; //move packet pointer adding the ethernet size to get the ip pointer
	capture_len -= SIZE_ETHERNET; //decrease the capture len yet to be read

	ip = (struct sniff_ip*)(packet); 
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//too_short("Invalid IP header length: %u bytes\n", size_ip);
		return NULL;
	}
	
	packet += size_ip; //move packet pointer adding the ethernet size to get the tcp pointer
	capture_len -= size_ip; //decrease the capture len yet to be read
	
	tcp = (struct sniff_tcp*)(packet);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		//too_short("Invalid TCP header length: %u bytes\n", size_tcp);
		return NULL;
	}
	
	packet += size_tcp; //move packet pointer adding the tcp size to get the payload pointer
	capture_len -= size_tcp; //decrease the capture len yet to be read
	
	(*payload_lenght) = capture_len; // Now capture_len is equal to the payload len. We can use it in the calling function
	
	return (char*) packet; //packet now point to payload

}

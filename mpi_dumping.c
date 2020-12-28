#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

// PCAP packet struct
typedef struct {
	char data[65535];
} Packet;

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

#define UDP 0
#define TCP 1

char* dump_TCP_packet(char *packet);
char* dump_UDP_packet(char *packet);
void problem_pkt(struct timeval ts, const char *reason);
void too_short(struct timeval ts, const char *truncated_hdr);

/*Knuth-Morris-Pratt String Matching Algorithm's functions.*/
int kmp_matcher (char text[], char pattern[]);
void kmp_prefix (char pattern[], int *prefix);

int main (int argc, char *argv[]){
	int my_rank, comm_sz;
	MPI_Init(NULL, NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &comm_sz);

	/* Building MPI_Packet Datatype */
	MPI_Datatype MPI_Packet;
	int array_of_blocklengths[] = {65535};
	MPI_Aint array_of_displacements[] = {0};
	MPI_Datatype array_of_types[] = {MPI_CHAR};
	MPI_Type_create_struct(1, array_of_blocklengths, array_of_displacements, array_of_types, &MPI_Packet);
	MPI_Type_commit(&MPI_Packet);

	/* Getting packet type from input */
	int packet_type;
	if (argc == 3) {
		if (strcmp(argv[2], "udp") == 0) {
			packet_type = UDP;
		}
		else if (strcmp(argv[2], "tcp") == 0) {
			packet_type = TCP;
		}
		else {
			printf("USAGE ./serial <file.pcap> [tcp/udp]\n");
			exit(1);
		}
	}
	else {
		printf("USAGE: ./serial <file.pcap> [tcp/udp]\n");
		exit(1);
	}

	int num_packets, flag = 0;
	Packet *a = NULL;
	if (my_rank == 0){ //rank 0 is in charge of gathering all Packets
		char errbuff[PCAP_ERRBUF_SIZE];
		struct pcap_pkthdr *header;
		pcap_t *pcap = pcap_open_offline(argv[1], errbuff);
		if (pcap == NULL) {	//check error in pcap file opening
			fprintf(stderr, "error reading pcap file: %s\n", errbuff);
			flag = -1;
		}
		else {
			a = malloc(sizeof(Packet));
			int size_a = 1;
			num_packets = 0;
			const unsigned char *data;
			unsigned char *data_copy;
			int i;
			while ((i = pcap_next_ex(pcap, &header, &data)) >= 0) {
				data_copy = malloc(header->len); //allocate memory to copy packet data
				memcpy(data_copy, data, header->len);
				memcpy(a[num_packets].data, data_copy, header->len); //we store the payload in the array of payloads
				num_packets++;
				if (num_packets == size_a) {
					a = realloc(a, (size_a*2)*sizeof(Packet));
					size_a *= 2;
				}
			}
			pcap_close(pcap);
			if (!(size_a == num_packets))
			a = realloc(a, num_packets*sizeof(Packet)); //we reallocate memory to get even
		}
	}

	MPI_Bcast(&num_packets, 1, MPI_INT, 0, MPI_COMM_WORLD);
	MPI_Bcast(&flag, 1, MPI_INT, 0, MPI_COMM_WORLD);
	//we check for error in pcap file opening
	if (flag == -1) {
		MPI_Finalize();
		return 0;
	}
	/* At this point, we have the total size, so we can allocate local arrays of packets */
	int *local_size = malloc(comm_sz*sizeof(int)); //array that stores the number of packets that each process must have
	int *displ = malloc(comm_sz*sizeof(int)); //array of displacement for Scatterv


	for (int i = 0; i < comm_sz; i++) {
		local_size[i] = num_packets/comm_sz;
	} local_size[0] += num_packets%comm_sz;

	int offset = 0;
	for (int i = 0; i < comm_sz; i++) {
		displ[i] = offset;
		offset += local_size[i];
	}


	Packet *local_packets = malloc(local_size[my_rank]*sizeof(Packet)); //every process allocates the memory needed for storing its share of Packets
	MPI_Scatterv(a, local_size, displ, MPI_Packet, local_packets, local_size[my_rank], MPI_Packet, 0, MPI_COMM_WORLD);
	free(a);

  double local_start, local_finish, local_elapsed, elapsed;
	MPI_Barrier(MPI_COMM_WORLD);
	local_start = MPI_Wtime();
	/* Every Process now has its share of packets, it's time to dump the payloads! */
	char **local_payloads = malloc(local_size[my_rank]*sizeof(char*)); //we allocate memory for the local array of payloads

	for (int i = 0; i < local_size[my_rank]; i++) {
		char* payload;
		if(packet_type == UDP) //udp
			payload = dump_UDP_packet(local_packets[i].data); // Getting the payload
		else //tcp
			payload = dump_TCP_packet(local_packets[i].data); // Getting the payload
		if(payload != NULL) {  // Save payload into array of payload
			local_payloads[i] = malloc(strlen(payload)+1);
			memcpy(local_payloads[i], payload, strlen(payload));
		}
		else { // If the packet is not valid we just save a " " string inside local array of payloads
			local_payloads[i] = malloc(1);
			memcpy(local_payloads[i], " ", 1);
		}
	}

	char *S[] = {"http", "Linux", "NOTIFY", "LOCATION"}; //Strings we want to find
	int size_S = 4;
	int *local_string_count = calloc(size_S, sizeof(int));
	int *global_string_count = calloc(size_S, sizeof(int));

	/* For each payload, we call the string matching algorithm for every string in S */
	for (int k = 0; k < local_size[my_rank]; k++)
		for (int i = 0; i < size_S; i++)
				local_string_count[i] += kmp_matcher(local_payloads[k],S[i]);

	MPI_Reduce(local_string_count, global_string_count, size_S, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD); //with this call, we get the total values in global_string_count
	local_finish = MPI_Wtime();
	local_elapsed = local_finish - local_start;

	MPI_Reduce(&local_elapsed, &elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

	if (my_rank == 0) {
		printf("Printing the number of appereances of each string throughout the entire pcap file:\n");
		for (int i = 0; i < size_S; i++)
			printf("%s: %d times!\n", S[i], global_string_count[i]);
			// Now we print performance evaluation
		printf("Elapsed time = %f seconds\n", elapsed);
	}

	MPI_Type_free(&MPI_Packet);
	MPI_Finalize();
	return 0;
}


void problem_pkt(struct timeval ts, const char *reason) {
	fprintf(stderr, "error: %s\n", reason);

}

void too_short(struct timeval ts, const char *truncated_hdr) {
	fprintf(stderr, "packetis truncated and lacks a full %s\n", truncated_hdr);
}

char* dump_UDP_packet(char *packet) {

	char* payload = packet + 42;

	return payload;
}

char* dump_TCP_packet(char *packet) {
	/* ethernet headers are always exactly 14 bytes */
	#define SIZE_ETHERNET 14

	//const struct sniff_ethernet *ethernet; // The ethernet header
	const struct sniff_ip *ip; // The IP header
	const struct sniff_tcp *tcp; // The TCP header
	char* payload; // Packet payload

	u_int size_ip;
	u_int size_tcp;


	//ethernet = (struct sniff_ethernet*)(packet);
	packet += SIZE_ETHERNET; //move packet pointer adding the ethernet size to get the ip pointer

	ip = (struct sniff_ip*)(packet);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return NULL;
	}

	packet += size_ip; //move packet pointer adding the ethernet size to get the tcp pointer
	tcp = (struct sniff_tcp*)(packet);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return NULL;
	}

	packet += size_tcp; //move packet pointer adding the tcp size to get the payload pointer
	payload = (char*)(packet);

	return payload;

}

int kmp_matcher (char text[], char pattern[]) {
	int text_len = strlen(text);
	int pattern_len = strlen(pattern);
	if (text_len < pattern_len) //no point trying to match things
		return 0;
	int *prefix_array = malloc(pattern_len*sizeof(int));
	kmp_prefix(pattern, prefix_array);
	int i = 0;
	int j = 0;
	int occurrences = 0; //counter for the number of occurrences of pattern in text
	while (i < text_len) {
		if (pattern[j] == text[i]) {
			j++;
			i++;
		}
		if (j == pattern_len) { //we have a match
			occurrences++;
			j = prefix_array[j-1]; //look for next match
		}
		else if (i < text_len && pattern[j] != text[i]) {
			if (j != 0)
				j = prefix_array[j-1];
			else
				i++;
		}
	}

	free(prefix_array);
	return occurrences;
}

void kmp_prefix (char pattern[], int *prefix) {
	int pattern_len = strlen(pattern);
	int j = 0;
	prefix[0] = 0; //first letter does not have any prefix
	int i = 1;
	while (i < pattern_len) {
		if (pattern[i] == pattern[j]){
			prefix[i] = j + 1;
			j++;
			i++;
		}
		else if (j != 0) {
			j = prefix[j-1];
		}
		else {
			prefix[i] = 0;
			i++;
		}
	}
}

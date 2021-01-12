/* Compilation: mpicc -Wall mpi_idea3.c -o mpi_idea3 -lpcap */

#include <mpi.h>
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

const unsigned char* dump_TCP_packet(const unsigned char *packet);
const unsigned char* dump_UDP_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len);
void problem_pkt(struct timeval ts, const char *reason);
void too_short(struct timeval ts, const char *truncated_hdr);
int kmp_matcher (char text[], char pattern[]);
void kmp_prefix (char pattern[], int *prefix); 

int main (int argc, char *argv[]){
	int my_rank, comm_sz;
	MPI_Init(NULL, NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &comm_sz);
	
	
	/* Getting packet type from input */
	int packet_type;
	char *strings_file_path;
	if (argc == 4) {
		strings_file_path = argv[2];
		if (strcmp(argv[3], "udp") == 0) {
			packet_type = UDP;
		}
		else if (strcmp(argv[3], "tcp") == 0) {
			packet_type = TCP;
		}
		else {
			printf("USAGE ./serial <file.pcap> <strings.txt> [tcp/udp]\n");
			exit(1);
		}
	}	
	else {
		printf("USAGE: ./serial <file.pcap> <strings.txt> [tcp/udp]\n");
		exit(1);
	}
	
	//we read strings for the string matching from txt file 
	char **array_of_strings = malloc(sizeof(char *));
	int array_of_strings_length = 1;	
	int count = 0; //actual number of strings

	//open file and check errors
	FILE *fp = fopen(strings_file_path,"r");
	if (fp == NULL) {
		perror("error opening file: ");
		exit(1);
	}
	char str[100]; //buffer when we save the strings in the file
	
	while( fscanf(fp, "%s", str) != EOF ) //we read all the file word by word
	{

		array_of_strings[count] = malloc(strlen(str)+1); //we have to allocate memory for storing this payload
		if (count < array_of_strings_length) {
			memcpy(array_of_strings[count], str, strlen(str)); //copy string into array
			count++;
		}
		else { //count == array_of_strings_length
			//it looks like we exceeded maximum capacity of array, so we use a realloc to reallocate memory
			array_of_strings = (char **)realloc(array_of_strings, (array_of_strings_length*2)*sizeof(char *));
			memcpy(array_of_strings[count], str, strlen(str)); //copy string into array
			count++;
			array_of_strings_length *= 2;
		}
	}
	fclose(fp);
	
	// If array is not full, we reallocate memory 
	if (!(count == array_of_strings_length))
		array_of_strings = (char **)realloc(array_of_strings, (count*sizeof(char *)));
	array_of_strings_length = count;
	
	int total_size, flag = 0;
	char *global_buff = NULL;

	if (my_rank == 0) {
		char errbuff[PCAP_ERRBUF_SIZE];
		struct pcap_pkthdr header;
		pcap_t *pcap = pcap_open_offline(argv[1], errbuff);
		if (pcap == NULL) {	//check error in pcap file opening
			fprintf(stderr, "error reading pcap file: %s\n", errbuff);
			flag = -1;
		}
		else {
			const unsigned char *packet;
			int count = 0; //keep tracks of global_buff length
			while ((packet = pcap_next(pcap, &header)) != NULL) {
				const unsigned char* payload;
				if(packet_type == UDP) 
					payload = dump_UDP_packet(packet, header.ts, header.caplen); // Getting the payload
				else //tcp
					payload = dump_TCP_packet(packet); // Getting the payload
				if (payload != NULL) {
					int size = strlen((char*) payload)+2;	
					if(count == 0) {
						global_buff = calloc(size, sizeof(char));
					}
					else	{
						global_buff = realloc(global_buff, (count+size)*sizeof(char));
					}
					strcat(global_buff, " "); //to avoid strings that should not be there	
					strcat(global_buff, (char*) payload);
					count += size;
				}
			}
			total_size = count;
			pcap_close(pcap);
		}
	}
	MPI_Bcast(&total_size, 1, MPI_INT, 0, MPI_COMM_WORLD);
	MPI_Bcast(&flag, 1, MPI_INT, 0, MPI_COMM_WORLD);
	
	if(flag == -1) {
		free(global_buff);
		MPI_Finalize();
		return 0;
	}
	
	/* At this point, we have the total size, so we can allocate local arrays */

	int *local_size = malloc(comm_sz*sizeof(int)); //array that stores the number of lines that each process must have
	int *displ = malloc(comm_sz*sizeof(int)); //array of displacement for Scatterv 
	
	for (int i = 0; i < comm_sz; i++) {
		local_size[i] = total_size/comm_sz;
	} local_size[0] += total_size%comm_sz;
	
	int offset = 0;
	for (int i = 0; i < comm_sz; i++) {
		displ[i] = offset;
		offset += local_size[i];
	}
	int *local_string_count = calloc(array_of_strings_length, sizeof(int)); 
	int *global_string_count = calloc(array_of_strings_length, sizeof(int)); 
	
	char *local_buff = malloc(local_size[my_rank]*sizeof(char));
	
	MPI_Scatterv(global_buff, local_size, displ, MPI_CHAR, local_buff, local_size[my_rank], MPI_CHAR, 0, MPI_COMM_WORLD);
	
	for (int i = 0; i < array_of_strings_length; i++) 
				local_string_count[i] += kmp_matcher(local_buff,array_of_strings[i]);
				
	MPI_Reduce(local_string_count, global_string_count, array_of_strings_length, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);
	
	if (my_rank == 0) {
		printf("Printing the number of appereances of each string throughout the entire pcap file:\n");
		for (int i = 0; i < array_of_strings_length; i++)
			printf("%s: %d times!\n", array_of_strings[i], global_string_count[i]);
	}
	
	free(local_buff);
	free(global_buff);
	free(local_string_count);
	free(global_string_count);
	MPI_Finalize();
	return 0;
}


void problem_pkt(struct timeval ts, const char *reason) {
	fprintf(stderr, "error: %s\n", reason);

}

void too_short(struct timeval ts, const char *truncated_hdr) { 
	fprintf(stderr, "packetis truncated and lacks a full %s\n", truncated_hdr); 
}

const unsigned char* dump_UDP_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len) {
	
	const unsigned char* payload = packet + 42;
	
	//printf("payload= \n%s\n", payload);
	
	return payload;
}

const unsigned char* dump_TCP_packet(const unsigned char *packet) {
	/* ethernet headers are always exactly 14 bytes */
	#define SIZE_ETHERNET 14

	//const struct sniff_ethernet *ethernet; // The ethernet header 
	const struct sniff_ip *ip; // The IP header 
	const struct sniff_tcp *tcp; // The TCP header 
	const unsigned char* payload; // Packet payload 

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
	payload = (u_char *)(packet);
	
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
	

	
	
	
		
		
	
		
	

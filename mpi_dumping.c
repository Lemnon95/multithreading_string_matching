/* Compilation: mpicc -Wall mpi_dumping.c -o mpi_dumping -lpcap */

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "packet_dumping.h"

// PCAP packet struct
typedef struct {
	unsigned int len;
	char data[65535];
} Packet;



#define UDP 0
#define TCP 1

/*Knuth-Morris-Pratt String Matching Algorithm's functions.*/
int kmp_matcher (char text[], char pattern[], int *prefix_array);
int* kmp_prefix (char pattern[]);

int main (int argc, char *argv[]){
	int my_rank, comm_sz;
	MPI_Init(NULL, NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &comm_sz);

	/* Building MPI_Packet Datatype */
	Packet dummy;
	MPI_Datatype MPI_Packet;
	int array_of_blocklengths[] = {1, 65535};
	MPI_Aint array_of_displacements[2];
	MPI_Aint len_addr, data_addr;
	array_of_displacements[0] = 0;
	MPI_Get_address(&dummy.len, &len_addr);
	MPI_Get_address(&dummy.data, &data_addr);
	array_of_displacements[1] = data_addr - len_addr;
	MPI_Datatype array_of_types[] = {MPI_UNSIGNED, MPI_CHAR};
	MPI_Type_create_struct(2, array_of_blocklengths, array_of_displacements, array_of_types, &MPI_Packet);
	MPI_Type_commit(&MPI_Packet);
	
	char * strings_file_path;

	/* Getting packet type from input */
	int packet_type;
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
			int size_a = 1;//gcc -g -Wall -fopenmp openmp_data.c -o openmp_data -lpcap
			num_packets = 0;
			const unsigned char *data;
			int i;
			while ((i = pcap_next_ex(pcap, &header, &data)) >= 0) {
				memcpy(a[num_packets].data, data, header->len); //we store the payload in the array of payloads
				a[num_packets].len = header->len;
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
		unsigned int payload_length;
		if(packet_type == UDP) //udp
			payload = dump_UDP_packet(local_packets[i].data, &payload_length , local_packets[i].len); // Getting the payload
		else //tcp
			payload = dump_TCP_packet(local_packets[i].data, &payload_length , local_packets[i].len); // Getting the payload
		if(payload != NULL) {  // Save payload into array of payload
			local_payloads[i] = malloc(payload_length+1);
			memcpy(local_payloads[i], payload, payload_length);
		}
		else { // If the packet is not valid we just save a " " string inside local array of payloads
			local_payloads[i] = malloc(1);
			memcpy(local_payloads[i], " ", 1);
		}
	}

	int *local_string_count = calloc(array_of_strings_length, sizeof(int));
	int *global_string_count = calloc(array_of_strings_length, sizeof(int));
	int **prefix_array = malloc(array_of_strings_length*sizeof(int*));
	for (int i = 0; i < array_of_strings_length; i++) {
		prefix_array[i] = kmp_prefix(array_of_strings[i]);
	}

	/* For each payload, we call the string matching algorithm for every string in S */
	for (int k = 0; k < local_size[my_rank]; k++)
		for (int i = 0; i < array_of_strings_length; i++)
				local_string_count[i] += kmp_matcher(local_payloads[k],array_of_strings[i], prefix_array[i]);

	MPI_Reduce(local_string_count, global_string_count, array_of_strings_length, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD); //with this call, we get the total values in global_string_count
	local_finish = MPI_Wtime();
	local_elapsed = local_finish - local_start;

	MPI_Reduce(&local_elapsed, &elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

	if (my_rank == 0) {
		printf("Printing the number of appereances of each string throughout the entire pcap file:\n");
		for (int i = 0; i < array_of_strings_length; i++)
			printf("%s: %d times!\n", array_of_strings[i], global_string_count[i]);
			// Now we print performance evaluation
		printf("Elapsed time = %f seconds\n", elapsed);
	}

	MPI_Type_free(&MPI_Packet);
	MPI_Finalize();
	return 0;
}

int kmp_matcher (char text[], char pattern[], int *prefix_array) {
	int text_len = strlen(text);
	int pattern_len = strlen(pattern);
	if (text_len < pattern_len) //no point trying to match things
		return 0;
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
	return occurrences;
}

int* kmp_prefix (char pattern[]) {
	int pattern_len = strlen(pattern);
	int *prefix = malloc(pattern_len*sizeof(int));
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
	return prefix;
}


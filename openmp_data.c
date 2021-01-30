/* 	Compilation: gcc -g -Wall -fopenmp openmp_data.c -o openmp_data -lpcap
	Usage: ./openmp_data <file.pcap> <string.txt> thread_number [tcp/udp]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "timer.h"
#include "packet_dumping.h"
#include <omp.h>

struct pkt_str {
	unsigned char *data;
	unsigned int len;
};

#define UDP 0
#define TCP 1

/*Knuth-Morris-Pratt String Matching Algorithm's functions.*/
int kmp_matcher (char text[], char pattern[], int *prefix_array);
int* kmp_prefix (char pattern[]);

int main(int argc, char *argv[]) {
	pcap_t *pcap;	//pointer to the pcap file
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filepath;
	char *strings_file_path;
	int thread_count;
	int packet_type = UDP; //default udp

	if (argc==4 || argc ==5) {
		filepath = argv[1]; //get filename from command-line
		strings_file_path = argv[2];
		thread_count = atoi(argv[3]); //get thread number from command-line

		if(argc == 5) { //get packet type from command-line
			if(strcmp(argv[4], "udp") == 0)
				packet_type=UDP;
			else if (strcmp(argv[4], "tcp") == 0)
				packet_type=TCP;
			else {
				printf("USAGE ./openmp_data <file.pcap> <string.txt> thread_number [tcp/udp]\n");
				exit(1);
			}
		}
	}
	else {
		printf("USAGE: ./openmp_data <file.pcap> <string.txt> thread_number [tcp/udp]\n");
		exit(1);
	}

	/* Reading strings for the string matching from txt file */
	char **array_of_strings = malloc(sizeof(char *)); // for storing the patterns for string matching
	int array_of_strings_length = 1; //keeps track of array's size
	int count = 0; //actual number of strings

	//open file and check for errors
	FILE *fp = fopen(strings_file_path,"r");
	if (fp == NULL) {
		perror("error opening file: ");
		exit(1);
	}
	char str[100]; //buffer for saving the strings once pulled out by fscanf

	while(fscanf(fp, "%s", str) != EOF) //we read all the file word by word
	{

		array_of_strings[count] = malloc(strlen(str)); //we have to allocate memory for this string
		if (count < array_of_strings_length) {
			strcpy(array_of_strings[count], str); //copy string into array
			count++; //actual number of strings have grown by 1
		}
		else { //count == array_of_strings_length
			//it looks like we exceeded maximum capacity of array, so we use a realloc to reallocate memory
			array_of_strings = (char **)realloc(array_of_strings, (array_of_strings_length*2)*sizeof(char *));
			strcpy(array_of_strings[count], str); //copy string into array
			count++; //actual number of strings have grown by 1
			array_of_strings_length *= 2;
		}
	}
	fclose(fp);

	/* If array is not full, we reallocate memory */
	if (!(count == array_of_strings_length))
		array_of_strings = (char **)realloc(array_of_strings, (count*sizeof(char *)));
	array_of_strings_length = count;


	//now we open the pcap file
	pcap = pcap_open_offline(filepath, errbuf);	//opening the pcap file
	if (pcap == NULL) {	//check error in pcap file
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	struct pcap_pkthdr *header;
	const unsigned char * data; // data object
	struct pkt_str *array_of_packets = malloc(sizeof(struct pkt_str));
	int packet_count = 0; //number of packets into pcap file
	int array_of_packets_length = 1; //array size
	int i;

	while((i = pcap_next_ex(pcap,&header,&data)) >=0) {
		if(packet_count == array_of_packets_length) {
			//it looks like we exceeded maximum capacity of array, so we use a realloc to reallocate memory
			array_of_packets = realloc(array_of_packets, (array_of_packets_length*2)*sizeof(struct pkt_str));
			array_of_packets_length *= 2;
		}
		//push packet struct into array of packets
		array_of_packets[packet_count].data = malloc(header->caplen); //allocate memory to copy packet data
		memcpy(array_of_packets[packet_count].data, data, header->caplen);
		array_of_packets[packet_count].len = header->caplen;
		packet_count++;

	}
	if (!(packet_count == array_of_packets_length))
		array_of_packets = realloc (array_of_packets, packet_count*sizeof(struct pkt_str)); //we reallocate memory to get even

	char *array_of_payloads[packet_count];

	/* Start the performance evaluation */
	double start = omp_get_wtime();

	#pragma omp parallel for num_threads(thread_count) schedule(guided) shared(array_of_payloads, array_of_packets, packet_type)
	for (int i = 0; i < packet_count; i++) {
		char * data = (char*)array_of_packets[i].data; // Get current packet
		int packet_len = array_of_packets[i].len; // Get current packet len
		char* payload;
		unsigned int payload_length;
		if(packet_type == UDP) //udp
			payload = dump_UDP_packet(data, &payload_length, packet_len); // Getting the payload
		else //tcp
			payload = dump_TCP_packet(data, &payload_length, packet_len); // Getting the payload

		if(payload != NULL) {  // Save payload into array of payload
			array_of_payloads[i] = malloc(payload_length);
			memcpy(array_of_payloads[i], payload, payload_length);
		}
		else { // If the packet is not valid we save a " " message into array of payloads
			array_of_payloads[i] = malloc(1);
			memcpy(array_of_payloads[i], " ", 1);
		}
	}

	int *string_count = calloc(array_of_strings_length, sizeof(int)); // Using calloc because we want to initialize every member to 0
	int *private_string_count;
	int **prefix_array = malloc(array_of_strings_length*sizeof(int*));
	/* Main thread is in charge of building the prefix_array */
	for (int i = 0; i < array_of_strings_length; i++) {
		prefix_array[i] = kmp_prefix(array_of_strings[i]);
	}

	#pragma omp parallel num_threads(thread_count) private (private_string_count) shared(string_count)
	{
		private_string_count = calloc(array_of_strings_length, sizeof(int)); // Using calloc because we want to initialize every member to 0
		// For each payload, we call the string matching algorithm for every string in S
		#pragma omp for schedule(guided) collapse(2)
		for (int k = 0; k < packet_count; k++) //for every payload
			for (int i = 0; i < array_of_strings_length; i++) //for every string
					private_string_count[i] += kmp_matcher(array_of_payloads[k], array_of_strings[i], prefix_array[i]);

		// Merge private string count into shared string count array
		#pragma omp critical
		{
		for (int i = 0; i < array_of_strings_length; i++)
			string_count[i] += private_string_count[i];
		}
		free(private_string_count);
	}

	// Stop the performance evaluation
	double finish = omp_get_wtime();

	// Now we print the output

	printf("Printing the number of appereances of each string throughout the entire pcap file:\n");
	for (int i = 0; i < array_of_strings_length; i++)
		if(string_count[i] != 0)
			printf("%s: %d times!\n", array_of_strings[i], string_count[i]);

	// Now we print performance evaluation
	printf("Elapsed time = %f seconds\n", finish-start);

	// We have to free previously allocated memory
	for(int i=0; i<packet_count; i++){
		free(array_of_payloads[i]);
	} // free(array_of_payloads) not needed cause it has been allocated in the stack

	for (int i = 0; i < packet_count; i++) {
			free(array_of_packets[i].data);
	} free(array_of_packets);

	free(string_count);

	for (int i = 0; i < array_of_strings_length; i++) {
		free(prefix_array[i]);
	} free(prefix_array);

	for (int i = 0; i < array_of_strings_length; i++) {
		free(array_of_strings[i]);
	} free(array_of_strings);

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

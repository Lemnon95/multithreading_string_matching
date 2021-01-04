/* 	Compilation: gcc -g serial.c -o serial -lpcap
	Usage: ./serial <file.pcap>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "timer.h"
#include "packet_dumping.h"


#define UDP 0
#define TCP 1


/*Knuth-Morris-Pratt String Matching Algorithm's functions.*/
int kmp_matcher (char text[], char pattern[]);
void kmp_prefix (char pattern[], int *prefix); 

	

int main(int argc, char *argv[]) {
	pcap_t *pcap;	//pointer to the pcap file
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	char *filepath;

	int packet_type = UDP; //default udp
	
	if (argc==2 || argc ==3) { 
		filepath = argv[1]; //get filename from command-line
		
		if(argc == 3) { //get packet type from command-line
			if(strcmp(argv[2], "udp") == 0)
				packet_type=UDP;
			else if (strcmp(argv[2], "tcp") == 0)
				packet_type=TCP;
			else {
				printf("USAGE ./serial <file.pcap> [tcp/udp]\n");
				exit(1);
			}
		}
	}
	else {
		printf("USAGE: ./serial <file.pcap> [tcp/udp]\n");
		exit(1);
	}

	pcap = pcap_open_offline(filepath, errbuf);	//opening the pcap file
	if (pcap == NULL) {	//check error in pcap file
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	int count = 0; //actual number of payloads
	char **array_of_payloads = malloc(sizeof(char *));
	int array_of_payloads_length = 1; //keeps track of the size of the array of payloads
	char *S[] = {"http", "Linux", "NOTIFY", "LOCATION"}; //Strings we want to find
	int size_S = 4;
	int *string_count = calloc(size_S, sizeof(int)); //using calloc because we want to initialize every member to 0
	
	const unsigned char* data;
	int i;
	unsigned char * data_copy; //copy of data object
	unsigned int payload_lenght;
	/* Loop extracting packets as long as we have something to read, storing them inside array_of_payloads */
	
	/* Start the performance evaluation */
	double start;
	GET_TIME(start);
	while ((i = pcap_next_ex(pcap, &header, &data)) >= 0) {
		char* payload;
		data_copy = malloc(header->len); //allocate memory to copy packet data
		memcpy(data_copy, data, header->len); 
		if(packet_type == UDP) //udp
			payload = dump_UDP_packet(data_copy, &payload_lenght, header->len); //getting the payload
		else //tcp
			payload = dump_TCP_packet(data_copy, &payload_lenght, header->len); //getting the payload
			
		if(payload != NULL) { //we store it in array of payloads
			array_of_payloads[count] = malloc(payload_lenght+1); //we have to allocate memory for storing this payload
			if (count < array_of_payloads_length) {
				memcpy(array_of_payloads[count], payload, payload_lenght);
				count++;
			}
			else { //count == array_of_payloads_length
				//it looks like we exceeded maximum capacity of array, so we use a realloc to reallocate memory
				array_of_payloads = (char **)realloc(array_of_payloads, (array_of_payloads_length*2)*sizeof(char *)); 
				memcpy(array_of_payloads[count], payload, payload_lenght);
				count++;
				array_of_payloads_length *= 2;
			}
		}
		else {
			//printf("The packet reading has not been completed succesfully!\n");
		}
	}
	
	/* If array is not full, we reallocate memory */
	if (!(count == array_of_payloads_length))
		array_of_payloads = (char **)realloc(array_of_payloads, (count*sizeof(char *)));
	
	
	
	/* For each payload, we call the string matching algorithm for every string in S */
	for (int k = 0; k < count; k++)
		for (int i = 0; i < size_S; i++) 
				string_count[i] += kmp_matcher(array_of_payloads[k],S[i]);
				
	
	/* Stop the performance evaluation */		
	double finish;
	GET_TIME(finish);
	
	/* Now we print the output */
	printf("Printing the number of appereances of each string throughout the entire pcap file:\n");
	for (int i = 0; i < size_S; i++)
		printf("%s: %d times!\n", S[i], string_count[i]);
		
	/* Now we print performance evaluation */
	printf("Elapsed time = %f seconds\n", finish-start);

	/* We have to free previously allocated memory */
	for (int k = 0; k < count; k++) {
		free(array_of_payloads[k]);
	} free(array_of_payloads);
	free(string_count);
	return 0;
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

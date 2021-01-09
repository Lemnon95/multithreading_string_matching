
/* 	Compilation: gcc -g serial.c -o serial -lpcap
	Usage: ./serial <file.pcap> <string.txt> [udp/tcp]
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
int kmp_matcher (char text[], char pattern[], int *prefix_array);
int* kmp_prefix (char pattern[]);

	

int main(int argc, char *argv[]) {
	pcap_t *pcap;	//pointer to the pcap file
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	char *filepath;
	char *strings_file_path;

	int packet_type = UDP; //default udp
	
	if (argc==3 || argc ==4) { 
		filepath = argv[1]; //get filename from command-line
		strings_file_path = argv[2];
		
		if(argc == 4) { //get packet type from command-line
			if(strcmp(argv[3], "udp") == 0)
				packet_type=UDP;
			else if (strcmp(argv[3], "tcp") == 0)
				packet_type=TCP;
			else {
				printf("USAGE ./serial <file.pcap> <string.txt> [tcp/udp]\n");
				exit(1);
			}
		}
	}
	else {
		printf("USAGE: ./serial <file.pcap> <string.txt> [tcp/udp]\n");
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

	count = 0; //actual number of payloads
	char **array_of_payloads = malloc(sizeof(char *));
	int array_of_payloads_length = 1; //keeps track of the size of the array of payloads
	//char *S[] = {"http", "Linux", "NOTIFY", "LOCATION"}; //Strings we want to find
	//int size_S = 4;
	int *string_count = calloc(array_of_strings_length, sizeof(int)); //using calloc because we want to initialize every member to 0
	
	const unsigned char* data;
	int i;
	unsigned char * data_copy; //copy of data object
	unsigned int payload_lenght;
	/* Loop extracting packets as long as we have something to read, storing them inside array_of_payloads */
	
	/* Start the performance evaluation */
	double start;
	GET_TIME(start);
	
	//Start reading pcap file
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
	int **prefix_array = malloc(array_of_strings_length*sizeof(int*));
	/* Main thread is in charge of building the prefix_array */
	for (int i = 0; i < array_of_strings_length; i++) {
		prefix_array[i] = kmp_prefix(array_of_strings[i]);
	}
	for (int k = 0; k < count; k++)
		for (int i = 0; i < array_of_strings_length; i++) 
				string_count[i] += kmp_matcher(array_of_payloads[k],array_of_strings[i], prefix_array[i]);
				
	
	/* Stop the performance evaluation */		
	double finish;
	GET_TIME(finish);
	
	/* Now we print the output */
	printf("Printing the number of appereances of each string throughout the entire pcap file:\n");
	for (int i = 0; i < array_of_strings_length; i++)
		printf("%s: %d times!\n", array_of_strings[i], string_count[i]);
		
	/* Now we print performance evaluation */
	printf("Elapsed time = %f seconds\n", finish-start);

	/* We have to free previously allocated memory */
	for (int k = 0; k < count; k++) {
		free(array_of_payloads[k]);
	} free(array_of_payloads);
	free(string_count);
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

/*	Compilation: gcc -g -Wall -fopenmp live_openmp_task.c -o live_openmp_task -lpcap
	USAGE: sudo ./live_openmp_task interface <string.txt> thread_count [udp/tcp]
	interface example -> wlo1
	For select an interface run "tcpdump -D" and choose one option
*/

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "packet_dumping.h"

#define UDP 0
#define TCP 1

static int signalFlag = 0;

void signalHandler(int val);
/*Knuth-Morris-Pratt String Matching Algorithm's functions.*/
int kmp_matcher (char text[], char pattern[], int *prefix_array);
int* kmp_prefix (char pattern[]);

int main(int argc, char *argv[]) {
	
	char errbuf[PCAP_ERRBUF_SIZE];				//buffer use to print errors
	char * interface; 		//need for tcpdump sniffing
	char * strings_file_path; 	//file containing strings for matching
	int thread_count; 		//number of threads
	int packet_type = UDP; 		//default udp
	struct bpf_program filter;	//The compiled filter expression
	bpf_u_int32 mask;		//The netmask of our sniffing device
	bpf_u_int32 net; 		//The IP of our sniffing device
	
	if(argc==5 || argc==4) {
		interface = argv[1];
		strings_file_path = argv[2];
		thread_count = atoi(argv[3]);
		if(argc == 5) { //get packet type from command-line
			if(strcmp(argv[4], "udp") == 0)
				packet_type=UDP;
			else if (strcmp(argv[4], "tcp") == 0)
				packet_type=TCP;
			else {
				printf("USAGE ./live_openmp_task interface <string.txt> thread_count [udp/tcp]\n");
				exit(1);
			}
		}
	
	}
	else {
		printf("USAGE ./live_openmp_task interface <string.txt> thread_count [udp/tcp]\n");
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

		array_of_strings[count] = malloc(strlen(str)); //we have to allocate memory for storing this string
		if (count < array_of_strings_length) {
			strcpy(array_of_strings[count], str); //copy string into array
			count++;
		}
		else { //count == array_of_strings_length
			//it looks like we exceeded maximum capacity of array, so we use a realloc to reallocate memory
			array_of_strings = (char **)realloc(array_of_strings, (array_of_strings_length*2)*sizeof(char *));
			strcpy(array_of_strings[count], str); //copy string into array
			count++;
			array_of_strings_length *= 2;
		}
	}
	fclose(fp);
	
	/* If array is not full, we reallocate memory */
	if (!(count == array_of_strings_length))
		array_of_strings = (char **)realloc(array_of_strings, (count*sizeof(char *)));
	array_of_strings_length = count;
	
	
	/* Now building prefix array */
	int **prefix_array = malloc(array_of_strings_length*sizeof(int*));
	/* Main thread is in charge of building the prefix_array */
	for (int i = 0; i < array_of_strings_length; i++) {
		prefix_array[i] = kmp_prefix(array_of_strings[i]);
	}
	
	
	//finding net and mask values
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", interface);
		net = 0;
		mask = 0;
	}	
	
	//now initialize sniffer session
	pcap_t * live_handle = 
		pcap_open_live(interface, BUFSIZ, 1, 0, errbuf);
	if (live_handle == NULL) { //errors check
		 fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		 return(2);
	 }
	
	//set sniffing rules	 
	
	char * type;
	if (packet_type == UDP)
		type = "udp";
	else
		type = "tcp";
		
	if (pcap_compile(live_handle, &filter, type, 0, net) == -1) {
	 	fprintf(stderr, "Couldn't parse filter %s: %s\n", type, pcap_geterr(live_handle));	
		 return(1);
	}
	 
	if (pcap_setfilter(live_handle, &filter) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", type, pcap_geterr(live_handle));
		return(1);
	}
	 
	//sniffing procedure
	
	struct pcap_pkthdr header;						// The header that pcap gives us
	const u_char *packet;							// The actual packet
	int array_of_payload_length = 10; 					// keeps track of the size of the array of packets
	char *array_of_payloads[array_of_payload_length];  			// array containing captured packets
	int packet_count=0;							// actual number of packet into array
	int total_count=0;							// increased when packet_count is reinitialize to 0
	int *string_count = calloc(array_of_strings_length, sizeof(int)); 	// using calloc because we want to initialize every member to 0
	char* payload;
	unsigned int packet_len;
	char * data_copy; //copy of data object
	int *private_string_count; //used into every task
	
	printf("\nWork in progress...\nPress ctrl+c to stop sniffing procedure\n");
	printf("You can stop the procedure only if at least one %s packet has been read\n", type);
	
	//Initialize items for execute the procedure until ctrl+C pressed
	struct sigaction action;
	action.sa_handler = signalHandler;
	sigaction(SIGINT, &action, NULL);
	
	#pragma omp parallel num_threads(thread_count)
	{
		#pragma omp single 
		{
			while (signalFlag == 0 ) {	//cycle until ctrl+C pressed
			
				packet = pcap_next(live_handle, &header);
				
				if(packet_count<array_of_payload_length) {	//if there is space, add payload into array

					data_copy = malloc(header.len); //allocate memory to copy packet data
					memcpy(data_copy, packet, header.len); //copy packet data
					if(packet_type == UDP) //udp
						payload = dump_UDP_packet(data_copy, &packet_len, header.len); //getting the payload
					else //tcp
						payload = dump_TCP_packet(data_copy, &packet_len, header.len); //getting the payload
								
					if(payload != NULL) { //we store it in array of payloads
					
						array_of_payloads[packet_count] = malloc(packet_len); //we have to allocate memory for storing this payload
						strcpy(array_of_payloads[packet_count], payload); //copy payload into array
					}
					else { // If the packet is not valid we save a " " message into array of payloads
						array_of_payloads[packet_count] = malloc(1);
						strcpy(array_of_payloads[packet_count], " ");
					}
					packet_count++;
					
				}
				else {	// create new task to submit to a thread
				
					#pragma omp task firstprivate(array_of_payloads, packet_count) private(private_string_count) shared(string_count, array_of_strings_length, array_of_strings)
					{
						// Using calloc because we want to initialize every member to 0
				 		private_string_count = calloc(array_of_strings_length, sizeof(int)); 
				 		
						for (int k = 0; k < packet_count; k++) { //for every packets 
							for (int i =0 ; i < array_of_strings_length; i++) //for every string
								private_string_count[i] += kmp_matcher(array_of_payloads[k],array_of_strings[i], prefix_array[i]);
						}
						
						// Merge private string count into shared string count array
						#pragma omp critical
						{
						for (int i = 0; i < array_of_strings_length; i++)
							string_count[i]+=private_string_count[i];
						}
					 	free(private_string_count);
						
					} //close task
					
					packet_count=0;
					total_count++;			
				}	
			
			}
		} //close omp single
	} //close omp parallel
	
	pcap_close(live_handle);	//close sniffing session
	
	//add data not used in the last cycle
	if (packet_count!=0)
		for (int k = 0; k < packet_count; k++) //for every packets 
			for (int i =0 ; i < array_of_strings_length; i++) //for every string
				string_count[i] += kmp_matcher(array_of_payloads[k],array_of_strings[i], prefix_array[i]);
	
	//calculate total count
	total_count = (total_count*array_of_payload_length) + packet_count;
	printf("\n\n%d packet sniffed\n\n", total_count);
	
	// Now we print the output
	int check = 0;
	printf("Printing the number of appereances of each string throughout the entire pcap file:\n");
	for (int i = 0; i < array_of_strings_length; i++) {
		if(string_count[i] != 0) {
			printf("%s: %d times!\n", array_of_strings[i], string_count[i]);
			check = 1;
		}
	}
	if (check==0)
		printf("Oops! We have not found any matches\n");
		
			
	/* We have to free previously allocated memory */
	for (int i = 0; i < array_of_strings_length; i++) {
		free(prefix_array[i]);
	} free(prefix_array);
	

	for (int i = 0; i < array_of_strings_length; i++) {
		free(array_of_strings[i]);
	} free(array_of_strings);
	
	free(array_of_payloads);
	
	free(string_count);

	return 0;
	 
}

void signalHandler(int val) {
	signalFlag = 1;
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

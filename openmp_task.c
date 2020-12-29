/* 	Compilation: gcc -g -Wall -fopenmp openmp_task.c -o openmp_task -lpcap
	Usage: ./openmp_task <file.pcap> thread_number [tcp/udp]
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


#define UDP 0
#define TCP 1

/*Knuth-Morris-Pratt String Matching Algorithm's functions.*/
int kmp_matcher (char text[], char pattern[]);
void kmp_prefix (char pattern[], int *prefix); 


int main(int argc, char *argv[]) {
	pcap_t *pcap;	//pointer to the pcap file
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	char *filepath;
	int thread_count;
	int packet_type = UDP; //default udp
	
	if (argc==3 || argc ==4) { 
		filepath = argv[1]; //get filename from command-line
		thread_count = atoi(argv[2]); //get thread number from command-line
		
		if(argc == 4) { //get packet type from command-line
			if(strcmp(argv[3], "udp") == 0)
				packet_type=UDP;
			else if (strcmp(argv[3], "tcp") == 0)
				packet_type=TCP;
			else {
				printf("USAGE ./serial <file.pcap> thread_number [tcp/udp]\n");
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
	//char **array_of_payloads = malloc(sizeof(char *));
	int array_of_payloads_length = 100; //keeps track of the size of the array of payloads
	char *array_of_payloads[array_of_payloads_length];
	char *S[] = {"http", "Linux", "NOTIFY", "LOCATION"}; //Strings we want to find
	int size_S = 4;
	int *string_count = calloc(size_S, sizeof(int)); //using calloc because we want to initialize every member to 0
	
	int exit_flag = 0;
	int packet_count=0;
	int *private_string_count;
	unsigned char * data_copy; //copy of data object
	unsigned int packet_len;
	int i;
	
	double start = omp_get_wtime();
	
	#pragma omp parallel num_threads(thread_count)
	{
		#pragma omp single 
		{
			//Only the thread 0 read the pcap file and create task for the other threads
			while (exit_flag==0) { //exit only when an exit signal arrive
				packet_count = 0; //Reinitialize the packet counter
				
				//Cycle for a number of packet indicated by array_of_payloads_length or until the end of the pcap file
				while (	packet_count<array_of_payloads_length &&  (i = pcap_next_ex(pcap,&header,&packet)) >=0) {
					const unsigned char* payload;
					data_copy = malloc(header->len); //allocate memory to copy packet data
					memcpy(data_copy, packet, header->len); 
					if(packet_type == UDP) //udp
						payload = dump_UDP_packet(data_copy, &packet_len, header->len); //getting the payload
					else //tcp
						payload = dump_TCP_packet(data_copy, &packet_len, header->len); //getting the payload
						
					if(payload != NULL) { //we store it in array of payloads
			
						array_of_payloads[packet_count] = malloc(packet_len+1); //we have to allocate memory for storing this payload
						memcpy(array_of_payloads[packet_count], payload,  packet_len); //copy payload into array
						count++;
					}
					else { // If the packet is not valid we save a " " message into array of payloads
						array_of_payloads[packet_count] = malloc(1);
						memcpy(array_of_payloads[packet_count], " ", 1);
					}
					packet_count++;
														
				}

				
				#pragma omp task firstprivate(array_of_payloads, packet_count) private(private_string_count) shared(string_count, size_S, S)
				{

				 	private_string_count = calloc(size_S, sizeof(int)); // Using calloc because we want to initialize every member to 0
				 	
				 	for (int k = 0; k < packet_count; k++) //for every payload
						for (int i =0 ; i < size_S; i++) //for every string 
							private_string_count[i] += kmp_matcher((char*)array_of_payloads[k],S[i]);
								
	
				 	// Merge private string count into shared string count array
					#pragma omp critical
					{
					for (int i = 0; i < size_S; i++)
						string_count[i]+=private_string_count[i];
					}
			 	
				 	free(private_string_count);
				}
				
				//if we read less packet than array_of_payloads_length means thath the pcap file is ended
				if (packet_count<array_of_payloads_length)
					exit_flag = 1;
					
			} //end of while cicle
		} //end of single pragma
	} //end of parallel pragma
	
	double finish = omp_get_wtime();
	
	/* Now we print the output */
	printf("Printing the number of appereances of each string throughout the entire pcap file:\n");
	for (int i = 0; i < size_S; i++)
		printf("%s: %d times!\n", S[i], string_count[i]);
		
	// Now we print performance evaluation 
	printf("Elapsed time = %f seconds\n", finish-start);

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

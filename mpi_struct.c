#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	char data[10];
} Payload;

int main (int argc, char *argv[]) {
	int my_rank, comm_sz;
	MPI_Init(NULL, NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &comm_sz);
	
	MPI_Datatype MPI_Payload;
	int array_of_blocklengths[] = {10};
	MPI_Aint array_of_displacements[] = {0};
	MPI_Datatype array_of_types[] = {MPI_CHAR};
	
	MPI_Type_create_struct(1, array_of_blocklengths, array_of_displacements, array_of_types, &MPI_Payload);
	MPI_Type_commit(&MPI_Payload);
	
	int n = 6; //total number of packets
	int local_n = n/comm_sz; //number of packets for single node
	/* Now that we have the number of payloads/packets for each node, we can allocate memory for an array of payloads */
	Payload *local_buff = malloc(local_n*sizeof(Payload));
	Payload *a = NULL;
	if (my_rank == 0) {
		a = malloc(n*sizeof(Payload));
		char msg[10];
		for (int i = 0; i < n; i++) {
			printf("Enter a max 9 character length string\n");
			scanf("%s", msg);
			strcpy(a[i].data, msg);
		}
	}
	
	MPI_Scatter(a, local_n, MPI_Payload, local_buff, local_n, MPI_Payload, 0, MPI_COMM_WORLD);
	free(a);
	
	printf("Hi from process %d, here are the strings:\n", my_rank);
	printf("%s\n", local_buff[0].data);
	printf("%s\n", local_buff[1].data);
	
	
	MPI_Type_free(&MPI_Payload);
	MPI_Finalize();
	return 0;
}

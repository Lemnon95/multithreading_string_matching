# Introduction

The aim of the project is to produce a **multithread** application that performs the Knutth-Morris-Pratt algorithm for string matching, on a series of pcap packets. 
The project consists of 1 serial program, and of 3 multithread programs, of which 2 have been realized using **OpenMP** library, and the one remaining using **Open MPI**.

## Technologies

* C Programming Language
* [Open MPI](https://www.open-mpi.org/)
* [Open MP](https://www.openmp.org/)
* [TCP Dump & Libpcap](https://www.tcpdump.org/)
* [Vagrant by Hashi Corp](https://www.vagrantup.com/)

## MPI Program

The MPI Program has been realized under the "Data Parallelism" paradigm. The load is divided among each node by equally splitting the pcap packets.
To perform tests, it has been used vagrant, in conjunction with the Vagrant file made by [@mrahtz](https://github.com/mrahtz) in this [repository](https://github.com/mrahtz/mpi-vagrant).

## Open MP Programs

openmp_data.c: data prallelism.
openmp_task.c: task parallelims.


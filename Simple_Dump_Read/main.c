#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "globals.h"
#include <windows.h>

int main(int argc, char **argv) {
	pcap_t *fp; 
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	int res;
	
	log_file = fopen("log.txt", "w");

	WRITE_TO_LOG("Start main");
	if(argc!=2) {
		fprintf(stderr, "Usage: %s filename", argv[0]);
		exit(EXIT_FAILURE);
	}

	/*Create the source string from the filename*/
	WRITE_TO_LOG("Creating the source string from the filename");
	if(pcap_createsrcstr(
		source,					//To keep source string
		PCAP_SRC_FILE,			//We're opening a file
		NULL,					//Remote host
		NULL,					//Port on the remote host
		argv[1],	//Name of the file to be opened
		errbuf) != 0)
	{
		fprintf(stderr, "\nError creating source string: %s", errbuf);
		exit(EXIT_FAILURE);
	}
	/*Open the capture file*/
	WRITE_TO_LOG("Open the capture file");
	if((fp=pcap_open(
		source,				//Device name
		65536,				//Portion of the packet to be captured
		PCAP_OPENFLAG_PROMISCUOUS, //Promiscuous mode
		1000,				//Read timeout
		NULL,				//Authentication on remote host
		errbuf))==NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s: %s", argv[1], errbuf);
		exit(EXIT_FAILURE);
	}

	WRITE_TO_LOG("Calling dispatch handler");

	while((res=pcap_next_ex(fp, &header, &pkt_data))>=0) {
		dispatch_handler(NULL, header, pkt_data);
	}

	if(res==-1) {
		fprintf(stderr, "Error opening the file for reading packets: %s\n", pcap_geterr(fp));
		exit(EXIT_FAILURE);
	}

	//pcap_loop(fp, 0, dispatch_handler, NULL);
	WRITE_TO_LOG("Calling perform_regex");
	perform_regex("regex_list.txt", "C:\\smtp_dump_output.txt");
	//perform_regex("regex_list.txt", "C:\\agentlog.txt");
	Sleep(10000);
	

	WRITE_TO_LOG("Exiting..");
	fclose(log_file);

}
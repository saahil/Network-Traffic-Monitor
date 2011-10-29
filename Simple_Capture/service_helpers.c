#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "globals.h"
#include <windows.h>

void main(int argc, char* argv[]) {
	pcap_if_t *alldevs; 
	pcap_if_t *d; 
	int inum; 
	int i=0;
	pcap_t *adhandle; 
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp";
	struct bpf_program fcode;
	pcap_dumper_t *dumpfile;
	/*
	service_status.dwServiceType = SERVICE_WIN32;
	service_status.dwCurrentState = SERVICE_START_PENDING;
	service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	service_status.dwWin32ExitCode = 0;
	service_status.dwServiceSpecificExitCode = 0;
	service_status.dwCheckPoint = 0;
	service_status.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandler("Sniffer", (LPHANDLER_FUNCTION)control_handler);
	if(hStatus == (SERVICE_STATUS_HANDLE)0) {
		return;
	}
	//Initialize service now
	service_status.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &service_status);
*/
	if(argc!=2) {
		fprintf(stderr, "Usage: %s filename", argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("Wait while I get the list of devices...\n");
	/*Get the list of devices here*/
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf)==-1) {
		fprintf(stderr, "Failed to get device list due to error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	for(d=alldevs; d; d=d->next) {
		printf("%d. %s", ++i, d->name);
		if(d->description)
			printf("(%s)\n", d->description);
		else
			printf("(No description available)\n");
	}

	if(i==0)
		printf("\nNo interfaces found on this machine. Make sure WinPCap is installed\n");

	//printf("\nEnter the interface number of your choice(1-%d):", i);
	//scanf("%d", &inum);
	inum = 1; //Remove if the device list on the machine contains more than 1 device description 

	if((inum<1) || (inum>i)) {
		printf("\nChoice out of range. Exiting...");
		pcap_freealldevs(alldevs);
		exit(1);
	}

	for(d=alldevs,i=0; i<inum-1; d=d->next,i++);

	/*Use pcap_open for non kernel dump*/
	if((adhandle=pcap_open(d->name,		/*Name of the device*/
						   65536,		/*Capture the entire packet*/
						   PCAP_OPENFLAG_PROMISCUOUS,
						   1000,		/*Timeout value*/
						   NULL,		/*Authentication*/
						   errbuf
						   )) == NULL) 
	{
		fprintf(stderr, "\nUnable to open the adapter. Maybe its not supported by WinPCap: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		exit(1);
	}

	/*Or use pcal_open_live for a kernel dump. Might be unsupported. So check it out and see if you stub your toe ;)*/
//	if((adhandle=pcap_open_live(d->name, 100, 1, 20, errbuf)) == NULL) {
//		fprintf(stderr, "\nError with pcap_open_live: %s", errbuf);
//		exit(EXIT_FAILURE);
//	}
	
	/*Check for link layer, 'cause we'll make this shit work only with Ethernet*/
	if(pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "This program only works on Ethernet networks\nExiting...\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	if(d->addresses != NULL) {
		/*Retrieve the mask of the first address of the network*/
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		/*Assume the interface in Class c*/
		netmask = 0xffffff;
	}

	/*Create the filter now with the netmask*/
	if(pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr, "\nUnable to compile the network filter.\nExiting...");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	if(pcap_setfilter(adhandle, &fcode)<0) {
		fprintf(stderr, "\nSome error with setting the filter\nExiting...");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	if((dumpfile=pcap_dump_open(adhandle, argv[1])) == NULL) {
		fprintf(stderr, "Error opening the dump file\nExiting..\n");
		exit(EXIT_FAILURE);
	}

	printf("\nNow listening on device: %s\n", d->name);

	/*Don't need the device list anymore. So free it*/
	pcap_freealldevs(alldevs);

	
	/*Aaaaaaaand start the capture!*/
	/*Change the callback to packet_handler_stdio to dump the contents on the screen instead. The parameters passed are NULL
	**Whereas for packet_handler_file_dump the parameter is the intended out_file name*/
	pcap_loop(adhandle, 0, packet_handler_file_dump, (unsigned char *)dumpfile);


	/*Or comment the entire callback above and use the following for a live dump. Seems cooler. But might be out of its elements.*/
//	if(pcap_live_dump(adhandle, argv[1], atoi(argv[2]), atoi(argv[3])) == -1) {
//		fprintf(stderr, "\nError with pcap_live_dump: %s\nExiting...\n", pcap_geterr(adhandle));
//		exit(EXIT_FAILURE);
//	}
	//return 0;
}

void control_handler(DWORD request) {
	switch (request) {
		case SERVICE_CONTROL_STOP:
			service_status.dwWin32ExitCode = 0;
			service_status.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(hStatus, &service_status);
			return;
		case SERVICE_CONTROL_SHUTDOWN:
			service_status.dwWin32ExitCode = 0;
			service_status.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(hStatus, &service_status);
			return;
		default:
			break;
	}

	SetServiceStatus(hStatus, &service_status);

	return;
}
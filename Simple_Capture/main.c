#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "globals.h"
#include <windows.h>

void service_main(int argc, char **argv) {
	SERVICE_TABLE_ENTRY service_table[2];
	service_table[0].lpServiceName = "Sniffer";
	service_table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)service_main;
	service_table[1].lpServiceName = NULL;
	service_table[1].lpServiceProc = NULL;

	StartServiceCtrlDispatcher(service_table);

	//return 0;
}

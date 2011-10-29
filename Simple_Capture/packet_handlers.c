#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "globals.h"

void packet_handler_stdio_udp(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct tm pktime;
	char strtime[16];
	time_t local_tv_sec;
	ip_header *ih;
	udp_header *uh;
	u_short sport, dport;
	u_int ip_len;
	FILE *out_file;
	u_int i;
	u_char *udp_data;

	out_file = fopen("C:/simple_out.dump", "w");

	/*Into the file*/
	fprintf(out_file, "%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
	
	/*Get the timestamp from the header*/
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&pktime, &local_tv_sec);
	strftime(strtime, sizeof(strtime), "%H:%M:%S", &pktime);

	fprintf(out_file, "%s\t%.6d\t%d\n", strtime, header->ts.tv_usec, header->len);

	/*For position of the ip header*/
	ih = (ip_header*)(pkt_data+14); /*Length of the ethernet header*/

	/*For the position of the UDP header*/
	ip_len = (ih->ver_ihl & 0xf)*4;
	uh = (udp_header*)((u_char*)ih+ip_len);

	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/*Printing IP addresses and UDP ports on source and destination*/
	fprintf(out_file, "%d.%d.%d.%d:%d->%d.%d.%d.%d:%d\n", 
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport, 
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);

	/*Reach the UDP data*/
	udp_data = (u_char*)uh+8;
	fprintf(out_file, "UDP data length: %d\n", uh->len);

	/*Print the packet*/
	for(i=1; i<uh->len; i++) {
		fprintf(out_file, "%c", udp_data[i-1]);
		//if((i%16)==0) fprintf(out_file, "\n");
	}
	fprintf(out_file, "\n\n");
}

void packet_handler_stdio_tcp(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	FILE *out_file;

	out_file = fopen("C:/simple_out.dump", "w");

	/*Into the file*/
	//fprintf(out_file, "%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
	
	extract_tcp_info(out_file, header, pkt_data);
	fclose(out_file);
	Sleep(1000);
	printf("\n\n");
}

void packet_handler_file_dump(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	/*Dump the contents into the pcap file*/
	printf("Reading now...\n");
	pcap_dump(param, header, pkt_data);
	printf("Done recording for this packet.\n");
}

void extract_tcp_info(FILE *out_file, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct tm pktime;
	char strtime[16];
	time_t local_tv_sec;
	ip_header *ih;
	tcp_header *th;
	u_short sport, dport;
	u_int ip_len;
	u_int i;
	u_char *tcp_data;
	u_int data_offset;

	/*Get the timestamp from the header*/
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&pktime, &local_tv_sec);
	strftime(strtime, sizeof(strtime), "%H:%M:%S", &pktime);

	fprintf(out_file, "%s\t%d\n", strtime, header->len);

	/*For position of the ip header*/
	ih = (ip_header*)(pkt_data+14); /*Length of the ethernet header*/

	/*For the position of the TCP header*/
	ip_len = (ih->ver_ihl & 0xf)*4;
	th = (tcp_header*)((u_char*)ih+ip_len);

	sport = ntohs(th->sport);
	dport = ntohs(th->dport);

	/*Printing IP addresses and TCP ports on source and destination*/
	fprintf(out_file, "%d.%d.%d.%d:%d->%d.%d.%d.%d:%d\n", 
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport, 
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);

	/*Skip the header options*/
	data_offset = th->data_offset & 0xf0;
	data_offset = data_offset >> 4;
	
	/*Reach the tcp data*/
	tcp_data = (u_char*)th+(data_offset*4);

	/*Print the packet*/
	for(i=1; i<(ih->tlen-ip_len-data_offset*4); i++) {
		fprintf(out_file, "%c", tcp_data[i-1]);
		/*if((i%16)==0) {
			fprintf(out_file, "\n");
		}*/
	}

	fprintf(out_file, "\n\n");
}
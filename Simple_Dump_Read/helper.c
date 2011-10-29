#include <stdio.h>
#include <stdlib.h>
#include "pcre.h"
#include <pcap.h>
#include <string.h>
#include <errno.h>
#include "globals.h"
#include <windows.h>
#define LINE_LEN 16
#define LOG_FILE "log.txt"

void WRITE_TO_LOG(char *line) {
	/*
	FILE *log_file;

	if(!(log_file=fopen(LOG_FILE, "a+"))) {
		fprintf(stderr, "Error opening log file\n");
		exit(EXIT_FAILURE);
	}*/

	fprintf(log_file, line);
	fprintf(log_file, "\n");
	//fclose(log_file);
}

void COPY_TO_FILE(const char *source_name, const char *dest_name) {
	FILE *source; 
	FILE *dest;
	char *buf;

	source = fopen(source_name, "r");
	dest = fopen(dest_name, "w");
	buf = malloc(sizeof(char)*200);
	memset(buf, 0, 200);

	while(fgets(buf, sizeof(buf), source)) {
		fputs(buf, dest);
		memset(buf, 0, 200);
	}

	fclose(source);
	fclose(dest);

	source = fopen(source_name, "w");
	fclose(source);
}


void dispatch_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	u_int i = 0;
	FILE* out_file;
	/*Unused variable*/
	(VOID)temp1;

	out_file = fopen("C:\\smtp_dump_output.txt", "w");

	extract_tcp_info(out_file, header, pkt_data);
	/*
	fprintf(out_file, "%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

	for(i=1; i<(header->caplen+1); i++) {
		fprintf(out_file, "%.2x", pkt_data[i-1]);
		if((i%LINE_LEN)==0) fprintf(out_file, "\n");
	}
	fprintf(out_file, "\n\n");
	*/
	fclose(out_file);
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
		/*if((i%LINE_LEN)==0) {
			fprintf(out_file, "\n");
		}*/
	}

	fprintf(out_file, "\n\n");
}

void perform_regex(const char *regex_path, const char *test_file) {
	FILE *regex_source;
	FILE *text_file;
	char *cur_regex;
	char *cur_text;
	pcre *re;
	const char *errptr;
	int erroffset;
	const int ovecsize = 30;
	int ovector[30];
	int rc;
	char *log_string;

	cur_regex = malloc(sizeof(char)*120);
	
	memset(cur_regex, 0, 120);

	regex_source = fopen(regex_path, "r");
	if(!regex_source) {
		fprintf(stderr, "Error opening the file containing regular expressions.\n");
		exit(EXIT_FAILURE);
	}
		
	text_file = fopen(test_file, "r");
	if(!text_file) {
		//errcode = GetLastError();
		perror("Error opening the source file:");
		exit(EXIT_FAILURE);
	}

	cur_text = malloc(sizeof(char)*120);
	log_string = malloc(sizeof(char)*50);

	while(fgets(cur_regex, 120, regex_source))
	{
		memset(log_string, 0, 50);
		sprintf(log_string, "Comparing regex- %s", cur_regex);
		WRITE_TO_LOG(log_string);

		if((re=pcre_compile(cur_regex, PCRE_MULTILINE, &errptr, &erroffset, NULL)) == NULL) {
			fprintf(stderr, "Error compiling the regular expression\n");
			exit(EXIT_FAILURE);
		}

		printf("Testing this regex right now- %s\n\n", cur_regex);
				
		memset(cur_text, 0, 120);
		
		fseek(text_file,0,SEEK_SET);

		while(fgets(cur_text, 120, text_file)) {
			
			rc=pcre_exec(re, NULL, cur_text, (int)strlen(cur_text), 0, 0, ovector, ovecsize);

			if(rc<0) { /*no matches found*/
			}

			else {
				if(rc==0) {
					rc = ovecsize/3;
					fprintf(stderr, "Ovector can only hold %d no. of re matches\n", rc-1);
					exit(EXIT_FAILURE);
				}

				memset(log_string, 0, 50);
				sprintf(log_string, "Found in line- %s", cur_text);
				WRITE_TO_LOG(log_string);
				
				/*for(i=0; i<rc-1; i++) {
					substring_start = cur_text + ovector[i];
					memset(substring, 0, ovector[i+1]-ovector[i]);
					memcpy(substring, substring_start, ovector[i+1]-ovector[i]);
					printf("%s\n", substring);
				}
				substring_start = cur_text + ovector[i];
				memset(substring, 0, strlen(cur_text)-ovector[i]);
				memcpy(substring, substring_start, strlen(cur_text)-ovector[i]);
				printf("%s\n", substring);*/
			}
			free(cur_text);
			cur_text = malloc(sizeof(char)*120);
			memset(cur_text, 0, 120);
		}
		cur_regex = malloc(sizeof(char)*120);
		memset(cur_regex, 0, 120);
	}

	fclose(regex_source);
	fclose(text_file);
	//free(log_string);
	free(cur_text);
	free(cur_regex);
}
#include <stdio.h>
#include <stdlib.h>
#include <pcre.h>
#include <windows.h>

typedef struct {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

typedef struct {
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flags_fo;
	u_char ttl;
	u_char proto;
	u_short crc;
	ip_address saddr;
	ip_address daddr;
	u_int op_pad;
} ip_header;

typedef struct {
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
} udp_header;

typedef struct {
	u_short sport; 
	u_short dport;
	u_int seq;
	u_int ack;
	u_char data_offset; /*Actually this also includes 4 higher order bits as reserved*/
						/*Hence this will be ANDed with 0xf0 and shifted to the right 4 bits before getting actual offset*/
	u_char flags;
	u_short win_size;
	u_short checksum;
	u_short urgent;
} tcp_header;

void dispatch_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
void perform_regex(const char *regex_path, const char *test_file);
void WRITE_TO_LOG(char *line);
void COPY_TO_FILE(const char *source_name, const char *dest_name);
void control_handler(DWORD request);
void service_main(int argc, char **argv);
void extract_tcp_info(FILE *out_file, const struct pcap_pkthdr *header, const u_char *pkt_data);

SERVICE_STATUS          service_status; 
SERVICE_STATUS_HANDLE   hStatus; 
FILE *log_file;
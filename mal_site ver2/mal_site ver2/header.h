#pragma once
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define ETHERNET_REVERSED 0x100
#define IP4 0x0800
#define IP4_REVERSED 0x0008
#define ARP_PROTO 0x0806
#define ARP_PROTO_REVERSED 0x0608
#define REQUEST_REVERSED 0x100
#define REPLY_REVERSED 0x200
#define MAC_LEN 6
#define PRO_LEN 4
#define IP_LEN 4
#define CHANNEL_SIZE 16
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define TCP 6
#define PROTO0_OFFSET 12
#define PROTO1_OFFSET 13
#define TIMEOUT 1000
#define ETH_DMAC_OFFSET 0
#define ETH_SMAC_OFFSET 6
#define ETH_LENGTH 14
#define IPV4_LENGTH_OFFSET 0
#define IPV4_PROTO_OFFSET 9
#define IPV4_SIP_OFFSET 12
#define IPV4_DIP_OFFSET 16
#define ARP_SIP_OFFSET 28
#define ARP_SMAC_OFFSET 22
#define ARP_DMAC_OFFSET 32
#define TCP_DPORT_OFFSET1 2
#define TCP_DPORT_OFFSET2 3
#define TCP_LENGTH_OFFSET 12
#define BUF_SIZE 256
#define WORD_NUM 0x7F //출력가능한 아스키의 범위
#define PATTERN_BUF 256 //패턴크기 버퍼
#define MAX_LENGTH 2000 //모든 문자열의 총 길이

struct FILTER;
struct ETH;
struct ARP;
struct DATA;
struct RELAY;
struct PARA;
class control;
class controller;

void mstrncpy(unsigned char* target, unsigned char* source, int num);
void my_ntoa(unsigned char* source, unsigned char* target, int len);
void packet_handler(u_char* u_para, const struct pcap_pkthdr *header, const u_char *packet);
void start_capture();
void handler(control* pos);
int data_cmp(const unsigned char* source1, const unsigned char* source2, int len);
void read_pattern(char* src);
int build();
int linking(int state, char next);
int is_bad_url(char* url);

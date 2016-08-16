#pragma once
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define ETH_PROTO_OFFSET 12
#define TCP 6
#define MAC_LEN 6
#define PRO_LEN 4
#define IP_LEN 4
#define PORT_LEN 2
#define CHANNEL_SIZE 16
#define IP4 0x0800
#define ETH_DMAC_OFFSET 0
#define ETH_SMAC_OFFSET 6
#define ETH_LENGTH 14
#define IPV4_PROTO_OFFSET 9
#define IPV4_LENGTH_OFFSET 0
#define IPV4_SIZE_OFFSET 2
#define IPV4_CHKSUM_OFFSET 10
#define IPV4_SIP_OFFSET 12
#define IPV4_DIP_OFFSET 16
#define TCP_SPORT_OFFSET 0
#define TCP_DPORT_OFFSET 2
#define TCP_SEQUENCE_OFFSET 4
#define TCP_ACKNOWLEDGEMENT_OFFSET 8
#define TCP_LENGTH_OFFSET 12
#define TCP_FLAG_OFFSET 13
#define TCP_CHKSUM_OFFSET 16

int data_cmp(const u_char* source1, const u_char* source2, int len);
void mstrncpy(u_char* target, u_char* source, int num);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *packet);
u_short in_cksum(u_short *addr, int len, long sum);
void mncopy(u_char* destination, u_char* source, int len);
void mnswap(u_char* destination, u_char* source, int len);
inline u_short mntohs(u_short s);
inline u_long mntohl(u_long l);
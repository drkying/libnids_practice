#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include "stdint.h"
#include <signal.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include "nids.h"
#include "time.h"
#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

int i, rank, flag;
//rank用于统计程序实际接收的包数
//flag为1时表示程序已经接收到结束的信号，即将退出
//flag为0时，表示程序正在运行
//i用于标识已输出包的个数
//alldata用于存储待输出的数据
pthread_t tid;


typedef struct
{
	char* buf;
	char* data;
	int data_len;
} datas;
datas* alldata = NULL;


//mac头定义
typedef struct _MAC_FRAME_HEADER
{
	char m_cDstMacAddress[6];    //目的mac地址
	char m_cSrcMacAddress[6];    //源mac地址
	short m_cType;            //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp
};


//将ip地址转换为字符串形式
char* addres(struct tuple4 addr)
{
	static char buf[256];
	printf("\n");
	strcpy(buf, int_ntoa(addr.saddr));
	sprintf(buf + strlen(buf), ":%i", addr.source);
	strcat(buf, " -> ");
	strcat(buf, int_ntoa(addr.daddr));
	sprintf(buf + strlen(buf), ":%i", addr.dest);
	return buf;
}

//使用hexdump形式输出数据
static void hexDump(const void* p, int size)	
{
	const uint8_t* c = p;
	int j = 0;
	while (size > 0)
	{
		unsigned i;
		printf("0x%04x  ", j);
		for (i = 0; i < 16; i++)
		{
			if (i < size)
				printf("%02x", c[i]);
			else
				printf("  ");
			if (i % 2 == 1)
				printf(" ");
		}
		for (i = 0; i < 16; i++)
		{
			if (i < size)
				printf("%c", c[i] >= 32 && c[i] < 127 ? c[i] : '.');
			else
				printf(" ");
		}
		printf("\n");
		c += 16;
		if (size <= 16)
			break;
		size -= 16;
		j += 16;
	}
}


void* print(void* arg)	//带参数x时的输出函数，输出包的内容
{
	while (flag == 0)
	{
		if (i < rank)
		{
			printf("\n");
			puts(alldata[i % 10000].buf);
			hexDump(alldata[i % 10000].data, alldata[i % 10000].data_len);
			i++;
		}
		else if (i == rank) continue;
		else if (i > rank)
		{
			printf("error");
			exit(1);
		}
	}
}

void print1() {	//不带参数x时开启的线程
	while (flag == 0);
}
void callback_nox(struct ip* a_packet)
{
	if (a_packet->ip_p == 6)	
	{
		char s[4];
		//获取客户端与服务器端的端口
		s[0] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[1];//大端字节序与小端字节序的转换
		s[1] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[0];
		s[2] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[3];
		s[3] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[2];
		

		uint16_t srcport, destport;
		memcpy(&srcport, s, 2);
		memcpy(&destport, s + 2, 2);
		
		//输出客户端与服务器端的ip和端口
		char buf[256];
		strcpy(buf, int_ntoa(a_packet->ip_src));
		sprintf(buf + strlen(buf), ":%u", srcport);
		strcat(buf, " -> ");
		strcat(buf, int_ntoa(a_packet->ip_dst));
		sprintf(buf + strlen(buf), ":%u", destport);
		strcat(buf, "   --TCP");
		puts(buf);
		rank++;
	}
	if (a_packet->ip_p == 17)
	{
		char s[4];
		//获取客户端与服务器端的端口
		s[0] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[1];//大端字节序与小端字节序的转换
		s[1] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[0];
		s[2] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[3];
		s[3] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[2];
		
		uint16_t srcport, destport;
		memcpy(&srcport, s, 2);
		memcpy(&destport, s + 2, 2);
		
		//输出客户端与服务器端的ip和端口
		char buf[256];
		strcpy(buf, int_ntoa(a_packet->ip_src));
		sprintf(buf + strlen(buf), ":%u", srcport);
		strcat(buf, " -> ");
		strcat(buf, int_ntoa(a_packet->ip_dst));
		sprintf(buf + strlen(buf), ":%u", destport);
		strcat(buf, "   --UDP");
		puts(buf);
		rank++;
	}

}
void callback_withx(struct ip* a_packet, int len)
{
	if (a_packet->ip_p == 6)	//tcp
	{
		char s[4];
		//获取客户端与服务器端的端口
		s[0] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[1];//大端字节序与小端字节序的转换
		s[1] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[0];
		s[2] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[3];
		s[3] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[2];
		
		
		//将客户端与服务器端的ip和端口转换为字符串存入buf中
		uint16_t srcport, destport;
		memcpy(&srcport, s, 2);
		memcpy(&destport, s + 2, 2);
		char buf[256];
		strcpy(buf, int_ntoa(a_packet->ip_src));
		sprintf(buf + strlen(buf), ":%u", srcport);
		strcat(buf, " -> ");
		strcat(buf, int_ntoa(a_packet->ip_dst));
		sprintf(buf + strlen(buf), ":%u", destport);
		strcat(buf, "   --TCP");

		//将每个包的数据和数据长度存入alldata中
		alldata[rank % 10000].buf = (char*)malloc(sizeof(char) * 100);
		alldata[rank % 10000].data = (char*)malloc(sizeof(char) * nids_last_pcap_header->len);
		memset(alldata[rank % 10000].buf, 0, sizeof(char) * 100);
		memset(alldata[rank % 10000].data, 0, sizeof(char) * nids_last_pcap_header->len);
		memcpy(alldata[rank % 10000].buf, buf, strlen(buf) + 1);
		memcpy(alldata[rank % 10000].data, nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER), nids_last_pcap_header->len - sizeof(struct _MAC_FRAME_HEADER));
		alldata[rank % 10000].data_len = nids_last_pcap_header->len - sizeof(struct _MAC_FRAME_HEADER);
		rank++;
	}
	if (a_packet->ip_p == 17)	//udp
	{
		char s[4];	
		
		//获取客户端与服务器端的端口
		s[0] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[1];	//大端字节序与小端字节序的转换
		s[1] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[0];
		s[2] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[3];
		s[3] = (nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER) + sizeof(struct ip))[2];
		
		
		//将转换后的数据保存
		uint16_t srcport, destport;	
		memcpy(&srcport, s, 2);
		memcpy(&destport, s + 2, 2);
		
		
		//将客户端与服务器端的ip和端口转换为字符串存入buf中
		char buf[256];	
		strcpy(buf, int_ntoa(a_packet->ip_src));
		sprintf(buf + strlen(buf), ":%u", srcport);
		strcat(buf, " -> ");
		strcat(buf, int_ntoa(a_packet->ip_dst));
		sprintf(buf + strlen(buf), ":%u", destport);
		strcat(buf, "   --UDP");

		//将每个包的数据和数据长度存入alldata中
		alldata[rank % 10000].buf = (char*)malloc(sizeof(char) * 100);	
		alldata[rank % 10000].data = (char*)malloc(sizeof(char) * nids_last_pcap_header->len);
		memset(alldata[rank % 10000].buf, 0, sizeof(char) * 100);
		memset(alldata[rank % 10000].data, 0, sizeof(char) * nids_last_pcap_header->len);
		memcpy(alldata[rank % 10000].buf, buf, strlen(buf) + 1);
		memcpy(alldata[rank % 10000].data, nids_last_pcap_data + sizeof(struct _MAC_FRAME_HEADER), nids_last_pcap_header->len - sizeof(struct _MAC_FRAME_HEADER));
		alldata[rank % 10000].data_len = nids_last_pcap_header->len - sizeof(struct _MAC_FRAME_HEADER);
		rank++;
	}


}
void sum_as()	//在程序退出前，输出统计信息
{
	flag = 1;
	pthread_join(tid, NULL);
	struct pcap_stat* sta;

	
	sta = (struct pcap_stat*)malloc(sizeof(struct pcap_stat));
	pcap_stats(nids_params.pcap_desc, sta);
	double rate = 100.0 - 1.0 * (rank) / (sta->ps_drop + sta->ps_recv) * 100;
	printf("\n%d packets captured\n%d packets received by filter\nthe loss rate is %.2lf%%\n", rank, sta->ps_drop + sta->ps_recv, rate);
	exit(0);
}
int main(int argc, char* argv[])
{

	i = 0; flag = 0;
	signal(SIGINT, sum_as);
	rank = 0;
	struct nids_chksum_ctl temp;
	temp.action = 1;
	temp.netaddr = 0;
	temp.mask = 0;
	nids_params.device = "enp12s0";
	nids_params.pcap_desc = pcap_open_live(nids_params.device, 16384, 1,
		nids_params.pcap_timeout, nids_errbuf);
	nids_register_chksum_ctl(&temp, 1);	//关闭校验和
	if (!nids_init())
	{
		fprintf(stderr, "%s\n", nids_errbuf);
		exit(1);
	}
	if (argc != 1)
	{
		if (strstr(argv[1], "x"))
		{
			pthread_create(&tid, NULL, print, NULL);	//开启输出的子线程
			alldata = (datas*)malloc(sizeof(datas) * 10000);
			nids_register_ip(callback_withx);
		}
		else
		{
			printf("parameter error!\n");
		}

	}
	else
	{
		pthread_create(&tid, NULL, print1, NULL);	//开启输出的子线程
		nids_register_ip(callback_nox);
	}

	nids_run();
}


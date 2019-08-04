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

char Way[10];
char* n1, * n2;
int i,n,sum=0,rank,flag;
pthread_t tid;
int sent,acc,rate;
typedef struct
{
    char *buf;
    char *data;
    int data_len;
} datas;
datas *alldata=NULL;

pthread_mutex_t now_t = PTHREAD_MUTEX_INITIALIZER;
typedef struct _MAC_FRAME_HEADER
{
    char m_cDstMacAddress[6];    //目的mac地址
    char m_cSrcMacAddress[6];    //源mac地址
    short m_cType;            //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp
};
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
void *print(void *arg)
{
    while(flag==0)
    {
        if(i<rank)
        {
            puts(alldata[i%10000].buf);
            hexDump(alldata[i%10000].data,alldata[i%10000].data_len);
            i++;
        }
        else if(i==rank) continue;
        else if(i>rank)
        {
            printf("error");
            exit(1);
        }

	}
}
void callback_nox(struct ip* a_packet)
{
    if(a_packet->ip_p==6)
    {
        char s[4];
        s[0]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[1];
        s[1]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[0];
        s[2]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[3];
        s[3]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[2];
        uint16_t srcport,destport;
        memcpy(&srcport,s,2);
        memcpy(&destport,s+2,2);
        char buf[256];
        strcpy(buf, int_ntoa(a_packet->ip_src));
        sprintf(buf + strlen(buf), ":%u",srcport);
        strcat(buf, " -> ");
        strcat(buf, int_ntoa(a_packet->ip_dst));
        sprintf(buf + strlen(buf), ":%u",destport);
        strcat(buf, "   --TCP");
        puts(buf);
    }
    if(a_packet->ip_p==17)
    {
        char s[4];
        s[0]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[1];
        s[1]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[0];
        s[2]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[3];
        s[3]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[2];
        uint16_t srcport,destport;
        memcpy(&srcport,s,2);
        memcpy(&destport,s+2,2);
        char buf[256];
        strcpy(buf, int_ntoa(a_packet->ip_src));
        sprintf(buf + strlen(buf), ":%u",srcport);
        strcat(buf, " -> ");
        strcat(buf, int_ntoa(a_packet->ip_dst));
        sprintf(buf + strlen(buf), ":%u",destport);
        strcat(buf, "   --UDP");
        puts(buf);
    }

}
void callback_withx(struct ip* a_packet, int len)
{
    if(a_packet->ip_p==6)
    {
        char s[4];
        s[0]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[1];
        s[1]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[0];
        s[2]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[3];
        s[3]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[2];
        uint16_t srcport,destport;
        memcpy(&srcport,s,2);
        memcpy(&destport,s+2,2);
        char buf[256];
        strcpy(buf, int_ntoa(a_packet->ip_src));
        sprintf(buf + strlen(buf), ":%u",srcport);
        strcat(buf, " -> ");
        strcat(buf, int_ntoa(a_packet->ip_dst));
        sprintf(buf + strlen(buf), ":%u",destport);
        strcat(buf, "   --TCP");


        alldata[rank%10000].buf=(char*)malloc(sizeof(char)*100);
        alldata[rank%10000].data=(char*)malloc(sizeof(char)*nids_last_pcap_header->len);
        memset(alldata[rank%10000].buf,0,sizeof(char)*100);
        memset(alldata[rank%10000].data,0,sizeof(char)*nids_last_pcap_header->len);
        memcpy(alldata[rank%10000].buf,buf,strlen(buf)+1);
        memcpy(alldata[rank%10000].data,nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER), nids_last_pcap_header->len-sizeof(struct _MAC_FRAME_HEADER));
        alldata[rank%10000].data_len=nids_last_pcap_header->len-sizeof(struct _MAC_FRAME_HEADER);
        rank++;
    }
    if(a_packet->ip_p==17)
    {
        char s[4];
        s[0]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[1];
        s[1]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[0];
        s[2]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[3];
        s[3]=(nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER)+sizeof(struct ip))[2];
        uint16_t srcport,destport;
        memcpy(&srcport,s,2);
        memcpy(&destport,s+2,2);
        char buf[256];
        strcpy(buf, int_ntoa(a_packet->ip_src));
        sprintf(buf + strlen(buf), ":%u",srcport);
        strcat(buf, " -> ");
        strcat(buf, int_ntoa(a_packet->ip_dst));
        sprintf(buf + strlen(buf), ":%u",destport);
        strcat(buf, "   --UDP");


        alldata[rank%10000].buf=(char*)malloc(sizeof(char)*100);
        alldata[rank%10000].data=(char*)malloc(sizeof(char)*nids_last_pcap_header->len);
        memset(alldata[rank%10000].buf,0,sizeof(char)*100);
        memset(alldata[rank%10000].data,0,sizeof(char)*nids_last_pcap_header->len);
        memcpy(alldata[rank%10000].buf,buf,strlen(buf)+1);
        memcpy(alldata[rank%10000].data,nids_last_pcap_data+sizeof(struct _MAC_FRAME_HEADER), nids_last_pcap_header->len-sizeof(struct _MAC_FRAME_HEADER));
        alldata[rank%10000].data_len=nids_last_pcap_header->len-sizeof(struct _MAC_FRAME_HEADER);
        rank++;
    }


}
void sum_as()
{
    flag=1;
    pthread_join(tid,NULL);
    printf("\n(hello)\n");

    struct pcap_stat* sta;

    // struct pcap *p= nids_params.pcap_desc;
	// pcap_stats(p,&sta);
    // double rate=1.0*(sta.ps_recv)/(sta.ps_drop+sta.ps_recv)*100;
    // printf("%d packets captured\n%d packets received by filter\nthe loss rate is %.2lf%%\n",sta.ps_recv,sta.ps_drop+sta.ps_recv,rate);

    sta=(struct pcap_stat *)malloc(sizeof(struct pcap_stat));
    pcap_stats(nids_params.pcap_desc,sta);
	double rate=1.0*(sta->ps_recv)/(sta->ps_drop+sta->ps_recv)*100;
    printf("%d packets captured\n%d packets received by filter\nthe loss rate is %.2lf%%\n",sta->ps_recv,sta->ps_drop+sta->ps_recv,rate);
}
int main(int argc, char* argv[])
{
    i=0;flag=0;
    signal (SIGINT, sum_as);
    sent=0;
    acc=0;
    rate=0;
    rank=0;
    pthread_create(&tid,NULL,print,NULL);
    alldata=(datas*)malloc(sizeof(datas)*10000);
    struct nids_chksum_ctl temp;
    temp.action = 1;
    temp.netaddr = 0;
    temp.mask = 0;

   // nids_params.device="enp12s0";
    nids_register_chksum_ctl(&temp, 1);
    if (!nids_init())
    {
        fprintf(stderr, "%s\n", nids_errbuf);
        exit(1);
    }
    if (argc != 1)
    {
        if (strstr(argv[1], "x"))
        {
            nids_register_ip(callback_withx);
        }
    }
    else
    {
        nids_register_ip(callback_withx);
    }

    nids_run();
}


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"
#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
char Way[10];char *n1,*n2;int n;
void addres(struct tuple4 addr)//将tuple4转换为ip字符串输出
{
    static char buf[256];
    printf("\n");
    strcpy (buf, int_ntoa (addr.saddr));
    sprintf (buf + strlen (buf), ":%i", addr.source);
    strcat (buf, " -> ");
    strcat (buf, int_ntoa (addr.daddr));
    sprintf (buf + strlen (buf), ":%i", addr.dest);
    puts(buf);
}

char* output_http(char *s,char *b)	//在s中查找b的位置，找到后输出该行（以'\r'为结束标志）
{
    char x[1024];
    n1=strstr(s,b);
    if(n1!=NULL)
    {
        n2=strstr(n1,"\r");
        strncpy(x,n1,(int)n2-(int)n1);
    }
	x[(int)n2-(int)n1]=0;
	n=strlen(s);
	n1=NULL;n2=NULL;
    if(x!=NULL) return x;
    else return NULL;
}
void http_callback(struct tcp_stream *http_connection, void **arg)
{
    char buf[1024];
    char *s;
    addres (http_connection->addr);	//输出来源和目标的ip，端口
	
	//tcp连接的不同状态
    if (http_connection->nids_state == NIDS_JUST_EST)
    {
        return;
    }
    if (http_connection->nids_state == NIDS_CLOSE)
    {
        return;
    }
    if (http_connection->nids_state == NIDS_RESET)
    {
        return;
    }


    if(http_connection->nids_state == NIDS_DATA)	//新数据到达时将其输出
    {
        if (http_connection->client.count_new)	//有新数据到达
            s = http_connection->client.data;
        else
            s = http_connection->server.data; 

		//输出http的相关数据
        write(2,output_http(s,"GET"),n);
        write(2,output_http(s,"PUT"),n);
        write(2,output_http(s,"HEAD"),n);
        write(2,output_http(s,"POST"),n);
        write(2,output_http(s,"TRACE"),n);
        write(2,output_http(s,"PATCH"),n);
        write(2,output_http(s,"DELETE"),n);
        write(2,output_http(s,"CONNECT"),n);
        write(2,output_http(s,"OPTIONS"),n);
        write(2,output_http(s,"Host"),n);
        write(2,output_http(s,"Connection"),n);
        write(2,output_http(s,"User-Agent"),n);
        write(2,output_http(s,"Accept"),n);
        write(2,output_http(s,"Referer"),n);
        write(2,output_http(s,"Encodeing"),n);
        write(2,output_http(s,"Accept-Language"),n);
        write(2,output_http(s,"If-Modified-Since"),n);
		
        return;
    }
    return;
}
int main()
{
    struct nids_chksum_ctl temp;
    temp.action=1;
    temp.netaddr=0;
    temp.mask=0;
    //nids_params.device="enp12s0";
	//nids_params.filename="xy.pcap";
    nids_register_chksum_ctl(&temp,1);	//关闭校验和
    if (!nids_init ())
    {
        fprintf(stderr,"%s\n",nids_errbuf);
        exit(1);
    }
    nids_register_tcp (http_callback);
    nids_run ();

}

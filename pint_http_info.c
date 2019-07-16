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
void addres(struct tuple4 addr)
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

char* output_http(char *s,char *b)
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
    // puts(s);
}
void http_callback(struct tcp_stream *http_connection, void **arg)
{
    char buf[1024];
    char *s;
    addres (http_connection->addr);
    if (http_connection->nids_state == NIDS_JUST_EST)
    {
        // connection described by http_connection is established
        // here we decide, if we wish to follow this stream
        // sample condition: if (http_connection->addr.dest!=23) return;
        // in this simple app we follow each stream, so..
        http_connection->client.collect++; // we want data received by a client
        http_connection->server.collect++; // and by a server, too
        http_connection->server.collect_urg++; // we want urgent data received by a
        // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
        http_connection->client.collect_urg++; // if we don't increase this value,
        // we won't be notified of urgent data
        // arrival
#endif
        // fprintf (stderr, "%s established\n", buf);
        return;
    }
    if (http_connection->nids_state == NIDS_CLOSE)
    {
        // connection has been closed normally
        //fprintf (stderr, "%s closing\n", buf);
        return;
    }
    if (http_connection->nids_state == NIDS_RESET)
    {
        // connection has been closed by RST
        // fprintf (stderr, "%s reset\n", buf);
        return;
    }

    if(http_connection->nids_state == NIDS_DATA)
    {

        if (http_connection->server.count_new_urg)
        {
            buf[strlen(buf)+1]=0;
            if(strstr(http_connection->server.data,"Host")!=NULL)
                buf[strlen(buf)]=http_connection->server.urgdata;
            write(1,buf,strlen(buf));
            return;
        }
        if (http_connection->client.count_new)
        {
            // new data for client
            s = http_connection->client.data; // from now on, we will deal with hlf var,
            // which will point to client side of conn
            puts("(<-)"); // symbolic direction of data
        }
        else
        {
            s = http_connection->server.data; // analogical
            puts("(->)");
        }
        //puts(buf); // we print the connection parameters
        // (saddr, daddr, sport, dport) accompanied
        // by data flow direction (-> or <-)

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
        write(2,output_http(s,"Referer"),n); // we print the newly arrived dataoutput_http(s,"GET");
        write(2,output_http(s,"Encodeing"),n);
        write(2,output_http(s,"Accept-Language"),n);
        write(2,output_http(s,"If-Modified-Since"),n);
        return;
    }
    return;
}
int main()
{
    //application private processing, not related to libnids
    //optional modification of libnids parameters
    // not reached in normal situation
    struct nids_chksum_ctl temp;
    temp.action=1;
    temp.netaddr=0;
    temp.mask=0;
    //nids_params.device="enp12s0";
//nids_params.filename="xy.pcap";
    nids_register_chksum_ctl(&temp,1);
    if (!nids_init ())
    {
        fprintf(stderr,"%s\n",nids_errbuf);
        exit(1);
    }
    nids_register_tcp (http_callback);
    nids_run ();

}

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
char Way[10];char *n1,*n2;int n;
static uint32_t myip;
static libnet_ptag_t tcp_tag = LIBNET_PTAG_INITIALIZER,
    ip_tag = LIBNET_PTAG_INITIALIZER;
static libnet_t *l = 0;
int raw_init_1()
{
    char errbuf[1024];
    l = libnet_init(LIBNET_RAW4,	/* injection type */
		    "enp12s0",	/* network interface */
		    errbuf);	/* error buffer */

    if (!l) {
	printf("%s\n", errbuf);
	return 0;
    } else
	return 1;
}

void nids_killtcp_seq_1(struct tcp_stream *a_tcp, int seqoff)
{
    if (!l)
	return;
    tcp_tag = libnet_build_tcp(a_tcp->addr.source, a_tcp->addr.dest,
	a_tcp->client.first_data_seq + 
		a_tcp->server.count + a_tcp->server.urg_count +
		(seqoff?(a_tcp->server.window/2):0), 
	0, 0x4, 32000, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp_tag);
    ip_tag =
	libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, 0, 12345, 0, 64,
			  IPPROTO_TCP, 0, a_tcp->addr.saddr,
			  a_tcp->addr.daddr, 0, 0, l, ip_tag);
    libnet_write(l);
    tcp_tag = libnet_build_tcp(a_tcp->addr.dest, a_tcp->addr.source,
        a_tcp->server.first_data_seq +
                a_tcp->client.count + a_tcp->client.urg_count +
                (seqoff?(a_tcp->client.window/2):0),
0, 0x4, 32000, 0,
			       0, LIBNET_TCP_H, NULL, 0, l, tcp_tag);
    ip_tag =
	libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, 0, 12345, 0, 64,
			  IPPROTO_TCP, 0, a_tcp->addr.daddr,
			  a_tcp->addr.saddr, 0, 0, l, ip_tag);
    libnet_write(l);
}
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
unsigned int ip_addr(const char *ip)
{
    int a, b, c, d;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4)
    {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
 
    return 0;
}
void http_callback(struct tcp_stream *http_connection, void **arg)
{
    char buf[1024];
    char *s;
    if (http_connection->nids_state == NIDS_JUST_EST)
    {
        
        if(http_connection->addr.saddr==myip)
		if (http_connection->addr.dest==443||http_connection->addr.dest==80) 
		{
            addres (http_connection->addr);
            nids_killtcp_seq_1(http_connection, 0);
            nids_killtcp_seq_1(http_connection, 1);
        }
    }

	return;
}
int main()
{
    struct nids_chksum_ctl temp;
    temp.action=1;
    temp.netaddr=0;
    temp.mask=0;
    nids_register_chksum_ctl(&temp,1);
    u_int myip=htonl(ip_addr("10.245.143.30"));

    nids_params.device="enp12s0";
    raw_init_1();
	//nids_params.filename="xy.pcap";

    if (!nids_init ())
    {
        fprintf(stderr,"%s\n",nids_errbuf);
        exit(1);
    }
    nids_register_tcp (http_callback);
    nids_run ();

}

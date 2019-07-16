#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include "nids.h"
#define MAX 99999
#define int_ntoa(x)	 inet_ntoa(*((struct in_addr *)&x))
FILE *fp;char *filepath="a.pcap";int fd;int times,flag,buf_len;
u_char *buf,*oragin;
struct pcap_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};
struct pcap_sf_pkthdr {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
};
void Writepcapheader(){
    fp = fopen(filepath, "wb");
    struct pcap_file_header head;
    head.magic=0xa1b2c3d4;//magic number
    head.version_major = 2;//version major
    head.version_minor = 4;//version minor
    head.thiszone=0;//this zone
    head.sigfigs=0; //sigfigs
    head.snaplen=65535;//snaplen
    head.linktype=1; //data link type
    fd = open(filepath,O_CREAT|O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR);
    int left = sizeof(head),ret;
    char * ptr = &head;
    while(left>0){
        ret = write(fd,ptr,left);
        left -=ret;
        ptr += ret;
    }
    fsync(fd);
}

void writebuf2pcap(u_char *t,int left){
    int ret;
    u_char *s=t;
    // left = strlen(buf);
    while(left >0){
        ret = write(fd,s,left);
        s += ret;
        left -= ret;
        fsync(fd);
    }
    memset(oragin,0,sizeof(oragin));
    buf=oragin;
    buf_len=0;
    fsync(fd);
}
int writePcaptobuf(){
    int i;
    struct pcap_sf_pkthdr h;
    int len=(*nids_last_pcap_header).caplen;

    if(len>65535){
        len = 65535;
    }
    int left = sizeof(h),ret;
    h.ts.tv_sec = (uint32_t)(*nids_last_pcap_header).ts.tv_sec;
    h.ts.tv_usec = (uint32_t)(*nids_last_pcap_header).ts.tv_usec;

    h.caplen = (*nids_last_pcap_header).caplen;
    h.len = (*nids_last_pcap_header).len;

    char * ptr = &h;

    if(buf_len+len>=MAX){
        writebuf2pcap(oragin,buf_len);
    }
    // write(fd,ptr,left);
    // write(fd,nids_last_pcap_data,len);
    for(i=0;i<left;i++)
    {
        buf[0]=ptr[i];
        buf++;
        buf_len++;
    }
    for(i=0;i<len;i++)
    {
        buf[0]=nids_last_pcap_data[i];
        buf++;
        buf_len++;
    }
    fsync(fd);
    return 0;
}

void ip_func(struct ip *qitem){
    if(qitem->ip_p!=6) return;
    times++;
    writePcaptobuf();
   // printf("%d,%d,%d,%d,\n",sizeof(struct pcap_sf_pkthdr),strlen(nids_last_pcap_data),strlen(buf),sizeof(buf));
    //puts(nids_last_pcap_data);
    if(times>=1000){
        writebuf2pcap(oragin,buf_len);
        fclose(fp);
        exit(0);
    }
} 
int main(){
    buf=(u_char*)malloc(sizeof(u_char)*MAX);
    oragin=buf;buf_len=0;
    memset(oragin,0,sizeof(oragin));
    times=0;buf_len=0;
    struct nids_chksum_ctl temp;
    temp.action=1;
    temp.netaddr=0;
    temp.mask=0;
    //nids_params.device="enp12s0";
    nids_register_chksum_ctl(&temp,1);
    Writepcapheader();
    if (!nids_init ())
    {
        fprintf(stderr,"%s\n",nids_errbuf);
        exit(1);
    }
    nids_register_ip(ip_func);
    nids_run ();
}

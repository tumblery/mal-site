#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdlib.h> 
#include <string.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libipq/libipq.h>

#define PCAP_CNT_MAX 10
#define PCAP_SNAPSHOT 1024
#define PCAP_TIMEOUT 100
typedef enum {false, true} bool;     

void packet_deny(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
bool check_site(char* site);
void wirteLog(FILE* fp,char* site);


int main(int argc, char* argv[]){
	 char *dev;
         char errbuf[PCAP_ERRBUF_SIZE];
         bpf_u_int32 net;
         bpf_u_int32 netmask;
         struct in_addr net_addr, mask_addr;
         pcap_t *pd;
      
         if(!(dev = pcap_lookupdev(errbuf))) {
                  perror(errbuf);
            }
        
         if(pcap_lookupnet(dev, &net, &netmask, errbuf) < 0) {
                  perror(errbuf);
            }
        
         net_addr.s_addr = net;
         mask_addr.s_addr = netmask;
        
         printf("Device : %s\n", dev);
         printf("Net Address : %s\n", inet_ntoa(net_addr));
         printf("Netmask : %s\n", inet_ntoa(mask_addr));
        
         pd = pcap_open_live(dev, PCAP_SNAPSHOT, 1, PCAP_TIMEOUT, errbuf); 
        
         pcap_loop(pd, -1, packet_deny, 0); 
                
         return 1;
 }
bool check_site(char* site){
	FILE *fp;
	char* URL;
	fp = fopen("mal_site.txt","r");
	while(!feof(fp)){
		fscanf(fp,"%s",URL);
		if(!strcmp(URL,site)){
			return true;
		}
	}
	return false;
		
}
void writeLog(FILE* fp,char* site){
	fprintf(fp,"Denied to %s",site);
	}
void packet_deny(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
 {
      //when I wrote this, I want to express the number of packet. but I forgot.
      struct ip *iph;
      struct ether_header *ep;
      struct tcphdr *tcph;
      unsigned short e_type;
      char* site;
      char *hoffset, *Eoffset;
      const u_char *tmp;
      int len = h->len;
      int chcnt = 0;
      ep = (struct ether_header *)p;
      e_type = ntohs(ep->ether_type);    
                     
      
      if( e_type ==  ETHERTYPE_IP ){
	p += sizeof(struct ether_header);
        iph = (struct ip *) p;
       	tcph = (struct tcp *)(p + iph->ip_hl * 4);
	if(ntohs(tcph->dest) == 80 || ntohs(tcph->dest) == 433){//if packet is http
		tmp = (h + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
		hoffset = strstr((char*)tmp,"Host: ");
		if(hoffset != NULL){
			Eoffset = strstr((char*)hoffset,"\r\n");
			site = (char *)malloc(Eoffset - hoffset	- 5);
			strncpy(site,hoffset+6,Eoffset-hoffset-6);
			site[Eoffset - hoffset -5 -1] ="\0";
			if(check_site(site)){
				writeLog(cp,site);
                              }
		}
        }                 
         return ;
      
}

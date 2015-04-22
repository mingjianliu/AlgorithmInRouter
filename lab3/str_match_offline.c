/* 
 * EL7373 (Spring 2014) High Performance Switches and Routers
 *
 * Lab 1 - IP Lookup Algorithms
 *
 * ip_lookup_offline.c
 *
 * TA: Kuan-yin Chen (cgi0911@gmail.com)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#define DEBUG

#define ETHER_ADDR_LEN  6   /* MAC address is 6 bytes */
#define SIZE_ETHERNET 14    /* Ethernet header is 14 bytes */

/* struct for Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* struct for IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr      ip_src;
    struct in_addr      ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

const struct sniff_ethernet     *eth_hdr;
const struct sniff_ip           *ip_hdr;
char                            keyword[1000];              /* keyword buffer */
unsigned long int               pkt_cnt = 0;                /* total processed packet # */
unsigned long int               match_pkt_cnt = 0;




int naive_str_match(const char   *text,
                    const int    text_len )
{
    int ret = -1;       // ret = -1 means no match
    int kwd_len = strlen(keyword);

    for(int i = 0 ; i <= (text_len - kwd_len) ; i++){
        int matched = 1;

        for(int j=0 ; j < kwd_len ; j++){
            if( keyword[j] != text[i+j]) {
                matched = 0;
                break;
            }
        }

        if( matched == 1 ){
            ret = i;
            break;
        }
    }

    return ret;
}


/* called upon every packet arrival */
void my_callback(u_char *user, 
                 const struct pcap_pkthdr *pkthdr, 
                 const u_char *pktdata)
{
    static char         ip_src_str[20];             // String expression of source IP
    static char         ip_dst_str[20];             // String expression of dest IP
    static u_char       protocol;                   // Protocol number (1 byte)
    static int          location;                   // Store the location of first occurrence of keyword

    pkt_cnt ++;
    ip_hdr =    (struct sniff_ip *)(pktdata + SIZE_ETHERNET);

    strcpy(ip_src_str, inet_ntoa(ip_hdr->ip_src));  // Translate uint_32 to IP string expression
    strcpy(ip_dst_str, inet_ntoa(ip_hdr->ip_dst));  // Translate uint_32 to IP string expression
    protocol =  (ip_hdr->ip_p);                     // Get protocol number

    location = naive_str_match((char *)pktdata, pkthdr->len);

    if( location != -1 ){
        match_pkt_cnt ++;
        printf("Packet #%-10ld - src ip = %-20s    dst ip = %-20s    port = %-5d    keyword found at text[%d]\n",    \
                pkt_cnt, ip_src_str, ip_dst_str, protocol, location);
    }
}




/* main function */
int main(int argc, char **argv)
{
    int     ret;                        /* return code */
    char    errbuf[PCAP_ERRBUF_SIZE];   /* Error message buffer */    
    pcap_t  *descr;                     /* pcap descriptor */

    /* argc < 3 means no filename is input from the command line. */
    if( argc < 3 ){
        printf("You forgot to enter trace file and keyword file name!\n");
        exit(1);
    }

    /* read keyword from keyword file. */
    FILE * kwd_fp = fopen(argv[2], "r");
    fgets(keyword, 1000, kwd_fp);
    keyword[strlen(keyword)-1] = '\0';  // Remove the '\n' at end of string
    printf("Using keyword: %s\n", keyword);


    /* open file for sniffing */
    descr = pcap_open_offline(argv[1], errbuf);
    
    /* error check - halt if cannot open file. */
    if(descr == NULL)
    {
        printf("pcap_open_offline(): %s\n",errbuf);
        exit(1);
    }


    /* pcap looping! */
    pcap_loop(descr, -1, my_callback, NULL);

    /* print results */
    printf("Total packets processed = %ld\n", pkt_cnt);
    printf("Total matching packets = %ld\n", match_pkt_cnt);

    return 0;       
}

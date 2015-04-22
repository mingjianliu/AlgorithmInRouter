#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <math.h>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <map>
#include <iostream>
#include <string>
#include <pcap.h>
#include <csignal>
#include <unistd.h>

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
unsigned long int               pkt_cnt = 0;    /* total processed packet # */
std::map<int, int>              counters;       /* use a STL map to keep counters of each port */
pcap_t                          *descr;

/* Structure of binary trie node */
struct BtNode{
    BtNode  *left;      /* for 0 */
    BtNode  *right;     /* for 1 */
    uint32_t     ipaddr;
    int     equalto,bigthan,redun;
};

typedef struct
{
     uint32_t     ipaddr;
     int          prelen,portnum,bigthan,equalto;
}    ipaddrpoints;

bool operator<(const ipaddrpoints &a, const ipaddrpoints &b){
  if(a.ipaddr!=b.ipaddr)   return a.ipaddr<b.ipaddr;
  else                     return a.prelen<b.prelen;
}

struct BtNode                   *bt_root;       /* pointer to the root node of the binary tree */
using namespace std;
vector<ipaddrpoints> points;         /* list all the points*/
int countnum=0;                      /* Count all the points */






/* Initialize binary trie node */
BtNode* init_btnode(){
    BtNode *ret = (BtNode *)malloc(sizeof(BtNode));
    ret->left = NULL;
    ret->right = NULL;
    ret->ipaddr = 0;
    ret->bigthan = -1;
    ret->equalto = -1;
    return ret;
}

/* Clean up binary trie */
void free_bt(BtNode *root){

    if(root->left != NULL){
        free_bt(root->left);
    }
    if(root->right != NULL){
        free_bt(root->right);
    }

    free(root);
}

void fillinpoint(ipaddrpoints &temp, uint32_t prefix, int prelen, int portnum)
{
          
     temp.ipaddr=prefix;
     temp.prelen=prelen; 
     temp.portnum=portnum;
}

/* Parse the routing table file (in_fn is the variable for its file name) */
void parse_rules(char *in_fn){
    FILE        *fp;
    char        pre_exp[100];      /* prefix expression, e.g. 1.2.3.0/24 */
    int         portnum;    
    in_addr     prefix_in_addr;
    uint32_t    prefix_l,prefix_h;
    int         prelen;

    fp = fopen(in_fn, "r");
    if( fp == NULL ){
        fprintf(stderr, "Cannot read routing table file %s.\n", in_fn);
        exit(1);
    }    
    ipaddrpoints temp;    

    while( fscanf(fp, "%s %d\n", pre_exp, &portnum) != EOF ){
        char *slash_ptr = strchr(pre_exp, '/');         /* Find '/' location in pre_exp */
        if(slash_ptr != NULL){
            char    dot_notation[100];
            char    prelen_str[10];
            strncpy(dot_notation, pre_exp, slash_ptr-pre_exp);
            dot_notation[slash_ptr-pre_exp] = '\0';     /* Don't forget to add a '\0' to signal end of string! */
            strncpy(prelen_str, slash_ptr+1, 3 );
            prelen_str[3] = '\0';                       /* Don't forget to add a '\0' to signal end of string! */
            prelen = atoi(prelen_str);

            inet_aton(dot_notation, &prefix_in_addr);   /* Convert string to in_addr */
            prefix_l = htonl(prefix_in_addr.s_addr);      /* get the 32-bit integer in in_addr. htonl to correct the endian problem */
            long int mask=pow(2,(32-prelen))-1;                /* get the second point under prefix with all ones in other bits*/
            prefix_h=prefix_l+mask;
            /*insert two points*/
            countnum++;
            fillinpoint(temp,prefix_l,prelen,portnum);
            points.push_back(temp);
            countnum++;              
            fillinpoint(temp,prefix_h,prelen,portnum);
            points.push_back(temp);
             
        }
        else{
            inet_aton(pre_exp, &prefix_in_addr);
            prefix_l = htonl(prefix_in_addr.s_addr);      /* get the 32-bit integer in in_addr. htonl to correct the endian problem */
            prelen = 32;
            /*insert one points*/
            countnum++;
            fillinpoint(temp,prefix_l,prelen,portnum);
            points.push_back(temp);                       
        }
    }
}

void show(const ipaddrpoints & rr)
{

    std::cout<<rr.ipaddr<<"\t"<<rr.portnum<<"\t"<<rr.bigthan<<"\t"<<rr.equalto<<"\t"<<std::endl;
}

int comparePrefixLen(int number)
{
     int port=0;
     if(points[number].ipaddr==points[number+1].ipaddr)
          port=comparePrefixLen(number+1);
     else   
          port=points[number].portnum;          
     return port;
}

/* set the port number when the IP for lookup satisfy '='*/
void setequalport(int countnumb)
{	
     int number=0;
     for(;number<countnumb;number++)
     {
         int port;                    
         if (number!=countnumb-1){
            port=comparePrefixLen(number);
            points[number].equalto=port;
            }
         else
            points[number].equalto=points[number].portnum; 
     }
     return;
}

int findportnumber(int const number)
{
     int temp=number-1;
     int port=0;
     if (temp==-1)      printf("Error when finding bigger than port number!!\n");
     for(;temp>-1;temp--)
     {
         long int mask=pow(2,(32-points[temp].prelen));
         if(points[temp].ipaddr&0x00000001)                             
                 continue;
         if(points[number].ipaddr>=(points[temp].ipaddr+mask-1))     
                 continue;    
         return port=points[temp].portnum;                                                                                  
     }  
     return port;    /*for the last ip address which have no bigger than port number*/
}

/* set the port number when the IP for lookup satisfy '>'*/
void setbiggerport(int const countnumb)
{
     int port;
     for(int number=0;number<countnumb;number++)
     {
         if(points[number].prelen==32)                    //when the prefix length equals to 32, use the previous bigthan
             points[number].bigthan=points[number-1].bigthan;             
         else if(points[number].ipaddr&0x00000001)                  
         //when the point is the higher point under one prefix's segment, i.e. ends with '1', search the lowwer point that does not coressponding to it.      
             points[number].bigthan=findportnumber(number);
         else    
             points[number].bigthan=points[number].equalto;
             
     }
}

int halfAndRound(int const number)
{
     int temp=(number>>1)+(number&1);
     return temp;
}

void insertpoints(BtNode *root,int total,int testnum)
{
        BtNode *curr_node=root;
        int temp=total; 
        int temp2=halfAndRound(temp);
        if(temp>>1)         
        {    
           curr_node->left=init_btnode();
           curr_node->right=init_btnode();
            insertpoints(curr_node->left,temp2,testnum);
            insertpoints(curr_node->right,temp2,testnum+temp2);        
            int countt=testnum+temp2;
            if(countt>countnum)
            {
            curr_node->ipaddr=0;
            curr_node->redun=1;
            return;
            }
            else
            {          
            curr_node->redun=0;
            curr_node->ipaddr=points[countt-1].ipaddr;
            curr_node->equalto=points[countt-1].equalto;
            curr_node->bigthan=points[countt-1].bigthan;
            }
        }
        return;
}       

/* Look up an IP address (represented in a uint32_t) */
int lookup_ip(BtNode *root, uint32_t ip){
    uint32_t    temp_ip = ip;
    BtNode      *curr_node = root;
    int         curr_verdict=0;
    int         number=countnum;
    do
    {
         number=halfAndRound(number);
         if(curr_node->redun==1)
         {
            curr_node=curr_node->left;
            continue;         
         }
         else if(temp_ip==curr_node->ipaddr) 
         {
            curr_verdict=curr_node->equalto;
            return curr_verdict;
         }
         else if(temp_ip>curr_node->ipaddr) 
         {
            curr_verdict=curr_node->bigthan;
            curr_node=curr_node->right;
            continue;
         }
         else if(temp_ip<curr_node->ipaddr) 
         {
            curr_node=curr_node->left;
            continue;
         }

    }while(number>>1);

return curr_verdict;        
}

/* called upon every packet arrival */
void my_callback(u_char *user, 
                 const struct pcap_pkthdr *pkthdr, 
                 const u_char *pktdata)
{
    static uint32_t     dst_addr;
    static int          verdict;

    ip_hdr =    (struct sniff_ip *)(pktdata + SIZE_ETHERNET);

    pkt_cnt ++;

    dst_addr = htonl(ip_hdr->ip_dst.s_addr);    /* IMPORTANT! htonl to reverse the endian */

    verdict = lookup_ip(bt_root, dst_addr);

    if( counters.find(verdict) == counters.end() ){
        counters[verdict] = 1;
    }
    else{
        counters[verdict] ++;
    }

#ifdef DEBUG
    fprintf(stderr, "Packet #%-10ld - dest ip %s  port=%d\n", pkt_cnt, inet_ntoa(ip_hdr->ip_dst), verdict);
#endif
}

/* Alarm handler */
void alarm_handler(int sig){
    pcap_breakloop(descr);
}        



int main(int argc, char **argv)
{
    //int     ret;        /* return code */
    char    errbuf[PCAP_ERRBUF_SIZE];   /* Error message buffer */
   
    /* argc < 3 means no filename is input from the command line. */
    if( argc < 3 ){
        printf("You forgot to enter dump file and routing table file name!\n");
        exit(1);
    }
    countnum=0;
    parse_rules(argv[2]);
    sort(points.begin(),points.end());          
    //insert port number for '>' and'=' in each point
    setequalport(countnum);
    setbiggerport(countnum);
    
    //build binary trie 
    bt_root = init_btnode();         
    //insert all points into the binary trie
    insertpoints(bt_root,countnum,0);
    
    /* open file for sniffing */
    descr = pcap_open_live(argv[1], BUFSIZ, 0, 2000, errbuf);
    
    /* error check - halt if cannot open file. */
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    /* Set up linux alarm to 20 seconds*/
    alarm(20);
    signal(SIGALRM, alarm_handler);

    /* pcap looping! */
    pcap_loop(descr, -1, my_callback, NULL);

    /* print results */
    for( std::map<int,int>::iterator cit=counters.begin() ; cit != counters.end() ; ++cit){
        printf("Port #%-5d: %-10d packets\n", cit->first, cit->second);
    }

    /* finish up */
    fprintf(stderr, "Done with packet processing! Looked up %ld packets.\n", pkt_cnt);        
    free_bt(bt_root);

    return 0;
}


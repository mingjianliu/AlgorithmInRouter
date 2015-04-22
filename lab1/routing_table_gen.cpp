#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <iostream>
#include <sstream>

#define IP_LEN 32

int main(int argc, char *argv[]){
    int         n_rules;    // # of rules to generate
    int         n_ports;    // Possible port number
    int         prelen;     // Prefix length
    int         portnum;    // Output port number
    uint32_t    ip_int;     // IP in 32-bit integer
    struct in_addr ip_addr; // in_addr struct for IP
    std::map<std::string, int>              rtable;
                            // Use an STL map to store generated rules, also check duplicated rules
    std::map<std::string, int>::iterator    rit;
                            // Iterator to rtable.
    int         isdup;      // Flag for checking whether current rule is a duplicate.

    /* Check # of arguments */
    if( argc != 3 ){
        fprintf(stderr, "Invalid arguments!\nUsage: ./routing_table_gen.out [n_rules] [n_ports]\n");
        exit(1);
    }

    /* Read in arguments */
    n_rules = atoi(argv[1]);
    n_ports = atoi(argv[2]);

    /* Random seeding */
    srand(time(NULL));

    /* Generate n_rules rules */
    for(int i=0 ; i<n_rules ; i++){
        do{
            isdup = 0;                                                      // Reset duplication flag

            prelen = int ((double)rand()/RAND_MAX * IP_LEN) + 1;            // Randomly generate a prefix length 1 - 32
            ip_int = 0;

            for(int j=0 ; j<prelen ; j++){
                int digit = ((double)rand()/RAND_MAX > 0.5 ? 1 : 0);        // Randomly generate a digit (1 or 0)
                ip_int = (ip_int << 1) + digit;                             // Append it to tail.
            }

            ip_int = ip_int << (IP_LEN - prelen);                           // Fill 0 at the tail of ip_dec.
            ip_addr.s_addr = htonl(ip_int);                                 // htonl to reverse byte order.

            std::stringstream pre_exp;                                      // Prefix expression
            pre_exp << inet_ntoa(ip_addr);
            if( prelen < 32 )   pre_exp << "/" << prelen;                   // Attach prefix length to string if < 32

            /* Check for duplication */
            if( rtable.find(pre_exp.str()) != rtable.end() ){
                isdup = 1;                                                  // the key is found in table. set flag to 1.
            }
            else{
                portnum = int ((double)rand()/RAND_MAX * n_ports) + 1;      // Randomly generate an output port #
                rtable[pre_exp.str()] = portnum;                            // Insert key to table, whose value is portnum
            }     
        } while(isdup);
    }

    /* Iterate over the rule_table and print the rules */
    for( rit=rtable.begin() ; rit!=rtable.end() ; ++rit){
        std::cout << rit->first << " " << rit->second << std::endl;
    }
}

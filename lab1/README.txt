
1. This reference code provides the following functionality:
   - Read packets from an offline packet trace (in this case, trace.dump)
   - Lookup each packet's IP in a routing table (in this case, routing_table.txt or routing_table2.txt)

2. To compile the ip-lookup-offline code, type in the command line:
   $ g++ ip_lookup_offline.c -o a.out -lpcap
   (Of course you can choose another output file name.)

3. To run ip-lookup-offline, type in the command line:
   $ ./a.out [file name of packet trace] [file name of routing table]
   For example,
   $ ./a.out trace.dump routing_table.txt

4. To compile the routing table generator code, type in the command line:
   $ g++ routing_table_gen.cpp -o b.out

5. To run routing table generator, type in the command line:
   $ ./b.out [# of rules to generator] [# of possible port numbers] > [file name of routing table]
   For example,
   $ ./b.out 100000 100 > routing_table.txt
   , which generates 100000 rules, with 100 possible port numbers (1-100), and write to routing_table.txt

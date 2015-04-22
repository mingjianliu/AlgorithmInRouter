1. For how to use pcap, please refer to Lab 1.


2. How to compile?

   g++ str_match_offline.c -o str_match.out -lpcap


3. How to run the reference code?

   ./str_match.out [pcap file name] [keyword file name]

   For example:
   ./str_match.out http-espn2012.pcap keyword.txt


4. How to verify your code?

   Try to use Wireshark to show the contents of the packets!


5. Note that keyword is case sensitive!


6. Only one keyword in the first line of keyword file.

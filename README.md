# Packet Sniffer
This application sniffs packets.

To compile this program, type:

    make

To run this program, compile it first, then type:

    ./ipk-sniffer {-i interface | --interface interface}{-p port}{-t | --tcp}{-u | --udp}{--arp}{--icmp}{-n number}
    
Where 
 * interface is name of an active interface  
   If {-i | --interface} parameter is missing, application only prints list of active interfaces
 * port is port that packets should be sniffed on  
   If {-p} parameter is missing, program will sniff on all ports
 * number is a number of packets that should be sniffed  
      If {-n} parameter is missing, program sniffs only 1 packet (-n 1 like)

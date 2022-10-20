// Name: Packet Sniffer
// Author: Hugo Hežel | xhezel00
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <time.h>

#define MAC_ADDRESS_LENGTH 6
#define IPV4_ADDRESS_LENGTH 4

#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

typedef struct ProgramParameters{
    char *interface;
    char *port;
    int tcp;
    int udp;
    int icmp;
    int arp;
    unsigned int n;
} ProgramParameters;

void print_help(){

    printf("This application sniffs packets.\n");
    printf("To compile this program, type:\n\n");
    printf("    make\n\n");
    printf("To run this program, compile it first, then type:\n\n");
    printf("    ./ipk-sniffer {-i interface | --interface interface}{-p port}{-t | --tcp}{-u | --udp}{--arp}{--icmp}{-n number}\n\n");
    printf("Where \n");
    printf("    - interface is name of an active interface\n");
    printf("      If {-i | --interface} parameter is missing, application only prints list of active interfaces\n");
    printf("    - port is port that packets should be sniffed on\n");
    printf("      If {-p} parameter is missing, program will sniff on all ports\n");
    printf("    - number is a number of packets that should be sniffed\n");
    printf("      If {-n} parameter is missing, program sniffs only 1 packet (-n 1 like)\n");

}

void set_default_program_parameters( ProgramParameters *program_parameters ){

    program_parameters->interface = NULL;
    program_parameters->port = NULL;
    program_parameters->tcp = 0;
    program_parameters->udp = 0;
    program_parameters->icmp = 0;
    program_parameters->arp = 0;
    program_parameters->n = 1;

}

void handle_arguments( int argc, char*argv[], ProgramParameters *program_parameters ){

    struct option long_options[] = {

        {"interface", optional_argument, NULL, 'i'},
        {"tcp", no_argument, NULL, 't'},
        {"udp", no_argument, NULL, 'u'},
        {"arp", no_argument, NULL, 'a'},
        {"icmp", no_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}

    };

    char opt;    

    while( ( opt = getopt_long(argc, argv, "i::p:tun:h" ,long_options, NULL) ) != -1 ){

        switch( opt ){

            case 'i':
                
                if( OPTIONAL_ARGUMENT_IS_PRESENT ){

                    program_parameters->interface = optarg;

                }else{

                    program_parameters->interface = NULL;

                }

                break;

            case 'p':

                program_parameters->port = optarg;
                break;

            case 't':
                
                program_parameters->tcp = 1;
                break;

            case 'u':

                program_parameters->udp = 1;
                break;

            case 'n':

                program_parameters->n = atoi( optarg );
                break;
            
            case 'a':
                program_parameters->arp = 1;
                break;
            
            case 'c':
                program_parameters->icmp = 1;
                break;

            case 'h':
                print_help();
                exit(1);

            default:
                fprintf(stderr, "Unknown program argument.\n");
                exit(1);
                break;

        }

    }

}

void print_active_interfaces( char *errbuf ){

    // Following ideas were used from this site:
    // http://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
    // Define neede variables for this function
    // Interfaces should contain all active interfaces
    // Temp is temporary variable for looping trough interfaces
    // Int i represents order of interface
    pcap_if_t *interfaces, *temp;
    int i;
    
    // Call and check return of pcap_findalldevs()
    if( pcap_findalldevs(&interfaces, errbuf) == 1 ){

        fprintf(stderr, "Error occurred when calling pcap_findalldevs().\n");
        exit(2);

    }

    // Loop through interfaces and print them
    for( temp = interfaces; temp; temp = temp->next ){

        printf("Interface %d: %s\n", i++, temp->name);

    }

}

pcap_t *session_setup( ProgramParameters *program_parameters, char *errbuf ){

    // Following ideas were use from this site:
    // https://www.tcpdump.org/pcap.html
    // Define the needed variables
    bpf_u_int32 mask;               // Our netmask
    bpf_u_int32 net;                // Our ip
    pcap_t *handle;                 // Session handle
    struct bpf_program fp;          // The compiled filter

    char *filter_exp = malloc( sizeof(char) * 1024 );  // The filter expression

    if( program_parameters->tcp == 1 ){

        if( program_parameters->port != NULL ){

            strcat(filter_exp, "(tcp and port ");
            strcat(filter_exp, program_parameters->port);
            strcat(filter_exp, ")");

        }else{

            strcat(filter_exp, "tcp");

        }

    }
    
    if( program_parameters->udp == 1 ){

        if( filter_exp[0] == '\0' ){

            if( program_parameters->port != NULL ){

                strcat(filter_exp, "(udp and port ");
                strcat(filter_exp, program_parameters->port);
                strcat(filter_exp, ")");

            }else{

                strcat(filter_exp, "udp");

            }

        }else{
            
            if( program_parameters->port != NULL ){

                strcat(filter_exp, " or (udp and port ");
                strcat(filter_exp, program_parameters->port);
                strcat(filter_exp, ")");

            }else{

                strcat(filter_exp, " or udp");

            }

        }

    }
    
    if( program_parameters->icmp == 1 ){
        
        if( filter_exp[0] == '\0' ){

            if( program_parameters->port != NULL ){

                strcat(filter_exp, "(icmp and port ");
                strcat(filter_exp, program_parameters->port);
                strcat(filter_exp, ") or (icmp6 and port ");
                strcat(filter_exp, program_parameters->port);
                strcat(filter_exp, ")");

            }else{

                strcat(filter_exp, "icmp or icmp6");

            }

        }else{
            
            if( program_parameters->port != NULL ){

                strcat(filter_exp, " or (icmp and port ");
                strcat(filter_exp, program_parameters->port);
                strcat(filter_exp, ") or (icmp6 and port ");
                strcat(filter_exp, program_parameters->port);
                strcat(filter_exp, ")");

            }else{

                strcat(filter_exp, " or icmp or icmp6");

            }

        }

    }
    
    if( program_parameters->arp == 1 ){

        if( filter_exp[0] == '\0' ){

            if( program_parameters->port != NULL ){

                strcat(filter_exp, "(arp and port ");
                strcat(filter_exp, program_parameters->port);
                strcat(filter_exp, ")");

            }else{

                strcat(filter_exp, "arp");

            }

        }else{
            
            if( program_parameters->port != NULL ){

                strcat(filter_exp, " or (arp and port ");
                strcat(filter_exp, program_parameters->port);
                strcat(filter_exp, ")");

            }else{

                strcat(filter_exp, " or arp");

            }

        }

    }

    // Find the properties for the interface
    if( pcap_lookupnet( program_parameters->interface, &net, &mask, errbuf ) == -1 ){

        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", program_parameters->interface, errbuf);
        exit(1);

    }

    // Open the session in promiscuous mode
    handle = pcap_open_live(program_parameters->interface, BUFSIZ, 1, 1000, errbuf);

    // Check
    if( handle == NULL ){

        fprintf(stderr, "Couldn't open device %s: %s\n", program_parameters->interface, errbuf);
        exit(1);

    }

    // Compile the filter
    if( pcap_compile( handle, &fp, filter_exp, 0, net ) == -1 ){

        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);

    }

    // Set the filter
    if( pcap_setfilter( handle, &fp ) == -1 ){

        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);

    }

    return handle;

}

void print_mac_address(u_char *address_ptr){

    for( int i = 0; i < MAC_ADDRESS_LENGTH; i++ ){
            
        // Start with ":" except the first char
        if( i != 0 ){

            printf(":");

        }

        // Print the char
        printf("%x", address_ptr[i]);

    }

}

void print_info_from_tcp( const u_char *tcp_message ){

    // Get a tcp header
    struct tcphdr *tcp_header = (struct tcphdr *)tcp_message;

    printf("src port: %hu\n", ntohs(tcp_header->source));
    printf("dst port: %hu\n", ntohs(tcp_header->dest));

}

void print_info_from_udp( const u_char *udp_message ){

    // Get a udp header
    struct udphdr *udp_header = (struct udphdr *)udp_message;

    printf("src port: %hu\n", ntohs(udp_header->source));
    printf("dst port: %hu\n", ntohs(udp_header->dest));

}

void print_info_from_ipv4( const u_char *ipv4_message ){

    // Get a ipv4 header
    struct ip *ipv4_header = (struct ip *)ipv4_message;
    
    printf("src IP: %s\n", inet_ntoa(ipv4_header->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ipv4_header->ip_dst));
    
    if( (unsigned char)ipv4_header->ip_p == 6 ){

        print_info_from_tcp( &ipv4_message[ sizeof(struct ip) ] );

    }else if( (unsigned char)ipv4_header->ip_p == 17 ){

        print_info_from_udp( &ipv4_message[ sizeof(struct ip) ] );

    }
    
}

void print_info_from_ipv6( const u_char *ipv6_message ){

    // Get a ipv6 header
    struct ipv6hdr *ipv6_header = (struct ipv6hdr *)ipv6_message;

    if( (unsigned char)ipv6_header->nexthdr == 6 ){

        print_info_from_tcp( &ipv6_message[ sizeof(struct ip) ] );

    }else if( (unsigned char)ipv6_header->nexthdr == 17 ){

        print_info_from_udp( &ipv6_message[ sizeof(struct ip) ] );

    }

}

void print_info_from_arp( const u_char *arp_message ){

    // Get a ARP header
    struct ether_arp *arp_header = (struct ether_arp *)arp_message;

    printf("src IP: ");

    for( int i = 0; i < 4; i++ ){
        if( i != 0 ){
            printf(".%u", arp_header->arp_spa[i]);
        }else{
            printf("%u", arp_header->arp_spa[i]);
        }
    }

    printf("\n");
    
    printf("dst IP: ");

    for( int i = 0; i < 4; i++ ){
        if( i != 0 ){
            printf(".%u", arp_header->arp_tpa[i]);
        }else{
            printf("%u", arp_header->arp_tpa[i]);
        }
    }

    printf("\n");

}

void print_packet_info( const u_char *packet, struct pcap_pkthdr *header ){

    // Following ideas were use from this site:
    // http://yuba.stanford.edu/~casado/pcap/section2.html
    // Get an ethernet header from packet
    struct ether_header *ethernet_header = (struct ether_header *) packet;

    // Get the timestamp
    // This code was use from this site:
    // https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
    struct tm *time = localtime(&header->ts.tv_sec);
    char buf[100];
    size_t len_time = strftime(buf, 99, "%FT%T%z", time);
    // move last 2 digits
    if (len_time > 1){
        char minute[] = {buf[len_time - 2], buf[len_time - 1], '\0'};
        sprintf(buf + len_time - 2, ":%s", minute);
    }

    // PRINT TIMESTAMP
    printf("timestamp: %s\n", buf);

    // PRINT SOURCE MAC ADDRESS
    printf("src MAC: ");
    print_mac_address( ethernet_header->ether_shost );
    printf("\n");

    // PRINT DESTINATION MAC ADDRESS
    printf("dst MAC: ");
    print_mac_address( ethernet_header->ether_dhost );
    printf("\n");

    // PRINT FRAME LENGTH
    printf("frame length: %d\n", header->len);

    unsigned short ethernet_type_int = ntohs( ethernet_header->ether_type );
    
    // If type is IPv4
    if( ethernet_type_int == ETHERTYPE_IP ){

        print_info_from_ipv4( &packet[ sizeof(struct ether_header) ] );
    
    // If type is IPv6
    }else if( ethernet_type_int == ETHERTYPE_IPV6 ){
        
        print_info_from_ipv6( &packet[ sizeof(struct ether_header) ] );

    // If type is ARP
    }else if( ethernet_type_int == ETHERTYPE_ARP ){

        print_info_from_arp( &packet[ sizeof(struct ether_header) ] );

    }

    printf("\n");

}

int main( int argc, char *argv[] ){

    // Define structure for program's parameters
    ProgramParameters program_parameters;

    // Define needed variables
    // Error string for pcap functions
    char errbuf[PCAP_ERRBUF_SIZE];
    // The actual packet
    const u_char *packet;
    // The header that pcap gives us
    struct pcap_pkthdr header;

    // Set the default values for program's parameters
    set_default_program_parameters( &program_parameters );

    // Process given arguments
    handle_arguments( argc, argv, &program_parameters );

    // Check if interpret argument has been given with value
    if( program_parameters.interface == NULL ){

        // Print all active interfaces
        print_active_interfaces( errbuf );

        // Exit application without error code
        exit(0);

    }

    // Set up the session and get the handle
    pcap_t *handle = session_setup( &program_parameters, errbuf);

    // While there are packets to be printed
    while( program_parameters.n > 0 ){

        // Grab a packet
        packet = pcap_next( handle, &header );

        // Temporary variable for storing characters of packet line
        // This array of characters will be printed after hex codes of packet line's characters
        char packet_line_tail[16];

        // j index represents index of current character according to packet line
        // It is used to know when exactly print parts of packet line
        int j = 0;

        // Print the packet's info
        print_packet_info( packet, &header );

        // For every character in packet
        for( int i = 0; i < header.len; i++ ){

            // Get the j index
            j = i % 16;

            // Check if new line should come
            if( j == 0 ){

                printf("0x%04x: ", i);

            }

            // Print hex code of packet's character
            printf("%02x ",packet[i]);

            // Store packet's character to array of characters
            if( isprint(packet[i]) ){

                packet_line_tail[j] = packet[i];

            }else{

                packet_line_tail[j] = '.';

            }

            // If this is last character of the packet line
            // Or if this is the last character of the packet
            if( j == 15 || i == header.len - 1 ){

                // Print the padding between hex codes and packet line's characters
                for( int x = j; x < 15; x++ ){

                    printf("   ");

                }

                // Print the packet line's characters with new line afterwards
                for( int z = 0; z <= j; z++ ){

                    printf("%c", packet_line_tail[z]);

                }

                // Print the new line after packet line's characters
                printf("\n");

                // Reset the j index
                j = 0;

            }

        }

        // Padding between packets
        printf("\n");

        // Decrease number of packets to be printed
        program_parameters.n -= 1;

    }

    // Close the session
    pcap_close( handle );
    
    // Close the program
    return 0;

}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include "sniffer_ioctl.h"

#include <linux/ip.h>
#include <linux/tcp.h>

#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>

static char * program_name;
static char * dev_file = "/dev/sniffer.dev";
char buf_i[100];
char buf_o[100];

    #define MY_USER_NIPQUAD(addr) \
            ((unsigned char *)&addr)[0], \
            ((unsigned char *)&addr)[1], \
            ((unsigned char *)&addr)[2], \
            ((unsigned char *)&addr)[3]

unsigned char buffer[2000];

void usage() 
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}

int print_packet(FILE * f, unsigned char * pkt, int len)
{
    struct iphdr * ip_header;
    struct tcphdr * tcp_header;
    int saddr, sport, daddr, dport;
    int i;
    ip_header = (struct iphdr *) pkt;
    tcp_header = (void *) ip_header + ip_header->ihl*4;
    saddr = ip_header->saddr;
    sport = tcp_header->source;
    daddr = ip_header->daddr;
    dport = tcp_header->dest;

    fprintf(f, "%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d", MY_USER_NIPQUAD(saddr),
                                                      ntohs(sport),
                                                      MY_USER_NIPQUAD(daddr),
                                                      ntohs(dport));
    
    for(i = 0; i < len; i++){
        if(i % 64 == 0) fprintf(f, "\n");
        fprintf(f, "%.2x ", pkt[i]);
    }

    fprintf(f, "\n");

    return 0;
}

int main(int argc, char **argv)
{
    int c;
    char *input_file, *output_file = NULL;
    program_name = argv[0];

    input_file= dev_file;

    while((c = getopt(argc, argv, "i:o:")) != -1) {
        switch (c) {
        case 'i':
            strcpy(buf_i, optarg);
            input_file = buf_i;
            break;
        case 'o':
            strcpy(buf_o, optarg);
            output_file = buf_o;
            break;
        default:
            usage();
        }
    }

    int fdin, err;
    FILE * fout;


    fdin = open(input_file, O_RDONLY);

    if(output_file == NULL){
        fout = stdout;
    } else{
        fout = fopen(output_file, "w+");
    }

    while(1){
        int len;

        len = read(fdin, buffer, 2000);
        if(len > 0){
            print_packet(fout, buffer, len);
        } else{
            break;
        }
    }

    close(fdin);
    fclose(fout);

    return 0;
}

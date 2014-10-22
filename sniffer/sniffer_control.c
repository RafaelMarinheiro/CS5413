#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include "sniffer_ioctl.h"

#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>

static char * program_name;
static char * dev_file = "/dev/sniffer.dev";

void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
                "parameters: \n"
                "    --mode [enable|disable]\n"
                "    --src_ip [url|any] : default is any \n"
                "    --src_port [XXX|any] : default is any \n"
                "    --dst_ip [url|any] : default is any \n" 
                "    --dst_port [XXX|any] : default is any \n"
                "    --action [capture|dpi] : default is null\n", program_name);
    exit(EXIT_FAILURE);
}

int sniffer_send_command(struct sniffer_flow_entry *flow)
{

    return 0;
}

int main(int argc, char **argv)
{
    int c;
    program_name = argv[0];
    char helper[80];

    struct sniffer_flow_entry flow_entry;
    struct hostent *h;

    int action = 0;

    flow_entry.any_src_ip = 1;
    flow_entry.any_dest_ip = 1;
    flow_entry.any_src_port = 1;
    flow_entry.any_dest_port = 1;
    flow_entry.action = SNIFFER_ACTION_NULL;

    while(1) {
        static struct option long_options[] = 
        {
            {"mode", required_argument, 0, 0},
            {"src_ip", required_argument, 0, 0},
            {"src_port", required_argument, 0, 0},
            {"dst_ip", required_argument, 0, 0},
            {"dst_port", required_argument, 0, 0},
            {"action", required_argument, 0, 0},
            {"dev", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long (argc, argv, "", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case 0:
            // printf("option %d %s", option_index, long_options[option_index].name);
            // if (optarg)
            //     printf(" with arg %s", optarg);
            // printf("\n");

            switch(option_index) {
            case 0:     // mode
                if(strcmp(optarg, "enable") == 0){
                    action = 1;
                } else if(strcmp(optarg, "disable") == 0){
                    action = -1;
                }
                break;
            case 1:     // src_ip
                if(strcmp(optarg, "any") != 0){
                    if ((h = gethostbyname(optarg)) == NULL) {
                        fprintf(stderr, "gethostbyname(%s) failed %s\n", optarg, strerror(errno));
                        return 1;
                    }
                    flow_entry.any_src_ip = 0;
                    memcpy(&flow_entry.src_ip, h->h_addr_list[0], sizeof(flow_entry.src_ip));
                }
                break;
            case 2:     // src_port
                if(strcmp(optarg, "any") != 0){
                    flow_entry.any_src_port = 0;
                    flow_entry.src_port = atoi(optarg);
                }
                break;
            case 3:     // dst_ip
                if(strcmp(optarg, "any") != 0){
                    if ((h = gethostbyname(optarg)) == NULL) {
                        fprintf(stderr, "gethostbyname(%s) failed %s\n", optarg, strerror(errno));
                        return 1;
                    }
                    flow_entry.any_dest_ip = 0;
                    memcpy(&flow_entry.dest_ip, h->h_addr_list[0], sizeof(flow_entry.dest_ip));
                }
                break;
            case 4:     // dst_port
                if(strcmp(optarg, "any") != 0){
                    flow_entry.any_dest_port = 0;
                    flow_entry.dest_port = atoi(optarg);
                }
                break;
            case 5:     // action
                if(strcmp(optarg, "capture") == 0){
                    flow_entry.action = SNIFFER_ACTION_CAPTURE;
                } else if(strcmp(optarg, "dpi") == 0){
                    flow_entry.action = SNIFFER_ACTION_DPI;
                }
                break;
            case 6:     // dev
                strcpy(dev_file, optarg);
                break;
            }
            break;
        default:
            usage();
        }
    }

    int fd, err;

    fd = open(dev_file, O_RDONLY);

    if(action == 1){
        err = ioctl(fd, SNIFFER_FLOW_ENABLE, &flow_entry);
        if(err == -1){
            printf("SNIFFER_FLOW_ENABLE failed: %s\n", strerror(errno));
        } else{
            // printf("SUCCESS\n");
        }
    } else if(action == -1){
        err = ioctl(fd, SNIFFER_FLOW_DISABLE, &flow_entry);
        if(err == -1){
            printf("SNIFFER_FLOW_DISABLE failed: %s\n", strerror(errno));
        } else{
            // printf("SUCCESS\n");
        }
    } else{
        usage();
    }

    close(fd);

    return 0;
}

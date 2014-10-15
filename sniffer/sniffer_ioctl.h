#ifndef __SNIFFER_IOCTL__
#define __SNIFFER_IOCTL__

struct sniffer_flow_entry {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    
    unsigned int	any_src_ip:1,
    				any_dest_ip:1,
    				any_src_port:1,
    				any_dest_port:1;

    unsigned int	action:4;
};

#define SNIFFER_IOC_MAGIC       'p'

#define SNIFFER_FLOW_ENABLE     _IOW(SNIFFER_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define SNIFFER_FLOW_DISABLE    _IOW(SNIFFER_IOC_MAGIC, 0x2, struct sniffer_flow_entry)

#define SNIFFER_IOC_MAXNR   0x3

#define SNIFFER_ACTION_NOT_FOUND	0x4
#define SNIFFER_ACTION_NULL     	0x0
#define SNIFFER_ACTION_CAPTURE  	0x1
#define SNIFFER_ACTION_DPI      	0x2

#endif /* __SNIFFER_IOCTL__ */

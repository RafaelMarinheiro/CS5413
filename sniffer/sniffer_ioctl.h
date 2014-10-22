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

#define DPI_KEY_LEN 5
#define DPI_KEY "You g"

#define SNIFFER_IOC_MAGIC       'p'

#define SNIFFER_FLOW_ENABLE     _IOW(SNIFFER_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define SNIFFER_FLOW_DISABLE    _IOW(SNIFFER_IOC_MAGIC, 0x2, struct sniffer_flow_entry)

#define SNIFFER_IOC_MAXNR   0x3

#define SNIFFER_FLOW_ACTIVE 0x8
#define SNIFFER_ACTION_MASK 0x3

#define IS_FLOW_ACTIVE(flow_action) ((flow_action & SNIFFER_FLOW_ACTIVE) != 0)
#define SET_FLOW_ACTIVE(flow_action) (flow_action | SNIFFER_FLOW_ACTIVE)
#define GET_FLOW_ACTION(flow_action) (flow_action & SNIFFER_ACTION_MASK)

#define SNIFFER_ACTION_NOT_FOUND	0x0
#define SNIFFER_ACTION_NULL     	0x1
#define SNIFFER_ACTION_CAPTURE  	0x2
#define SNIFFER_ACTION_DPI      	0x3

#endif /* __SNIFFER_IOCTL__ */

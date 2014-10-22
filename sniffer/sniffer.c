/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */

#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>

#include "sniffer_ioctl.h"
#include "sniffer_flowtable.h"

MODULE_AUTHOR("Rafael Marinheiro");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
static atomic_t refcnt;

static int hook_chain = NF_INET_LOCAL_IN;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;

// skb buffer between kernel and user space
struct list_head skbs;

//Lock free
struct list_head * skb_buf_first = &skbs;
struct list_head * skb_buf_last = &skbs;
struct list_head * skb_buf_divider = &skbs;

// skb wrapper for buffering
static DEFINE_SEMAPHORE(skb_buffer_mutex);
static DEFINE_SPINLOCK(skb_buffer_spinlock);
static DECLARE_WAIT_QUEUE_HEAD(skb_buffer_waitqueue);
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};

char my_unique_buf[2000];
struct ts_config * pattern_matcher;

////////////////
// Flow table //
////////////////

struct sniffer_flow_table flow_table;

////////////////
// Proc File  //
////////////////

int sniffer_read_procfile(char *buf, char **start, off_t offset, int count,
                      int *eof, void *data){
    int limit = count - 80;
    int i = 1;
    int len = 0;
    struct sniffer_flow_table * rule;

    char helper[21];

    len += sprintf(buf+len, "%-4s%-10s%-20s%-10s%-20s%-10s%-10s\n", "#", "[command]", "[src_ip]", "[src_port]", "[dst_ip]", "[dst_port]", "[action]");
    // printk(KERN_DEBUG "%-4s%-10s%-20s%-10s%-20s%-10s%-10s\n", "#", "[command]", "[src_ip]", "[src_port]", "[dst_ip]", "[dst_port]", "[action]");
    list_for_each_entry(rule, &(flow_table.list), list){
        if(len > limit) break;

        len += sprintf(buf+len,"%-4d",i);
        
        if(IS_FLOW_ACTIVE(rule->entry.action)){
            len += sprintf(buf+len,"%-10s","enable");
        } else{
            len += sprintf(buf+len,"%-10s","disable");
        }
        
        if(rule->entry.any_src_ip){
            len += sprintf(buf+len,"%-20s", "any");
        } else{
            sprintf(helper, "%d.%d.%d.%d", MY_NIPQUAD(rule->entry.src_ip));
            len += sprintf(buf+len,"%-20s", helper);
        }

        if(rule->entry.any_src_port){
            len += sprintf(buf+len,"%-10s", "any");
        } else{
            len += sprintf(buf+len,"%-10d", rule->entry.src_port);
        }

        if(rule->entry.any_dest_ip){
            len += sprintf(buf+len,"%-20s", "any");
        } else{
            sprintf(helper, "%d.%d.%d.%d", MY_NIPQUAD(rule->entry.dest_ip));
            len += sprintf(buf+len,"%-20s", helper);
        }

        if(rule->entry.any_dest_port){
            len += sprintf(buf+len,"%-10s", "any");
        } else{
            len += sprintf(buf+len,"%-10d", rule->entry.dest_port);
        }

        if(GET_FLOW_ACTION(rule->entry.action) == SNIFFER_ACTION_NULL){
            len += sprintf(buf+len,"%-10s", "None");
        } else if(GET_FLOW_ACTION(rule->entry.action) == SNIFFER_ACTION_CAPTURE){
            len += sprintf(buf+len,"%-10s", "Capture");
        } else if(GET_FLOW_ACTION(rule->entry.action) == SNIFFER_ACTION_DPI){
            len += sprintf(buf+len,"%-10s", "DPI");
        } else{
            len += sprintf(buf+len,"%-10s", "<ERROR>");
        }
        len += sprintf(buf+len, "\n");
        i++;
    }

    *eof = 1;

    return len;
}

static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}

static inline void print_skb(struct sk_buff * skb){
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sniffer_flow_entry flow;
    iph = ip_hdr(skb);
    tcph = ip_tcp_hdr(iph);
    flow.src_ip = iph->saddr;
    flow.src_port = ntohs(tcph->source);
    flow.dest_ip = iph->daddr;
    flow.dest_port = ntohs(tcph->dest);
    printk(KERN_DEBUG "READING %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", MY_NIPQUAD(flow.src_ip), flow.src_port, MY_NIPQUAD(flow.dest_ip), flow.dest_port); 
}

/* From kernel to userspace */
static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    struct skb_list * node;
    struct sk_buff * packet;
    int len;
    void * mine_data;
    int retval = 0;

    if(!atomic_dec_and_test(&refcnt)){
        int at;
        at = atomic_read(&refcnt);
        printk(KERN_DEBUG "Ocupado =( %d\n", at);
        retval = -EBUSY;
        goto i_have_atomic;
    }

    if(down_interruptible(&skb_buffer_mutex)){
        retval = -ERESTARTSYS;
        goto i_have_atomic;
    }

    while (skb_buf_divider == skb_buf_last){
        up(&skb_buffer_mutex);

        if(file->f_flags & O_NONBLOCK){
            retval = -EAGAIN;
            goto i_have_atomic;
        }

        if(wait_event_interruptible(skb_buffer_waitqueue, skb_buf_divider != skb_buf_last)){
            retval = -ERESTARTSYS;
            goto i_have_atomic;
        }

        if(down_interruptible(&skb_buffer_mutex)){
            retval = -ERESTARTSYS;
            goto i_have_atomic;
        }
    }
    

    node = list_entry(skb_buf_divider->next, struct skb_list, list);
    packet = node->skb;
    len = packet->len;

    // print_skb(packet);

    if(len > count){
        printk(KERN_DEBUG "Need %d bytes\n", len);
        retval = -EFAULT;
        goto i_have_mutex;
    }

    mine_data = skb_header_pointer(packet, 0, len, my_unique_buf);
    if(mine_data != NULL){
        copy_to_user(buf, mine_data, len);
    } else{
        len = 0;
    }

    skb_buf_divider = skb_buf_divider->next;
    kfree_skb(packet);

    retval = len;

    // printk(KERN_DEBUG "READ %d bytes\n", len);
    // printk("LIST: %x %x %x\n", skb_buf_first, skb_buf_divider, skb_buf_last);

    i_have_mutex:
        up(&skb_buffer_mutex);
    i_have_atomic:
        atomic_inc(&refcnt);
    i_have_nothing:

    return retval;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
    struct cdev *cdev = inode->i_cdev;
    int cindex = iminor(inode);

    if (!cdev) {
        printk(KERN_ERR "cdev error\n");
        return -ENODEV;
    }

    if (cindex != 0) {
        printk(KERN_ERR "Invalid cindex number %d\n", cindex);
        return -ENODEV;
    }

    return 0;
}

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
    return 0;
}

static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long err =0 ;
    struct sniffer_flow_entry flow_entry;

    if (_IOC_TYPE(cmd) != SNIFFER_IOC_MAGIC)
        return -ENOTTY; 
    if (_IOC_NR(cmd) > SNIFFER_IOC_MAXNR)
        return -ENOTTY;
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err)
        return -EFAULT;

    switch(cmd) {
    case SNIFFER_FLOW_ENABLE:
        err = copy_from_user(&flow_entry, (void __user *) arg, sizeof(flow_entry));
        if(err == 0){
            long code = enable_sniffer_flow(&flow_table, &flow_entry);
            if(code < 0){
                printk(KERN_ERR "Failed to add entry!\n");
            }
        } else{
            err = -EINVAL;
        }
        
        break;
    case SNIFFER_FLOW_DISABLE:
        err = copy_from_user(&flow_entry, (void __user *) arg, sizeof(flow_entry));
        if(err == 0){
            long code = disable_sniffer_flow(&flow_table, &flow_entry);
            if(code < 0){
                printk(KERN_ERR "Failed to remove entry!\n");
            }
        } else{
            err = -EINVAL;
        }

        break;
    default:
        printk(KERN_DEBUG "Unknown command\n");
        err = -EINVAL;
    }

    return err;
}

static struct file_operations sniffer_fops = {
    .open = sniffer_fs_open,
    .release = sniffer_fs_release,
    .read = sniffer_fs_read,
    .unlocked_ioctl = sniffer_fs_ioctl,
    .owner = THIS_MODULE,
};

static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
        const struct net_device *indev, const struct net_device *outdev,
        int (*okfn) (struct sk_buff*))
{
    struct iphdr *iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = ip_tcp_hdr(iph);
        if (ntohs(tcph->dest) == 22)
            return NF_ACCEPT;

        if (ntohs(tcph->dest) != 22) {
            struct sniffer_flow_entry flow;
            unsigned int action;
            unsigned int active;
            unsigned int will_capture;

            flow.src_ip = iph->saddr;
            flow.src_port = ntohs(tcph->source);
            flow.dest_ip = iph->daddr;
            flow.dest_port = ntohs(tcph->dest);

            action = match_sniffer_flow_table(&flow_table, &flow);
            active = IS_FLOW_ACTIVE(action);
            action = GET_FLOW_ACTION(action);
            will_capture = 0;

            if(action == SNIFFER_ACTION_NOT_FOUND){
                active = 0;
                will_capture = 0;
            } else if(action == SNIFFER_ACTION_NULL){
                //Do nothing
                will_capture = 0;
            } else if(action == SNIFFER_ACTION_CAPTURE){
                will_capture = 1;
            } else if(action == SNIFFER_ACTION_DPI){
                int pos;
                struct ts_state state;

                /* search for "hanky" at offset 20 until end of packet */
                pos = skb_find_text(skb, 0, INT_MAX, pattern_matcher, &state);

                if(pos != UINT_MAX){
                    will_capture = 1;
                }
            } else{
                active = 0;
                will_capture = 0;
            }

            if(will_capture){
                struct sk_buff * pcopy;
                struct skb_list * new_node;
                printk(KERN_DEBUG "CAPTURED %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", MY_NIPQUAD(flow.src_ip), flow.src_port, MY_NIPQUAD(flow.dest_ip), flow.dest_port);    
            
                pcopy = skb_clone(skb, GFP_ATOMIC);
                new_node = kmalloc(sizeof(struct skb_list), GFP_ATOMIC);
                new_node->skb = pcopy;
                if(pcopy != NULL && new_node != NULL){
                    // Spinlock
                    int sp_flags;
                    spin_lock_irqsave(&skb_buffer_spinlock, sp_flags);
                    {
                        //Lock Free
                        new_node->list.next = &skbs;
                        skb_buf_last->next = &(new_node->list);
                        skb_buf_last = skb_buf_last->next;

                        // printk("LIST: %x %x %x | %x\n", skb_buf_first, skb_buf_divider, skb_buf_last, skb_buf_first->next);

                        while(skb_buf_first != skb_buf_divider){
                            struct skb_list * node;
                            struct sk_buff * packet;
                            struct list_head * temp;

                            temp = skb_buf_first;
                            skb_buf_first = skb_buf_first->next;

                            if(temp != &skbs){
                                node = list_entry(temp, struct skb_list, list);
                                kfree(node);
                            }

                            // printk("LIST: %x %x %x\n", skb_buf_first, skb_buf_divider, skb_buf_last);
                        }
                    }
                    spin_unlock_irqrestore(&skb_buffer_spinlock, sp_flags);

                    wake_up_interruptible(&skb_buffer_waitqueue);
                } else{
                    if(pcopy) kfree_skb(pcopy);
                    if(new_node) kfree(new_node);
                    printk(KERN_ERR "Not enough memory to copy the packet\n");
                }
            }

            if(active){
                printk(KERN_DEBUG "ACCEPTED %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", MY_NIPQUAD(flow.src_ip), flow.src_port, MY_NIPQUAD(flow.dest_ip), flow.dest_port);
                return NF_ACCEPT;
            } else{
                printk(KERN_DEBUG "REJECTED %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", MY_NIPQUAD(flow.src_ip), flow.src_port, MY_NIPQUAD(flow.dest_ip), flow.dest_port);
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static int __init sniffer_init(void)
{
    int status = 0;

    printk(KERN_DEBUG "sniffer_init\n");

    //EDITED

    INIT_LIST_HEAD(&(flow_table.list));

    //END EDITED

    status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
    if (status <0) {
        printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
        goto out;
    }

    cdev_init(&sniffer_cdev, &sniffer_fops);
    status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
    if (status < 0) {
        printk(KERN_ERR "cdev_add failed %d\n", status);
        goto out_cdev;
        
    }

    atomic_set(&refcnt, 1);
    INIT_LIST_HEAD(&skbs);

    create_proc_read_entry("sniffer", 0, NULL, sniffer_read_procfile, NULL);

    pattern_matcher = textsearch_prepare("kmp", DPI_KEY, DPI_KEY_LEN, GFP_KERNEL, TS_AUTOLOAD);
    if(pattern_matcher == NULL){
        status = -ENOMEM;
        goto out_matcher;
    } 

    /* register netfilter hook */
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    nf_hook_ops.hook = sniffer_nf_hook;
    nf_hook_ops.pf = PF_INET;
    nf_hook_ops.hooknum = hook_chain;
    nf_hook_ops.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }

    return 0;

out_add:
    textsearch_destroy(pattern_matcher);
out_matcher:
    remove_proc_entry("sniffer", NULL);
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{
    if (nf_hook_ops.hook) {
        nf_unregister_hook(&nf_hook_ops);
        memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    }
    textsearch_destroy(pattern_matcher);
    remove_proc_entry("sniffer", NULL);
    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
}

module_init(sniffer_init);
module_exit(sniffer_exit);
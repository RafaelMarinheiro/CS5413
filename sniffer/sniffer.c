/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */

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

MODULE_AUTHOR("");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;

static int hook_chain = NF_INET_LOCAL_IN;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;

// skb buffer between kernel and user space
struct list_head skbs;

// skb wrapper for buffering
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};

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
    printk(KERN_DEBUG "%-4s%-10s%-20s%-10s%-20s%-10s%-10s\n", "#", "[command]", "[src_ip]", "[src_port]", "[dst_ip]", "[dst_port]", "[action]");
    list_for_each_entry(rule, &(flow_table.list), list){
        if(len > limit) break;

        len += sprintf(buf+len,"%-4d",i);
        len += sprintf(buf+len,"%-10s","enable");
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

        if(rule->entry.action == SNIFFER_ACTION_NULL){
            len += sprintf(buf+len,"%-10s", "None");
        } else if(rule->entry.action == SNIFFER_ACTION_CAPTURE){
            len += sprintf(buf+len,"%-10s", "Capture");
        } else{
            len += sprintf(buf+len,"%-10s", "DPI");
        }
        len += sprintf(buf+len, "\n");
        i++;
    }

    *eof = 1;

    return len;
}


// {
//          int i, j, len = 0;
//          int limit = count - 80; /* Don't print more than this */
//          for (i = 0; i < scull_nr_devs && len <= limit; i++) {
//              struct scull_dev *d = &scull_devices[i];
//              struct scull_qset *qs = d->data;
//              if (down_interruptible(&d->sem))
//                  return -ERESTARTSYS;
//              len += sprintf(buf+len,"\nDevice %i: qset %i, q %i, sz %li\n",
//                      i, d->qset, d->quantum, d->size);
//              for (; qs && len <= limit; qs = qs->next) { /* scan the list */
//                  len += sprintf(buf + len, "  item at %p, qset at %p\n",
//                          qs, qs->data);
//                  if (qs->data && !qs->next) /* dump only the last item */
//                      for (j = 0; j < d->qset; j++) {
// ￼￼} }
// if (qs->data[j])
//     len += sprintf(buf + len,
//             "    % 4i: %8p\n",
//             j, qs->data[j]);
//              up(&scull_devices[i].sem);
//          }
// *eof = 1;
// return len; }

static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}

/* From kernel to userspace */
static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    printk(KERN_DEBUG "Hello World\n");
    return 0;
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
            flow.src_ip = ntohl(iph->saddr);
            flow.src_port = ntohs(tcph->source);
            flow.dest_ip = ntohl(iph->daddr);
            flow.dest_port = ntohs(tcph->dest);

            if(match_sniffer_flow_table(&flow_table, &flow) != SNIFFER_ACTION_NOT_FOUND){
                printk(KERN_DEBUG "Accepted %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", MY_NIPQUAD(flow.src_ip), flow.src_port, MY_NIPQUAD(flow.dest_ip), flow.dest_port);    
                return NF_ACCEPT;
            } else{
                printk(KERN_DEBUG "Rejected %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", MY_NIPQUAD(flow.src_ip), flow.src_port, MY_NIPQUAD(flow.dest_ip), flow.dest_port);    
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

    atomic_set(&refcnt, 0);
    INIT_LIST_HEAD(&skbs);

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

    create_proc_read_entry("sniffer", 0, NULL, sniffer_read_procfile, NULL);

    return 0;

out_add:
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{
    remove_proc_entry("sniffer", NULL);
    if (nf_hook_ops.hook) {
        nf_unregister_hook(&nf_hook_ops);
        memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    }
    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
}

module_init(sniffer_init);
module_exit(sniffer_exit);
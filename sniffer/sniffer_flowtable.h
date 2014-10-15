#ifndef __SNIFFER_FLOW_TABLE__
#define __SNIFFER_FLOW_TABLE__

	#include <linux/kernel.h>
	#include <linux/slab.h>
	#include <linux/list.h>
	#include "sniffer_ioctl.h"


	#define MY_NIPQUAD(addr) \
			((unsigned char *)&addr)[0], \
			((unsigned char *)&addr)[1], \
			((unsigned char *)&addr)[2], \
			((unsigned char *)&addr)[3]
	
	struct sniffer_flow_table {
		struct list_head list;
		struct sniffer_flow_entry entry;
	};

	unsigned int match_exact_same_flow(struct sniffer_flow_entry * rule, struct sniffer_flow_entry * flow);
	unsigned int match_sniffer_flow_entry(struct sniffer_flow_entry * rule, struct sniffer_flow_entry * flow);
	unsigned int match_sniffer_flow_table(struct sniffer_flow_table * table, struct sniffer_flow_entry * flow);
	
	//First disable and then add as head
	int enable_sniffer_flow(struct sniffer_flow_table * table, struct sniffer_flow_entry * flow);
	
	//Remove all that match the flow
	int disable_sniffer_flow(struct sniffer_flow_table * table, struct sniffer_flow_entry * flow);

	//////////////////////////////
	//Implementation            //
	//////////////////////////////

	unsigned int match_exact_same_flow(struct sniffer_flow_entry * rule, struct sniffer_flow_entry * flow){
		unsigned int match = 1;
		match = (rule->any_src_ip != flow->any_src_ip || (rule->src_ip != flow->src_ip)) ? 0 : match;
		match = (rule->any_dest_ip != flow->any_dest_ip || (rule->dest_ip != flow->dest_ip)) ? 0 : match;
		match = (rule->any_src_port != flow->any_src_port || (rule->src_port != flow->src_port)) ? 0 : match;
		match = (rule->any_dest_port != flow->any_dest_port || (rule->dest_port != flow->dest_port)) ? 0 : match;

		return match;
	}

	unsigned int match_sniffer_flow_entry(struct sniffer_flow_entry * rule, struct sniffer_flow_entry * flow){
		unsigned int match = 1;
		match = (rule->any_src_ip == 0 && (rule->src_ip != flow->src_ip)) ? 0 : match;
		match = (rule->any_dest_ip == 0 && (rule->dest_ip != flow->dest_ip)) ? 0 : match;
		match = (rule->any_src_port == 0 && (rule->src_port != flow->src_port)) ? 0 : match;
		match = (rule->any_dest_port == 0 && (rule->dest_port != flow->dest_port)) ? 0 : match;

		return (match == 1) ? rule->action : SNIFFER_ACTION_NOT_FOUND;
	}

	unsigned int match_sniffer_flow_table(struct sniffer_flow_table * table, struct sniffer_flow_entry * flow){
		struct sniffer_flow_table * rule;
		unsigned int action = SNIFFER_ACTION_NOT_FOUND;

		list_for_each_entry(rule, &(table->list), list){
			action = match_sniffer_flow_entry(&(rule->entry), flow);

			if(action != SNIFFER_ACTION_NOT_FOUND) break;
		}

		return action;
	}

	int enable_sniffer_flow(struct sniffer_flow_table * table, struct sniffer_flow_entry * flow){
		int ret = 0;
		
		struct sniffer_flow_table * new_rule = kmalloc(sizeof(struct sniffer_flow_table), GFP_KERNEL);
		
		if(new_rule){
			int removed = disable_sniffer_flow(table, flow);

			new_rule->entry = *flow;
			list_add(&(new_rule->list), &(table->list));
			ret = removed;
			
			{
				printk(KERN_INFO, "Adding entry ");
				if(flow->any_src_ip){
					printk(KERN_INFO, "<ANY>:");
				} else{
					printk(KERN_INFO, "%pI4:", flow->src_ip);
				}
				if(flow->any_src_port){
					printk(KERN_INFO, "<ANY> -> ");
				} else{
					printk(KERN_INFO, "%d -> ", flow->src_port);
				}
				if(flow->any_dest_ip){
					printk(KERN_INFO, "<ANY>:");
				} else{
					printk(KERN_INFO, "%pI4:", flow->dest_ip);
				}
				if(flow->any_dest_port){
					printk(KERN_INFO, "<ANY>\n");
				} else{
					printk(KERN_INFO, "%d\n", flow->dest_port);
				}
			}
		} else{
			ret = -1;
		}

		return ret;
	}

	int disable_sniffer_flow(struct sniffer_flow_table * table, struct sniffer_flow_entry * flow){
		struct sniffer_flow_table * rule, * temp_rule;

		unsigned int removed = 0;

		list_for_each_entry_safe(rule, temp_rule, &(table->list), list){
			//If the rule is contained, then we remove it
			if(match_sniffer_flow_entry(flow, &(rule->entry)) != SNIFFER_ACTION_NOT_FOUND){
				{
					printk(KERN_INFO, "Removing entry ");
					if(rule->entry.any_src_ip){
						printk(KERN_INFO, "<ANY>:");
					} else{
						printk(KERN_INFO, "%pI4:", rule->entry.src_ip);
					}
					if(rule->entry.any_src_port){
						printk(KERN_INFO, "<ANY> -> ");
					} else{
						printk(KERN_INFO, "%d -> ", rule->entry.src_port);
					}
					if(rule->entry.any_dest_ip){
						printk(KERN_INFO, "<ANY>:");
					} else{
						printk(KERN_INFO, "%pI4:", rule->entry.dest_ip);
					}
					if(rule->entry.any_dest_port){
						printk(KERN_INFO, "<ANY>\n");
					} else{
						printk(KERN_INFO, "%d\n", rule->entry.dest_port);
					}
				}

				list_del(&(rule->list));
				kfree(rule);
				removed++;
			}
		}

		return removed;
	}




#endif
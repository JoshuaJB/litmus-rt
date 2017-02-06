/*
 * page_dev.h - Implementation of the page coloring for cache and bank partition. 
 *              The file will keep a pool of colored pages. MMU can allocate pages with 
 *		        specific color or bank number.
 * Author: Namhoon Kim (namhoonk@cs.unc.edu)
 */
 
#ifndef _LITMUS_PAGE_DEV_H
#define _LITMUS_PAGE_DEV_H

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/mmzone.h>

#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/litmus.h>

int llc_partition_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);
int dram_partition_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);

#endif /* _LITMUS_PAGE_DEV_H */
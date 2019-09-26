/*
 * page_dev.h - Implementation of the page coloring for cache and bank partition.
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

#include <litmus/sched_trace.h>
#include <litmus/litmus.h>

int llc_partition_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);
int dram_partition_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);
int bank_to_partition(unsigned int bank);
int get_area_index(int cpu);
int is_in_correct_bank(struct page* page, int cpu);
int is_in_llc_partition(struct page* page, int cpu);

#endif /* _LITMUS_PAGE_DEV_H */

#ifndef LITMUS_REPLICATE_LIB_H
#define LITMUS_REPLICATE_LIB_H

#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/mm_inline.h>

struct shared_lib_page {
	struct page *master_page;
	struct page *r_page[NR_CPUS];
	unsigned long int master_pfn;
	unsigned long int r_pfn[NR_CPUS];
	struct list_head list;
};

extern struct list_head shared_lib_pages;

#endif

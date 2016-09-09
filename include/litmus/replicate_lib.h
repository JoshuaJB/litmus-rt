#ifndef LITMUS_REPLICATE_LIB_H
#define LITMUS_REPLICATE_LIB_H

#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/mm_inline.h>

struct shared_lib_page {
	struct page *p_page;
	struct page *r_page;
	unsigned long p_pfn;
	unsigned long r_pfn;
	struct list_head list;
};

extern struct list_head shared_lib_pages;

#endif

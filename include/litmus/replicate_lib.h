#ifndef LITMUS_REPLICATE_LIB_H
#define LITMUS_REPLICATE_LIB_H

#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/mm_inline.h>

struct shared_lib_page {
	struct page *p_page;
	unsigned long pfn;
	struct list_head list;
};

#endif

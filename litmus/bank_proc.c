/*
 * bank_proc.c -- Implementation of the page coloring for cache and bank partition.
 *                The file will keep a pool of colored pages. Users can require pages with
 *                specific color or bank number
 *                Part of the code is modified from Jonathan Herman's code.
 */
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

#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/litmus.h>

#define LITMUS_LOCKDEP_NAME_MAX_LEN 50

// This Address Decoding is used in imx6-sabredsd platform
#define BANK_MASK  0x38000000
#define BANK_SHIFT  27
#define CACHE_MASK  0x0000f000
#define CACHE_SHIFT 12

#define PAGES_PER_COLOR 2000
#define NUM_BANKS	8
#define NUM_COLORS	16

unsigned int NUM_PAGE_LIST;  //8*16

unsigned int number_banks;
unsigned int number_cachecolors;

unsigned int set_partition_max = 0x0000ffff;
unsigned int set_partition_min = 0;
unsigned int bank_partition_max = 0x000000ff;
unsigned int bank_partition_min = 0;

int show_page_pool = 0;
int refill_page_pool = 0;
spinlock_t reclaim_lock;

unsigned int set_partition[9] = {
        0x00000003,  /* Core 0, and Level A*/
        0x00000003,  /* Core 0, and Level B*/
        0x0000000C,  /* Core 1, and Level A*/
        0x0000000C,  /* Core 1, and Level B*/
        0x00000030,  /* Core 2, and Level A*/
        0x00000030,  /* Core 2, and Level B*/
        0x000000C0,  /* Core 3, and Level A*/
        0x000000C0,  /* Core 3, and Level B*/
        0x0000ff00,  /* Level C */
};

unsigned int bank_partition[9] = {
        0x00000010,  /* Core 0, and Level A*/
        0x00000010,  /* Core 0, and Level B*/
        0x00000020,  /* Core 1, and Level A*/
        0x00000020,  /* Core 1, and Level B*/
        0x00000040,  /* Core 2, and Level A*/
        0x00000040,  /* Core 2, and Level B*/
        0x00000080,  /* Core 3, and Level A*/
        0x00000080,  /* Core 3, and Level B*/
        0x0000000c,  /* Level C */
};

unsigned int set_index[9] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

unsigned int bank_index[9] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

int node_index[9] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1
};

struct mutex void_lockdown_proc;

/*
 * Every page list should contain a lock, a list, and a number recording how many pages it store
 */
struct color_group {
	spinlock_t lock;
	char _lock_name[LITMUS_LOCKDEP_NAME_MAX_LEN];
	struct list_head list;
	atomic_t nr_pages;
};


static struct color_group *color_groups;

/*
 * Naive function to count the number of 1's
 */
unsigned int counting_one_set(unsigned int v)
{
    unsigned int c; // c accumulates the total bits set in v

    for (c = 0; v; v >>= 1)
    {
        c += v & 1;
    }
    return c;
}

unsigned int two_exp(unsigned int e)
{
    unsigned int v = 1;
    for (; e>0; e-- )
    {
        v=v*2;
    }
    return v;
}

/* helper functions to find the next colored pool index */
static inline unsigned int first_index(unsigned long node)
{
	unsigned int bank_no = 0, color_no = 0;

	while(bank_no < NUM_BANKS) {
		if ((bank_partition[node]>>bank_no) & 0x1)
			break;
		bank_no++;
	}
	while(color_no < NUM_COLORS) {
		if ((set_partition[node]>>color_no) & 0x1)
			break;
		color_no++;
	}
	return NUM_COLORS*bank_no + color_no;
}

static inline unsigned int last_index(unsigned long node)
{
	unsigned int bank_no = NUM_BANKS-1, color_no = NUM_COLORS-1;

	while(bank_no >= 0) {
		if ((bank_partition[node]>>bank_no) & 0x1)
			break;
		bank_no--;
	}
	while(color_no >= 0) {
		if ((set_partition[node]>>color_no) & 0x1)
			break;
		color_no--;
	}
	return NUM_COLORS*bank_no + color_no;
}

static inline unsigned int next_color(unsigned long node, unsigned int current_color)
{
	int try = 0, ret = 0;
	current_color++;
	if (current_color == NUM_COLORS) {
		current_color = 0;
		ret = 1;
	}

	while (try < NUM_COLORS) {
		if ((set_partition[node]>>current_color)&0x1)
			break;
		current_color++;
		if (current_color == NUM_COLORS) {
			current_color = 0;
			ret = 1;
		}
		try++;
	}
	if (!ret)
		return current_color;
	else
		return current_color + NUM_COLORS;
}

static inline unsigned int next_bank(unsigned long node, unsigned int current_bank)
{
	int try = 0;
	current_bank++;
	if (current_bank == NUM_BANKS) {
		current_bank = 0;
	}

	while (try < NUM_BANKS) {
		if ((bank_partition[node]>>current_bank)&0x1)
			break;
		current_bank++;
		if (current_bank == NUM_BANKS) {
			current_bank = 0;
		}
		try++;
	}
	return current_bank;
}

static inline unsigned int get_next_index(unsigned long node, unsigned int current_index)
{
	unsigned int bank_no, color_no, color_ret, bank_ret;
	bank_no = current_index>>4; // 2^4 = 16 colors
	color_no = current_index - bank_no*NUM_COLORS;
	bank_ret = bank_no;
	color_ret = next_color(node, color_no);
	if (color_ret >= NUM_COLORS) {
		// next bank
		color_ret -= NUM_COLORS;
		bank_ret = next_bank(node, bank_no);
	}

	return bank_ret * NUM_COLORS + color_ret;
}

/* Decoding page color, 0~15 */
static inline unsigned int page_color(struct page *page)
{
	return ((page_to_phys(page)& CACHE_MASK) >> CACHE_SHIFT);
}

/* Decoding page bank number, 0~7 */
static inline unsigned int page_bank(struct page *page)
{
	return ((page_to_phys(page)& BANK_MASK) >> BANK_SHIFT);
}

static inline unsigned int page_list_index(struct page *page)
{
    unsigned int idx;
    idx = (page_color(page) + page_bank(page)*(number_cachecolors));

    return idx;
}



/*
 * It is used to determine the smallest number of page lists.
 */
static unsigned long smallest_nr_pages(void)
{
	unsigned long i, min_pages;
	struct color_group *cgroup;
	cgroup = &color_groups[16*2];
	min_pages =atomic_read(&cgroup->nr_pages);
	for (i = 16*2; i < NUM_PAGE_LIST; ++i) {
		cgroup = &color_groups[i];
		if (atomic_read(&cgroup->nr_pages) < min_pages)
			min_pages = atomic_read(&cgroup->nr_pages);
	}
	return min_pages;
}

static void show_nr_pages(void)
{
	unsigned long i;
	struct color_group *cgroup;
	printk("show nr pages***************************************\n");
	for (i = 0; i < NUM_PAGE_LIST; ++i) {
		cgroup = &color_groups[i];
		printk("(%03ld) =  %03d, ", i, atomic_read(&cgroup->nr_pages));
		if((i % 8) ==7) {
		    printk("\n");
		}
	}
}

/*
 * Add a page to current pool.
 */
void add_page_to_color_list(struct page *page)
{
	const unsigned long color = page_list_index(page);
	struct color_group *cgroup = &color_groups[color];
	BUG_ON(in_list(&page->lru) || PageLRU(page));
	BUG_ON(page_count(page) > 1);
	spin_lock(&cgroup->lock);
	list_add_tail(&page->lru, &cgroup->list);
	atomic_inc(&cgroup->nr_pages);
	SetPageLRU(page);
	spin_unlock(&cgroup->lock);
}

/*
 * Replenish the page pool.
 * If the newly allocate page is what we want, it will be pushed to the correct page list
 * otherwise, it will be freed.
 * A user needs to invoke this function until the page pool has enough pages.
 */
static int do_add_pages(void)
{
	struct page *page, *page_tmp;
	LIST_HEAD(free_later);
	unsigned long color;
	int ret = 0;
	int i = 0;
	int free_counter = 0;
	unsigned long counter[128]= {0};

	// until all the page lists contain enough pages
	for (i=0; i< 1024*20;i++) {
		page = alloc_page(GFP_HIGHUSER_MOVABLE);

		if (unlikely(!page)) {
			printk(KERN_WARNING "Could not allocate pages.\n");
			ret = -ENOMEM;
			goto out;
		}
		color = page_list_index(page);
		counter[color]++;
		if (atomic_read(&color_groups[color].nr_pages) < PAGES_PER_COLOR && color>=0) {
			add_page_to_color_list(page);
		} else {
			// Pages here will be freed later
			list_add_tail(&page->lru, &free_later);
			free_counter++;
		}
	}

	// Free the unwanted pages
	list_for_each_entry_safe(page, page_tmp, &free_later, lru) {
		list_del(&page->lru);
		__free_page(page);
	}
out:
        return ret;
}

/*
 * Provide pages for replacement according cache color
 * This should be the only implementation here
 * This function should not be accessed by others directly.
 *
 */
static struct page *new_alloc_page_color( unsigned long color)
{
//	printk("allocate new page color = %d\n", color);
	struct color_group *cgroup;
	struct page *rPage = NULL;

	if( (color <0) || (color)>(number_cachecolors*number_banks -1)) {
		TRACE_CUR("Wrong color %lu\n", color);
		goto out;
	}


	cgroup = &color_groups[color];
	spin_lock(&cgroup->lock);
	if (unlikely(!atomic_read(&cgroup->nr_pages))) {
		TRACE_CUR("No free %lu colored pages.\n", color);
		goto out_unlock;
	}
	rPage = list_first_entry(&cgroup->list, struct page, lru);
	BUG_ON(page_count(rPage) > 1);
	//get_page(rPage);
	list_del(&rPage->lru);
	atomic_dec(&cgroup->nr_pages);
	ClearPageLRU(rPage);
out_unlock:
	spin_unlock(&cgroup->lock);
out:
	return rPage;
}

struct page* get_colored_page(unsigned long color)
{
	return new_alloc_page_color(color);
}

/*
 * provide pages for replacement according to
 * node = 0 for Level A tasks in Cpu 0
 * node = 1 for Level B tasks in Cpu 0
 * node = 2 for Level A tasks in Cpu 1
 * node = 3 for Level B tasks in Cpu 1
 * node = 4 for Level A tasks in Cpu 2
 * node = 5 for Level B tasks in Cpu 2
 * node = 6 for Level A tasks in Cpu 3
 * node = 7 for Level B tasks in Cpu 3
 * node = 8 for Level C tasks
 */
struct page *new_alloc_page(struct page *page, unsigned long node, int **x)
{
	struct page *rPage = NULL;
	int try = 0;
	unsigned int idx;

	if (node_index[node] == -1)
		idx = first_index(node);
	else
		idx = node_index[node];

	BUG_ON(idx<0 || idx>127);
	rPage =  new_alloc_page_color(idx);
	if (node_index[node] == last_index(node))
		node_index[node] = first_index(node);
	else
		node_index[node]++;

	while (!rPage)  {
		try++;
		if (try>=256)
			break;
		idx = get_next_index(node, idx);
		printk(KERN_ALERT "try = %d out of page! requesting node  = %ld, idx = %d\n", try, node, idx);
		BUG_ON(idx<0 || idx>127);
		rPage = new_alloc_page_color(idx);
	}
	node_index[node] = idx;
	return rPage;
}


/*
 * Reclaim pages.
 */
void reclaim_page(struct page *page)
{
	const unsigned long color = page_list_index(page);
	spin_lock(&reclaim_lock);
	put_page(page);
	add_page_to_color_list(page);

	spin_unlock(&reclaim_lock);
	printk("Reclaimed page(%ld) = color %x, bank %x, [color] =%d \n", color, page_color(page), page_bank(page), atomic_read(&color_groups[color].nr_pages));
}


/*
 * Initialize the numbers of banks and cache colors
 */
static void __init init_variables(void)
{
	number_banks = counting_one_set(BANK_MASK);
	number_banks = two_exp(number_banks);

	number_cachecolors = counting_one_set(CACHE_MASK);
	number_cachecolors = two_exp(number_cachecolors);
	NUM_PAGE_LIST = number_banks * number_cachecolors;
        printk(KERN_WARNING "number of banks = %d, number of cachecolors=%d\n", number_banks, number_cachecolors);
	mutex_init(&void_lockdown_proc);
	spin_lock_init(&reclaim_lock);

}


/*
 * Initialize the page pool
 */
static int __init init_color_groups(void)
{
	struct color_group *cgroup;
	unsigned long i;
	int err = 0;

        printk("NUM_PAGE_LIST = %d\n", NUM_PAGE_LIST);
        color_groups = kmalloc(NUM_PAGE_LIST *sizeof(struct color_group), GFP_KERNEL);

	if (!color_groups) {
		printk(KERN_WARNING "Could not allocate color groups.\n");
		err = -ENOMEM;
	}else{

		for (i = 0; i < NUM_PAGE_LIST; ++i) {
			cgroup = &color_groups[i];
			atomic_set(&cgroup->nr_pages, 0);
			INIT_LIST_HEAD(&cgroup->list);
			spin_lock_init(&cgroup->lock);
		}
	}
        return err;
}

int set_partition_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i = 0;
	mutex_lock(&void_lockdown_proc);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	if (write) {
            printk("New set Partition : \n");
	    for(i =0;i <9;i++)
            {
                set_index[i] = 0;
                printk("set[%d] = %x \n", i, set_partition[i]);
            }
	}
out:
	mutex_unlock(&void_lockdown_proc);
	return ret;
}

int bank_partition_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i = 0;
	mutex_lock(&void_lockdown_proc);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	if (write) {
	    for(i =0;i <9;i++)
            {
                bank_index[i] = 0;
            }
	}
out:
	mutex_unlock(&void_lockdown_proc);
	return ret;
}

int show_page_pool_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0;
	mutex_lock(&void_lockdown_proc);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	if (write) {
            show_nr_pages();
	}
out:
	mutex_unlock(&void_lockdown_proc);
	return ret;
}

int refill_page_pool_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0;
	mutex_lock(&void_lockdown_proc);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	if (write) {
            do_add_pages();
			show_nr_pages();
	}
out:
	mutex_unlock(&void_lockdown_proc);
	return ret;
}

/*
 * Initialzie this proc
 */
static int __init litmus_color_init(void)
{
	int err=0;
	printk("Init bankproc.c\n");
	printk(KERN_INFO "Registering LITMUS^RT color and bank proc.\n");
out:
	return err;
}

module_init(litmus_color_init);


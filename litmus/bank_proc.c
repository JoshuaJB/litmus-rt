/*
 * bank_proc.c -- Implementation of the page coloring for cache and bank partition. 
 *                The file will keep a pool of colored pages. Users can require pages with 
 *		  specific color or bank number.
 *                Part of the code is modified from Jonathan Herman's code  
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

#define PAGES_PER_COLOR 1024
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
//    unsigned int v; // count the number of bits set in v
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

unsigned int num_by_bitmask_index(unsigned int bitmask, unsigned int index)
{
    unsigned int pos = 0;

    while(true)
    {
        if(index ==0 && (bitmask & 1)==1)
        {
            break;
        }
        if(index !=0 && (bitmask & 1)==1){
            index--;
        }
        pos++;
        bitmask = bitmask >>1;

    }
    return pos;
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
//    printk("address = %lx, ", page_to_phys(page));
//    printk("color(%d), bank(%d), indx = %d\n", page_color(page), page_bank(page), idx);

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
		printk("(%03d) =  %03d, ", i, atomic_read(&cgroup->nr_pages));
		if((i % 8) ==7){
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
 */
static int do_add_pages(void)
{
	//printk("LITMUS do add pages\n");
	
	struct page *page, *page_tmp;
	LIST_HEAD(free_later);
	unsigned long color;
	int ret = 0;
	int i = 0;
	int free_counter = 0;
	unsigned long counter[128]= {0}; 
        
        //printk("Before refill : \n");
        //show_nr_pages();

	// until all the page lists contain enough pages 
	//for (i =0; i<5; i++) {
	for (i=0; i< 1024*100;i++) {
	//while (smallest_nr_pages() < PAGES_PER_COLOR) {
       //         printk("smallest = %d\n", smallest_nr_pages());	
		page = alloc_page(GFP_HIGHUSER_MOVABLE);
	    //    page = alloc_pages_exact_node(0, GFP_HIGHUSER_MOVABLE, 0);
	
		if (unlikely(!page)) {
			printk(KERN_WARNING "Could not allocate pages.\n");
			ret = -ENOMEM;
			goto out;
		}
		color = page_list_index(page);
		counter[color]++;
	//	printk("page(%d) = color %x, bank %x, [color] =%d \n", color, page_color(page), page_bank(page), atomic_read(&color_groups[color].nr_pages));
                //show_nr_pages();
		if (atomic_read(&color_groups[color].nr_pages) < PAGES_PER_COLOR && color>=32) {
		//if ( PAGES_PER_COLOR && color>=16*2) {
			add_page_to_color_list(page);
	//		printk("add page(%d) = color %x, bank %x\n", color, page_color(page), page_bank(page));
		} else{
			// Pages here will be freed later 
			list_add_tail(&page->lru, &free_later);
			free_counter++;
		        //list_del(&page->lru);
		//        __free_page(page);
	//		printk("useless page(%d) = color %x, bank %x\n", color,  page_color(page), page_bank(page));
		}
               //show_nr_pages();
                /*
                if(free_counter >= PAGES_PER_COLOR)
                {
                    printk("free unwanted page list eariler");
                    free_counter = 0;
	            list_for_each_entry_safe(page, page_tmp, &free_later, lru) {
		        list_del(&page->lru);
		        __free_page(page);
	            }

                    show_nr_pages();
                }
                */
        }
/*        printk("page counter = \n");
        for (i=0; i<128; i++)
        {
            printk("(%03d) = %4d, ", i , counter[i]);
            if(i%8 == 7){
                printk("\n");
            }

        }
*/	
        //printk("After refill : \n");
        //show_nr_pages();
#if 1
	// Free the unwanted pages
	list_for_each_entry_safe(page, page_tmp, &free_later, lru) {
		list_del(&page->lru);
		__free_page(page);
	}
#endif
out:
        return ret;
}

/*
 * Provide pages for replacement according cache color 
 * This should be the only implementation here
 * This function should not be accessed by others directly. 
 * 
 */ 
static struct  page *new_alloc_page_color( unsigned long color)
{
//	printk("allocate new page color = %d\n", color);	
	struct color_group *cgroup;
	struct page *rPage = NULL;
		
	if( (color <0) || (color)>(number_cachecolors*number_banks -1)) {
		TRACE_CUR("Wrong color %lu\n", color);	
//		printk(KERN_WARNING "Wrong color %lu\n", color);
		goto out;
	}

		
	cgroup = &color_groups[color];
	spin_lock(&cgroup->lock);
	if (unlikely(!atomic_read(&cgroup->nr_pages))) {
		TRACE_CUR("No free %lu colored pages.\n", color);
//		printk(KERN_WARNING "no free %lu colored pages.\n", color);
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
	if( smallest_nr_pages() == 0)
        {
		do_add_pages();
       //     printk("ERROR(bank_proc.c) = We don't have enough pages in bank_proc.c\n");        
        
        }
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
//	printk("allocate new page node = %d\n", node);	
//	return alloc_pages_exact_node(node, GFP_HIGHUSER_MOVABLE, 0);
	struct color_group *cgroup;
	struct page *rPage = NULL;
	unsigned int color;
	

        unsigned int idx = 0;
        idx += num_by_bitmask_index(set_partition[node], set_index[node]);
        idx += number_cachecolors* num_by_bitmask_index(bank_partition[node], bank_index[node]);
	//printk("node  = %d, idx = %d\n", node, idx);

	rPage =  new_alloc_page_color(idx);
        
            
        set_index[node] = (set_index[node]+1) % counting_one_set(set_partition[node]);
        bank_index[node] = (bank_index[node]+1) % counting_one_set(bank_partition[node]);
	return rPage; 
}


/*
 * Reclaim pages.
 */
void reclaim_page(struct page *page)
{
	const unsigned long color = page_list_index(page);
	unsigned long nr_reclaimed = 0;
	spin_lock(&reclaim_lock);
    	put_page(page);
	add_page_to_color_list(page);

	spin_unlock(&reclaim_lock);
	printk("Reclaimed page(%d) = color %x, bank %x, [color] =%d \n", color, page_color(page), page_bank(page), atomic_read(&color_groups[color].nr_pages));
}


/*
 * Initialize the numbers of banks and cache colors 
 */ 
static int __init init_variables(void)
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
	int ret = 0, i = 0;
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
	int ret = 0, i = 0;
	mutex_lock(&void_lockdown_proc);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	if (write) {
            do_add_pages();
	}
out:
	mutex_unlock(&void_lockdown_proc);
	return ret;
}

static struct ctl_table cache_table[] =
{
        
	{
		.procname	= "C0_LA_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[0],
		.maxlen		= sizeof(set_partition[0]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},	
	{
		.procname	= "C0_LB_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[1],
		.maxlen		= sizeof(set_partition[1]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},	
	{
		.procname	= "C1_LA_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[2],
		.maxlen		= sizeof(set_partition[2]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},
	{
		.procname	= "C1_LB_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[3],
		.maxlen		= sizeof(set_partition[3]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},
	{
		.procname	= "C2_LA_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[4],
		.maxlen		= sizeof(set_partition[4]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},
	{
		.procname	= "C2_LB_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[5],
		.maxlen		= sizeof(set_partition[5]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},
	{
		.procname	= "C3_LA_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[6],
		.maxlen		= sizeof(set_partition[6]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},
	{
		.procname	= "C3_LB_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[7],
		.maxlen		= sizeof(set_partition[7]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},	
	{
		.procname	= "Call_LC_set",
		.mode		= 0666,
		.proc_handler	= set_partition_handler,
		.data		= &set_partition[8],
		.maxlen		= sizeof(set_partition[8]),
		.extra1		= &set_partition_min,
		.extra2		= &set_partition_max,
	},	
	{
		.procname	= "C0_LA_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[0],
		.maxlen		= sizeof(set_partition[0]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},
	{
		.procname	= "C0_LB_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[1],
		.maxlen		= sizeof(set_partition[1]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},		
	{
		.procname	= "C1_LA_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[2],
		.maxlen		= sizeof(set_partition[2]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},
	{
		.procname	= "C1_LB_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[3],
		.maxlen		= sizeof(set_partition[3]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},
	{
		.procname	= "C2_LA_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[4],
		.maxlen		= sizeof(set_partition[4]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},	
	{
		.procname	= "C2_LB_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[5],
		.maxlen		= sizeof(set_partition[5]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},		
	{
		.procname	= "C3_LA_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[6],
		.maxlen		= sizeof(set_partition[6]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},	
	{
		.procname	= "C3_LB_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[7],
		.maxlen		= sizeof(set_partition[7]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},	
	{
		.procname	= "Call_LC_bank",
		.mode		= 0666,
		.proc_handler	= bank_partition_handler,
		.data		= &bank_partition[8],
		.maxlen		= sizeof(set_partition[8]),
		.extra1		= &bank_partition_min,
		.extra2		= &bank_partition_max,
	},	
	{
		.procname	= "show_page_pool",
		.mode		= 0666,
		.proc_handler	= show_page_pool_handler,
		.data		= &show_page_pool,
		.maxlen		= sizeof(show_page_pool),
	},		{
		.procname	= "refill_page_pool",
		.mode		= 0666,
		.proc_handler	= refill_page_pool_handler,
		.data		= &refill_page_pool,
		.maxlen		= sizeof(refill_page_pool),
	},	
	{ }
};

static struct ctl_table litmus_dir_table[] = {
	{
		.procname	= "litmus",
 		.mode		= 0555,
		.child		= cache_table,
	},
	{ }
};


static struct ctl_table_header *litmus_sysctls;


/*
 * Initialzie this proc 
 */
static int __init litmus_color_init(void)
{
	int err=0;
        printk("Init bankproc.c\n");

	init_variables();

	printk(KERN_INFO "Registering LITMUS^RT proc color sysctl.\n");

	litmus_sysctls = register_sysctl_table(litmus_dir_table);
	if (!litmus_sysctls) {
		printk(KERN_WARNING "Could not register LITMUS^RT color sysctl.\n");
		err = -EFAULT;
		goto out;
	}

	init_color_groups();			
	do_add_pages();

	printk(KERN_INFO "Registering LITMUS^RT color and bank proc.\n");
out:
	return err;
}

module_init(litmus_color_init);


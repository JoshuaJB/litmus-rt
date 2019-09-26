/*
 * page_dev.c - Implementation of the page coloring for cache and bank partition.
 *              The file will keep a pool of colored pages. MMU can allocate pages with
 *		        specific color or bank number.
 * Author: Namhoon Kim (namhoonk@cs.unc.edu)
 */

#include <litmus/page_dev.h>
#include <litmus/debug_trace.h>

// This Address Decoding is used in imx6-sabredsd platform
#define NUM_BANKS	8
#define BANK_MASK	0x38000000
#define BANK_SHIFT  27

#define NUM_COLORS	16
#define CACHE_MASK  0x0000f000
#define CACHE_SHIFT 12

#define NR_LLC_PARTITIONS		9
#define NR_DRAM_PARTITIONS		5

struct mutex dev_mutex;

/* Initial partitions for LLC and DRAM bank */
/* 4 color for each core, all colors for Level C */
unsigned int llc_partition[NR_LLC_PARTITIONS] = {
	0x0000000f,  /* Core 0, and Level A*/
	0x0000000f,  /* Core 0, and Level B*/
	0x000000f0,  /* Core 1, and Level A*/
	0x000000f0,  /* Core 1, and Level B*/
	0x00000f00,  /* Core 2, and Level A*/
	0x00000f00,  /* Core 2, and Level B*/
	0x0000f000,  /* Core 3, and Level A*/
	0x0000f000,  /* Core 3, and Level B*/
	0x0000ffff,  /* Level C */
};

/* 1 bank for each core, 2 banks for Level C */
unsigned int dram_partition[NR_DRAM_PARTITIONS] = {
	0x00000010,
	0x00000020,
	0x00000040,
	0x00000080,
	0x0000000f,
};

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

int bank_to_partition(unsigned int bank)
{
	int i;
	unsigned int bank_bit = 0x1<<bank;

	for (i = 0; i<NR_DRAM_PARTITIONS; i++) {
		if (dram_partition[i] & bank_bit)
			return i;
	}

	return -EINVAL;
}

int get_area_index(int cpu)
{
	int index = 0x10, area_index = 0;

	while (index < 0x100) {
		if (dram_partition[cpu]&index)
			break;
		index = index << 1;
		area_index++;
	}

	return area_index;
}

/* use this function ONLY for Lv.A/B pages */
int is_in_correct_bank(struct page* page, int cpu)
{
	int bank;
	unsigned int page_bank_bit;

	bank = page_bank(page);
	page_bank_bit = 1 << bank;

	if (cpu == -1 || cpu == NR_CPUS)
		return (page_bank_bit & dram_partition[NR_CPUS]);
	else
		return (page_bank_bit & dram_partition[cpu]);
}

int is_in_llc_partition(struct page* page, int cpu)
{
	int color;
	unsigned int page_color_bit;

	color = page_color(page);
	page_color_bit = 1 << color;

	if (cpu == -1 || cpu == NR_CPUS)
		return (page_color_bit & llc_partition[8]);
	else
		return (page_color_bit & (llc_partition[cpu*2] | llc_partition[cpu*2+1]));
}

/* Bounds for values */
unsigned int llc_partition_max = 0x0000ffff;
unsigned int llc_partition_min = 0;
unsigned int dram_partition_max = 0x000000ff;
unsigned int dram_partition_min = 0;

/* slabtest module */
int buf_size = 0;
int buf_num = 1;

int slabtest_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	int** testbuffer;
	mutex_lock(&dev_mutex);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (ret)
		goto out;

	if (write) {
		int idx;
		int n_data = buf_size/sizeof(int);

		printk(KERN_INFO "-------SLABTEST on CPU%d with %d buffer size\n", raw_smp_processor_id(), buf_size);

		testbuffer = kmalloc(sizeof(int*)*buf_num, GFP_KERNEL|GFP_COLOR|GFP_CPU1);

		for (idx=0; idx<buf_num; idx++)
		{
			printk(KERN_INFO "kmalloc size %d, n_data %d\n", buf_size, n_data);
			testbuffer[idx] = kmalloc(buf_size, GFP_KERNEL|GFP_COLOR|GFP_CPU1);

			if (!testbuffer[idx]) {
				printk(KERN_ERR "kmalloc failed size = %d\n", buf_size);
				goto out;
			}
		}


		/* do test */
		for (idx=0; idx<buf_num; idx++)
		{
			int t = 0;
			printk(KERN_INFO "kmalloc size = %d n_data = %d\n", buf_size, n_data);
			printk(KERN_INFO "write data to buffer\n");
			for (i = 0; i < n_data; i++) {
				testbuffer[idx][i] = i%27;
			}
			printk(KERN_INFO "read data from buffer\n");
			for (i = 0; i < n_data; i++) {
				t += testbuffer[idx][i];
				//printk(KERN_INFO "[%d] = %d\n", i, testbuffer[idx][i]);
			}
		}

		for (idx=0; idx<buf_num; idx++)
			kfree(testbuffer[idx]);

		kfree(testbuffer);
		printk(KERN_INFO "-------SLABTEST FINISHED on CPU%d\n", raw_smp_processor_id());
	}
out:
	mutex_unlock(&dev_mutex);
	return ret;
}

int num_buffer_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = 0;
	mutex_lock(&dev_mutex);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (ret)
		goto out;

	if (write) {
		printk(KERN_INFO "buf_num = %d\n", buf_num);
	}
out:
	mutex_unlock(&dev_mutex);
	return ret;
}

static struct ctl_table partition_table[] =
{

	{
		.procname	= "C0_LA_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[0],
		.maxlen		= sizeof(llc_partition[0]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "C0_LB_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[1],
		.maxlen		= sizeof(llc_partition[1]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "C1_LA_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[2],
		.maxlen		= sizeof(llc_partition[2]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "C1_LB_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[3],
		.maxlen		= sizeof(llc_partition[3]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "C2_LA_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[4],
		.maxlen		= sizeof(llc_partition[4]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "C2_LB_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[5],
		.maxlen		= sizeof(llc_partition[5]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "C3_LA_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[6],
		.maxlen		= sizeof(llc_partition[6]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "C3_LB_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[7],
		.maxlen		= sizeof(llc_partition[7]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "Call_LC_color",
		.mode		= 0666,
		.proc_handler	= llc_partition_handler,
		.data		= &llc_partition[8],
		.maxlen		= sizeof(llc_partition[8]),
		.extra1		= &llc_partition_min,
		.extra2		= &llc_partition_max,
	},
	{
		.procname	= "C0_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[0],
		.maxlen		= sizeof(llc_partition[0]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},
	{
		.procname	= "C1_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[1],
		.maxlen		= sizeof(llc_partition[1]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},
	{
		.procname	= "C2_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[2],
		.maxlen		= sizeof(llc_partition[2]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},
	{
		.procname	= "C3_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[3],
		.maxlen		= sizeof(llc_partition[3]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},
	{
		.procname	= "CS_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[4],
		.maxlen		= sizeof(llc_partition[4]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},
	{
		.procname	= "slabtest",
		.mode		= 0666,
		.proc_handler	= slabtest_handler,
		.data		= &buf_size,
		.maxlen		= sizeof(buf_size),
	},
	{
		.procname	= "num_buffer",
		.mode		= 0666,
		.proc_handler	= num_buffer_handler,
		.data		= &buf_num,
		.maxlen		= sizeof(buf_num),
	},
	{ }
};

static struct ctl_table litmus_dir_table[] = {
	{
		.procname	= "litmus",
		.mode		= 0555,
		.child		= partition_table,
	},
	{ }
};

static struct ctl_table_header *litmus_sysctls;

int llc_partition_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	mutex_lock(&dev_mutex);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	if (write) {
		printk("New LLC Partition : \n");
	    for(i = 0; i < NR_LLC_PARTITIONS; i++) {
			printk("llc_partition[%d] = 0x%04x\n", i, llc_partition[i]);
		}
	}
out:
	mutex_unlock(&dev_mutex);
	return ret;
}

int dram_partition_handler(struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	mutex_lock(&dev_mutex);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	if (write) {
		for(i = 0; i < NR_DRAM_PARTITIONS; i++) {
			printk("dram_partition[%d] = 0x%04x\n", i, dram_partition[i]);
		}
	}
out:
	mutex_unlock(&dev_mutex);
	return ret;
}

/*
 * Initialize this page_dev proc.
 */
static int __init init_litmus_page_dev(void)
{
	int err = 0;

	printk("Initialize page_dev.c\n");

	mutex_init(&dev_mutex);

	litmus_sysctls = register_sysctl_table(litmus_dir_table);
	if (!litmus_sysctls) {
		printk(KERN_WARNING "Could not register LITMUS^RT page_dev sysctl.\n");
		err = -EFAULT;
		goto out;
	}

	printk(KERN_INFO "Registering LITMUS^RT page_dev proc.\n");
out:
	return err;
}

static void __exit exit_litmus_page_dev(void)
{
	mutex_destroy(&dev_mutex);
}

module_init(init_litmus_page_dev);
module_exit(exit_litmus_page_dev);

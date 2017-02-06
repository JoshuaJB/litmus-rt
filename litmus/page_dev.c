/*
 * page_dev.c - Implementation of the page coloring for cache and bank partition. 
 *              The file will keep a pool of colored pages. MMU can allocate pages with 
 *		        specific color or bank number.
 * Author: Namhoon Kim (namhoonk@cs.unc.edu)
 */
 
#include <litmus/page_dev.h>

#define NR_PARTITIONS		9

struct mutex dev_mutex;

/* Initial partitions for LLC and DRAM bank */
/* 4 color for each core, all colors for Level C */
unsigned int llc_partition[NR_PARTITIONS] = {
	0x00000003,  /* Core 0, and Level A*/
	0x00000003,  /* Core 0, and Level B*/
	0x0000000C,  /* Core 1, and Level A*/
	0x0000000C,  /* Core 1, and Level B*/
	0x00000030,  /* Core 2, and Level A*/
	0x00000030,  /* Core 2, and Level B*/
	0x000000C0,  /* Core 3, and Level A*/
	0x000000C0,  /* Core 3, and Level B*/
	0x0000ffff,  /* Level C */
};

/* 1 bank for each core, 2 banks for Level C */
unsigned int dram_partition[NR_PARTITIONS] = {
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

/* Bounds for values */ 
unsigned int llc_partition_max = 0x0000ffff;
unsigned int llc_partition_min = 0;
unsigned int dram_partition_max = 0x000000ff;
unsigned int dram_partition_min = 0;

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
		.procname	= "C0_LA_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[0],
		.maxlen		= sizeof(llc_partition[0]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},
	{
		.procname	= "C0_LB_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[1],
		.maxlen		= sizeof(llc_partition[1]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},		
	{
		.procname	= "C1_LA_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[2],
		.maxlen		= sizeof(llc_partition[2]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},
	{
		.procname	= "C1_LB_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[3],
		.maxlen		= sizeof(llc_partition[3]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},
	{
		.procname	= "C2_LA_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[4],
		.maxlen		= sizeof(llc_partition[4]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},	
	{
		.procname	= "C2_LB_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[5],
		.maxlen		= sizeof(llc_partition[5]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},		
	{
		.procname	= "C3_LA_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[6],
		.maxlen		= sizeof(llc_partition[6]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},	
	{
		.procname	= "C3_LB_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[7],
		.maxlen		= sizeof(llc_partition[7]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
	},	
	{
		.procname	= "Call_LC_dram",
		.mode		= 0666,
		.proc_handler	= dram_partition_handler,
		.data		= &dram_partition[8],
		.maxlen		= sizeof(llc_partition[8]),
		.extra1		= &dram_partition_min,
		.extra2		= &dram_partition_max,
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
	    for(i = 0; i < NR_PARTITIONS; i++) {
			printk("llc_partition[%d] = %x\n", i, llc_partition[i]);
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
		for(i = 0; i < NR_PARTITIONS; i++) {
			printk("dram_partition[%d] = %x\n", i, dram_partition[i]);
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

	printk(KERN_INFO "Registering LITMUS^RT proc page_dev sysctl.\n");

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
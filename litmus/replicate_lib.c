#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/migrate.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>

#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/cache_proc.h>
#include <litmus/mc2_common.h>
#include <litmus/replicate_lib.h>

DEFINE_PER_CPU(struct list_head, shared_lib_page_list);

#define shared_lib_pages_for(cpu_id)	(&per_cpu(shared_lib_page_list, cpu_id))
#define local_shared_lib_pages()	(this_cpu_ptr(&shared_lib_page_list))

#define INVALID_PFN				(0xffffffff)

static int __init litmus_replicate_lib_init(void)
{
	int cpu, ret = 0;

	printk(KERN_INFO "Registering LITMUS^RT Per-core Shared Library module.\n");

	for_each_online_cpu(cpu) {
		INIT_LIST_HEAD(shared_lib_pages_for(cpu));
		printk(KERN_INFO "CPU%d PSL-list initialized.\n", cpu);
	}

	return ret;
}

static void litmus_replicate_lib_exit(void)
{
	return;
}

module_init(litmus_replicate_lib_init);
module_exit(litmus_replicate_lib_exit);

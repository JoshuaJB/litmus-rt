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
#include <linux/random.h>
#include <linux/sched.h>

#include <litmus/rt_param.h>
#include <litmus/litmus.h>
#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/cache_proc.h>
#include <litmus/mc2_common.h>

#include <asm/hardware/cache-l2x0.h>
#include <asm/cacheflush.h>

#define UNLOCK_ALL	0x00000000 /* allocation in any way */
#define LOCK_ALL        (~UNLOCK_ALL)
#define MAX_NR_WAYS	16
#define MAX_NR_COLORS	16
#define CACHELINE_SIZE 32
#define INTS_IN_CACHELINE (CACHELINE_SIZE/sizeof(int))
#define CACHELINES_IN_1KB (1024 / sizeof(cacheline_t))

typedef struct cacheline
{
        int line[INTS_IN_CACHELINE];
} __attribute__((aligned(CACHELINE_SIZE))) cacheline_t;

void mem_lock(u32 lock_val, int cpu);

/*
 * unlocked_way[i] : allocation can occur in way i
 *
 * 0 = allocation can occur in the corresponding way
 * 1 = allocation cannot occur in the corresponding way
 */
u32 unlocked_way[MAX_NR_WAYS]  = {
	0xFFFFFFFE, /* way 0 unlocked */
	0xFFFFFFFD,
	0xFFFFFFFB,
	0xFFFFFFF7,
	0xFFFFFFEF, /* way 4 unlocked */
	0xFFFFFFDF,
	0xFFFFFFBF,
	0xFFFFFF7F,
	0xFFFFFEFF, /* way 8 unlocked */
	0xFFFFFDFF,
	0xFFFFFBFF,
	0xFFFFF7FF,
	0xFFFFEFFF, /* way 12 unlocked */
	0xFFFFDFFF,
	0xFFFFBFFF,
	0xFFFF7FFF,
};

u32 nr_unlocked_way[MAX_NR_WAYS+1]  = {
	0x0000FFFF, /* all ways are locked. usable = 0*/
	0x0000FFFE, /* way ~0 unlocked. usable = 1 */
	0x0000FFFC,
	0x0000FFF8,
	0x0000FFF0,
	0x0000FFE0,
	0x0000FFC0,
	0x0000FF80,
	0x0000FF00,
	0x0000FE00,
	0x0000FC00,
	0x0000F800,
	0x0000F000,
	0x0000E000,
	0x0000C000,
	0x00008000,
	0x00000000, /* way ~15 unlocked. usable = 16 */
};

u32 way_partition[4] = {
	0xfffffff0, /* cpu0 */
	0xffffff0f, /* cpu1 */
	0xfffff0ff, /* cpu2 */
	0xffff0fff, /* cpu3 */
};

u32 way_partitions[9] = {
	0xffff00ff, /* cpu0 A */
	0xffff00ff, /* cpu0 B */
	0xffff00ff, /* cpu1 A */
	0xffff00ff, /* cpu1 B */
	0xffff00ff, /* cpu2 A */
	0xffff00ff, /* cpu2 B */
	0xffff00ff, /* cpu3 A */
	0xffff00ff, /* cpu3 B */
	0xffffff00, /* lv C */
};

u32 prev_lockdown_d_reg[5] = {
	0x0000FF00,
	0x0000FF00,
	0x0000FF00,
	0x0000FF00,
	0x000000FF, /* share with level-C */
};

u32 prev_lockdown_i_reg[5] = {
	0x0000FF00,
	0x0000FF00,
	0x0000FF00,
	0x0000FF00,
	0x000000FF, /* share with level-C */
};

u32 prev_lbm_i_reg[8] = {
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};

u32 prev_lbm_d_reg[8] = {
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};

static void __iomem *cache_base;
static void __iomem *lockreg_d;
static void __iomem *lockreg_i;

static u32 cache_id;

struct mutex actlr_mutex;
struct mutex l2x0_prefetch_mutex;
struct mutex lockdown_proc;
static u32 way_partition_min;
static u32 way_partition_max;

static int zero = 0;
static int one = 1;

static int l1_prefetch_proc;
static int l2_prefetch_hint_proc;
static int l2_double_linefill_proc;
static int l2_data_prefetch_proc;
static int os_isolation;
static int use_part;

struct mutex debug_mutex;

u32 lockdown_reg[9] = {
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};


#define ld_d_reg(cpu) ({ int __cpu = cpu; \
			void __iomem *__v = cache_base + L2X0_LOCKDOWN_WAY_D_BASE + \
			__cpu * L2X0_LOCKDOWN_STRIDE; __v; })
#define ld_i_reg(cpu) ({ int __cpu = cpu; \
			void __iomem *__v = cache_base + L2X0_LOCKDOWN_WAY_I_BASE + \
			__cpu * L2X0_LOCKDOWN_STRIDE; __v; })

int lock_all;
int nr_lockregs;
static raw_spinlock_t cache_lock;
static raw_spinlock_t prefetch_lock;
static void ***flusher_pages = NULL;

extern void l2c310_flush_all(void);

static inline void cache_wait_way(void __iomem *reg, unsigned long mask)
{
	/* wait for cache operation by line or way to complete */
	while (readl_relaxed(reg) & mask)
		cpu_relax();
}

#ifdef CONFIG_CACHE_L2X0
static inline void cache_wait(void __iomem *reg, unsigned long mask)
{
	/* cache operations by line are atomic on PL310 */
}
#else
#define cache_wait	cache_wait_way
#endif

static inline void cache_sync(void)
{
	void __iomem *base = cache_base;

	writel_relaxed(0, base + L2X0_CACHE_SYNC);
	cache_wait(base + L2X0_CACHE_SYNC, 1);
}

static void print_lockdown_registers(int cpu)
{
	int i;
	//for (i = 0; i < nr_lockregs; i++) {
	for (i = 0; i < 4; i++) {
		printk("P%d Lockdown Data CPU %2d: 0x%04x\n", cpu,
				i, readl_relaxed(ld_d_reg(i)));
		printk("P%d Lockdown Inst CPU %2d: 0x%04x\n", cpu,
				i, readl_relaxed(ld_i_reg(i)));
	}
}

static void test_lockdown(void *ignore)
{
	int i, cpu;

	cpu = smp_processor_id();
	printk("Start lockdown test on CPU %d.\n", cpu);

	for (i = 0; i < nr_lockregs; i++) {
		printk("CPU %2d data reg: 0x%8p\n", i, ld_d_reg(i));
		printk("CPU %2d inst reg: 0x%8p\n", i, ld_i_reg(i));
	}

	printk("Lockdown initial state:\n");
	print_lockdown_registers(cpu);
	printk("---\n");

	for (i = 0; i < nr_lockregs; i++) {
		writel_relaxed(1, ld_d_reg(i));
		writel_relaxed(2, ld_i_reg(i));
	}
	printk("Lockdown all data=1 instr=2:\n");
	print_lockdown_registers(cpu);
	printk("---\n");

	for (i = 0; i < nr_lockregs; i++) {
		writel_relaxed((1 << i), ld_d_reg(i));
		writel_relaxed(((1 << 8) >> i), ld_i_reg(i));
	}
	printk("Lockdown varies:\n");
	print_lockdown_registers(cpu);
	printk("---\n");

	for (i = 0; i < nr_lockregs; i++) {
		writel_relaxed(UNLOCK_ALL, ld_d_reg(i));
		writel_relaxed(UNLOCK_ALL, ld_i_reg(i));
	}
	printk("Lockdown all zero:\n");
	print_lockdown_registers(cpu);

	printk("End lockdown test.\n");
}

void litmus_setup_lockdown(void __iomem *base, u32 id)
{
	cache_base = base;
	cache_id = id;
	lockreg_d = cache_base + L2X0_LOCKDOWN_WAY_D_BASE;
	lockreg_i = cache_base + L2X0_LOCKDOWN_WAY_I_BASE;

	if (L2X0_CACHE_ID_PART_L310 == (cache_id & L2X0_CACHE_ID_PART_MASK)) {
		nr_lockregs = 8;
	} else {
		printk("Unknown cache ID!\n");
		nr_lockregs = 1;
	}

	mutex_init(&actlr_mutex);
	mutex_init(&l2x0_prefetch_mutex);
	mutex_init(&lockdown_proc);
	mutex_init(&debug_mutex);
	raw_spin_lock_init(&cache_lock);
	raw_spin_lock_init(&prefetch_lock);

	test_lockdown(NULL);
}

int way_partition_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	unsigned long flags;

	mutex_lock(&lockdown_proc);

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;

	if (write) {
		printk("Way-partition settings:\n");
		for (i = 0; i < 9; i++) {
			printk("0x%08X\n", way_partitions[i]);
		}
		for (i = 0; i < 4; i++) {
			writel_relaxed(~way_partitions[i*2], cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
			writel_relaxed(~way_partitions[i*2], cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
		}
	}

	local_irq_save(flags);
	print_lockdown_registers(smp_processor_id());
	l2c310_flush_all();
	local_irq_restore(flags);
out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

int lock_all_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	unsigned long flags;

	mutex_lock(&lockdown_proc);

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;

	if (write && lock_all == 1) {
		for (i = 0; i < nr_lockregs; i++) {
			writel_relaxed(0xFFFF, cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
			writel_relaxed(0xFFFF, cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
		}
/*
		for (i = 0; i < nr_lockregs;  i++) {
			barrier();
			mem_lock(LOCK_ALL, i);
			barrier();
			//writel_relaxed(nr_unlocked_way[0], ld_d_reg(i));
			//writel_relaxed(nr_unlocked_way[0], ld_i_reg(i));
		}
*/
	}
	if (write && lock_all == 0) {
		for (i = 0; i < nr_lockregs; i++) {
			writel_relaxed(0x0, cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
			writel_relaxed(0x0, cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
		}

	}

	local_irq_save(flags);
	print_lockdown_registers(smp_processor_id());
	l2c310_flush_all();
	local_irq_restore(flags);
out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

void cache_lockdown(u32 lock_val, int cpu)
{
	__asm__ __volatile__ (
"	str	%[lockval], [%[dcachereg]]\n"
"	str	%[lockval], [%[icachereg]]\n"
	:
	: [dcachereg] "r" (ld_d_reg(cpu)),
	  [icachereg] "r" (ld_i_reg(cpu)),
	  [lockval] "r" (lock_val)
	: "cc");
}

void do_partition(enum crit_level lv, int cpu)
{
	u32 regs;
	unsigned long flags;

	if (lock_all || !use_part)
		return;
	raw_spin_lock_irqsave(&cache_lock, flags);
	switch(lv) {
		case CRIT_LEVEL_A:
			regs = ~way_partitions[cpu*2];
			regs &= 0x0000ffff;
			break;
		case CRIT_LEVEL_B:
			regs = ~way_partitions[cpu*2+1];
			regs &= 0x0000ffff;
			break;
		case CRIT_LEVEL_C:
		case NUM_CRIT_LEVELS:
			regs = ~way_partitions[8];
			regs &= 0x0000ffff;
			break;
		default:
			BUG();

	}
	barrier();

	writel_relaxed(regs, cache_base + L2X0_LOCKDOWN_WAY_D_BASE + cpu * L2X0_LOCKDOWN_STRIDE);
	writel_relaxed(regs, cache_base + L2X0_LOCKDOWN_WAY_I_BASE + cpu * L2X0_LOCKDOWN_STRIDE);
	barrier();

	raw_spin_unlock_irqrestore(&cache_lock, flags);
}

void lock_cache(int cpu, u32 val)
{
	unsigned long flags;

	local_irq_save(flags);
	if (val != 0xffffffff) {
		writel_relaxed(val, cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
					   cpu * L2X0_LOCKDOWN_STRIDE);
		writel_relaxed(val, cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
					   cpu * L2X0_LOCKDOWN_STRIDE);
	}
	else {
		int i;
		for (i = 0; i < 4; i++)
			do_partition(CRIT_LEVEL_A, i);
	}
	local_irq_restore(flags);
}

int use_part_proc_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0;

	mutex_lock(&lockdown_proc);

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;


	printk("USE_PART HANDLER = %d\n", use_part);

out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

int os_isolation_proc_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0;

	mutex_lock(&lockdown_proc);

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;


	printk("OS_ISOLATION HANDLER = %d\n", os_isolation);

out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

int lockdown_reg_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;

	mutex_lock(&lockdown_proc);

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;

	if (write) {
		for (i = 0; i < nr_lockregs; i++) {
			writel_relaxed(lockdown_reg[i], cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
			writel_relaxed(lockdown_reg[i], cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
		}
	}

out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

int lockdown_global_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;

	mutex_lock(&lockdown_proc);

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;

	if (write) {
		for (i = 0; i < nr_lockregs; i++) {
			writel_relaxed(lockdown_reg[8], cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
			writel_relaxed(lockdown_reg[8], cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
		}
	}

out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

void inline enter_irq_mode(void)
{
	int cpu = smp_processor_id();

	if (os_isolation == 0)
		return;
	prev_lockdown_i_reg[cpu] = readl_relaxed(ld_i_reg(cpu));
	prev_lockdown_d_reg[cpu] = readl_relaxed(ld_d_reg(cpu));
	writel_relaxed(way_partitions[8], ld_i_reg(cpu));
	writel_relaxed(way_partitions[8], ld_d_reg(cpu));
}

void inline exit_irq_mode(void)
{
	int cpu = smp_processor_id();

	if (os_isolation == 0)
		return;

	writel_relaxed(prev_lockdown_i_reg[cpu], ld_i_reg(cpu));
	writel_relaxed(prev_lockdown_d_reg[cpu], ld_d_reg(cpu));
}

/* Operate on the Cortex-A9's ACTLR register */
#define ACTLR_L2_PREFETCH_HINT	(1 << 1)
#define ACTLR_L1_PREFETCH	(1 << 2)

/*
 * Change the ACTLR.
 * @mode	- If 1 (0), set (clear) the bit given in @mask in the ACTLR.
 * @mask	- A mask in which one bit is set to operate on the ACTLR.
 */
static void actlr_change(int mode, int mask)
{
	u32 orig_value, new_value, reread_value;

	if (0 != mode && 1 != mode) {
		printk(KERN_WARNING "Called %s with mode != 0 and mode != 1.\n",
				__FUNCTION__);
		return;
	}

	/* get the original value */
	asm volatile("mrc p15, 0, %0, c1, c0, 1" : "=r" (orig_value));

	if (0 == mode)
		new_value = orig_value & ~(mask);
	else
		new_value = orig_value | mask;

	asm volatile("mcr p15, 0, %0, c1, c0, 1" : : "r" (new_value));
	asm volatile("mrc p15, 0, %0, c1, c0, 1" : "=r" (reread_value));

	printk("ACTLR: orig: 0x%8x  wanted: 0x%8x  new: 0x%8x\n",
			orig_value, new_value, reread_value);
}

int litmus_l1_prefetch_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&actlr_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);

	if (!ret && write) {
		mode = *((int*)table->data);
		actlr_change(mode, ACTLR_L1_PREFETCH);
	}
	mutex_unlock(&actlr_mutex);

	return ret;
}

int litmus_l2_prefetch_hint_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&actlr_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!ret && write) {
		mode = *((int*)table->data);
		actlr_change(mode, ACTLR_L2_PREFETCH_HINT);
	}
	mutex_unlock(&actlr_mutex);

	return ret;
}


/* Operate on the PL-310's Prefetch Control Register, L310_PREFETCH_CTRL */
#define L2X0_PREFETCH_DOUBLE_LINEFILL	(1 << 30)
#define L2X0_PREFETCH_INST_PREFETCH	(1 << 29)
#define L2X0_PREFETCH_DATA_PREFETCH	(1 << 28)
static void l2x0_prefetch_change(int mode, int mask)
{
	u32 orig_value, new_value, reread_value;

	if (0 != mode && 1 != mode) {
		printk(KERN_WARNING "Called %s with mode != 0 and mode != 1.\n",
				__FUNCTION__);
		return;
	}

	orig_value = readl_relaxed(cache_base + L310_PREFETCH_CTRL);

	if (0 == mode)
		new_value = orig_value & ~(mask);
	else
		new_value = orig_value | mask;

	writel_relaxed(new_value, cache_base + L310_PREFETCH_CTRL);
	reread_value = readl_relaxed(cache_base + L310_PREFETCH_CTRL);

	printk("l2x0 prefetch: orig: 0x%8x  wanted: 0x%8x  new: 0x%8x\n",
			orig_value, new_value, reread_value);
}

int litmus_l2_double_linefill_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&l2x0_prefetch_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!ret && write) {
		mode = *((int*)table->data);
		l2x0_prefetch_change(mode, L2X0_PREFETCH_DOUBLE_LINEFILL);
	}
	mutex_unlock(&l2x0_prefetch_mutex);

	return ret;
}

int litmus_l2_data_prefetch_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&l2x0_prefetch_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!ret && write) {
		mode = *((int*)table->data);
		l2x0_prefetch_change(mode, L2X0_PREFETCH_DATA_PREFETCH|L2X0_PREFETCH_INST_PREFETCH);
	}
	mutex_unlock(&l2x0_prefetch_mutex);

	return ret;
}

extern void *msgvaddr;

int do_measure(void) {
	lt_t t1, t2;
	int i;

	barrier();
	t1 = litmus_clock();
	color_read_in_mem_lock(0xFFFF7FFF, 0xFFFF8000, msgvaddr, msgvaddr + 65536);
	t2 = litmus_clock() - t1;
	barrier();

	for (i = 0; i < 8; i++) {
		cache_lockdown(0xFFFF8000, i);
	}
	printk("mem read time %lld\n", t2);

	return 0;
}

int debug_test_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = 0;

	if (write) {
		ret = do_measure();
	}

	return ret;
}


int do_perf_test_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);

int setup_flusher_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);

static struct ctl_table cache_table[] =
{
	{
		.procname	= "C0_LA_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[0],
		.maxlen		= sizeof(way_partitions[0]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C0_LB_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[1],
		.maxlen		= sizeof(way_partitions[1]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C1_LA_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[2],
		.maxlen		= sizeof(way_partitions[2]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C1_LB_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[3],
		.maxlen		= sizeof(way_partitions[3]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C2_LA_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[4],
		.maxlen		= sizeof(way_partitions[4]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C2_LB_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[5],
		.maxlen		= sizeof(way_partitions[5]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C3_LA_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[6],
		.maxlen		= sizeof(way_partitions[6]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C3_LB_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[7],
		.maxlen		= sizeof(way_partitions[7]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "Call_LC_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[8],
		.maxlen		= sizeof(way_partitions[8]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "lock_all",
		.mode		= 0666,
		.proc_handler	= lock_all_handler,
		.data		= &lock_all,
		.maxlen		= sizeof(lock_all),
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "l1_prefetch",
		.mode		= 0644,
		.proc_handler	= litmus_l1_prefetch_proc_handler,
		.data		= &l1_prefetch_proc,
		.maxlen		= sizeof(l1_prefetch_proc),
	},
	{
		.procname	= "l2_prefetch_hint",
		.mode		= 0644,
		.proc_handler	= litmus_l2_prefetch_hint_proc_handler,
		.data		= &l2_prefetch_hint_proc,
		.maxlen		= sizeof(l2_prefetch_hint_proc),
	},
	{
		.procname	= "l2_double_linefill",
		.mode		= 0644,
		.proc_handler	= litmus_l2_double_linefill_proc_handler,
		.data		= &l2_double_linefill_proc,
		.maxlen		= sizeof(l2_double_linefill_proc),
	},
	{
		.procname	= "l2_data_prefetch",
		.mode		= 0644,
		.proc_handler	= litmus_l2_data_prefetch_proc_handler,
		.data		= &l2_data_prefetch_proc,
		.maxlen		= sizeof(l2_data_prefetch_proc),
	},
	{
		.procname	= "os_isolation",
		.mode		= 0644,
		.proc_handler	= os_isolation_proc_handler,
		.data		= &os_isolation,
		.maxlen		= sizeof(os_isolation),
	},
	{
		.procname	= "use_part",
		.mode		= 0644,
		.proc_handler	= use_part_proc_handler,
		.data		= &use_part,
		.maxlen		= sizeof(use_part),
	},
	{
		.procname	= "do_perf_test",
		.mode		= 0644,
		.proc_handler	= do_perf_test_proc_handler,
	},
	{
		.procname	= "setup_flusher",
		.mode		= 0644,
		.proc_handler	= setup_flusher_proc_handler,
	},
	{
		.procname	= "lockdown_reg_0",
		.mode		= 0644,
		.proc_handler	= lockdown_reg_handler,
		.data		= &lockdown_reg[0],
		.maxlen		= sizeof(lockdown_reg[0]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "lockdown_reg_1",
		.mode		= 0644,
		.proc_handler	= lockdown_reg_handler,
		.data		= &lockdown_reg[1],
		.maxlen		= sizeof(lockdown_reg[1]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "lockdown_reg_2",
		.mode		= 0644,
		.proc_handler	= lockdown_reg_handler,
		.data		= &lockdown_reg[2],
		.maxlen		= sizeof(lockdown_reg[2]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "lockdown_reg_3",
		.mode		= 0644,
		.proc_handler	= lockdown_reg_handler,
		.data		= &lockdown_reg[3],
		.maxlen		= sizeof(lockdown_reg[3]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "lockdown_regs",
		.mode		= 0644,
		.proc_handler	= lockdown_global_handler,
		.data		= &lockdown_reg[8],
		.maxlen		= sizeof(lockdown_reg[8]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "debug_test",
		.mode		= 0644,
		.proc_handler	= debug_test_handler,
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

u32 color_read_in_mem(u32 lock_val, u32 unlock_val, void *start, void *end)
{
	u32 v = 0;

	__asm__ __volatile__ (
"	.align 5\n"
"	str	%[lockval], [%[cachereg]]\n"
"1:	ldr	%[val], [%[addr]], #32		@ 32 bytes = 1 cache line\n"
"	cmp	%[end], %[addr]			@ subtracts addr from end\n"
"	bgt	1b\n				@ read more, if necessary\n"
	: [addr] "+r" (start),
	  [val] "+r" (v)
	: [end] "r" (end),
#ifdef CONFIG_CACHE_L2X0
	  [cachereg] "r" (ld_d_reg(raw_smp_processor_id())),
#else
	  [cachereg] "r" (lockreg_d),
#endif
	  [lockval] "r" (lock_val)
	: "cc");

	return v;
}


/*
 * Prefetch by reading the first word of each cache line in a page.
 *
 * @lockdown_reg: address of the lockdown register to write
 * @lock_val: value to be written to @lockdown_reg
 * @unlock_val: will unlock the cache to this value
 * @addr: start address to be prefetched
 * @end_addr: end address to prefetch (exclusive)
 *
 * Assumes: addr < end_addr AND addr != end_addr
 */
u32 color_read_in_mem_lock(u32 lock_val, u32 unlock_val, void *start, void *end)
{
#ifndef CONFIG_CACHE_L2X0
	unsigned long flags;
#endif
	u32 v = 0;

#ifndef CONFIG_CACHE_L2X0
	raw_spin_lock_irqsave(&prefetch_lock, flags);
#endif

	__asm__ __volatile__ (
"	.align 5\n"
"	str	%[lockval], [%[cachereg]]\n"
"1:	ldr	%[val], [%[addr]], #32		@ 32 bytes = 1 cache line\n"
"	cmp	%[end], %[addr]			@ subtracts addr from end\n"
"	bgt	1b\n				@ read more, if necessary\n"
"	str	%[unlockval], [%[cachereg]]\n"
	: [addr] "+r" (start),
	  [val] "+r" (v)
	: [end] "r" (end),
#ifdef CONFIG_CACHE_L2X0
	  [cachereg] "r" (ld_d_reg(raw_smp_processor_id())),
#else
	  [cachereg] "r" (lockreg_d),
#endif
	  [lockval] "r" (lock_val),
	  [unlockval] "r" (unlock_val)
	: "cc");

#ifndef CONFIG_CACHE_L2X0
	raw_spin_unlock_irqrestore(&prefetch_lock, flags);
#endif

	return v;
}

extern void v7_flush_kern_dcache_area(void *, size_t);
extern void v7_flush_kern_cache_all(void);
/*
 * Ensure that this page is not in the L1 or L2 cache.
 * Since the L1 cache is VIPT and the L2 cache is PIPT, we can use either the
 * kernel or user vaddr.
 */
void color_flush_page(void *vaddr, size_t size)
{
	v7_flush_kern_dcache_area(vaddr, size);
	//v7_flush_kern_cache_all();
}

extern struct page* get_colored_page(unsigned long color);

int setup_flusher_array(void)
{
	int color, way, ret = 0;
	struct page *page;

	if (flusher_pages != NULL)
		goto out;

	flusher_pages = (void***) kmalloc(MAX_NR_WAYS
			* sizeof(*flusher_pages), GFP_KERNEL);
	if (!flusher_pages) {
		printk(KERN_WARNING "No memory for flusher array!\n");
		ret = -EINVAL;
		goto out;
	}
	for (way = 0; way < MAX_NR_WAYS; way++) {
		void **flusher_color_arr;
		flusher_color_arr = (void**) kmalloc(sizeof(**flusher_pages)
				* MAX_NR_COLORS, GFP_KERNEL);
		if (!flusher_color_arr) {
			printk(KERN_WARNING "No memory for flusher array!\n");
			ret = -ENOMEM;
			goto out_free;
		}

		flusher_pages[way] = flusher_color_arr;
		for (color = 0; color < MAX_NR_COLORS; color++) {
			int node;
			node = color + 112; // populate from bank 7
			page = get_colored_page(node);
			if (!page) {
				printk(KERN_WARNING "no more colored pages\n");
				ret = -EINVAL;
				goto out_free;
			}
			flusher_pages[way][color] = page_address(page);
			if (!flusher_pages[way][color]) {
				printk(KERN_WARNING "bad page address\n");
				ret = -EINVAL;
				goto out_free;
			}
		}
	}

out:
	return ret;
out_free:
	for (way = 0; way < MAX_NR_WAYS; way++) {
		for (color = 0; color < MAX_NR_COLORS; color++) {
			/* not bothering to try and give back colored pages */
		}
		kfree(flusher_pages[way]);
	}
	kfree(flusher_pages);
	flusher_pages = NULL;
	return ret;
}

void flush_cache(int all)
{
	int way, color, cpu;
	unsigned long flags;

	raw_spin_lock_irqsave(&cache_lock, flags);
	cpu = raw_smp_processor_id();

	prev_lbm_i_reg[cpu] = readl_relaxed(ld_i_reg(cpu));
	prev_lbm_d_reg[cpu] = readl_relaxed(ld_d_reg(cpu));
	for (way=0;way<MAX_NR_WAYS;way++) {
		if (( (0x00000001 << way) & (prev_lbm_d_reg[cpu]) ) &&
			!all)
			continue;
		for (color=0;color<MAX_NR_COLORS;color++) {
			void *vaddr = flusher_pages[way][color];
			u32 lvalue  = unlocked_way[way];
			color_read_in_mem_lock(lvalue, LOCK_ALL,
					       vaddr, vaddr + PAGE_SIZE);
		}

	}

	writel_relaxed(prev_lbm_i_reg[cpu], ld_i_reg(cpu));
	writel_relaxed(prev_lbm_d_reg[cpu], ld_d_reg(cpu));
	raw_spin_unlock_irqrestore(&cache_lock, flags);
}

/* src = shared, dst = local */
#if 1 // random
asmlinkage long sys_run_test(int type, int size, cacheline_t *src, cacheline_t *dst, lt_t __user *ts)
{
	/* size is in KB */
	long ret = 0;
	lt_t t1, t2;
	int numlines = size * CACHELINES_IN_1KB;
	int next, sum = 0, ran;
	unsigned long flags;

	get_random_bytes(&ran, sizeof(int));
	next = ran % ((size*1024)/sizeof(cacheline_t));

	//preempt_disable();
	if (type == 1) {
		int i, j;
		color_read_in_mem_lock(0x0000FFF0, 0x0000000f, (void*)src, (void*)src + size*1024);
		color_read_in_mem_lock(0x0000FF0F, 0x0000000f, (void*)dst, (void*)dst + size*1024);

		local_irq_save(flags);
		t1 = litmus_clock();
		for (i = 0; i < numlines; i++) {
			next = src[next].line[0];
			for (j = 1; j < INTS_IN_CACHELINE; j++) {
				//dst[next].line[j] = src[next].line[j]; // read
				src[next].line[j] = dst[next].line[j]; // write
			}
		}
		t2 = litmus_clock();
		local_irq_restore(flags);
		sum = next + (int)t2;
		t2 -= t1;
		ret = put_user(t2, ts);
	}
	else {
		int i, j;
		color_read_in_mem_lock(0x0000FF0F, 0x0000000f, (void*)dst, (void*)dst + size*1024);
		local_irq_save(flags);
		t1 = litmus_clock();
		for (i = 0; i < numlines; i++) {
			next = src[next].line[0];
			for (j = 1; j < INTS_IN_CACHELINE; j++) {
				//dst[next].line[j] = src[next].line[j]; //read
				src[next].line[j] = dst[next].line[j]; //write
			}
		}
		t2 = litmus_clock();
		local_irq_restore(flags);
		sum = next + (int)t2;
		t2 -= t1;
		ret = put_user(t2, ts);
		v7_flush_kern_dcache_area(src, size*1024);
	}
	//preempt_enable();
	flush_cache(1);

	return ret;
}
#else
// sequential
asmlinkage long sys_run_test(int type, int size, cacheline_t *src, cacheline_t *dst, lt_t __user *ts)
{
	/* size is in KB */
	long ret = 0;
	lt_t t1, t2;
	int numlines = size * CACHELINES_IN_1KB;
	int sum = 0;
	unsigned long flags;

	//preempt_disable();
	if (type == 1) {
		int i, j;
		color_read_in_mem_lock(0x0000FFF0, 0x0000000f, (void*)src, (void*)src + size*1024);
		color_read_in_mem_lock(0x0000FF0F, 0x0000000f, (void*)dst, (void*)dst + size*1024);

		local_irq_save(flags);
		t1 = litmus_clock();
		for (i = 0; i < numlines; i++) {
			for (j = 0; j < INTS_IN_CACHELINE; j++) {
				//dst[i].line[j] = src[i].line[j]; // read
				src[i].line[j] = dst[i].line[j]; // write
			}
		}
		t2 = litmus_clock();
		local_irq_restore(flags);
		sum = (int)(t1 + t2);
		t2 -= t1;
		ret = put_user(t2, ts);
	}
	else {
		int i, j;
		color_read_in_mem_lock(0x0000FF0F, 0x0000000f, (void*)dst, (void*)dst + size*1024);
		local_irq_save(flags);
		t1 = litmus_clock();
		for (i = 0; i < numlines; i++) {
			for (j = 0; j < INTS_IN_CACHELINE; j++) {
				//dst[i].line[j] = src[i].line[j]; //read
				src[i].line[j] = dst[i].line[j]; //write
			}
		}
		t2 = litmus_clock();
		local_irq_restore(flags);
		sum = (int)(t1 + t2);
		t2 -= t1;
		ret = put_user(t2, ts);
		v7_flush_kern_dcache_area(src, size*1024);
	}
	//preempt_enable();
	flush_cache(1);

	return ret;
}
#endif

asmlinkage long sys_lock_buffer(void* vaddr, size_t size, u32 lock_way, u32 unlock_way)
{
	/* size is in bytes */
	long ret = 0;
	u32 lock_val, unlock_val;

	lock_val = ~lock_way & 0x0000ffff;
	unlock_val = ~unlock_way & 0x0000ffff;
	color_read_in_mem_lock(lock_val, unlock_val, (void*)vaddr, (void*)vaddr + size);

	return ret;
}

#define TRIALS 1000

static int perf_test(void) {
	struct page *page, *page2;
	void *vaddr, *vaddr2;
	u32 *data, *data2;
	int i, n, num_pages = 1;
	unsigned int order = 2;
	lt_t t1 = 0, t2 = 0;

	for (i = 0; i < order; i++) {
		num_pages = num_pages*2;
	}

	printk("Number of pages: %d\n", num_pages);
	page = alloc_pages(__GFP_MOVABLE, order);
	if (!page) {
		printk(KERN_WARNING "No memory\n");
		return -ENOMEM;
	}

	page2 = alloc_pages(__GFP_MOVABLE, order);
	if (!page2) {
		printk(KERN_WARNING "No memory\n");
		return -ENOMEM;
	}

	vaddr = page_address(page);
	if (!vaddr)
		printk(KERN_WARNING "%s: vaddr is null\n", __FUNCTION__);
	data = (u32*) vaddr;

	vaddr2 = page_address(page2);
	if (!vaddr2)
		printk(KERN_WARNING "%s: vaddr2 is null\n", __FUNCTION__);
	data2 = (u32*) vaddr2;

	for (i = 32; i < 4096; i *= 2) {
		for (n = 0; n < TRIALS; n++) {
			invalidate_kernel_vmap_range(vaddr, 8192);
			invalidate_kernel_vmap_range(vaddr2, 8192);
			barrier();
			t1 = litmus_clock();
			memcpy(vaddr2, vaddr, i);
			barrier();
			t2 += litmus_clock() - t1;
		}
		printk("Size %d, average for memcpy %lld\n", i, t2>>9);
	}
	//free_page((unsigned long)vaddr);
	free_pages((unsigned long)vaddr, order);
	free_pages((unsigned long)vaddr2, order);

	return 0;
}

int do_perf_test_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = 0;

	if (write) {
		ret = perf_test();
	}

	return ret;
}

int setup_flusher_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = -EINVAL;

	if (write && flusher_pages == NULL) {
		ret = setup_flusher_array();
		printk(KERN_INFO "setup flusher return: %d\n", ret);

	}
	else if (flusher_pages) {
		printk(KERN_INFO "flusher_pages is already set!\n");
		ret = 0;
	}

	return ret;
}

static struct ctl_table_header *litmus_sysctls;

static int __init litmus_sysctl_init(void)
{
	int ret = 0;

	printk(KERN_INFO "Registering LITMUS^RT proc sysctl.\n");
	litmus_sysctls = register_sysctl_table(litmus_dir_table);
	if (!litmus_sysctls) {
		printk(KERN_WARNING "Could not register LITMUS^RT sysctl.\n");
		ret = -EFAULT;
		goto out;
	}

	way_partition_min = 0x00000000;
	way_partition_max = 0x0000FFFF;

out:
	return ret;
}

module_init(litmus_sysctl_init);

/*
 * litmus.c -- Implementation of the LITMUS syscalls,
 *             the LITMUS intialization code,
 *             and the procfs interface..
 */
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/sysrq.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/reboot.h>
#include <linux/stop_machine.h>
#include <linux/sched/rt.h>
#include <linux/rwsem.h>
#include <linux/interrupt.h>
#include <linux/migrate.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>

#include <litmus/litmus.h>
#include <litmus/bheap.h>
#include <litmus/trace.h>
#include <litmus/rt_domain.h>
#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/cache_proc.h>
#include <litmus/mc2_common.h>

#ifdef CONFIG_SCHED_CPU_AFFINITY
#include <litmus/affinity.h>
#endif

#ifdef CONFIG_SCHED_LITMUS_TRACEPOINT
#define CREATE_TRACE_POINTS
#include <trace/events/litmus.h>
#endif

extern void l2c310_flush_all(void);

/* Number of RT tasks that exist in the system */
atomic_t rt_task_count 		= ATOMIC_INIT(0);

#ifdef CONFIG_RELEASE_MASTER
/* current master CPU for handling timer IRQs */
atomic_t release_master_cpu = ATOMIC_INIT(NO_CPU);
#endif

static struct kmem_cache * bheap_node_cache;
extern struct kmem_cache * release_heap_cache;

struct bheap_node* bheap_node_alloc(int gfp_flags)
{
	return kmem_cache_alloc(bheap_node_cache, gfp_flags);
}

void bheap_node_free(struct bheap_node* hn)
{
	kmem_cache_free(bheap_node_cache, hn);
}

struct release_heap* release_heap_alloc(int gfp_flags);
void release_heap_free(struct release_heap* rh);

/**
 * Get the quantum alignment as a cmdline option.
 * Default is staggered quanta, as this results in lower overheads.
 */
static bool aligned_quanta = 0;
module_param(aligned_quanta, bool, 0644);

u64 cpu_stagger_offset(int cpu)
{
	u64 offset = 0;

	if (!aligned_quanta) {
		offset = LITMUS_QUANTUM_LENGTH_NS;
		do_div(offset, num_possible_cpus());
		offset *= cpu;
	}
	return offset;
}

/*
 * sys_set_task_rt_param
 * @pid: Pid of the task which scheduling parameters must be changed
 * @param: New real-time extension parameters such as the execution cost and
 *         period
 * Syscall for manipulating with task rt extension params
 * Returns EFAULT  if param is NULL.
 *         ESRCH   if pid is not corrsponding
 *	           to a valid task.
 *	   EINVAL  if either period or execution cost is <=0
 *	   EPERM   if pid is a real-time task
 *	   0       if success
 *
 * Only non-real-time tasks may be configured with this system call
 * to avoid races with the scheduler. In practice, this means that a
 * task's parameters must be set _before_ calling sys_prepare_rt_task()
 *
 * find_task_by_vpid() assumes that we are in the same namespace of the
 * target.
 */
asmlinkage long sys_set_rt_task_param(pid_t pid, struct rt_task __user * param)
{
	struct rt_task tp;
	struct task_struct *target;
	int retval = -EINVAL;

	printk("Setting up rt task parameters for process %d.\n", pid);

	if (pid < 0 || param == 0) {
		goto out;
	}
	if (copy_from_user(&tp, param, sizeof(tp))) {
		retval = -EFAULT;
		goto out;
	}

	/* Task search and manipulation must be protected */
	read_lock_irq(&tasklist_lock);
	rcu_read_lock();
	if (!(target = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		rcu_read_unlock();
		goto out_unlock;
	}
	rcu_read_unlock();

	if (is_realtime(target)) {
		/* The task is already a real-time task.
		 * We cannot not allow parameter changes at this point.
		 */
		retval = -EBUSY;
		goto out_unlock;
	}

	/* set relative deadline to be implicit if left unspecified */
	if (tp.relative_deadline == 0)
		tp.relative_deadline = tp.period;

	if (tp.exec_cost <= 0)
		goto out_unlock;
	if (tp.period <= 0)
		goto out_unlock;
	if (min(tp.relative_deadline, tp.period) < tp.exec_cost) /*density check*/
	{
		printk(KERN_INFO "litmus: real-time task %d rejected "
		       "because task density > 1.0\n", pid);
		goto out_unlock;
	}
	if (tp.cls != RT_CLASS_HARD &&
	    tp.cls != RT_CLASS_SOFT &&
	    tp.cls != RT_CLASS_BEST_EFFORT)
	{
		printk(KERN_INFO "litmus: real-time task %d rejected "
				 "because its class is invalid\n", pid);
		goto out_unlock;
	}
	if (tp.budget_policy != NO_ENFORCEMENT &&
	    tp.budget_policy != QUANTUM_ENFORCEMENT &&
	    tp.budget_policy != PRECISE_ENFORCEMENT)
	{
		printk(KERN_INFO "litmus: real-time task %d rejected "
		       "because unsupported budget enforcement policy "
		       "specified (%d)\n",
		       pid, tp.budget_policy);
		goto out_unlock;
	}
#ifdef CONFIG_PGMRT_SUPPORT
	if (tp.pgm_type < PGM_NOT_A_NODE || tp.pgm_type > PGM_INTERNAL) {
		printk(KERN_INFO "litmus: real-time task %d rejected "
				"because of unknown PGM node type specified (%d)\n",
				pid, tp.pgm_type);
		goto out_unlock;
	}
#endif

	target->rt_param.task_params = tp;

	retval = 0;
      out_unlock:
	read_unlock_irq(&tasklist_lock);
      out:
	return retval;
}

/*
 * Getter of task's RT params
 *   returns EINVAL if param or pid is NULL
 *   returns ESRCH  if pid does not correspond to a valid task
 *   returns EFAULT if copying of parameters has failed.
 *
 *   find_task_by_vpid() assumes that we are in the same namespace of the
 *   target.
 */
asmlinkage long sys_get_rt_task_param(pid_t pid, struct rt_task __user * param)
{
	int retval = -EINVAL;
	struct task_struct *source;
	struct rt_task lp;
	if (param == 0 || pid < 0)
		goto out;
	read_lock(&tasklist_lock);
	if (!(source = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		goto out_unlock;
	}
	lp = source->rt_param.task_params;
	read_unlock(&tasklist_lock);
	/* Do copying outside the lock */
	retval =
	    copy_to_user(param, &lp, sizeof(lp)) ? -EFAULT : 0;
	return retval;
      out_unlock:
	read_unlock(&tasklist_lock);
      out:
	return retval;

}

/*
 *	This is the crucial function for periodic task implementation,
 *	It checks if a task is periodic, checks if such kind of sleep
 *	is permitted and calls plugin-specific sleep, which puts the
 *	task into a wait array.
 *	returns 0 on successful wakeup
 *	returns EPERM if current conditions do not permit such sleep
 *	returns EINVAL if current task is not able to go to sleep
 */
asmlinkage long sys_complete_job(void)
{
	int retval = -EPERM;
	if (!is_realtime(current)) {
		retval = -EINVAL;
		goto out;
	}
	/* Task with negative or zero period cannot sleep */
	if (get_rt_period(current) <= 0) {
		retval = -EINVAL;
		goto out;
	}
	/* The plugin has to put the task into an
	 * appropriate queue and call schedule
	 */
	retval = litmus->complete_job();
      out:
	return retval;
}

/*	This is an "improved" version of sys_complete_job that
 *      addresses the problem of unintentionally missing a job after
 *      an overrun.
 *
 *	returns 0 on successful wakeup
 *	returns EPERM if current conditions do not permit such sleep
 *	returns EINVAL if current task is not able to go to sleep
 */
asmlinkage long sys_wait_for_job_release(unsigned int job)
{
	int retval = -EPERM;
	if (!is_realtime(current)) {
		retval = -EINVAL;
		goto out;
	}

	/* Task with negative or zero period cannot sleep */
	if (get_rt_period(current) <= 0) {
		retval = -EINVAL;
		goto out;
	}

	retval = 0;

	/* first wait until we have "reached" the desired job
	 *
	 * This implementation has at least two problems:
	 *
	 * 1) It doesn't gracefully handle the wrap around of
	 *    job_no. Since LITMUS is a prototype, this is not much
	 *    of a problem right now.
	 *
	 * 2) It is theoretically racy if a job release occurs
	 *    between checking job_no and calling sleep_next_period().
	 *    A proper solution would requiring adding another callback
	 *    in the plugin structure and testing the condition with
	 *    interrupts disabled.
	 *
	 * FIXME: At least problem 2 should be taken care of eventually.
	 */
	while (!retval && job > current->rt_param.job_params.job_no)
		/* If the last job overran then job <= job_no and we
		 * don't send the task to sleep.
		 */
		retval = litmus->complete_job();
      out:
	return retval;
}

/*	This is a helper syscall to query the current job sequence number.
 *
 *	returns 0 on successful query
 *	returns EPERM if task is not a real-time task.
 *      returns EFAULT if &job is not a valid pointer.
 */
asmlinkage long sys_query_job_no(unsigned int __user *job)
{
	int retval = -EPERM;
	if (is_realtime(current))
		retval = put_user(current->rt_param.job_params.job_no, job);

	return retval;
}

/* sys_null_call() is only used for determining raw system call
 * overheads (kernel entry, kernel exit). It has no useful side effects.
 * If ts is non-NULL, then the current Feather-Trace time is recorded.
 */
asmlinkage long sys_null_call(cycles_t __user *ts)
{
	long ret = 0;
	cycles_t now;

	if (ts) {
		now = get_cycles();
		ret = put_user(now, ts);
	}

	return ret;
}

asmlinkage long sys_reservation_create(int type, void __user *config)
{
    return litmus->reservation_create(type, config);
}

asmlinkage long sys_reservation_destroy(unsigned int reservation_id, int cpu)
{
    return litmus->reservation_destroy(reservation_id, cpu);
}

static unsigned long color_mask;

static inline unsigned long page_color(struct page *page)
{
    return ((page_to_phys(page) & color_mask) >> PAGE_SHIFT);
}

extern int isolate_lru_page(struct page *page);
extern void putback_movable_page(struct page *page);
extern struct page *new_alloc_page(struct page *page, unsigned long node, int **x);

asmlinkage long sys_set_page_color(int cpu)
{
	long ret = 0;
	//struct page *page_itr = NULL;
	struct vm_area_struct *vma_itr = NULL;
	int nr_pages = 0, nr_shared_pages = 0, nr_failed = 0, nr_not_migrated = 0;
	unsigned long node;
	enum crit_level lv;
	struct mm_struct *mm;
		
	LIST_HEAD(pagelist);
	LIST_HEAD(shared_pagelist);
	
	migrate_prep();
	
	rcu_read_lock();
	get_task_struct(current);
	rcu_read_unlock();
	mm = get_task_mm(current);
	put_task_struct(current);

	//down_read(&current->mm->mmap_sem);
	down_read(&mm->mmap_sem);
	TRACE_TASK(current, "SYSCALL set_page_color\n");
	vma_itr = mm->mmap;
	while (vma_itr != NULL) {
		unsigned int num_pages = 0, i;
		struct page *old_page = NULL;
		
		num_pages = (vma_itr->vm_end - vma_itr->vm_start) / PAGE_SIZE;
		// print vma flags
		//printk(KERN_INFO "flags: 0x%lx\n", vma_itr->vm_flags);
		//printk(KERN_INFO "start - end: 0x%lx - 0x%lx (%lu)\n", vma_itr->vm_start, vma_itr->vm_end, (vma_itr->vm_end - vma_itr->vm_start)/PAGE_SIZE);
		//printk(KERN_INFO "vm_page_prot: 0x%lx\n", vma_itr->vm_page_prot);
		for (i = 0; i < num_pages; i++) {
			old_page = follow_page(vma_itr, vma_itr->vm_start + PAGE_SIZE*i, FOLL_GET|FOLL_SPLIT);
			
			if (IS_ERR(old_page))
				continue;
			if (!old_page)
				continue;

			if (PageReserved(old_page)) {
				TRACE("Reserved Page!\n");
				put_page(old_page);
				continue;
			}
			
			TRACE_TASK(current, "addr: %08x, pfn: %x, _mapcount: %d, _count: %d\n", vma_itr->vm_start + PAGE_SIZE*i, __page_to_pfn(old_page), page_mapcount(old_page), page_count(old_page));
			
			//if (page_mapcount(old_page) == 1) {
				ret = isolate_lru_page(old_page);
				if (!ret) {
					list_add_tail(&old_page->lru, &pagelist);
					inc_zone_page_state(old_page, NR_ISOLATED_ANON + !PageSwapBacked(old_page));
					nr_pages++;
				} else {
					TRACE_TASK(current, "isolate_lru_page failed\n");
					TRACE_TASK(current, "page_lru = %d PageLRU = %d\n", page_lru(old_page), PageLRU(old_page));
					nr_failed++;
				}
				//printk(KERN_INFO "PRIVATE _mapcount = %d, _count = %d\n", page_mapcount(old_page), page_count(old_page));
				put_page(old_page);
			//}
			/*
			else {
				nr_shared_pages++;
				//printk(KERN_INFO "SHARED _mapcount = %d, _count = %d\n", page_mapcount(old_page), page_count(old_page));
				put_page(old_page);
			}
			*/
		}
		
		vma_itr = vma_itr->vm_next;
	}

	//list_for_each_entry(page_itr, &pagelist, lru) {
//		printk(KERN_INFO "B _mapcount = %d, _count = %d\n", page_mapcount(page_itr), page_count(page_itr));
//	}
	
	ret = 0;
	if (!is_realtime(current))
		lv = 1;
	else {
		lv = tsk_rt(current)->mc2_data->crit;
	}
	
	if (cpu == -1)
		node = 8;
	else
		node = cpu*2 + lv;
		
	if (!list_empty(&pagelist)) {
		ret = migrate_pages(&pagelist, new_alloc_page, NULL, node, MIGRATE_SYNC, MR_SYSCALL);
		TRACE_TASK(current, "%ld pages not migrated.\n", ret);
		printk(KERN_INFO "%ld pages not migrated.\n", ret);
		nr_not_migrated = ret;
		if (ret) {
			putback_movable_pages(&pagelist);
		}
	}
	
	/* handle sigpage and litmus ctrl_page */
/*	vma_itr = current->mm->mmap;
	while (vma_itr != NULL) {
		if (vma_itr->vm_start == tsk_rt(current)->addr_ctrl_page) {
			TRACE("litmus ctrl_page = %08x\n", vma_itr->vm_start);
			vma_itr->vm_page_prot = PAGE_SHARED;
			break;
		}
		vma_itr = vma_itr->vm_next;
	}
*/
	up_read(&mm->mmap_sem);

/*	
	list_for_each_entry(page_itr, &shared_pagelist, lru) {
		TRACE("S Anon=%d, pfn = %lu, _mapcount = %d, _count = %d\n", PageAnon(page_itr), __page_to_pfn(page_itr), page_mapcount(page_itr), page_count(page_itr));
	}
*/	
	TRACE_TASK(current, "nr_pages = %d nr_failed = %d\n", nr_pages, nr_failed);
	printk(KERN_INFO "node = %ld, nr_migrated_pages = %d, nr_shared_pages = %d, nr_failed = %d\n", node, nr_pages-nr_not_migrated, nr_failed-2, nr_failed);
	//printk(KERN_INFO "node = %d\n", cpu_to_node(smp_processor_id()));
	flush_cache(1);
	
	return ret;
}

/* sys_test_call() is a test system call for developing */
asmlinkage long sys_test_call(unsigned int param)
{
	long ret = 0;
	unsigned long flags;
	struct vm_area_struct *vma_itr = NULL;
	
	TRACE_CUR("test_call param = %d\n", param);
	
	if (param == 0) {
		down_read(&current->mm->mmap_sem);
		vma_itr = current->mm->mmap;
		while (vma_itr != NULL) {
			printk(KERN_INFO "--------------------------------------------\n");
			printk(KERN_INFO "vm_start : %lx\n", vma_itr->vm_start);
			printk(KERN_INFO "vm_end   : %lx\n", vma_itr->vm_end);
			printk(KERN_INFO "vm_flags : %lx\n", vma_itr->vm_flags);
			printk(KERN_INFO "vm_prot  : %x\n", pgprot_val(vma_itr->vm_page_prot));
			printk(KERN_INFO "VM_SHARED? %ld\n", vma_itr->vm_flags & VM_SHARED);
	/*		if (vma_itr->vm_file) {
				struct file *fp = vma_itr->vm_file;
				unsigned long fcount = atomic_long_read(&(fp->f_count));
				printk(KERN_INFO "f_count : %ld\n", fcount);
				if (fcount > 1) {
					vma_itr->vm_page_prot = pgprot_noncached(vma_itr->vm_page_prot);
				}
			}
			printk(KERN_INFO "vm_prot2 : %x\n", pgprot_val(vma_itr->vm_page_prot));
	*/		
			vma_itr = vma_itr->vm_next;
		}
		printk(KERN_INFO "--------------------------------------------\n");
		up_read(&current->mm->mmap_sem);
		
		local_irq_save(flags);
		l2c310_flush_all();
		local_irq_restore(flags);
	}
	else if (param == 1) {
		int i;
		flush_cache(1);
		for (i = 0; i < 4; i++) {
			lock_cache(i, 0x00003fff);
		}
	}
	else if (param == 2) {
		int i;
		for (i = 0; i < 4; i++) {
			lock_cache(i, 0xffffffff);
		}
	}
	return ret;
}

/* p is a real-time task. Re-init its state as a best-effort task. */
static void reinit_litmus_state(struct task_struct* p, int restore)
{
	struct rt_task  user_config = {};
	void*  ctrl_page     = NULL;

	if (restore) {
		/* Safe user-space provided configuration data.
		 * and allocated page. */
		user_config = p->rt_param.task_params;
		ctrl_page   = p->rt_param.ctrl_page;
	}

	/* We probably should not be inheriting any task's priority
	 * at this point in time.
	 */
	WARN_ON(p->rt_param.inh_task);

	/* Cleanup everything else. */
	memset(&p->rt_param, 0, sizeof(p->rt_param));

	/* Restore preserved fields. */
	if (restore) {
		p->rt_param.task_params = user_config;
		p->rt_param.ctrl_page   = ctrl_page;
	}
}

long litmus_admit_task(struct task_struct* tsk)
{
	long retval = 0;

	BUG_ON(is_realtime(tsk));

	tsk_rt(tsk)->heap_node = NULL;
	tsk_rt(tsk)->rel_heap = NULL;

	if (get_rt_relative_deadline(tsk) == 0 ||
	    get_exec_cost(tsk) >
			min(get_rt_relative_deadline(tsk), get_rt_period(tsk)) ) {
		TRACE_TASK(tsk,
			"litmus admit: invalid task parameters "
			"(e = %lu, p = %lu, d = %lu)\n",
			get_exec_cost(tsk), get_rt_period(tsk),
			get_rt_relative_deadline(tsk));
		retval = -EINVAL;
		goto out;
	}

	INIT_LIST_HEAD(&tsk_rt(tsk)->list);

	/* allocate heap node for this task */
	tsk_rt(tsk)->heap_node = bheap_node_alloc(GFP_ATOMIC);
	tsk_rt(tsk)->rel_heap = release_heap_alloc(GFP_ATOMIC);

	if (!tsk_rt(tsk)->heap_node || !tsk_rt(tsk)->rel_heap) {
		printk(KERN_WARNING "litmus: no more heap node memory!?\n");

		retval = -ENOMEM;
		goto out;
	} else {
		bheap_node_init(&tsk_rt(tsk)->heap_node, tsk);
	}

	preempt_disable();

	retval = litmus->admit_task(tsk);

	if (!retval) {
		sched_trace_task_name(tsk);
		sched_trace_task_param(tsk);
		atomic_inc(&rt_task_count);
	}

	preempt_enable();

out:
	if (retval) {
		if (tsk_rt(tsk)->heap_node)
			bheap_node_free(tsk_rt(tsk)->heap_node);
		if (tsk_rt(tsk)->rel_heap)
			release_heap_free(tsk_rt(tsk)->rel_heap);
	}
	return retval;
}

void litmus_clear_state(struct task_struct* tsk)
{
    BUG_ON(bheap_node_in_heap(tsk_rt(tsk)->heap_node));
    bheap_node_free(tsk_rt(tsk)->heap_node);
    release_heap_free(tsk_rt(tsk)->rel_heap);

    atomic_dec(&rt_task_count);
    reinit_litmus_state(tsk, 1);
}

/* called from sched_setscheduler() */
void litmus_exit_task(struct task_struct* tsk)
{
	if (is_realtime(tsk)) {
		sched_trace_task_completion(tsk, 1);

		litmus->task_exit(tsk);
	}
}

static DECLARE_RWSEM(plugin_switch_mutex);

void litmus_plugin_switch_disable(void)
{
	down_read(&plugin_switch_mutex);
}

void litmus_plugin_switch_enable(void)
{
	up_read(&plugin_switch_mutex);
}

static int __do_plugin_switch(struct sched_plugin* plugin)
{
	int ret;


	/* don't switch if there are active real-time tasks */
	if (atomic_read(&rt_task_count) == 0) {
		TRACE("deactivating plugin %s\n", litmus->plugin_name);
		ret = litmus->deactivate_plugin();
		if (0 != ret)
			goto out;

		TRACE("activating plugin %s\n", plugin->plugin_name);
		ret = plugin->activate_plugin();
		if (0 != ret) {
			printk(KERN_INFO "Can't activate %s (%d).\n",
			       plugin->plugin_name, ret);
			plugin = &linux_sched_plugin;
		}

		printk(KERN_INFO "Switching to LITMUS^RT plugin %s.\n", plugin->plugin_name);
		litmus = plugin;
	} else
		ret = -EBUSY;
out:
	TRACE("do_plugin_switch() => %d\n", ret);
	return ret;
}

static atomic_t ready_to_switch;

static int do_plugin_switch(void *_plugin)
{
	unsigned long flags;
	int ret = 0;

	local_save_flags(flags);
	local_irq_disable();
	hard_irq_disable();

	if (atomic_dec_and_test(&ready_to_switch))
	{
		ret = __do_plugin_switch((struct sched_plugin*) _plugin);
		atomic_set(&ready_to_switch, INT_MAX);
	}

	do {
		cpu_relax();
	} while (atomic_read(&ready_to_switch) != INT_MAX);

	local_irq_restore(flags);
	return ret;
}

/* Switching a plugin in use is tricky.
 * We must watch out that no real-time tasks exists
 * (and that none is created in parallel) and that the plugin is not
 * currently in use on any processor (in theory).
 */
int switch_sched_plugin(struct sched_plugin* plugin)
{
	int err;
	struct domain_proc_info* domain_info;

	BUG_ON(!plugin);

	if (atomic_read(&rt_task_count) == 0) {
		down_write(&plugin_switch_mutex);

		deactivate_domain_proc();

		get_online_cpus();
		atomic_set(&ready_to_switch, num_online_cpus());
		err = stop_cpus(cpu_online_mask, do_plugin_switch, plugin);
		put_online_cpus();

		if (!litmus->get_domain_proc_info(&domain_info))
			activate_domain_proc(domain_info);

		up_write(&plugin_switch_mutex);
		return err;
	} else
		return -EBUSY;
}

/* Called upon fork.
 * p is the newly forked task.
 */
void litmus_fork(struct task_struct* p)
{
	if (is_realtime(p)) {
		/* clean out any litmus related state, don't preserve anything */
		reinit_litmus_state(p, 0);
		/* Don't let the child be a real-time task.  */
		p->sched_reset_on_fork = 1;
	} else
		/* non-rt tasks might have ctrl_page set */
		tsk_rt(p)->ctrl_page = NULL;

	/* od tables are never inherited across a fork */
	p->od_table = NULL;
}

/* Called upon execve().
 * current is doing the exec.
 * Don't let address space specific stuff leak.
 */
void litmus_exec(void)
{
	struct task_struct* p = current;

	if (is_realtime(p)) {
		WARN_ON(p->rt_param.inh_task);
		if (tsk_rt(p)->ctrl_page) {
			free_page((unsigned long) tsk_rt(p)->ctrl_page);
			tsk_rt(p)->ctrl_page = NULL;
		}
	}
}

/* Called when dead_tsk is being deallocated
 */
void exit_litmus(struct task_struct *dead_tsk)
{
	/* We also allow non-RT tasks to
	 * allocate control pages to allow
	 * measurements with non-RT tasks.
	 * So check if we need to free the page
	 * in any case.
	 */
	if (tsk_rt(dead_tsk)->ctrl_page) {
		TRACE_TASK(dead_tsk,
			   "freeing ctrl_page %p\n",
			   tsk_rt(dead_tsk)->ctrl_page);
		free_page((unsigned long) tsk_rt(dead_tsk)->ctrl_page);
	}

	/* Tasks should not be real-time tasks any longer at this point. */
	BUG_ON(is_realtime(dead_tsk));
}

void litmus_do_exit(struct task_struct *exiting_tsk)
{
	/* This task called do_exit(), but is still a real-time task. To avoid
	 * complications later, we force it to be a non-real-time task now. */

	struct sched_param param = { .sched_priority = MAX_RT_PRIO - 1 };

	TRACE_TASK(exiting_tsk, "exiting, demoted to SCHED_FIFO\n");
	sched_setscheduler_nocheck(exiting_tsk, SCHED_FIFO, &param);
}

void litmus_dealloc(struct task_struct *tsk)
{
	/* tsk is no longer a real-time task */
	TRACE_TASK(tsk, "Deallocating real-time task data\n");
	litmus->task_cleanup(tsk);
	litmus_clear_state(tsk);
}

/* move current non-RT task to a specific CPU */
int litmus_be_migrate_to(int cpu)
{
	struct cpumask single_cpu_aff;

	cpumask_clear(&single_cpu_aff);
	cpumask_set_cpu(cpu, &single_cpu_aff);
	return sched_setaffinity(current->pid, &single_cpu_aff);
}

#ifdef CONFIG_MAGIC_SYSRQ
int sys_kill(int pid, int sig);

static void sysrq_handle_kill_rt_tasks(int key)
{
	struct task_struct *t;
	read_lock(&tasklist_lock);
	for_each_process(t) {
		if (is_realtime(t)) {
			sys_kill(t->pid, SIGKILL);
		}
	}
	read_unlock(&tasklist_lock);
}

static struct sysrq_key_op sysrq_kill_rt_tasks_op = {
	.handler	= sysrq_handle_kill_rt_tasks,
	.help_msg	= "quit-rt-tasks(X)",
	.action_msg	= "sent SIGKILL to all LITMUS^RT real-time tasks",
};
#endif

extern struct sched_plugin linux_sched_plugin;

static int litmus_shutdown_nb(struct notifier_block *unused1,
				unsigned long unused2, void *unused3)
{
	/* Attempt to switch back to regular Linux scheduling.
	 * Forces the active plugin to clean up.
	 */
	if (litmus != &linux_sched_plugin) {
		int ret = switch_sched_plugin(&linux_sched_plugin);
		if (ret) {
			printk("Auto-shutdown of active Litmus plugin failed.\n");
		}
	}
	return NOTIFY_DONE;
}

static struct notifier_block shutdown_notifier = {
	.notifier_call = litmus_shutdown_nb,
};

static int __init _init_litmus(void)
{
	/*      Common initializers,
	 *      mode change lock is used to enforce single mode change
	 *      operation.
	 */
#if defined(CONFIG_CPU_V7)
	unsigned int line_size_log = 5; // 2^5 = 32 byte
	unsigned int cache_info_sets = 2048; // 64KB (way_size) / 32B (line_size) = 2048
	printk("LITMIS^RT-ARM kernel\n");
#endif

	printk("Starting LITMUS^RT kernel\n");

	register_sched_plugin(&linux_sched_plugin);

	bheap_node_cache    = KMEM_CACHE(bheap_node, SLAB_PANIC);
	release_heap_cache = KMEM_CACHE(release_heap, SLAB_PANIC);

#ifdef CONFIG_MAGIC_SYSRQ
	/* offer some debugging help */
	if (!register_sysrq_key('x', &sysrq_kill_rt_tasks_op))
		printk("Registered kill rt tasks magic sysrq.\n");
	else
		printk("Could not register kill rt tasks magic sysrq.\n");
#endif
	init_litmus_proc();

	register_reboot_notifier(&shutdown_notifier);

#if defined(CONFIG_CPU_V7)
	color_mask = ((cache_info_sets << line_size_log) - 1) ^ (PAGE_SIZE - 1);
	printk("Page color mask %lx\n", color_mask);
#endif

	return 0;
}

static void _exit_litmus(void)
{
	unregister_reboot_notifier(&shutdown_notifier);

	exit_litmus_proc();
	kmem_cache_destroy(bheap_node_cache);
	kmem_cache_destroy(release_heap_cache);
}

module_init(_init_litmus);
module_exit(_exit_litmus);

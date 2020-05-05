/*
 * litmus/mc2_common.c
 *
 * Common functions for MC2 plugin.
 */

#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include <litmus/litmus.h>
#include <litmus/sched_plugin.h>
#include <litmus/sched_trace.h>

#include <litmus/mc2_common.h>

long mc2_task_client_init(struct task_client *tc, struct mc2_task *mc2_param, struct task_struct *tsk, struct reservation *res)
{
	task_client_init(tc, tsk, res);
	if ((mc2_param->crit < CRIT_LEVEL_A) ||
		(mc2_param->crit > CRIT_LEVEL_C))
		return -EINVAL;

	TRACE_TASK(tsk, "mc2_task_client_init: crit_level = %d\n", mc2_param->crit);

	return 0;
}

asmlinkage long sys_set_mc2_task_param(pid_t pid, struct mc2_task __user * param)
{
	struct task_struct *target;
	int retval = -EINVAL;
	struct mc2_task *mp = kzalloc(sizeof(*mp), GFP_KERNEL);

	if (!mp)
		return -ENOMEM;

	printk("Setting up mc^2 task parameters for process %d.\n", pid);

	if (pid < 0 || param == 0) {
		goto out;
	}
	if (copy_from_user(mp, param, sizeof(*mp))) {
		retval = -EFAULT;
		goto out;
	}

	/* Task search and manipulation must be protected */
	read_lock_irq(&tasklist_lock);
	if (!(target = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		goto out_unlock;
	}

	if (is_realtime(target)) {
		/* The task is already a real-time task.
		 * We cannot not allow parameter changes at this point.
		 */
		retval = -EBUSY;
		goto out_unlock;
	}
	if (mp->crit < CRIT_LEVEL_A || mp->crit >= NUM_CRIT_LEVELS) {
		printk(KERN_INFO "litmus: real-time task %d rejected "
			"because of invalid criticality level\n", pid);
		goto out_unlock;
	}

	target->rt_param.mc2_data = mp;

	retval = 0;
out_unlock:
	read_unlock_irq(&tasklist_lock);
out:
	return retval;
}

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/hrtimer.h>

#include <litmus/litmus.h>
#include <litmus/bheap.h>
#include <litmus/rt_domain.h>
#include <litmus/jobs.h>
#include <litmus/np.h>
#include <litmus/sched_trace.h>
#include <litmus/debug_trace.h>
#include <litmus/reservations/gedf_reservation.h>

// Needed to store context during cross-CPU function calls
struct csd_wrapper {
	call_single_data_t csd;
	struct gedf_reservation_environment* gedf_env;
};

/* ******************************************************************************* */
/* returns 1 if res of a has earlier deadline than res of b */
static int edf_ready_order(struct bheap_node* a, struct bheap_node* b)
{
	return higher_res_prio(bheap2res(a), bheap2res(b));
}

/* Functions used to maintain a heap of cpu entries in edf order
 * cpu_lower_prio is the comparator function used to enforce edf order
 *
 * The next two functions must be called under domain.ready_lock of the reservation
 * update_cpu_position is called when cpu->linked changes
 * lowest_prio_cpu returns the lowest prio cpu
 */
static int cpu_lower_prio(struct bheap_node *_a, struct bheap_node *_b)
{
	struct gedf_cpu_entry *a, *b;
	a = _a->value;
	b = _b->value;
	return higher_res_prio(&b->linked->res, &a->linked->res);
}

static void update_cpu_position(struct gedf_cpu_entry* entry, struct bheap* cpu_heap)
{
	if (likely(bheap_node_in_heap(entry->hn)))
		bheap_delete(cpu_lower_prio, cpu_heap, entry->hn);
	bheap_insert(cpu_lower_prio, cpu_heap, entry->hn);
}

static struct gedf_cpu_entry* lowest_prio_cpu(struct bheap* cpu_heap)
{
	struct bheap_node* hn;
	hn = bheap_peek(cpu_lower_prio, cpu_heap);
	return hn->value;
}

static int edf_preemption_needed(
	struct gedf_reservation_environment* gedf_env,
	struct gedf_reservation* gedf_res)
{
	/* we need the read lock for edf_ready_queue */
	/* no need to preempt if there is nothing pending */
	if (bheap_empty(&gedf_env->domain.ready_queue))
		return 0;
	/* we need to reschedule if res doesn't exist */
	if (!gedf_res)
		return 1;

	/* NOTE: We cannot check for non-preemptibility since we
	 *       don't know what address space we're currently in.
	 */

	return higher_res_prio(__next_ready_res(&gedf_env->domain), &gedf_res->res);
}

/* ******************************************************************************** */
//TODO: add support for checking non-preemptivity
static void preempt(struct gedf_cpu_entry* entry)
{
	if (!entry->scheduled || entry->scheduled->res.ops->is_np(&entry->scheduled->res, entry->id))
		litmus_reschedule(entry->id);
}

static void requeue(
	struct gedf_reservation_environment* gedf_env,
	struct gedf_reservation* gedf_res)
{
	BUG_ON(!gedf_res);
	BUG_ON(is_queued_res(&gedf_res->res));

	if (lt_before_eq(gedf_res->res.replenishment_time, litmus_clock()))
		__add_ready_res(&gedf_env->domain, &gedf_res->res);
	else
		__add_release_res(&gedf_env->domain, &gedf_res->res);
}

static void link_task_to_cpu(
	struct gedf_reservation_environment* gedf_env,
	struct gedf_reservation* linked,
	struct gedf_cpu_entry* entry)
{

	if (entry->linked)
		entry->linked->linked_on = NULL;

	if (linked)
		linked->linked_on = entry;

	entry->linked = linked;
	update_cpu_position(entry, &gedf_env->cpu_heap);
}

static void unlink(
	struct gedf_reservation_environment* gedf_env,
	struct gedf_reservation* gedf_res)
{
	if (gedf_res->linked_on) {
		link_task_to_cpu(gedf_env, NULL, gedf_res->linked_on);
		gedf_res->linked_on = NULL;
	} else if (is_queued_res(&gedf_res->res)) {
		remove_res(&gedf_env->domain, &gedf_res->res);
	}
}

static void check_for_preemptions(struct gedf_reservation_environment* gedf_env)
{
	struct gedf_reservation* gedf_res;
	struct gedf_cpu_entry* last;

	if (bheap_empty(&gedf_env->cpu_heap))
		return;

	for (last = lowest_prio_cpu(&gedf_env->cpu_heap);
			edf_preemption_needed(gedf_env, last->linked);
			last = lowest_prio_cpu(&gedf_env->cpu_heap)) {
		gedf_res = (struct gedf_reservation*)__take_ready_res(&gedf_env->domain);
		if (last->linked && last->linked->res.cur_budget)
			requeue(gedf_env, last->linked);
		link_task_to_cpu(gedf_env, gedf_res, last);
		preempt(last);
	}
}

/* ******************************************************************************* */
static void gedf_shutdown(
	struct ext_reservation *res)
{
	res->env->ops->shutdown(res->env);
	clean_up_ext_reservation(res);
	kfree(res);
}

static int gedf_is_np(
	struct ext_reservation *res,
	int cpu)
{
	return res->env->ops->is_np(res->env, cpu);
}

static int gedf_task_is_np(
	struct ext_reservation *res,
	int cpu)
{
	struct task_struct* t = ((struct gedf_task_reservation*)res)->task;
	if (is_user_np(t)) {
		request_exit_np(t);
		return 1;
	} else if (is_kernel_np(t))
		return 1;

	return 0;
}

static void gedf_task_shutdown(
	struct ext_reservation *res)
{
	clean_up_ext_reservation(res);
	kfree(res);
}

static void gedf_on_preempt(
	struct ext_reservation *res,
	int cpu)
{
	res->env->ops->suspend(res->env, cpu);
}

static void gedf_on_schedule(
	struct ext_reservation *res,
	int cpu)
{
	res->env->ops->resume(res->env, cpu);
}

static struct task_struct* gedf_dispatch_client(
	struct ext_reservation* res,
	lt_t* time_slice,
	int cpu)
{
	return res->env->ops->dispatch(res->env, time_slice, cpu);
}

static struct task_struct* gedf_task_dispatch_client(
	struct ext_reservation* res,
	lt_t* time_slice,
	int cpu)
{
	return ((struct gedf_task_reservation*)res)->task;
}

static void gedf_replenish_budget(
	struct ext_reservation* res,
	int cpu)
{
	struct gedf_container_reservation* gedf_cont_res =
		(struct gedf_container_reservation*)res;
	res->budget_consumed = 0;
	res->cur_budget = gedf_cont_res->max_budget;
	res->replenishment_time += gedf_cont_res->period;
	res->priority = ULLONG_MAX - res->replenishment_time - gedf_cont_res->relative_deadline;
}

static void gedf_task_replenish_budget(
	struct ext_reservation* res,
	int cpu)
{
	struct task_struct* t = ((struct gedf_task_reservation*)res)->task;

	if (is_completed(t)) {
		sched_trace_task_completion(t, 0);
		prepare_for_next_period(t);
		tsk_rt(t)->completed = 0;
		sched_trace_task_release(t);
		res->priority = ULLONG_MAX - get_deadline(t);
		res->replenishment_time = get_release(t);
	} else {
		sched_trace_task_completion(t, 1);
		res->replenishment_time += get_rt_period(t);
		res->priority = ULLONG_MAX - res->replenishment_time - get_rt_relative_deadline(t);
		TRACE_TASK(t, "overrun budget!\n");
	}
	res->budget_consumed = 0;
	res->cur_budget = res->max_budget;
}

static void gedf_drain_budget(
	struct ext_reservation* res,
	lt_t how_much,
	int cpu)
{
	if (how_much > res->cur_budget)
		res->cur_budget = 0;
	else
		res->cur_budget -= how_much;
	res->budget_consumed += how_much;
	res->budget_consumed_total += how_much;

	res->env->ops->update_time(res->env, how_much, cpu);
}

static void gedf_task_drain_budget(
	struct ext_reservation* res,
	lt_t how_much,
	int cpu)
{
	struct task_struct* t = ((struct gedf_task_reservation*)res)->task;

	if (how_much > res->cur_budget || is_completed(t))
		res->cur_budget = 0;
	else
		res->cur_budget -= how_much;
	res->budget_consumed += how_much;
	res->budget_consumed_total += how_much;
}

static struct ext_reservation_ops gedf_cont_ops =
{
	.drain_budget = gedf_drain_budget,
	.replenish_budget = gedf_replenish_budget,
	.dispatch_client = gedf_dispatch_client,
	.on_schedule = gedf_on_schedule,
	.on_preempt = gedf_on_preempt,
	.is_np = gedf_is_np,
	.shutdown = gedf_shutdown
};

static struct ext_reservation_ops gedf_task_ops =
{
	.drain_budget = gedf_task_drain_budget,
	.replenish_budget = gedf_task_replenish_budget,
	.dispatch_client = gedf_task_dispatch_client,
	.is_np = gedf_task_is_np,
	.shutdown = gedf_task_shutdown
};

long alloc_gedf_task_reservation(
	struct gedf_task_reservation** _res,
	struct task_struct* task, lt_t max_budget)
{
	struct gedf_task_reservation* gedf_task_res;
	gedf_task_res = kzalloc(sizeof(*gedf_task_res), GFP_KERNEL);
	if (!gedf_task_res)
		return -ENOMEM;

	init_ext_reservation(&gedf_task_res->gedf_res.res, task->pid, &gedf_task_ops);

	gedf_task_res->task = task;
	gedf_task_res->gedf_res.res.priority = ULLONG_MAX - get_rt_relative_deadline(task);
	gedf_task_res->gedf_res.res.max_budget = max_budget;
	gedf_task_res->gedf_res.res.cur_budget = max_budget;

	*_res = gedf_task_res;
	return 0;
}

long alloc_gedf_container_reservation(
	struct gedf_container_reservation** _res,
	int id,
	lt_t max_budget,
	lt_t period,
	lt_t relative_deadline)
{
	struct gedf_container_reservation* gedf_cont_res;
	gedf_cont_res = kzalloc(sizeof(*gedf_cont_res), GFP_KERNEL);
	if (!gedf_cont_res)
		return -ENOMEM;

	init_ext_reservation(&gedf_cont_res->gedf_res.res, id, &gedf_cont_ops);

	gedf_cont_res->max_budget = max_budget;
	gedf_cont_res->period = period;
	gedf_cont_res->relative_deadline = relative_deadline;

	*_res = gedf_cont_res;
	return 0;
}

/* ******************************************************************************** */
static void gedf_env_shutdown(
	struct ext_reservation_environment* env)
{
	struct gedf_reservation_environment* gedf_env;
	struct ext_reservation* res;
	unsigned long flags;

	gedf_env = container_of(env, struct gedf_reservation_environment, env);

	domain_suspend_releases(&gedf_env->domain);

	raw_spin_lock_irqsave(&gedf_env->domain.ready_lock, flags);

	/* call shutdown on all scheduled reservations */
	while (!list_empty(&env->all_reservations)) {
		res = list_first_entry(&env->all_reservations,
					struct ext_reservation, all_list);
		list_del(&res->all_list);
		res->ops->shutdown(res);
	}
	raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);

	/* free memory */
	kfree(gedf_env->cpu_entries);
	kfree(gedf_env->cpu_node);
	kfree(gedf_env);
}

static int gedf_env_is_np(
	struct ext_reservation_environment* env,
	int cpu)
{
	struct gedf_reservation_environment* gedf_env =
		container_of(env, struct gedf_reservation_environment, env);
	struct gedf_reservation* scheduled =
		gedf_env->cpu_entries[cpu].scheduled;
	return scheduled && scheduled->res.ops->is_np(&scheduled->res, cpu);
}

static struct ext_reservation* gedf_find_res_by_id(
	struct ext_reservation_environment* env,
	int id)
{
	struct ext_reservation* res;
	struct gedf_reservation_environment* gedf_env;
	unsigned long flags;

	gedf_env = container_of(env, struct gedf_reservation_environment, env);

	raw_spin_lock_irqsave(&gedf_env->domain.ready_lock, flags);
	list_for_each_entry(res, &env->all_reservations, all_list) {
		if (res->id == id) {
			raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);
			return res;
		}
	}
	raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);
	return NULL;
}

/* This assumes that is is only called from res itself requesting to be removed
 * This WILL cause rt task to become lost if res is a scheduling entity
 */
static void gedf_env_remove_res(
	struct ext_reservation_environment* env,
	struct ext_reservation* res,
	int complete,
	int cpu)
{
	struct gedf_reservation_environment* gedf_env;
	struct gedf_reservation* gedf_res;
	unsigned long flags;

	gedf_env = container_of(env, struct gedf_reservation_environment, env);
	gedf_res = container_of(res, struct gedf_reservation, res);

	gedf_res->will_remove = complete;
	gedf_res->blocked = !complete;

	raw_spin_lock_irqsave(&gedf_env->domain.ready_lock, flags);
	list_del_init(&gedf_res->res.all_list);
	unlink(gedf_env, gedf_res);
	check_for_preemptions(gedf_env);
	raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);
	/* After preempt is called, schedule will update budget tracking.
	 * In update_time, the environment will detect that res(which is scheduled)
	 * wants to be removed.
	 * If the reservation is flagged for removal, the shutdown callback is called
	 * If the reservation is flagged as blocked, then it will not be requeued back
	 * into the domain, and will invoke on_preempt callback in env_dispatch.
	 * Because we unlinked it, after env_dispatch, res is essentially gone.
	 */
}

static void gedf_env_add_res(
	struct ext_reservation_environment* env,
	struct ext_reservation* res,
	int cpu)
{
	struct gedf_reservation_environment* gedf_env;
	struct gedf_reservation* gedf_res;
	unsigned long flags;

	gedf_env = container_of(env, struct gedf_reservation_environment, env);
	gedf_res = container_of(res, struct gedf_reservation, res);

	res->par_env = env;
	gedf_res->will_remove = 0;
	gedf_res->blocked = 0;

	raw_spin_lock_irqsave(&gedf_env->domain.ready_lock, flags);
	list_add_tail(&gedf_res->res.all_list, &env->all_reservations);
	requeue(gedf_env, gedf_res);
	check_for_preemptions(gedf_env);
	raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);
}

/* try_resume_timer: Attempt to resume the release timer locally.
 * @param csd_info Pointer to `info` field of struct call_single_data
 * @note Used as IPI callback, do not call directly. Lockless.
 */
static void try_resume_timer(void *csd_info)
{
	struct csd_wrapper* csd_wrapper = csd_info;
	struct gedf_reservation_environment* gedf_env = csd_wrapper->gedf_env;
	int cpu = smp_processor_id();
	struct gedf_cpu_entry* entry = &gedf_env->cpu_entries[cpu];
	// Abort if this CPU was suspended before we could process the IPI
	if (!bheap_node_in_heap(entry->hn))
		goto out;
	domain_resume_releases(&gedf_env->domain);
out:
	kfree(csd_wrapper);
}

/* gedf_env_suspend: Remove the specified core from scheduling consideration
 * @param env Environment to modify
 * @param cpu CPU to remove if present.
 * @note Safe to call if core already removed. Skips lock in that case.
 */
static void gedf_env_suspend(
	struct ext_reservation_environment* env,
	int cpu)
{
	struct gedf_reservation_environment* gedf_env;
	struct gedf_cpu_entry* entry;
	struct gedf_reservation* tmp;
	unsigned long flags;

	gedf_env = container_of(env, struct gedf_reservation_environment, env);
	entry = &gedf_env->cpu_entries[cpu];

	/* Ignore suspension requests on inactive cores
	 * This will not errantly fail, as the first thing resume() does is re-add the node
	 * This will only errantly pass if another core is simultaneously inside
	 * our critical section. The second check catches that.
	 * In all cases this will avoid taking the lock if we were never part of the container.
	 */
	if (!bheap_node_in_heap(entry->hn))
		return;

	raw_spin_lock_irqsave(&gedf_env->domain.ready_lock, flags);
	// Do not remove! See above comment.
	if (!bheap_node_in_heap(entry->hn))
		goto unlock;

	//TODO: More Graceful way to handle forbidden zone violation?
	BUG_ON(env->ops->is_np(env, cpu));

	gedf_env->num_cpus--;
	/* on env suspension, we need to preempt scheduled tasks, and unlink linked tasks */
	if (entry->linked) {
		tmp = entry->linked;
		unlink(gedf_env, entry->linked);
		requeue(gedf_env, tmp);
	}
	if (entry->scheduled && entry->scheduled->res.ops->on_preempt)
		entry->scheduled->res.ops->on_preempt(&entry->scheduled->res, cpu);
	entry->scheduled = NULL;

	/* this essentially removes the cpu from scheduling consideration */
	bheap_delete(cpu_lower_prio, &gedf_env->cpu_heap, entry->hn);

	check_for_preemptions(gedf_env);

	/* suspends rt_domain releases when the last core of env is preempted
	 * OR re-arm release timer on a different CPU */
	if (!gedf_env->num_cpus)
		domain_suspend_releases(&gedf_env->domain);
	else {
		struct csd_wrapper* csd_wrapper =
			kzalloc(sizeof(struct csd_wrapper), GFP_ATOMIC);
		csd_wrapper->gedf_env = gedf_env;
		csd_wrapper->csd.func = &try_resume_timer;
		csd_wrapper->csd.info = csd_wrapper;
		smp_call_function_single_async(
				lowest_prio_cpu(&gedf_env->cpu_heap)->id,
				&csd_wrapper->csd);
	}
unlock:
	raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);
}

/* gedf_env_resume: Add the specified core to scheduling consideration
 * @param env Environment to modify
 * @param cpu CPU to add if not yet added.
 * @note Safe to call if core already added.
 */
static void gedf_env_resume(
	struct ext_reservation_environment* env,
	int cpu)
{
	struct gedf_reservation_environment* gedf_env;
	struct gedf_cpu_entry* entry;
	unsigned long flags;
	// Needs to be volatile or it may be optimized to gedf_env->num_cpus
	volatile int tmp_cpus;

	gedf_env = container_of(env, struct gedf_reservation_environment, env);
	entry = &gedf_env->cpu_entries[cpu];

	// If we've already been resumed, do nothing
	if (bheap_node_in_heap(entry->hn))
		return;

	raw_spin_lock_irqsave(&gedf_env->domain.ready_lock, flags);
	// Check again. Our earlier check may have raced with this critical section
	if (bheap_node_in_heap(entry->hn)) {
		raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);
		return;
	}

	// Save how many cpus were resumed before us (if none, we need to restart the timer)
	tmp_cpus = gedf_env->num_cpus;

	/* adds cpu back to scheduling consideration */
	bheap_insert(cpu_lower_prio, &gedf_env->cpu_heap, entry->hn);
	gedf_env->num_cpus++;

	raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);

	// Keep this outside the lock. Resuming the timer may have side-effects.
	if (!tmp_cpus)
		domain_resume_releases(&gedf_env->domain);
}

static struct task_struct* gedf_env_dispatch(
	struct ext_reservation_environment* env,
	lt_t* time_slice,
	int cpu)
{
	struct gedf_reservation_environment* gedf_env;
	struct gedf_cpu_entry* entry;
	struct task_struct* next = NULL;
	unsigned long flags;
	int np = 0;

	gedf_env = container_of(env, struct gedf_reservation_environment, env);
	entry = &gedf_env->cpu_entries[cpu];

	BUG_ON(entry->id != cpu);

	if (entry->scheduled)
		np = entry->scheduled->res.ops->is_np(&entry->scheduled->res, cpu);

	raw_spin_lock_irqsave(&gedf_env->domain.ready_lock, flags);

	BUG_ON(!bheap_node_in_heap(entry->hn));
	BUG_ON(bheap_empty(&gedf_env->cpu_heap));

	/* update linked if linked for this cpu is empty */
	if (!entry->linked)
		check_for_preemptions(gedf_env);

	BUG_ON(!entry->linked && __peek_ready_res(&gedf_env->domain));

	/* if linked and scheduled differ, preempt and schedule accordingly */
	if (!np && entry->scheduled != entry->linked) {
		if (entry->scheduled && entry->scheduled->res.ops->on_preempt)
			entry->scheduled->res.ops->on_preempt(&entry->scheduled->res, cpu);
		if (entry->linked && entry->linked->res.ops->on_schedule)
			entry->linked->res.ops->on_schedule(&entry->linked->res, cpu);
		entry->scheduled = entry->linked;
	}
	raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);

	if (entry->scheduled) {
		/* let scheduled reservation decide what runs next */
		next = entry->scheduled->res.ops->dispatch_client(&entry->scheduled->res, time_slice, cpu);
		*time_slice = (*time_slice > entry->scheduled->res.cur_budget) ?
			entry->scheduled->res.cur_budget : *time_slice;
	} else {
		*time_slice = ULLONG_MAX;
	}

	return next;
}

static void gedf_env_update_time(
	struct ext_reservation_environment* env,
	lt_t how_much,
	int cpu)
{
	struct gedf_reservation_environment* gedf_env;
	struct gedf_cpu_entry* entry;
	unsigned long flags;

	gedf_env = container_of(env, struct gedf_reservation_environment, env);
	entry = &gedf_env->cpu_entries[cpu];

	BUG_ON(!bheap_node_in_heap(entry->hn));
	BUG_ON(entry->id != cpu);

	if (!entry->scheduled)
		return;

	/* tells scheduled res to drain its budget.
	 * In the situation of 2 cores having the same scheduled(detailed in comment below), the task will be
	 * out of budget. This means drain_budget just atomically sets cur_budget to 0 on drain.
	 * Therefore, no lock is needed for this operation
	 */
	entry->scheduled->res.ops->drain_budget(&entry->scheduled->res, how_much, cpu);

	/* if flagged for removal from environment, invoke shutdown callback */
	if (entry->scheduled->will_remove) {
		/* assumed to already been unlinked by whatever set will_remove */
		entry->scheduled->res.ops->shutdown(&entry->scheduled->res);
		entry->scheduled = NULL;
	}

	/* We need to lock this whole section due to how budget draining works.
	 * check_for_preemption can be called before budget is properly updated, which,
	 * through multiple parallel calls to check_for_preemption may end up linking
	 * a task that's out of budget(but not when it is ran through check_for_preemption) to
	 * a core other than this one.
	 * That core can then experience multiple reschedule calls due to the multiple calls to
	 * check_for_preemption, which will make the linked out of budget task into scheduled.
	 * Now we have an interesting dilemma. This core and the other core both sees that its
	 * scheduling the same out of budget task. So we need a way to break symmetry and let
	 * one core do nothing. By checking for !cur_budget and replenishing budget under a lock,
	 * we can achieve this.
	 */
	raw_spin_lock_irqsave(&gedf_env->domain.ready_lock, flags);
	if (entry->scheduled && !entry->scheduled->res.cur_budget) {
		entry->scheduled->res.ops->replenish_budget(&entry->scheduled->res, cpu);
		/* unlink and requeue if not blocked and not np*/
		if (!entry->scheduled->blocked &&
				!entry->scheduled->res.ops->is_np(&entry->scheduled->res, cpu)) {
			unlink(gedf_env, entry->scheduled);
			requeue(gedf_env, entry->scheduled);
			check_for_preemptions(gedf_env);
		}
	}
	raw_spin_unlock_irqrestore(&gedf_env->domain.ready_lock, flags);
}

/* callback for how the domain will release jobs */
static void gedf_env_release_jobs(rt_domain_t* rt, struct bheap* res)
{
	unsigned long flags;
	struct gedf_reservation_environment* gedf_env
		= container_of(rt, struct gedf_reservation_environment, domain);

	raw_spin_lock_irqsave(&rt->ready_lock, flags);
	__merge_ready(rt, res);
	check_for_preemptions(gedf_env);
	raw_spin_unlock_irqrestore(&rt->ready_lock, flags);
}

static struct ext_reservation_environment_ops gedf_env_ops = {
	.update_time = gedf_env_update_time,
	.dispatch = gedf_env_dispatch,
	.resume = gedf_env_resume,
	.suspend = gedf_env_suspend,
	.add_res = gedf_env_add_res,
	.remove_res = gedf_env_remove_res,
	.find_res_by_id = gedf_find_res_by_id,
	.is_np = gedf_env_is_np,
	.shutdown = gedf_env_shutdown
};

long alloc_gedf_reservation_environment(
	struct gedf_reservation_environment** _env,
	int max_cpus)
{
	struct gedf_reservation_environment* gedf_env;
	int i;
	int total_cpus = num_online_cpus();

	gedf_env = kzalloc(sizeof(struct gedf_reservation_environment), GFP_ATOMIC);
	if (!gedf_env)
		return -ENOMEM;
	/* We don't know which subset of CPUs we'll run on, so we must keep state
	 * for all of them */
	gedf_env->cpu_entries = kzalloc(sizeof(struct gedf_cpu_entry)*total_cpus, GFP_ATOMIC);
	if (!gedf_env->cpu_entries) {
		kfree(gedf_env);
		return -ENOMEM;
	}
	gedf_env->cpu_node = kzalloc(sizeof(struct bheap_node)*total_cpus, GFP_ATOMIC);
	if (!gedf_env->cpu_node) {
		kfree(gedf_env->cpu_entries);
		kfree(gedf_env);
		return -ENOMEM;
	}

	/* set environment callback actions */
	gedf_env->env.ops = &gedf_env_ops;
	INIT_LIST_HEAD(&gedf_env->env.all_reservations);

	gedf_env->num_cpus = 0;
	bheap_init(&gedf_env->cpu_heap);
	for (i = 0; i < max_cpus; i++) {
		gedf_env->cpu_entries[i].id = i;

		/* initialize cpu heap node */
		gedf_env->cpu_entries[i].hn = &gedf_env->cpu_node[i];
		bheap_node_init(&gedf_env->cpu_entries[i].hn, &gedf_env->cpu_entries[i]);
	}

	/* initialize environment domain */
	rt_domain_init(&gedf_env->domain, edf_ready_order, NULL, gedf_env_release_jobs);

	*_env = gedf_env;
	return 0;
}

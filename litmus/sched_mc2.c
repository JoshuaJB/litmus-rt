/*
 * litmus/sched_mc2.c
 * Copyright Joshua Bakita 2020, Namhoon Kim 2019, Bjorn Brandenburg 2018
 *
 * Implementation of the Mixed-Criticality on MultiCore scheduler
 *
 * This plugin implements a scheduling algorithm proposed in
 * "Mixed-Criticality Real-Time Scheduling for Multicore System" paper.
 */

#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include <litmus/sched_plugin.h>
#include <litmus/preempt.h>
#include <litmus/debug_trace.h>

#include <litmus/litmus.h>
#include <litmus/jobs.h>
#include <litmus/budget.h>
#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/trace.h>

#include <litmus/np.h>
#include <litmus/reservations/reservation.h>
#include <litmus/reservations/alloc.h>
#include <litmus/reservations/gedf_reservation.h>

#define BUDGET_ENFORCEMENT_AT_C 0

static void do_partition(task_class_t lv, int cpu) {
	/* Stub: this was implemented in cache_proc.c to switch out the way
	 * lockdown register on a context switch on the old i.MX6 boards that
	 * MC^2 used to use. On x86, we use RDT/resctrl subsystem as
	 * implemented by Intel's CAT and by AMD's Platform QoS Extensions. */
}

struct mc2_task_state {
	/* if cpu == -1, this task is a global task (level C) */
	int cpu;
	/* used to avoid cross-processor locks? */
	bool has_departed;
	/* sup and gedf task reservations */
	struct task_client res_info;
	struct ext_reservation* ext_res;
};

struct mc2_cpu_state {
	raw_spinlock_t lock;

	struct sup_reservation_environment* sup_envs;
	/* Timer for budget enforcement at all levels */
	struct hrtimer timer;

	int cpu;
	struct task_struct* scheduled;
};
static DEFINE_PER_CPU(struct mc2_cpu_state, mc2_cpu_state);

struct gedf_reservation_environment* gedf_env;

/* Used for Level-C budget tracking
 * Origin: ext_res_c1
 */
static DEFINE_PER_CPU(lt_t, last_update_time);

#define cpu_state_for(cpu_id)	(&per_cpu(mc2_cpu_state, cpu_id))
#define local_cpu_state()	(this_cpu_ptr(&mc2_cpu_state))

#define NUM_CRIT_LEVELS 3
#define NUM_SUP_ENVS 2
/**
 * sup_for_each_env - Iterate over single uniprocessor (sup) reservations
 * @env:  The &struct sup_reservation_environment to use as a loop cursor
 * @envs: The &struct sup_reservation_environment to start of env array
 */
#define sup_for_each_env(env, envs) \
	for (env=&envs[CRIT_LEVEL_A-CRIT_LEVEL_A]; \
	     env <= &envs[CRIT_LEVEL_B-CRIT_LEVEL_A]; env++)


/* get_mc2_state - get the task's state
 * Origin: P-RES
 */
static struct mc2_task_state* get_mc2_state(struct task_struct *tsk)
{
	return (struct mc2_task_state*)tsk_rt(tsk)->plugin_state;
}

/* get_task_crit_level - return the criticaility level of a task */
static task_class_t get_task_crit_level(struct task_struct *tsk)
{
	if (!tsk || !is_realtime(tsk))
		return NUM_CRIT_LEVELS;

	return tsk_rt(tsk)->task_params.cls;
}

/* task_depart - Remove a task from its reservation.
 *               If the job has remaining budget, drain it.
 *               Called by blocks() and task_exit().
 *
 * @job_complete	indicate whether job completes or not
 * @request_free	If the task should be freed (ext_res only)
 * Origin: P-RES
 */
static void task_departs(struct task_struct *tsk, int job_complete, int request_free)
{
	struct mc2_task_state* tinfo = get_mc2_state(tsk);

	BUG_ON(!is_realtime(tsk));
	tinfo->has_departed = true;

	if (get_task_crit_level(tsk) < CRIT_LEVEL_C) {
		struct reservation* res;
		struct reservation_client *client;
		client = &tinfo->res_info.client;
		BUG_ON(!client);
		res    = client->reservation;
		BUG_ON(!res);

		/* empty remaining budget
		 * This only happens if the job is completed and blocked */
		if (job_complete)
			res->cur_budget = 0;

		res->ops->client_departs(res, client, job_complete);
		TRACE_TASK(tsk, "client_departs: removed from reservation R%d with budget %llu\n", res->id, res->cur_budget);
	} else {
		struct ext_reservation* res = tinfo->ext_res;
		res->par_env->ops->remove_res(res->par_env, res, request_free, 0);
	}

	// We reschedule to choose a new task
	if (tinfo->cpu != -1)
		litmus_reschedule(tinfo->cpu);
	else
		litmus_reschedule_local();

	if (job_complete)
		sched_trace_task_completion(tsk, 0);
}

/* task_arrives - put a task into its reservation
 * @param tsk Task to add.
 * @note: Lock must be held.
 * @origin: P-RES, sched_ext, Joshua
 */
static void task_arrives(struct task_struct *tsk)
{
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	struct reservation* res;
	struct reservation_client *client;

	tinfo->has_departed = false;

	if (get_task_crit_level(tsk) < CRIT_LEVEL_C) {
		client = &tinfo->res_info.client;
		res    = client->reservation;
		res->ops->client_arrives(res, client);
		TRACE_TASK(tsk, "client_arrives: added to reservation R%d\n", res->id);
	} else {
		struct ext_reservation* res = tinfo->ext_res;
		res->par_env->ops->add_res(res->par_env, res, 0);
	}

	// We reschedule to check if current need to change to the new task
	if (tinfo->cpu != -1)
		litmus_reschedule(tinfo->cpu);
	else
		litmus_reschedule_local();
}

/* on_scheduling_timer - timer event for partitioned or global tasks
 *                       This timer is set in schedule() as requested
 *                       by any reservation.
 * Origin: Joshua
 */
static enum hrtimer_restart on_scheduling_timer(struct hrtimer *timer)
{
	litmus_reschedule_local();
	return HRTIMER_NORESTART;
}

/* mc2_complete_job - syscall backend for job completions
 * Origin: Joshua
 */
static long mc2_complete_job(void)
{
	if (get_task_crit_level(current) < CRIT_LEVEL_C)
		return complete_job_oneshot();
	else
		return complete_job();
}

/* mc2_dispatch - Select the next Level-A or -B task to schedule.
 * Origin: Joshua
 */
struct task_struct* mc2_dispatch(struct mc2_cpu_state* state)
{
	struct task_struct *tsk = NULL;
	struct sup_reservation_environment *env;

	// sup_envs is sorted by level (Level-A, then Level-B)
	sup_for_each_env(env, state->sup_envs) {
		// sup_dispatch iterates through active_reservations
		// which is sorted by priority (deadline in EDF, static
		// priority in RM) until it finds an active client.
		tsk = sup_dispatch(env);
		if (tsk)
			return tsk;
	}

	return NULL;
}

// Timestamping and cache partitioning
static inline void pre_schedule(struct task_struct *prev, int cpu)
{
	TS_SCHED_A_START;
	TS_SCHED_C_START;

	if (!prev || !is_realtime(prev))
		return;

	do_partition(CRIT_LEVEL_C, cpu);
}

// Timestamping and cache partitioning
static inline void post_schedule(struct task_struct *next, int cpu)
{
	task_class_t lev;
	if ((!next) || !is_realtime(next)) {
		//do_partition(NUM_CRIT_LEVELS, -1);
		return;
	}

	lev = get_task_crit_level(next);
	do_partition(lev, cpu);

	switch(lev) {
		case CRIT_LEVEL_A:
		case CRIT_LEVEL_B:
			TS_SCHED_A_END(next);
			break;
		case CRIT_LEVEL_C:
			TS_SCHED_C_END(next);
			break;
		default:
			break;
	}

}

/* mc2_schedule - main scheduler function. pick the next task to run
 * Origin: P-RES and Namhoon
 */
static struct task_struct* mc2_schedule(struct task_struct * prev)
{
	int np, blocks, exists;
	lt_t update;
	struct sup_reservation_environment* env;
	/* next == NULL means "schedule background work". */
	lt_t now = litmus_clock();
	struct mc2_cpu_state *state = local_cpu_state();
	lt_t global_next_scheduler_update = ULLONG_MAX;
	int cpu = smp_processor_id();

	raw_spin_lock(&state->lock);

	pre_schedule(prev, state->cpu);

	BUG_ON(prev && state->scheduled && state->scheduled != prev);
	BUG_ON(prev && state->scheduled && !is_realtime(prev));

	/* (0) Determine state */
	exists = state->scheduled != NULL;
	blocks = exists && !is_current_running();
	np = exists && is_np(state->scheduled);

	/* update time */
	sup_for_each_env(env, state->sup_envs) {
		env->will_schedule = true;
		sup_update_time(env, now);
	}

	// Blocked tasks have already been handled if `has_departed`
	BUG_ON(is_realtime(current) && blocks && !((struct mc2_task_state*)prev->rt_param.plugin_state)->has_departed);

	/* figure out what to schedule next */
	// Iterate through all core-local reservations to check if they have anything to run
	if (!np)
		state->scheduled = mc2_dispatch(state);

	// If core-local reservations have nothing to run, ask the global reservation
	// Note that gedf_env handles non-preemptivity internally
	if (!state->scheduled) {
		// We only update the gedf_env once all higher criticality work is done
		gedf_env->env.ops->resume(&gedf_env->env, cpu);
		gedf_env->env.ops->update_time(&gedf_env->env, now - *this_cpu_ptr(&last_update_time), cpu);
		*this_cpu_ptr(&last_update_time) = now;
		state->scheduled = gedf_env->env.ops->dispatch(&gedf_env->env, &global_next_scheduler_update, cpu);
		if (global_next_scheduler_update != ULLONG_MAX)
			global_next_scheduler_update += now;
	} else {
		gedf_env->env.ops->suspend(&gedf_env->env, cpu);
	}

	/* program scheduler timer */
	// This is safe as the no update timer needed magic value is ULLONG_MAX
	update = global_next_scheduler_update;
	sup_for_each_env(env, state->sup_envs) {
		// XXX: What is this???
		env->will_schedule = false;
		update = min(update, env->next_scheduler_update);
	}
	if (update == SUP_NO_SCHEDULER_UPDATE) {
		if (hrtimer_active(&state->timer)) {
			TRACE("canceling timer...at %llu\n",
				  ktime_to_ns(hrtimer_get_expires(&state->timer)));
			hrtimer_cancel(&state->timer);
		}
	} else if (ktime_to_ns(hrtimer_get_expires(&state->timer)) != update) {
		// Note that it's safe to call hrtimer_start on an already set timer
		TRACE("setting scheduler timer for %llu\n", update);
		/* We used to have to use __hrtimer_start_range_ns() to avoid
		 * wakeup, however it seems that the hrtimer system has been
		 * updated so that we no longer need that flag (or at least that's
		 * the descision that was made in budget.c and sched_pfair.c). */
		hrtimer_start(&state->timer,
				ns_to_ktime(update),
				HRTIMER_MODE_ABS_PINNED_HARD);
	}

	if (update < litmus_clock()) {
		/* uh oh, timer expired while we were scheduling */
		TRACE("timer expired while scheduling "
			  "update:%llu now:%llu actual:%llu\n",
			  update, now, litmus_clock());
		litmus_reschedule_local();
	}

	/* Notify LITMUS^RT core that we've arrived at a scheduling decision. */
	sched_state_task_picked();

	// Mark prev as no longer scheduled
	if (prev && prev != state->scheduled && is_realtime(prev)
	         && get_task_crit_level(prev) < CRIT_LEVEL_C) {
		struct mc2_task_state* tinfo = get_mc2_state(prev);
		struct reservation* res = tinfo->res_info.client.reservation;
		res->scheduled_on = NO_CPU;
	}

	if (prev && prev != state->scheduled && is_realtime(prev))
		TRACE_TASK(prev, "descheduled at %llu.\n", litmus_clock());
	if (state->scheduled)
		TRACE_TASK(state->scheduled, "scheduled at %llu.\n", litmus_clock());

	post_schedule(state->scheduled, state->cpu);
	raw_spin_unlock(&state->lock);
	return state->scheduled;
}

/* mc2_task_block: Called when a task should be removed from the ready queue.
 * Origin: P-RES
 */
static void mc2_task_block(struct task_struct *tsk)
{
	unsigned long flags;
	struct mc2_task_state* tinfo;
	struct mc2_cpu_state *state;

	preempt_disable();
	tinfo = get_mc2_state(tsk);
	if (tinfo->cpu != -1)
		state = cpu_state_for(tinfo->cpu);
	else
		state = local_cpu_state();
	preempt_enable();

	raw_spin_lock_irqsave(&state->lock, flags);
	TRACE_TASK(tsk, "thread suspends at %llu (state:%d, running:%d)\n",
		litmus_clock(), tsk->state, is_current_running());

	// Dequeue and reschedule
	task_departs(tsk, is_completed(tsk), 0);
	raw_spin_unlock_irqrestore(&state->lock, flags);
}

/* mc2_task_resume - Called when the state of tsk changes back to
 *                   TASK_RUNNING. We need to requeue the task.
 * @note May be called on the wrong CPU!
 */
static void mc2_task_resume(struct task_struct  *tsk)
{
	unsigned long flags;
	struct mc2_task_state* tinfo;
	struct mc2_cpu_state *state;

	TRACE_TASK(tsk, "thread wakes up at %llu\n", litmus_clock());

	preempt_disable();
	tinfo = get_mc2_state(tsk);
	if (tinfo->cpu != -1)
		state = cpu_state_for(tinfo->cpu);
	else
		state = local_cpu_state();
	preempt_enable();

	// We should never be resuming a task that we have no record of suspending
	BUG_ON(!tinfo->has_departed);

#ifdef CONFIG_SCHED_OVERHEAD_TRACE
	switch(get_task_crit_level(tsk)) {
		case CRIT_LEVEL_A:
			TS_RELEASE_LATENCY_A(get_release(tsk));
			break;
		case CRIT_LEVEL_B:
			TS_RELEASE_LATENCY_B(get_release(tsk));
			break;
		case CRIT_LEVEL_C:
			TS_RELEASE_LATENCY_C(get_release(tsk));
			break;
		default:
			break;
	}
#endif

	raw_spin_lock_irqsave(&state->lock, flags);

	task_arrives(tsk);

	TRACE_TASK(tsk, "mc2_resume()\n");

	raw_spin_unlock_irqrestore(&state->lock, flags);
}


/* mc2_admit_task - Setup mc2 task parameters
 * This is called before is_realtime(tsk) and before mc2_task_new()
 * We should be inside the context of the process attempting to become realtime
 * Called with preemption disabled and g_lock /not/ held
 * This only validates and initializes immutable state. This DOES NOT insert
 * anything into any runqueue or set up mutable state (such as release time)
 * For Level-A and -B, this creates a reservation if on is not specified.
 */
static long mc2_admit_task(struct task_struct *tsk)
{
	long err = -EINVAL;
	unsigned long flags;
	struct mc2_cpu_state *state;
	struct mc2_task_state *tinfo = kzalloc(sizeof(*tinfo), GFP_ATOMIC);
	struct rt_task *task_params = &tsk_rt(tsk)->task_params;

	if (!tinfo)
		return -ENOMEM;

	if (task_params->cls < CRIT_LEVEL_A || task_params->cls > CRIT_LEVEL_C) {
		printk(KERN_ERR "mc2_admit_task: invalid criticality level\n");
		err = -EINVAL;
		goto out;
	}

	// This is okay, as tinfo will be freed if we fail
	tinfo->has_departed = true;

	// Setup a core-local or global reservation as appropriate
	if (task_params->cls < CRIT_LEVEL_C) {
		struct sup_reservation_environment* env;
		struct reservation *res;
		/* We assume that the caller migrated to the correct CPU first
		 * if they intend to migrate to an existing reservation. */
		tinfo->cpu = task_cpu(tsk);
		state = cpu_state_for(task_cpu(tsk));
		env = &state->sup_envs[task_params->cls];
		raw_spin_lock_irqsave(&state->lock, flags);

		if ((res = sup_find_by_id(env, task_params->cpu))) {
			/* Explicitly created reservations go into the Level-A env,
			 * so make sure that this isn't a Level-B task if it wants
			 * to use an explicit reservation.
			 */
			if (task_params->cls != CRIT_LEVEL_A)
				err = -EINVAL;
			else
				err = 0;
		} else {
			// Implictly create a reservation
			struct reservation_config config;
			if (task_params->cpu > NR_CPUS) {
				printk(KERN_ERR "requested CPU %d does"
				       " not exist\n", task_params->cpu);
				err = -EINVAL;
				goto out;
			}
			config.id = tsk->pid;
			config.cpu = tsk_rt(tsk)->task_params.cpu;
			// If priority is LITMUS_NO_PRIORITY, EDF scheduling is implied
			config.priority = tsk_rt(tsk)->task_params.priority;
			config.polling_params.period = tsk_rt(tsk)->task_params.period;
			// Try to respect the budget management setting on the task
			if (tsk_rt(tsk)->task_params.budget_policy == NO_ENFORCEMENT)
				config.polling_params.budget = tsk_rt(tsk)->task_params.period;
			else
				config.polling_params.budget = tsk_rt(tsk)->task_params.exec_cost;
			config.polling_params.offset = tsk_rt(tsk)->task_params.phase;
			config.polling_params.relative_deadline = tsk_rt(tsk)->task_params.relative_deadline;

			err = alloc_polling_reservation(PERIODIC_POLLING, &config, &res);
			if (err) {
				printk(KERN_ERR "Unable to implicitly create a reservation\n");
				goto out;
			}
			sup_add_new_reservation(env, res);
			err = 0;
		}
		// Sets up task_client state to point to the reservation
		task_client_init(&tinfo->res_info, tsk, res);

		raw_spin_unlock_irqrestore(&state->lock, flags);
	} else if (task_params->cls == CRIT_LEVEL_C) {
		struct gedf_task_reservation* gedf_task_res;
		lt_t max_budget = ULLONG_MAX; // No enforcement
		tinfo->cpu = -1; // Indicates global
		if (tsk_rt(tsk)->task_params.budget_policy != NO_ENFORCEMENT)
			max_budget = tsk_rt(tsk)->task_params.exec_cost;

		// Sets parent of gedf_task_reservation to point to gedf_env
		if (!(err = alloc_gedf_task_reservation(&gedf_task_res, tsk, max_budget))) {
			gedf_task_res->gedf_res.res.par_env = &gedf_env->env;
			tinfo->ext_res = (struct ext_reservation*)gedf_task_res;
		}
	}

	// rt_param will be cleared if admission fails, so this is safe
	tsk_rt(tsk)->plugin_state = tinfo;
	// We delegate budget enforcement to reservations, so disable LITMUS's enforcement
	tsk_rt(tsk)->task_params.budget_policy = NO_ENFORCEMENT;
out:
	// This function is full of memory leaks. See alloc/init client/reservation.
	if (err)
		kfree(tinfo);

	return err;
}

/* mc2_task_new - A new real-time job is arrived. Release the next job
 *                at the next reservation replenish time
 * This is called after the task state has been initialized in mc2_admit_task,
 * and is_realtime(tsk).
 */
static void mc2_task_new(struct task_struct *tsk, int on_runqueue,
			  int is_running)
{
	unsigned long flags;
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	struct mc2_cpu_state *state;
	struct reservation *res;
	task_class_t lv = get_task_crit_level(tsk);
	lt_t release = 0;

	TRACE_TASK(tsk, "new RT task %llu (on_rq:%d, running:%d)\n",
		   litmus_clock(), on_runqueue, is_running);

	if (tinfo->cpu == -1)
		state = local_cpu_state();
	else
		state = cpu_state_for(tinfo->cpu);

	/* acquire the lock protecting the state and disable interrupts */
	raw_spin_lock_irqsave(&state->lock, flags);

	if (is_running) {
		state->scheduled = tsk;
		/* make sure this task should actually be running */
		litmus_reschedule_local();
	}

	if (lv == CRIT_LEVEL_C) {
		release = litmus_clock();
		tinfo->ext_res->replenishment_time = release;
	} else {
		res = sup_find_by_id(&state->sup_envs[lv], tinfo->res_info.client.reservation->id);
	}

	// Tasks can arrive in a blocked state if !on_runqueue && !is_running
	if (on_runqueue || is_running)
		task_arrives(tsk);

	// This has to happen after task arrival has set next_replenishment
	// Wait for the next hyperperiod
	if (lv != CRIT_LEVEL_C)
		release = res->next_replenishment;
	BUG_ON(!release);
	// This is safe, even when tasks wait for release. In that case,
	// LITMUS will automatically reconfigure the release time.
	release_at(tsk, release);

	TRACE_TASK(tsk, "mc2_task_new() next_release = %llu\n", release);

	raw_spin_unlock_irqrestore(&state->lock, flags);
}

/* mc2_reservation_destroy - reservation_destroy system call backend
 * @note Can only destroy Level-A reservations.
 * Origin: Namhoon
 */
static long mc2_reservation_destroy(unsigned int reservation_id, int cpu)
{
	struct mc2_cpu_state *state;
	struct reservation *res = NULL;
	unsigned long flags;
	long err = 0;

	/* if the reservation is partitioned reservation */
	state = cpu_state_for(cpu);
	raw_spin_lock_irqsave(&state->lock, flags);

	res = sup_find_by_id(&state->sup_envs[CRIT_LEVEL_A], reservation_id);
	if (res)
		destroy_reservation(res);
	else
		err = -EINVAL;

	raw_spin_unlock_irqrestore(&state->lock, flags);

	TRACE("Reservation destroyed err = %d\n", err);
	return err;
}

/* mc2_task_exit - Task became a normal task (not real-time task)
 */
static void mc2_task_exit(struct task_struct *tsk)
{
	unsigned long flags;
	struct mc2_task_state* tinfo;
	struct mc2_cpu_state *state;

	preempt_disable();
	tinfo = get_mc2_state(tsk);
	if (tinfo->cpu != -1)
		state = cpu_state_for(tinfo->cpu);
	else
		state = local_cpu_state();
	preempt_enable();

	raw_spin_lock_irqsave(&state->lock, flags);

	TRACE_TASK(tsk, "task exits at %llu (present:%d sched:%d)\n",
		litmus_clock(), is_present(tsk), state->scheduled == tsk);

	if (state->scheduled == tsk)
		state->scheduled = NULL;

	/* remove from queues and reschedule */
	if (tsk->state == TASK_RUNNING) 
		task_departs(tsk, 0, 1);

	// Cleanup any automatically created reservations
	if (tinfo->cpu != -1) {
		struct reservation* res = tinfo->res_info.client.reservation;
		// Automatically created reservations use the task's PID
		if (tsk->pid == res->id)
			destroy_reservation(res);
	}

	raw_spin_unlock_irqrestore(&state->lock, flags);

	kfree(tsk_rt(tsk)->plugin_state);
	tsk_rt(tsk)->plugin_state = NULL;
}

/* mc2_reservation_create - reservation_create system call backend
 * @note Can only be used to create Level-A reservations. Level-B and Level-C
 *       reservations are implicit (see mc2_admit_task()).
 * Origin: P-RES
 */
static long do_mc2_reservation_create(
	int res_type,
	struct reservation_config *config)
{
	struct mc2_cpu_state *state;
	struct reservation* res;
	struct reservation* new_res = NULL;
	unsigned long flags;
	long err;

	/* Allocate before we grab a spin lock. */
	switch (res_type) {
		case PERIODIC_POLLING:
		case SPORADIC_POLLING:
			err = alloc_polling_reservation(res_type, config, &new_res);
			break;

		case TABLE_DRIVEN:
			err = alloc_table_driven_reservation(config, &new_res);
			break;

		default:
			err = -EINVAL;
			break;
	}

	if (err)
		return err;

	/* Check if the reservation exists after creating the new one so that
	 * we only have to get the spin lock once.
	 */
	state = cpu_state_for(config->cpu);
	raw_spin_lock_irqsave(&state->lock, flags);
	res = sup_find_by_id(&state->sup_envs[CRIT_LEVEL_A], config->id);
	if (!res) {
		sup_add_new_reservation(&state->sup_envs[CRIT_LEVEL_A], new_res);
		err = config->id;
	} else {
		err = -EEXIST;
	}
	raw_spin_unlock_irqrestore(&state->lock, flags);

	if (err < 0)
		kfree(new_res);

	return err;
}

/* mc2_reservation_create: Optionally specify Level-A reservations
 * @description MC^2 uses two traditional reservation environments per core.
 *              (One for Level-B and one for Level-A.) This can only be used to
 *              create reservations in the Level-A environment. Ideally, I'd
 *              get rid of this entirely, but it's needed to specify the table
 *              layout if a table-driven reservation is used at Level-A.
 * Origin: P-RES + Joshua
 */
static long mc2_reservation_create(int res_type, void* __user _config)
{
	struct reservation_config config;

	TRACE("Attempt to create reservation (%d)\n", res_type);

	if (copy_from_user(&config, _config, sizeof(config)))
		return -EFAULT;

	if (config.cpu != -1 && (config.cpu < 0 || !cpu_online(config.cpu))) {
		printk(KERN_ERR "invalid reservation (%u): "
			"CPU %d offline\n", config.id, config.cpu);
		return -EINVAL;
	}

	// Reservations are only supported for core-local tasks
	if (config.cpu < 0)
		return -EINVAL;

	// Manually specified reservation IDs must be larger than NR_CPUS
	// as we autodetect task_param.cpu as a reservation if it's larger
	// than NR_CPUS. If less, we create an implicit reservation on the
	// specified core.
	if (config.id < NR_CPUS) {
		printk(KERN_WARNING "Invalid reservation ID %d on"
		       "core %d. MC^2 reservation IDs start at %d",
		       smp_processor_id(), config.id, NR_CPUS);
		return -EINVAL;
	}

	return do_mc2_reservation_create(res_type, &config);
}

/* Origin: P-RES */
static struct domain_proc_info mc2_domain_proc_info;

/* Origin: P-RES */
static long mc2_get_domain_proc_info(struct domain_proc_info **ret)
{
	*ret = &mc2_domain_proc_info;
	return 0;
}

/* Origin: P-RES */
static void mc2_setup_domain_proc(void)
{
	int i, cpu;
	int num_rt_cpus = num_online_cpus();

	struct cd_mapping *cpu_map, *domain_map;

	memset(&mc2_domain_proc_info, 0, sizeof(mc2_domain_proc_info));
	init_domain_proc_info(&mc2_domain_proc_info, num_rt_cpus, num_rt_cpus);
	mc2_domain_proc_info.num_cpus = num_rt_cpus;
	mc2_domain_proc_info.num_domains = num_rt_cpus;

	i = 0;
	for_each_online_cpu(cpu) {
		cpu_map = &mc2_domain_proc_info.cpu_to_domains[i];
		domain_map = &mc2_domain_proc_info.domain_to_cpus[i];

		cpu_map->id = cpu;
		domain_map->id = i;
		cpumask_set_cpu(i, cpu_map->mask);
		cpumask_set_cpu(cpu, domain_map->mask);
		++i;
	}
}

/* Origin: P-RES */
/* Called from an atomic environment */
static long mc2_activate_plugin(void)
{
	int cpu, res;
	struct mc2_cpu_state *state;
	struct sup_reservation_environment *env;
	lt_t now = litmus_clock();

	if ((res = alloc_gedf_reservation_environment(&gedf_env, num_online_cpus())) < 0)
		return res;

	for_each_online_cpu(cpu) {
		TRACE("Initializing CPU%d...\n", cpu);

		state = cpu_state_for(cpu);

		*this_cpu_ptr(&last_update_time) = now;
		gedf_env->env.ops->resume(&gedf_env->env, cpu);

		raw_spin_lock_init(&state->lock);
		state->cpu = cpu;
		state->scheduled = NULL;
		// Setup the reservation environments for this core
		state->sup_envs = kzalloc(
				sizeof(struct sup_reservation_environment)*NUM_SUP_ENVS,
				GFP_ATOMIC);
		sup_for_each_env(env, state->sup_envs)
			sup_init(env);
		// Setup the budget/quanta timer
		hrtimer_init(&state->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED_HARD);
		state->timer.function = on_scheduling_timer;
	}

	mc2_setup_domain_proc();

	return 0;
}

/* mc2_finish_switch: Clear scheduled when a non-rt task runs
 * Origin: Namhoon
 */
static void mc2_finish_switch(struct task_struct *prev)
{
	struct mc2_cpu_state *state = local_cpu_state();
	state->scheduled = is_realtime(current) ? current : NULL;
}

/* mc2_deactivate_plugin: Reset/clear/flush state
 * Origin: P-RES
 */
static long mc2_deactivate_plugin(void)
{
	int cpu;
	struct mc2_cpu_state *state;
	struct reservation *res;
	struct reservation *temp;
	struct sup_reservation_environment *env;

	gedf_env->env.ops->shutdown(&gedf_env->env);

	for_each_online_cpu(cpu) {
		state = cpu_state_for(cpu);
		raw_spin_lock(&state->lock);

		hrtimer_cancel(&state->timer);

		sup_for_each_env(env, state->sup_envs) {
			list_for_each_entry_safe(res, temp, &env->all_reservations, all_list)
				destroy_reservation(res);
		}

		raw_spin_unlock(&state->lock);
	}

	destroy_domain_proc_info(&mc2_domain_proc_info);
	return 0;
}

static struct sched_plugin mc2_plugin = {
	.plugin_name		= "MC2",
	.schedule		= mc2_schedule,
	.finish_switch		= mc2_finish_switch,
	.task_wake_up		= mc2_task_resume,
	.task_block			= mc2_task_block,
	.admit_task		= mc2_admit_task,
	.task_new		= mc2_task_new,
	.task_exit		= mc2_task_exit,
	.complete_job		= mc2_complete_job,
	.get_domain_proc_info	= mc2_get_domain_proc_info,
	.activate_plugin	= mc2_activate_plugin,
	.deactivate_plugin	= mc2_deactivate_plugin,
	.reservation_create	= mc2_reservation_create,
	.reservation_destroy	= mc2_reservation_destroy,
};

static int __init init_mc2(void)
{
	return register_sched_plugin(&mc2_plugin);
}

module_init(init_mc2);

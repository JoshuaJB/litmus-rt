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
#include <litmus/mc2_common.h>
#include <litmus/reservations/reservation.h>
#include <litmus/reservations/alloc.h>

#define BUDGET_ENFORCEMENT_AT_C 0

static void do_partition(enum crit_level lv, int cpu) {
	/* Stub: this was implemented in cache_proc.c to switch out the way
	 * lockdown register on a context switch on the old i.MX6 boards that
	 * MC^2 used to use. On x86, we use RDT/resctrl subsystem as
	 * implemented by Intel's CAT and by AMD's Platform QoS Extensions. */
}

// HISTORIC: Global env declared here

/* mc2_task_state - a task state structure */
struct mc2_task_state {
	struct task_client res_info;
	/* if cpu == -1, this task is a global task (level C) */
	int cpu;
	/* used to avoid cross-processor locks? */
	bool has_departed;
	struct mc2_task mc2_param;
};

/* mc2_cpu_state - maintain the scheduled state
 * timer : timer for partitioned tasks (level A and B)
 */
struct mc2_cpu_state {
	raw_spinlock_t lock;

	struct sup_reservation_environment sup_env;
	struct hrtimer timer;

	int cpu;
	struct task_struct* scheduled;
};

static DEFINE_PER_CPU(struct mc2_cpu_state, mc2_cpu_state);

#define cpu_state_for(cpu_id)	(&per_cpu(mc2_cpu_state, cpu_id))
#define local_cpu_state()	(this_cpu_ptr(&mc2_cpu_state))

/* get_mc2_state - get the task's state
 * Origin: P-RES
 */
static struct mc2_task_state* get_mc2_state(struct task_struct *tsk)
{
	return (struct mc2_task_state*)tsk_rt(tsk)->plugin_state;
}

/* get_task_crit_level - return the criticaility level of a task */
static enum crit_level get_task_crit_level(struct task_struct *tsk)
{
	struct mc2_task *mp;

	if (!tsk || !is_realtime(tsk))
		return NUM_CRIT_LEVELS;

	mp = tsk_rt(tsk)->mc2_data;

	if (!mp)
		return NUM_CRIT_LEVELS;
	else
		return mp->crit;
}

/* task_depart - Remove a task from its reservation.
 *               If the job has remaining budget, drain it.
 *               Called by blocks() and task_exit().
 *
 * @job_complete	indicate whether job completes or not
 * Origin: P-RES
 */
static void task_departs(struct task_struct *tsk, int job_complete)
{
	struct mc2_task_state* state = get_mc2_state(tsk);
	struct reservation* res;
	struct reservation_client *client;

	BUG_ON(!is_realtime(tsk));

	client = &state->res_info.client;
	BUG_ON(!client);
	res    = client->reservation;
	BUG_ON(!res);

	/* empty remaining budget
	 * This only happens if the job is completed and blocked */
	if (job_complete) {
		res->cur_budget = 0;
		sched_trace_task_completion(tsk, 0);
	}

	res->ops->client_departs(res, client, job_complete);
	state->has_departed = true;
	TRACE_TASK(tsk, "client_departs: removed from reservation R%d with budget %llu\n", res->id, res->cur_budget);
}

/* task_arrive - put a task into its reservation
 * Origin: P-RES
 */
static void task_arrives(struct task_struct *tsk)
{
	struct mc2_task_state* state = get_mc2_state(tsk);
	struct reservation* res;
	struct reservation_client *client;

	client = &state->res_info.client;
	res    = client->reservation;

	state->has_departed = false;

	res->ops->client_arrives(res, client);
	TRACE_TASK(tsk, "client_arrives: added to reservation R%d\n", res->id);
}

/* NOTE: drops state->lock */
/* mc2_update_timer_and_unlock - set a timer and g_timer and unlock
 *                               Whenever res_env.current_time is updated,
 *                               we check next_scheduler_update and set
 *                               a timer.
 *                               If there exist a global event which is
 *                               not armed on any CPU and g_timer is not
 *                               active, set a g_timer for that event.
 * Origin: P-RES
 */
static void mc2_update_timer_and_unlock(struct mc2_cpu_state *state)
{
	int local;
	lt_t update, now;

	update = state->sup_env.next_scheduler_update;
	now = state->sup_env.env.current_time;

	/* Be sure we're actually running on the right core,
	 * as pres_update_timer() is also called from pres_task_resume(),
	 * which might be called on any CPU when a thread resumes.
	 */
	local = local_cpu_state() == state;

	/* Must drop state lock before calling into hrtimer_start(), which
	 * may raise a softirq, which in turn may wake ksoftirqd. */
	raw_spin_unlock(&state->lock);

	// HISTORIC: Flushed events from global env and triggered scheduling

	if (update <= now) {
		litmus_reschedule(state->cpu);
	} else if (likely(local && update != SUP_NO_SCHEDULER_UPDATE)) {
		/* Reprogram our next scheduler update only if it is not already set correctly. */
		if (!hrtimer_active(&state->timer) ||
		    ktime_to_ns(hrtimer_get_expires(&state->timer)) != update) {
			TRACE("canceling timer...at %llu\n",
			      ktime_to_ns(hrtimer_get_expires(&state->timer)));
			hrtimer_cancel(&state->timer);
			TRACE("setting scheduler timer for %llu\n", update);
			/* We used to have to use __hrtimer_start_range_ns() to avoid
			 * wakeup, however it seems that the hrtimer system has been
			 * updated so that we no longer need that flag (or at least that's
			 * the descision that was made in budget.c and sched_pfair.c). */
			hrtimer_start(&state->timer,
					ns_to_ktime(update),
					HRTIMER_MODE_ABS_PINNED);
			if (update < litmus_clock()) {
				/* uh oh, timer expired while trying to set it */
				TRACE("timer expired during setting "
				      "update:%llu now:%llu actual:%llu\n",
				      update, now, litmus_clock());
				/* The timer HW may not have been reprogrammed
				 * correctly; force rescheduling now. */
				litmus_reschedule(state->cpu);
			}
		}
	} else if (unlikely(!local && update != SUP_NO_SCHEDULER_UPDATE)) {
		/* Poke remote core only if timer needs to be set earlier than
		 * it is currently set.
		 */
		TRACE("mc2_update_timer for remote CPU %d (update=%llu, "
		      "active:%d, set:%llu)\n",
			state->cpu,
			update,
			hrtimer_active(&state->timer),
			ktime_to_ns(hrtimer_get_expires(&state->timer)));
		if (!hrtimer_active(&state->timer) ||
		    ktime_to_ns(hrtimer_get_expires(&state->timer)) > update) {
			TRACE("poking CPU %d so that it can update its "
			       "scheduling timer (active:%d, set:%llu)\n",
			       state->cpu,
			       hrtimer_active(&state->timer),
			       ktime_to_ns(hrtimer_get_expires(&state->timer)));
			litmus_reschedule(state->cpu); // Re-added from P-RES
		}
	}
}

/* on_scheduling_timer - timer event for partitioned tasks
 * Origin: P-RES
 */
static enum hrtimer_restart on_scheduling_timer(struct hrtimer *timer)
{
	unsigned long flags;
	enum hrtimer_restart restart = HRTIMER_NORESTART;
	struct mc2_cpu_state *state;
	lt_t update, now;

	state = container_of(timer, struct mc2_cpu_state, timer);

	/* The scheduling timer should only fire on the local CPU, because
	 * otherwise deadlocks via timer_cancel() are possible.
	 * Note: this does not interfere with dedicated interrupt handling, as
	 * even under dedicated interrupt handling scheduling timers for
	 * budget enforcement must occur locally on each CPU.
	 */
	BUG_ON(state->cpu != raw_smp_processor_id());

	TS_ISR_START;

	raw_spin_lock_irqsave(&state->lock, flags);
	sup_update_time(&state->sup_env, litmus_clock());

	update = state->sup_env.next_scheduler_update;
	now = state->sup_env.env.current_time;

	TRACE_CUR("on_scheduling_timer at %llu, upd:%llu (for cpu=%d)\n",
		now, update, state->cpu);

	if (update <= now) {
		litmus_reschedule_local();
	} else if (update != SUP_NO_SCHEDULER_UPDATE) {
		hrtimer_set_expires(timer, ns_to_ktime(update));
		restart = HRTIMER_RESTART;
	}

	raw_spin_unlock_irqrestore(&state->lock, flags);
	// HISTORIC: Used to mark and IPI n lowest-prio CPUs for rescheduling here. n = gmp_update_time().

	TS_ISR_END;

	return restart;
}

/* mc2_complete_job - syscall backend for job completions
 * Origin: Namhoon
 */
static long mc2_complete_job(void)
{
	ktime_t next_release;
	long err;

	tsk_rt(current)->completed = 1;

	/* If this the first job instance, we need to reset replenish
	   time to the next release time */
	// This is a loose clone of prepare_for_next_period from jobs.c
	if (tsk_rt(current)->sporadic_release) {
		struct mc2_cpu_state *state;
		struct reservation_environment *env;
		struct mc2_task_state *tinfo;
		struct reservation *res = NULL;
		unsigned long flags;
		enum crit_level lv;

		//preempt_disable();
		local_irq_save(flags);

		tinfo = get_mc2_state(current);
		lv = get_task_crit_level(current);

		if (lv < CRIT_LEVEL_C) {
			state = cpu_state_for(tinfo->cpu);
			raw_spin_lock(&state->lock);
			env = &(state->sup_env.env);
			res = sup_find_by_id(&state->sup_env, tinfo->mc2_param.res_id);
			env->time_zero = tsk_rt(current)->sporadic_release_time;
		}
		else if (lv == CRIT_LEVEL_C) {
			// HISTORIC: Reset "time_zero" for the global env
		}
		else
			BUG();

		/* set next_replenishment time to synchronous release time */
		BUG_ON(!res);
		res->next_replenishment = tsk_rt(current)->sporadic_release_time;
		res->cur_budget = 0;
		res->env->change_state(res->env, res, RESERVATION_DEPLETED);

		raw_spin_unlock_irqrestore(&state->lock, flags);
		//preempt_enable();
	}

	sched_trace_task_completion(current, 0);
	/* update the next release time and deadline */
	prepare_for_next_period(current);
	sched_trace_task_release(current);
	next_release = ns_to_ktime(get_release(current)); // This is okay: prepare_for_next_period set it up
	preempt_disable();
	TRACE_CUR("next_release=%llu\n", get_release(current));
	if (get_release(current) > litmus_clock()) {
		// Sleep in interruptible mode (e.g. interrupts may wake us)
		set_current_state(TASK_INTERRUPTIBLE);
		// Enable preemption, but don't call schedule()
		preempt_enable_no_resched();
		TRACE_CUR("SLEEP: release=%llu now=%llu\n", get_release(current), litmus_clock());
		TRACE_CUR("Sleeping for %llu ns, aka until %llu\n", get_release(current) - litmus_clock(), ktime_to_ns(next_release));
		/* Other components of LITMUS^RT sleep Level-A and Level-B tasks
		 * for us, however, we have to make sure to correctly setup the
		 * state. For unclear reasons, that state ends up geting set as
		 * a side-effect of schedule_hrtimeout. As we don't actually want
		 * to sleep Level-A and Level-B tasks (otherwise they'll sleep
		 * twice), just sleep for an infintesimal amount of time to
		 * trigger the side effects. The side effects are NOT just:
		 * 1. schedule()
		 * 2. __set_current_state(TASK_RUNNING)
		 * 3. set_tsk_need_resched/preempt_set_need_resched/preempt_enable
		 * 4. litmus_reschedule_local()
		 */
		if (get_task_crit_level(current) < CRIT_LEVEL_C)
			next_release = ns_to_ktime(1); // FIXME: Hack to trigger side-effects
		err = schedule_hrtimeout(&next_release, HRTIMER_MODE_ABS);
	} else {
		/* release the next job immediately */
		err = 0;
		TRACE_CUR("TARDY: release=%llu now=%llu\n", get_release(current), litmus_clock());
		preempt_enable();
	}

	TRACE_CUR("mc2_complete_job returns at %llu\n", litmus_clock());

	tsk_rt(current)->completed = 0;
	return err;
}

/* mc2_dispatch - Select the next Level-A or -B task to schedule.
 * Origin: Namhoon
 */
struct task_struct* mc2_dispatch(struct sup_reservation_environment* sup_env, struct mc2_cpu_state* state)
{
	struct reservation *res, *next;
	struct task_struct *tsk = NULL;
	lt_t time_slice;

	// sup_env->active_reservations is sorted in order of priority (?)
	list_for_each_entry_safe(res, next, &sup_env->active_reservations, list) {
		if (res->state == RESERVATION_ACTIVE) {
			tsk = res->ops->dispatch_client(res, &time_slice);
			if (likely(tsk)) {
				sup_scheduler_update_after(sup_env, res->cur_budget);
				return tsk;
			}
		}
	}

	return NULL;
}

/* mc2_global_dispatch - Select the next Level-C task to schedule.
 */
struct task_struct* mc2_global_dispatch(struct mc2_cpu_state* state)
{
	// HISTORIC: Iterated through global env, called dispatch_client(), and set up EVENT_DRAIN
	lt_t time_slice;


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
	enum crit_level lev;
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
	/* next == NULL means "schedule background work". */
	lt_t now = litmus_clock();
	struct mc2_cpu_state *state = local_cpu_state();

	raw_spin_lock(&state->lock);

	pre_schedule(prev, state->cpu);

	BUG_ON(prev && state->scheduled && state->scheduled != prev);
	BUG_ON(prev && state->scheduled && !is_realtime(prev));

	/* (0) Determine state */
	exists = state->scheduled != NULL;
	blocks = exists && !is_current_running();
	np = exists && is_np(state->scheduled);

	/* update time */
	state->sup_env.will_schedule = true;
	sup_update_time(&state->sup_env, now);

	// HISTORIC: Level-C blocking task removal used to happen here
	// Blocked tasks have already been handled if `has_departed`
	BUG_ON(is_realtime(current) && blocks && !((struct mc2_task_state*)prev->rt_param.plugin_state)->has_departed);

	/* figure out what to schedule next */
	if (!np)
		state->scheduled = mc2_dispatch(&state->sup_env, state);

	// If no Level-A or -B tasks are scheduled, ask Level-C
	if (!state->scheduled) {
		// HISTORIC: global env time update
		state->scheduled = mc2_global_dispatch(state);
	} else {
		// HISTORIC: removed CPU from global env
	}

	/* Notify LITMUS^RT core that we've arrived at a scheduling decision. */
	sched_state_task_picked();

	/* program scheduler timer */
	state->sup_env.will_schedule = false;

	/* NOTE: drops state->lock */
	mc2_update_timer_and_unlock(state);

	// Mark prev as no longer scheduled
	raw_spin_lock(&state->lock);
	if (prev && prev != state->scheduled && is_realtime(prev)) {
		struct mc2_task_state* tinfo = get_mc2_state(prev);
		struct reservation* res = tinfo->res_info.client.reservation;
		res->scheduled_on = NO_CPU;
		TRACE_TASK(prev, "descheduled at %llu.\n", litmus_clock());
		/* if prev is preempted and a global task, find the lowest cpu and reschedule */
		if (tinfo->has_departed == false && get_task_crit_level(prev) == CRIT_LEVEL_C) {
			// HISTORIC: Asked lowest prio CPU to reschedule
		}
	}
	post_schedule(state->scheduled, state->cpu);
	raw_spin_unlock(&state->lock);

	if (prev && prev != state->scheduled && is_realtime(prev))
		TRACE_TASK(prev, "descheduled.\n");
	if (state->scheduled)
		TRACE_TASK(state->scheduled, "scheduled.\n");

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

	TRACE_TASK(tsk, "thread suspends at %llu (state:%d, running:%d)\n",
		litmus_clock(), tsk->state, is_current_running());

	preempt_disable();
	tinfo = get_mc2_state(tsk);
	if (tinfo->cpu != -1)
		state = cpu_state_for(tinfo->cpu);
	else
		state = local_cpu_state();
	preempt_enable();

	if (tinfo->cpu != -1) {
		raw_spin_lock_irqsave(&state->lock, flags);
		sup_update_time(&state->sup_env, litmus_clock());
		task_departs(tsk, is_completed(tsk));
		raw_spin_unlock_irqrestore(&state->lock, flags);
	} else {
		// HISTORIC: Level-C task departs
	}
}



/* mc2_task_resume - Called when the state of tsk changes back to
 *                   TASK_RUNNING. We need to requeue the task.
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

	/* Assumption: litmus_clock() is synchronized across cores,
	 * since we might not actually be executing on tinfo->cpu
	 * at the moment. */
	if (tinfo->cpu != -1) {
		sup_update_time(&state->sup_env, litmus_clock());
		task_arrives(tsk);
	} else {
		// HISTORIC: Re-add Level-C task
	}

	TRACE_TASK(tsk, "mc2_resume()\n");

	/* NOTE: drops state->lock */
	mc2_update_timer_and_unlock(state);
	local_irq_restore(flags);
}


/* mc2_admit_task - Setup mc2 task parameters
 */
static long mc2_admit_task(struct task_struct *tsk)
{
	long err = -EINVAL;
	unsigned long flags;
	struct reservation *res;
	struct mc2_cpu_state *state;
	struct mc2_task_state *tinfo = kzalloc(sizeof(*tinfo), GFP_ATOMIC);
	struct mc2_task *mp = tsk_rt(tsk)->mc2_data;

	if (!tinfo)
		return -ENOMEM;

	if (!mp) {
		printk(KERN_ERR "mc2_admit_task: criticality level has not been set\n");
		err = -ESRCH;
		goto out;
	}

	if (mp->crit < CRIT_LEVEL_C) {
		state = cpu_state_for(task_cpu(tsk));
		raw_spin_lock_irqsave(&state->lock, flags);

		res = sup_find_by_id(&state->sup_env, mp->res_id);

		/* found the appropriate reservation */
		if (res) {
			TRACE_TASK(tsk, "SUP FOUND RES ID\n");
			tinfo->mc2_param.crit = mp->crit;
			tinfo->mc2_param.res_id = mp->res_id;

			/* initial values */
			err = mc2_task_client_init(&tinfo->res_info, &tinfo->mc2_param, tsk, res);
			tinfo->cpu = task_cpu(tsk);
			tinfo->has_departed = true;
			tsk_rt(tsk)->plugin_state = tinfo;

			/* disable LITMUS^RT's per-thread budget enforcement */
			tsk_rt(tsk)->task_params.budget_policy = NO_ENFORCEMENT;
		}
		else {
			printk(KERN_WARNING "Could not find reservation %d on "
				"core %d for task %s/%d\n",
				tsk_rt(tsk)->task_params.cpu, state->cpu,
				tsk->comm, tsk->pid);
		}

		raw_spin_unlock_irqrestore(&state->lock, flags);
	} else if (mp->crit == CRIT_LEVEL_C) {
		// HISTORIC: Checked for res, initialized mc2_param, and "initialized task client"
	}
out:
	if (err)
		kfree(tinfo);

	return err;
}

/* mc2_task_new - A new real-time job is arrived. Release the next job
 *                at the next reservation replenish time
 */
static void mc2_task_new(struct task_struct *tsk, int on_runqueue,
			  int is_running)
{
	unsigned long flags;
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	struct mc2_cpu_state *state;
	struct reservation *res;
	enum crit_level lv = get_task_crit_level(tsk);
	lt_t release = 0;

	BUG_ON(lv < CRIT_LEVEL_A || lv > CRIT_LEVEL_C);

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
		// HISTORIC: got associated global reservation
		BUG(); // Unsupported ATM
	}
	else {
		res = sup_find_by_id(&state->sup_env, tinfo->mc2_param.res_id);
	}

	if (on_runqueue || is_running) {
		/* Assumption: litmus_clock() is synchronized across cores
		 * [see comment in pres_task_resume()] */
		if (lv == CRIT_LEVEL_C) {
			// HISTORIC: Updated global env time
		} else
			sup_update_time(&state->sup_env, litmus_clock());

		task_arrives(tsk);
		raw_spin_unlock_irqrestore(&state->lock, flags);

		TRACE("mc2_new()\n");

		raw_spin_lock(&state->lock);
		/* NOTE: drops state->lock */
		mc2_update_timer_and_unlock(state);
	} else {
		raw_spin_unlock_irqrestore(&state->lock, flags);
	}
	release = res->next_replenishment;

	BUG_ON(!release);

	TRACE_TASK(tsk, "mc2_task_new() next_release = %llu\n", release);
	release_at(tsk, release);
}

/* mc2_reservation_destroy - reservation_destroy system call backend
 * Origin: Namhoon
 */
static long mc2_reservation_destroy(unsigned int reservation_id, int cpu)
{
	struct mc2_cpu_state *state;
	struct reservation *res = NULL;
	unsigned long flags;
	long err = 0;

	if (cpu == -1) {
		// HISTORIC: Destroyed reservation and events
	} else {
		/* if the reservation is partitioned reservation */
		state = cpu_state_for(cpu);
		raw_spin_lock_irqsave(&state->lock, flags);

		res = sup_find_by_id(&state->sup_env, reservation_id);
		if (res)
			destroy_reservation(res);
		else
			err = -EINVAL;

		raw_spin_unlock_irqrestore(&state->lock, flags);
	}

	TRACE("Reservation destroyed err = %d\n", err);
	return err;
}

/* mc2_task_exit - Task became a normal task (not real-time task)
 */
static void mc2_task_exit(struct task_struct *tsk)
{
	unsigned long flags;
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	struct mc2_cpu_state *state;
	enum crit_level lv = tinfo->mc2_param.crit;

	if (tinfo->cpu != -1)
		state = cpu_state_for(tinfo->cpu);
	else
		state = local_cpu_state();
	raw_spin_lock_irqsave(&state->lock, flags);

	TRACE_TASK(tsk, "task exits at %llu (present:%d sched:%d)\n",
		litmus_clock(), is_present(tsk), state->scheduled == tsk);

	if (state->scheduled == tsk)
		state->scheduled = NULL;

	/* remove from queues */
	if (tsk->state == TASK_RUNNING) {
		/* Assumption: litmus_clock() is synchronized across cores
		 * [see comment in pres_task_resume()] */

		/* update both global and partitioned */
		if (lv < CRIT_LEVEL_C) {
			sup_update_time(&state->sup_env, litmus_clock());
		}
		else if (lv == CRIT_LEVEL_C) {
			// HISTORIC: Updated global env time.
		}
		task_departs(tsk, 0);

		/* NOTE: drops state->lock */
		TRACE("mc2_exit()\n");

		mc2_update_timer_and_unlock(state);
	} else {
		raw_spin_unlock(&state->lock);
	}

	// HISTORIC: Cleared state->scheduled if any of them was this task

	local_irq_restore(flags);

	kfree(tsk_rt(tsk)->plugin_state);
	tsk_rt(tsk)->plugin_state = NULL;
	kfree(tsk_rt(tsk)->mc2_data);
	tsk_rt(tsk)->mc2_data = NULL;
}

/* mc2_reservation_create - reservation_create system call backend
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
	if (config->cpu != -1) {
		state = cpu_state_for(config->cpu);
		raw_spin_lock_irqsave(&state->lock, flags);
		res = sup_find_by_id(&state->sup_env, config->id);
		if (!res) {
			sup_add_new_reservation(&state->sup_env, new_res);
			err = config->id;
		} else {
			err = -EEXIST;
		}
		raw_spin_unlock_irqrestore(&state->lock, flags);
	} else {
		// HISTORIC: Added global reservation
	}

	if (err < 0)
		kfree(new_res);

	return err;
}

/* Origin: P-RES */
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

	/* Table-driven reservations cannot be global */
	if (config.cpu == -1 && res_type == TABLE_DRIVEN)
		return -EINVAL;

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
static long mc2_activate_plugin(void)
{
	int cpu;
	struct mc2_cpu_state *state;

	// HISTORIC: Created global reservation env

	for_each_online_cpu(cpu) {
		TRACE("Initializing CPU%d...\n", cpu);

		state = cpu_state_for(cpu);

		// HISTORIC: Initialized CPU entry state for global env

		raw_spin_lock_init(&state->lock);
		state->cpu = cpu;
		state->scheduled = NULL;
		sup_init(&state->sup_env);

		hrtimer_init(&state->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
		state->timer.function = on_scheduling_timer;
	}

	mc2_setup_domain_proc();

	return 0;
}

/* mc2_finish_switch: Update important state
 * Origin: Namhoon
 */
static void mc2_finish_switch(struct task_struct *prev)
{
	struct mc2_cpu_state *state = local_cpu_state();

	state->scheduled = is_realtime(current) ? current : NULL;
	// HISTORIC: Initiated a reschedule on any flagged CPUs
}

/* mc2_deactivate_plugin: Reset/clear/flush state
 * Origin: P-RES
 */
static long mc2_deactivate_plugin(void)
{
	int cpu;
	struct mc2_cpu_state *state;
	struct reservation *res;

	for_each_online_cpu(cpu) {
		state = cpu_state_for(cpu);
		raw_spin_lock(&state->lock);

		hrtimer_cancel(&state->timer);

		// HISTORIC: Cleared global scheduling state

		while (!list_empty(&state->sup_env.all_reservations)) {
			res = list_first_entry(
				&state->sup_env.all_reservations,
			        struct reservation, all_list);
			destroy_reservation(res);
		}

		raw_spin_unlock(&state->lock);
	}

	// HISTORIC: Destroyed all Level-C reservations
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

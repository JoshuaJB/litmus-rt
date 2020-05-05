/*
 * litmus/sched_mc2.c
 *
 * Implementation of the Mixed-Criticality on MultiCore scheduler
 *
 * This plugin implements a scheduling algorithm proposed in
 * "Mixed-Criticality Real-Time Scheduling for Multicore System" paper.
 */

#include <linux/percpu.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include <litmus/sched_plugin.h>
#include <litmus/preempt.h>
#include <litmus/debug_trace.h>

#include <litmus/litmus.h>
#include <litmus/jobs.h>
#include <litmus/budget.h>
#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/cache_proc.h>
#include <litmus/trace.h>

#include <litmus/mc2_common.h>
#include <litmus/reservations/reservation.h>
#include <litmus/reservations/polling.h>
#include <litmus/reservations/table-driven.h>
#include <litmus/reservations/alloc.h>

#define BUDGET_ENFORCEMENT_AT_C 0

extern void do_partition(enum crit_level lv, int cpu);

/* _global_env - reservation container for level-C tasks*/
struct gmp_reservation_environment _global_env;

/* cpu_entry - keep track of a running task on a cpu
 * This state is used to decide the lowest priority cpu
 */
struct cpu_entry {
	struct task_struct *scheduled;
	lt_t deadline;
	int cpu;
	enum crit_level lv;
	/* if will_schedule is true, this cpu is already selected and
	   call mc2_schedule() soon. */
	bool will_schedule;
};

/* cpu_priority - a global state for choosing the lowest priority CPU */
struct cpu_priority {
	raw_spinlock_t lock;
	struct cpu_entry cpu_entries[NR_CPUS];
};

struct cpu_priority _lowest_prio_cpu;

/* mc2_task_state - a task state structure */
struct mc2_task_state {
	struct task_client res_info;
	/* if cpu == -1, this task is a global task (level C) */
	int cpu;
	bool has_departed;
	struct mc2_task mc2_param;
};

/* mc2_cpu_state - maintain the scheduled state
 * timer : timer for partitioned tasks (level A and B)
 * g_timer : timer for global tasks (level C)
 */
struct mc2_cpu_state {
	raw_spinlock_t lock;

	struct sup_reservation_environment sup_env;
	struct hrtimer timer;

	int cpu;
	struct task_struct* scheduled;
};

static int resched_cpu[NR_CPUS];
static DEFINE_PER_CPU(struct mc2_cpu_state, mc2_cpu_state);
static int level_a_priorities[NR_CPUS];

#define cpu_state_for(cpu_id)	(&per_cpu(mc2_cpu_state, cpu_id))
#define local_cpu_state()	(this_cpu_ptr(&mc2_cpu_state))

/* get_mc2_state - get the task's state */
static struct mc2_task_state* get_mc2_state(struct task_struct *tsk)
{
	struct mc2_task_state* tinfo;

	tinfo = (struct mc2_task_state*)tsk_rt(tsk)->plugin_state;

	if (tinfo)
		return tinfo;
	else
		return NULL;
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

/* task_depart - remove a task from its reservation
 *               If the job has remaining budget, drain it.
 *
 * @job_complete	indicate whether job completes or not
 */
static void task_departs(struct task_struct *tsk, int job_complete)
{
	struct mc2_task_state* tinfo = get_mc2_state(tsk);

	struct reservation* res = NULL;
	struct reservation_client *client = NULL;

	BUG_ON(!is_realtime(tsk));

	res    = tinfo->res_info.client.reservation;
	client = &tinfo->res_info.client;
	BUG_ON(!res);
	BUG_ON(!client);

	/* empty remaining budget */
	if (job_complete) {
		res->cur_budget = 0;
		sched_trace_task_completion(tsk, 0);
	}

	res->ops->client_departs(res, client, job_complete);
	tinfo->has_departed = true;
	TRACE_TASK(tsk, "Client departs with budget %llu at %llu\n", res->cur_budget, litmus_clock());
}

/* task_arrive - put a task into its reservation
 */
static void task_arrives(struct mc2_cpu_state *state, struct task_struct *tsk)
{
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	struct reservation* res;
	struct reservation_client *client;

	res    = tinfo->res_info.client.reservation;
	client = &tinfo->res_info.client;

	tinfo->has_departed = false;

	res->ops->client_arrives(res, client);
	TRACE_TASK(tsk, "Client arrives at %llu\n", litmus_clock());
}

/* get_lowest_prio_cpu - return the lowest priority cpu
 *                       This will be used for scheduling level-C tasks.
 *                       If all CPUs are running tasks which has
 *                       higher priority than level C, return NO_CPU.
 */
static int get_lowest_prio_cpu(lt_t priority)
{
	struct cpu_entry *ce;
	int cpu, ret = NO_CPU;
	lt_t latest_deadline = 0;

	if (priority == LITMUS_NO_PRIORITY)
		return ret;

	ce = &_lowest_prio_cpu.cpu_entries[local_cpu_state()->cpu];
	if (!ce->will_schedule && !ce->scheduled) {
		TRACE("CPU %d (local) is the lowest!\n", ce->cpu);
		return ce->cpu;
	} else {
		TRACE("Local CPU will_schedule=%d, scheduled=(%s/%d)\n", ce->will_schedule, ce->scheduled ? (ce->scheduled)->comm : "null", ce->scheduled ? (ce->scheduled)->pid : 0);
	}

	for_each_online_cpu(cpu) {
		ce = &_lowest_prio_cpu.cpu_entries[cpu];
		/* If a CPU will call schedule() in the near future, we don't
		   return that CPU. */
		/*
		TRACE("CPU %d will_schedule=%d, scheduled=(%s/%d:%d)\n", cpu, ce->will_schedule,
	      ce->scheduled ? (ce->scheduled)->comm : "null",
	      ce->scheduled ? (ce->scheduled)->pid : 0,
	      ce->scheduled ? (ce->scheduled)->rt_param.job_params.job_no : 0);
		*/
		if (!ce->will_schedule) {
			if (!ce->scheduled) {
				/* Idle cpu, return this. */
				TRACE("CPU %d is the lowest!\n", ce->cpu);
				return ce->cpu;
			} else if (ce->lv == CRIT_LEVEL_C &&
			           ce->deadline > latest_deadline) {
				latest_deadline = ce->deadline;
				ret = ce->cpu;
			}
		}
	}

	if (priority >= latest_deadline)
		ret = NO_CPU;

	TRACE("CPU %d is the lowest!\n", ret);

	return ret;
}

/* NOTE: drops state->lock */
/* mc2_update_timer_and_unlock - set a timer and g_timer and unlock
 *                               Whenever res_env.current_time is updated,
 *                               we check next_scheduler_update and set
 *                               a timer.
 *                               If there exist a global event which is
 *                               not armed on any CPU and g_timer is not
 *                               active, set a g_timer for that event.
 */
static void mc2_update_timer_and_unlock(struct mc2_cpu_state *state)
{
	int local, cpus;
	lt_t update, now;
	struct next_timer_event *event, *next;
	int reschedule[NR_CPUS];
	unsigned long flags;

	local_irq_save(flags);

	for (cpus = 0; cpus<NR_CPUS; cpus++)
		reschedule[cpus] = 0;

	update = state->sup_env.next_scheduler_update;
	now = state->sup_env.env.current_time;

	/* Be sure we're actually running on the right core,
	 * as pres_update_timer() is also called from pres_task_resume(),
	 * which might be called on any CPU when a thread resumes.
	 */
	local = local_cpu_state() == state;

	raw_spin_lock(&_global_env.lock);

	// This serves to adjust `update` and `reschedule` appropriately
	list_for_each_entry_safe(event, next, &_global_env.next_events, list) {
		/* If the event time is already passed, we call schedule() on
		   the lowest priority cpu */
		if (event->next_update >= update) {
			break;
		}

		if (event->next_update < litmus_clock()) {
			// If the timed expired and went unarmed (?), delete it (?)
			// Is this provably impossible? => No
			// Why does this exist?
			if (event->timer_armed_on == NO_CPU) {
				struct reservation *res = gmp_find_by_id(&_global_env, event->id);
				// If a CPU is available for Level-C tasks, mark that it needs to run the scheduler after this
				int cpu = get_lowest_prio_cpu(res?res->priority:0);
				//TRACE("GLOBAL EVENT PASSED!! poking CPU %d to reschedule\n", cpu);
				list_del(&event->list);
				kfree(event);
				if (cpu != NO_CPU) { // Else no Level-C CPU is available
					_lowest_prio_cpu.cpu_entries[cpu].will_schedule = true;
					reschedule[cpu] = 1;
				}
			}
		// If the event expire time is before the next scheduler update and the event
		// is unarmed or already armed on this CPU, arm it and move the scheduler update forward.
		// XXX: I don't get the second condition. If it's been armed, update was moved to
		// next_update. next_update never changes, so this is only useful if somehow update can
		// get moved past us
		// Once a timer is armed, it will never be disarmed unless next_update is changed
		// AKA next_update cannot be changed without setting timer_armed_on = NO_CPU
		} else if (event->next_update < update && (event->timer_armed_on == NO_CPU || event->timer_armed_on == state->cpu)) {
			event->timer_armed_on = state->cpu;
			update = event->next_update;
			break;
		}
	}
	/* Why might a timer not get armed?
	 * -> next_update == update
	 */

	/* Must drop state lock before calling into hrtimer_start(), which
	 * may raise a softirq, which in turn may wake ksoftirqd. */
	raw_spin_unlock(&_global_env.lock);
	local_irq_restore(flags);
	raw_spin_unlock(&state->lock);

	if (update <= now || reschedule[state->cpu]) {
		reschedule[state->cpu] = 0;
		litmus_reschedule(state->cpu);
	} else if (likely(local && update != SUP_NO_SCHEDULER_UPDATE)) {
		/* Reprogram our next scheduler update only if it is not already set correctly. */
		if (!hrtimer_active(&state->timer) ||
		    ktime_to_ns(hrtimer_get_expires(&state->timer)) != update) {
			TRACE("canceling timer...at %llu\n",
			      ktime_to_ns(hrtimer_get_expires(&state->timer)));
			hrtimer_cancel(&state->timer);
			TRACE("setting scheduler timer for %llu\n", update);
			/* We cannot use hrtimer_start() here because the
			 * wakeup flag must be set to zero. */
			__hrtimer_start_range_ns(&state->timer,
					ns_to_ktime(update),
					0 /* timer coalescing slack */,
					HRTIMER_MODE_ABS_PINNED,
					0 /* wakeup */);
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
			state->cpu, update, hrtimer_active(&state->timer),
			ktime_to_ns(hrtimer_get_expires(&state->timer)));
		if (!hrtimer_active(&state->timer) ||
		    ktime_to_ns(hrtimer_get_expires(&state->timer)) > update) {
			TRACE("poking CPU %d so that it can update its "
			       "scheduling timer (active:%d, set:%llu)\n",
			       state->cpu,
			       hrtimer_active(&state->timer),
			       ktime_to_ns(hrtimer_get_expires(&state->timer)));
			//raw_spin_lock(&state->lock);
			//preempt_if_preemptable(state->scheduled, state->cpu);
			//raw_spin_unlock(&state->lock);
			//reschedule[state->cpu] = 0;
		}
	}

	for (cpus = 0; cpus<NR_CPUS; cpus++) {
		if (reschedule[cpus]) {
			litmus_reschedule(cpus);
		}
	}

}

/* update_cpu_prio - Update cpu's priority
 *                   When a cpu picks a new task, call this function
 *                   to update cpu priorities.
 */
static void update_cpu_prio(struct mc2_cpu_state *state)
{
	struct cpu_entry *ce = &_lowest_prio_cpu.cpu_entries[state->cpu];
	enum crit_level lv = get_task_crit_level(state->scheduled);

	if (!state->scheduled) {
		/* cpu is idle. */
		ce->scheduled = NULL;
		ce->deadline = ULLONG_MAX;
		ce->lv = NUM_CRIT_LEVELS;
	} else if (lv == CRIT_LEVEL_C) {
		ce->scheduled = state->scheduled;
		ce->deadline = get_deadline(state->scheduled);
		ce->lv = lv;
	} else if (lv < CRIT_LEVEL_C) {
		/* If cpu is running level A or B tasks, it is not eligible
		   to run level-C tasks */
		ce->scheduled = state->scheduled;
		ce->deadline = 0;
		ce->lv = lv;
	}
};

/* on_scheduling_timer - timer event for partitioned tasks
 */
static enum hrtimer_restart on_scheduling_timer(struct hrtimer *timer)
{
	unsigned long flags;
	enum hrtimer_restart restart = HRTIMER_NORESTART;
	struct mc2_cpu_state *state;
	lt_t update, now;
	int global_schedule_now;
	int reschedule[NR_CPUS];
	int cpus;

	for (cpus = 0; cpus<NR_CPUS; cpus++)
		reschedule[cpus] = 0;

	state = container_of(timer, struct mc2_cpu_state, timer);

	/* The scheduling timer should only fire on the local CPU, because
	 * otherwise deadlocks via timer_cancel() are possible.
	 * Note: this does not interfere with dedicated interrupt handling, as
	 * even under dedicated interrupt handling scheduling timers for
	 * budget enforcement must occur locally on each CPU.
	 */
	BUG_ON(state->cpu != raw_smp_processor_id());

	TS_ISR_START;

	TRACE("Timer fired at %llu\n", litmus_clock());
	raw_spin_lock_irqsave(&state->lock, flags);
	now = litmus_clock();
	sup_update_time(&state->sup_env, now);

	update = state->sup_env.next_scheduler_update;
	now = state->sup_env.env.current_time;

	if (update <= now) {
		litmus_reschedule_local();
	} else if (update != SUP_NO_SCHEDULER_UPDATE) {
		hrtimer_set_expires(timer, ns_to_ktime(update));
		restart = HRTIMER_RESTART;
	}

	raw_spin_lock(&_global_env.lock);
	global_schedule_now = gmp_update_time(&_global_env, now);

	BUG_ON(global_schedule_now < 0 || global_schedule_now > 4);

	/* Find the lowest cpu, and call reschedule */
	while (global_schedule_now--) {
		int cpu = get_lowest_prio_cpu(0);
		if (cpu != NO_CPU && _lowest_prio_cpu.cpu_entries[cpu].will_schedule == false) {
			_lowest_prio_cpu.cpu_entries[cpu].will_schedule = true;
			if (cpu == state->cpu && update > now)
				; //litmus_reschedule_local();
			else
				reschedule[cpu] = 1;
		}
	}
	raw_spin_unlock(&_global_env.lock);
	raw_spin_unlock_irqrestore(&state->lock, flags);

	TS_ISR_END;

	for (cpus = 0; cpus<NR_CPUS; cpus++) {
		if (reschedule[cpus]) {
			litmus_reschedule(cpus);
		}
	}

	return restart;
}

/* mc2_complete_job - syscall backend for job completions
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
			state = local_cpu_state();
			raw_spin_lock(&state->lock);
			raw_spin_lock(&_global_env.lock);
			res = gmp_find_by_id(&_global_env, tinfo->mc2_param.res_id);
			_global_env.env.time_zero = tsk_rt(current)->sporadic_release_time;
		}
		else
			BUG();

		/* set next_replenishtime to synchronous release time */
		BUG_ON(!res);
		res->next_replenishment = tsk_rt(current)->sporadic_release_time;
		res->cur_budget = 0;
		res->env->change_state(res->env, res, RESERVATION_DEPLETED);

		if (lv == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);

		raw_spin_unlock(&state->lock);
		local_irq_restore(flags);
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

/* mc2_dispatch - Select the next task to schedule.
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

struct task_struct* mc2_global_dispatch(struct mc2_cpu_state* state)
{
	struct reservation *res, *next;
	struct task_struct *tsk = NULL;
	enum crit_level lv;
	lt_t time_slice;

	list_for_each_entry_safe(res, next, &_global_env.active_reservations, list) {
		BUG_ON(!res);
		if (res->state == RESERVATION_ACTIVE && res->scheduled_on == NO_CPU) {
			tsk = res->ops->dispatch_client(res, &time_slice);
			if (likely(tsk)) {
				lv = get_task_crit_level(tsk);
				if (lv != CRIT_LEVEL_C)
					BUG();
#if BUDGET_ENFORCEMENT_AT_C
				gmp_add_event_after(&_global_env, res->cur_budget, res->id, EVENT_DRAIN);
#endif
				res->event_added = 1;
				res->scheduled_on = state->cpu;
				return tsk;
			}
		}
	}

	return NULL;
}

static inline void pre_schedule(struct task_struct *prev, int cpu)
{
	TS_SCHED_A_START;
	TS_SCHED_C_START;

	if (!prev || !is_realtime(prev))
		return;

	do_partition(CRIT_LEVEL_C, cpu);
}

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
 */
static struct task_struct* mc2_schedule(struct task_struct * prev)
{
	int np, blocks, exists;
	/* next == NULL means "schedule background work". */
	lt_t now = litmus_clock();
	struct mc2_cpu_state *state = local_cpu_state();

	raw_spin_lock(&state->lock);

	pre_schedule(prev, state->cpu);

	if (state->scheduled && state->scheduled != prev)
		printk(KERN_ALERT "BUG1!!!!!!!! %s %s\n", state->scheduled ? (state->scheduled)->comm : "null", prev ? (prev)->comm : "null");
	if (state->scheduled && !is_realtime(prev))
		printk(KERN_ALERT "BUG2!!!!!!!! \n");

	/* (0) Determine state */
	exists = state->scheduled != NULL;
	blocks = exists && !is_current_running();
	np = exists && is_np(state->scheduled);

	/* update time */
	state->sup_env.will_schedule = true;
	sup_update_time(&state->sup_env, now);

	if (is_realtime(current) && blocks) {
		if (get_task_crit_level(current) == CRIT_LEVEL_C)
			raw_spin_lock(&_global_env.lock);
		task_departs(current, is_completed(current));
		if (get_task_crit_level(current) == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);
	}

	/* figure out what to schedule next */
	if (!np)
		state->scheduled = mc2_dispatch(&state->sup_env, state);

	if (!state->scheduled) {
		raw_spin_lock(&_global_env.lock);
		if (is_realtime(prev))
			gmp_update_time(&_global_env, now);
		state->scheduled = mc2_global_dispatch(state);
		_lowest_prio_cpu.cpu_entries[state->cpu].will_schedule = false;
		update_cpu_prio(state);
		raw_spin_unlock(&_global_env.lock);
	} else {
		raw_spin_lock(&_global_env.lock);
		_lowest_prio_cpu.cpu_entries[state->cpu].will_schedule = false;
		update_cpu_prio(state);
		raw_spin_unlock(&_global_env.lock);
	}

	/* Notify LITMUS^RT core that we've arrived at a scheduling decision. */
	sched_state_task_picked();

	/* program scheduler timer */
	state->sup_env.will_schedule = false;

	/* NOTE: drops state->lock */
	mc2_update_timer_and_unlock(state);

	raw_spin_lock(&state->lock);
	if (prev != state->scheduled && is_realtime(prev)) {
		struct mc2_task_state* tinfo = get_mc2_state(prev);
		struct reservation* res = tinfo->res_info.client.reservation;
		res->scheduled_on = NO_CPU;
		TRACE_TASK(prev, "descheduled at %llu.\n", litmus_clock());
		/* if prev is preempted and a global task, find the lowest cpu and reschedule */
		if (tinfo->has_departed == false && get_task_crit_level(prev) == CRIT_LEVEL_C) {
			int cpu;
			raw_spin_lock(&_global_env.lock);
			cpu = get_lowest_prio_cpu(res?res->priority:LITMUS_NO_PRIORITY);
			//TRACE("LEVEL-C TASK PREEMPTED!! poking CPU %d to reschedule\n", cpu);
			if (cpu != NO_CPU && _lowest_prio_cpu.cpu_entries[cpu].will_schedule == false) {
				_lowest_prio_cpu.cpu_entries[cpu].will_schedule = true;
				resched_cpu[cpu] = 1;
			}
			raw_spin_unlock(&_global_env.lock);
		}
	}

/*
	if (to_schedule != 0) {
		raw_spin_lock(&_global_env.lock);
		while (to_schedule--) {
			int cpu = get_lowest_prio_cpu(0);
			if (cpu != NO_CPU && _lowest_prio_cpu.cpu_entries[cpu].will_schedule == false) {
				_lowest_prio_cpu.cpu_entries[cpu].will_schedule = true;
				resched_cpu[cpu] = 1;
			}
		}
		raw_spin_unlock(&_global_env.lock);
	}
*/

	post_schedule(state->scheduled, state->cpu);

	raw_spin_unlock(&state->lock);
	if (state->scheduled) {
		TRACE_TASK(state->scheduled, "scheduled.\n");
	}

	return state->scheduled;
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

	/* Requeue only if self-suspension was already processed. */
	if (tinfo->has_departed)
	{
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
			task_arrives(state, tsk);
		} else {
			raw_spin_lock(&_global_env.lock);
			gmp_update_time(&_global_env, litmus_clock());
			task_arrives(state, tsk);
			raw_spin_unlock(&_global_env.lock);
		}

		/* NOTE: drops state->lock */
		TRACE_TASK(tsk, "mc2_resume()\n");
		raw_spin_unlock_irqrestore(&state->lock, flags);

		raw_spin_lock(&state->lock);
		mc2_update_timer_and_unlock(state);
	} else {
		TRACE_TASK(tsk, "resume event ignored, still scheduled\n");
	}

}


/* mc2_admit_task - Setup mc2 task parameters
 */
static long mc2_admit_task(struct task_struct *tsk)
{
	long err = 0;
	unsigned long flags;
	struct reservation *res;
	struct mc2_cpu_state *state;
	struct mc2_task_state *tinfo = kzalloc(sizeof(*tinfo), GFP_ATOMIC);
	struct mc2_task *mp = tsk_rt(tsk)->mc2_data;
	enum crit_level lv;

	if (!tinfo)
		return -ENOMEM;

	if (!mp) {
		printk(KERN_ERR "mc2_admit_task: criticality level has not been set\n");
		return -ESRCH;
	}

	lv = mp->crit;

	if (lv < CRIT_LEVEL_C) {
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
			err = -ESRCH;
		}

		raw_spin_unlock_irqrestore(&state->lock, flags);
	} else if (lv == CRIT_LEVEL_C) {
		state = local_cpu_state();
		raw_spin_lock_irqsave(&state->lock, flags);
		raw_spin_lock(&_global_env.lock);

		res = gmp_find_by_id(&_global_env, mp->res_id);

		/* found the appropriate reservation (or vCPU) */
		if (res) {
			TRACE_TASK(tsk, "GMP FOUND RES ID\n");
			tinfo->mc2_param.crit = mp->crit;
			tinfo->mc2_param.res_id = mp->res_id;

			/* initial values */
			err = mc2_task_client_init(&tinfo->res_info, &tinfo->mc2_param, tsk, res);
			tinfo->cpu = -1;
			tinfo->has_departed = true;
			tsk_rt(tsk)->plugin_state = tinfo;

			/* disable LITMUS^RT's per-thread budget enforcement */
			tsk_rt(tsk)->task_params.budget_policy = NO_ENFORCEMENT;
		}
		else {
			err = -ESRCH;
		}

		raw_spin_unlock(&_global_env.lock);
		raw_spin_unlock_irqrestore(&state->lock, flags);
	}

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
	struct mc2_cpu_state *state; // = cpu_state_for(tinfo->cpu);
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


	if (is_running) {
		state->scheduled = tsk;
		/* make sure this task should actually be running */
		litmus_reschedule_local();
	}

	/* acquire the lock protecting the state and disable interrupts */
	local_irq_save(flags);
	raw_spin_lock(&state->lock);

	if (lv == CRIT_LEVEL_C) {
		raw_spin_lock(&_global_env.lock);
		res = gmp_find_by_id(&_global_env, tinfo->mc2_param.res_id);
	}
	else {
		res = sup_find_by_id(&state->sup_env, tinfo->mc2_param.res_id);
	}

	if (on_runqueue || is_running) {
		/* Assumption: litmus_clock() is synchronized across cores
		 * [see comment in pres_task_resume()] */
		if (lv == CRIT_LEVEL_C) {
			gmp_update_time(&_global_env, litmus_clock());
		}
		else
			sup_update_time(&state->sup_env, litmus_clock());

		task_arrives(state, tsk);
		if (lv == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);
		/* NOTE: drops state->lock */
		raw_spin_unlock(&state->lock);
		local_irq_restore(flags);

		TRACE("mc2_new()\n");

		raw_spin_lock(&state->lock);
		mc2_update_timer_and_unlock(state);
	} else {
		if (lv == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);
		raw_spin_unlock(&state->lock);
		local_irq_restore(flags);
	}
	release = res->next_replenishment;

	if (!release) {
		TRACE_TASK(tsk, "mc2_task_new() next_release = %llu\n", release);
		BUG();
	}
	else
		TRACE_TASK(tsk, "mc2_task_new() next_release = NULL\n");
	release_at(tsk, release);
}

/* mc2_reservation_destroy - reservation_destroy system call backend
 */
static long mc2_reservation_destroy(unsigned int reservation_id, int cpu)
{
	struct mc2_cpu_state *state;
	struct reservation *res = NULL;
	unsigned long flags;
	long err = 0;

	if (cpu == -1) {
		struct next_timer_event *event;

		/* if the reservation is global reservation */
		raw_spin_lock_irqsave(&_global_env.lock, flags);

		res = gmp_find_by_id(&_global_env, reservation_id);
		if (res)
			destroy_reservation(res);
		else
			err = -EINVAL;

		/* delete corresponding event(s) (there may be at most two) */
		event = gmp_find_event_by_id(&_global_env, reservation_id);
		if (event) {
			list_del(&event->list);
			kfree(event);
		}
		event = gmp_find_event_by_id(&_global_env, reservation_id);
		if (event) {
			list_del(&event->list);
			kfree(event);
		}

		raw_spin_unlock_irqrestore(&_global_env.lock, flags);
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
	int cpu;

	local_irq_save(flags);
	if (tinfo->cpu != -1)
		state = cpu_state_for(tinfo->cpu);
	else
		state = local_cpu_state();

	raw_spin_lock(&state->lock);

	if (state->scheduled == tsk)
		state->scheduled = NULL;

	/* remove from queues */
	if (is_running(tsk)) {
		/* Assumption: litmus_clock() is synchronized across cores
		 * [see comment in pres_task_resume()] */

		/* update both global and partitioned */
		if (lv < CRIT_LEVEL_C) {
			sup_update_time(&state->sup_env, litmus_clock());
		}
		else if (lv == CRIT_LEVEL_C) {
			raw_spin_lock(&_global_env.lock);
			gmp_update_time(&_global_env, litmus_clock());
		}
		task_departs(tsk, 0);
		if (lv == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);

		/* NOTE: drops state->lock */
		TRACE("mc2_exit()\n");

		mc2_update_timer_and_unlock(state);
	} else {
		raw_spin_unlock(&state->lock);
	}

	if (lv == CRIT_LEVEL_C) {
		for_each_online_cpu(cpu) {
			state = cpu_state_for(cpu);
			if (state == local_cpu_state())
				continue;
			raw_spin_lock(&state->lock);

			if (state->scheduled == tsk)
				state->scheduled = NULL;

			raw_spin_unlock(&state->lock);
		}
	}

	local_irq_restore(flags);

	kfree(tsk_rt(tsk)->plugin_state);
	tsk_rt(tsk)->plugin_state = NULL;
	kfree(tsk_rt(tsk)->mc2_data);
	tsk_rt(tsk)->mc2_data = NULL;
}

/* mc2_reservation_create - reservation_create system call backend
 */
static long mc2_reservation_create(int res_type, void* __user _config)
{
	struct reservation_config config;
	struct mc2_cpu_state *state;
	struct reservation* res;
	struct reservation* new_res = NULL;
	unsigned long flags;
	long err;

	TRACE("Attempt to create reservation (%d)\n", res_type);

	if (copy_from_user(&config, _config, sizeof(config)))
		return -EFAULT;

	if (config.cpu != -1) {
		if (config.cpu < 0 || !cpu_online(config.cpu)) {
			printk(KERN_ERR "invalid reservation (%u): "
				   "CPU %d offline\n", config.id, config.cpu);
			return -EINVAL;
		}
	}

	/* Table-driven reservations cannot be global */
	if (config.cpu == -1 && res_type == TABLE_DRIVEN)
		return -EINVAL;

	/* Allocate before we grab a spin lock. */
	switch (res_type) {
		case PERIODIC_POLLING:
		case SPORADIC_POLLING:
			err = alloc_polling_reservation(res_type, &config, &new_res);
			break;

		case TABLE_DRIVEN:
			err = alloc_table_driven_reservation(&config, &new_res);
			break;

		default:
			err = -EINVAL;
			break;
	};

	if (err)
		return err;

	/* Check if the reservation exists after creating the new one so that
	 * we only have to get the spin lock once.
	 */
	if (config.cpu != -1) {
		state = cpu_state_for(config.cpu);
		raw_spin_lock_irqsave(&state->lock, flags);
		res = sup_find_by_id(&state->sup_env, config.id);
		if (!res) {
			sup_add_new_reservation(&state->sup_env, new_res);
			err = config.id;
		} else {
			err = -EEXIST;
		}
		raw_spin_unlock_irqrestore(&state->lock, flags);
	} else {
		raw_spin_lock_irqsave(&_global_env.lock, flags);
		res = gmp_find_by_id(&_global_env, config.id);
		if (!res) {
			gmp_add_new_reservation(&_global_env, new_res);
			err = config.id;
		} else {
			err = -EEXIST;
		}
		raw_spin_unlock_irqrestore(&_global_env.lock, flags);
	}

	if (err < 0)
		kfree(new_res);

	return err;
}

static struct domain_proc_info mc2_domain_proc_info;

static long mc2_get_domain_proc_info(struct domain_proc_info **ret)
{
	*ret = &mc2_domain_proc_info;
	return 0;
}

static void mc2_setup_domain_proc(void)
{
	int i, cpu;
	int num_rt_cpus = num_online_cpus();

	struct cd_mapping *cpu_map, *domain_map;

	memset(&mc2_domain_proc_info, sizeof(mc2_domain_proc_info), 0);
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

static long mc2_activate_plugin(void)
{
	int cpu;
	struct mc2_cpu_state *state;
	struct cpu_entry *ce;

	gmp_init(&_global_env);
	//raw_spin_lock_init(&_lowest_prio_cpu.lock);

	for_each_online_cpu(cpu) {
		TRACE("Initializing CPU%d...\n", cpu);

		resched_cpu[cpu] = 0;
		level_a_priorities[cpu] = 0;
		state = cpu_state_for(cpu);
		ce = &_lowest_prio_cpu.cpu_entries[cpu];

		ce->cpu = cpu;
		ce->scheduled = NULL;
		ce->deadline = ULLONG_MAX;
		ce->lv = NUM_CRIT_LEVELS;
		ce->will_schedule = false;

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

static void mc2_finish_switch(struct task_struct *prev)
{
	int cpus;
	enum crit_level lv = get_task_crit_level(prev);
	struct mc2_cpu_state *state = local_cpu_state();

	state->scheduled = is_realtime(current) ? current : NULL;
	if (lv == CRIT_LEVEL_C) {
		for (cpus = 0; cpus<NR_CPUS; cpus++) {
			if (resched_cpu[cpus] && state->cpu != cpus) {
				resched_cpu[cpus] = 0;
				litmus_reschedule(cpus);
			}
		}
	}
}

static long mc2_deactivate_plugin(void)
{
	int cpu;
	struct mc2_cpu_state *state;
	struct reservation *res;
	struct next_timer_event *event;
	struct cpu_entry *ce;

	for_each_online_cpu(cpu) {
		state = cpu_state_for(cpu);
		raw_spin_lock(&state->lock);

		hrtimer_cancel(&state->timer);

		ce = &_lowest_prio_cpu.cpu_entries[cpu];

		ce->cpu = cpu;
		ce->scheduled = NULL;
		ce->deadline = ULLONG_MAX;
		ce->lv = NUM_CRIT_LEVELS;
		ce->will_schedule = false;

		while (!list_empty(&state->sup_env.all_reservations)) {
			res = list_first_entry(
				&state->sup_env.all_reservations,
			        struct reservation, all_list);
			destroy_reservation(res);
		}

		raw_spin_unlock(&state->lock);
	}

	raw_spin_lock(&_global_env.lock);

	while (!list_empty(&_global_env.all_reservations)) {
		res = list_first_entry(
			&_global_env.all_reservations,
				struct reservation, all_list);
		destroy_reservation(res);
	}

	while (!list_empty(&_global_env.next_events)) {
		event = list_first_entry(
			&_global_env.next_events,
				struct next_timer_event, list);
		list_del(&event->list);
		kfree(event);
	}

	raw_spin_unlock(&_global_env.lock);

	destroy_domain_proc_info(&mc2_domain_proc_info);
	return 0;
}

static struct sched_plugin mc2_plugin = {
	.plugin_name		= "MC2",
	.schedule		= mc2_schedule,
	.finish_switch		= mc2_finish_switch,
	.task_wake_up		= mc2_task_resume,
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

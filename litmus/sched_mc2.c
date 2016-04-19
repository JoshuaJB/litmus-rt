/*
 * litmus/sched_mc2.c
 *
 * Implementation of the Mixed-Criticality on MultiCore scheduler
 *
 * Thus plugin implements a scheduling algorithm proposed in 
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
#include <litmus/reservation.h>
#include <litmus/polling_reservations.h>

//#define TRACE(fmt, args...) do {} while (false)
//#define TRACE_TASK(fmt, args...) do {} while (false)

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

/* crit_entry - maintain the logically running job (ghost job) */
struct crit_entry {
	enum crit_level level;
	struct task_struct *running;
};

/* mc2_cpu_state - maintain the scheduled state and ghost jobs
 * timer : timer for partitioned tasks (level A and B)
 * g_timer : timer for global tasks (level C)
 */
struct mc2_cpu_state {
	raw_spinlock_t lock;

	struct sup_reservation_environment sup_env;
	struct hrtimer timer;

	int cpu;
	struct task_struct* scheduled;
	struct crit_entry crit_entries[NUM_CRIT_LEVELS];
};

static int resched_cpu[NR_CPUS];
static DEFINE_PER_CPU(struct mc2_cpu_state, mc2_cpu_state);

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
 *               If the job has remaining budget, convert it to a ghost job
 *               and update crit_entries[]
 *               
 * @job_complete	indicate whether job completes or not              
 */
static void task_departs(struct task_struct *tsk, int job_complete)
{
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	//struct mc2_cpu_state* state = local_cpu_state();
	struct reservation* res = NULL;
	struct reservation_client *client = NULL;

	BUG_ON(!is_realtime(tsk));
	
	res    = tinfo->res_info.client.reservation;
	client = &tinfo->res_info.client;
	BUG_ON(!res);
	BUG_ON(!client);

/* 9/18/2015 fix start - no ghost job handling, empty remaining budget */
	if (job_complete) {
		res->cur_budget = 0;
		sched_trace_task_completion(tsk, 0);
	}
/* fix end */

	res->ops->client_departs(res, client, job_complete);
	tinfo->has_departed = true;
	TRACE_TASK(tsk, "CLIENT DEPART with budget %llu\n", res->cur_budget);
/* 9/18/2015 fix start - no remaining budget 
 *	
	if (job_complete && res->cur_budget) {
		struct crit_entry* ce;
		enum crit_level lv = tinfo->mc2_param.crit;
		
		ce = &state->crit_entries[lv];
		ce->running = tsk;
		res->is_ghost = state->cpu;
#if BUDGET_ENFORCEMENT_AT_C		
		gmp_add_event_after(&_global_env, res->cur_budget, res->id, EVENT_DRAIN);
#endif
		TRACE_TASK(tsk, "BECOME GHOST at %llu\n", litmus_clock());
 	}
 * fix -end
 */ 

}

/* task_arrive - put a task into its reservation
 *               If the job was a ghost job, remove it from crit_entries[]
 */
static void task_arrives(struct mc2_cpu_state *state, struct task_struct *tsk)
{
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	struct reservation* res;
	struct reservation_client *client;
	enum crit_level lv = get_task_crit_level(tsk);

	res    = tinfo->res_info.client.reservation;
	client = &tinfo->res_info.client;

	tinfo->has_departed = false;

	switch(lv) {
		case CRIT_LEVEL_A:
		case CRIT_LEVEL_B:
			TS_RELEASE_START;
			break;
		case CRIT_LEVEL_C:
			TS_RELEASE_C_START;
			break;
		default:
			break;
	}
	
	res->ops->client_arrives(res, client);
	
	if (lv != NUM_CRIT_LEVELS) {
		struct crit_entry *ce;
		ce = &state->crit_entries[lv];
		/* if the currrent task is a ghost job, remove it */
		if (ce->running == tsk)
			ce->running = NULL;
	}
	/* do we need this??
	if (resched_cpu[state->cpu]) 
		litmus_reschedule(state->cpu);
	*/
	
	switch(lv) {
		case CRIT_LEVEL_A:
		case CRIT_LEVEL_B:
			TS_RELEASE_END;
			break;
		case CRIT_LEVEL_C:
			TS_RELEASE_C_END;
			break;
		default:
			break;
	}	
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
	
	//raw_spin_lock(&_lowest_prio_cpu.lock);
	ce = &_lowest_prio_cpu.cpu_entries[local_cpu_state()->cpu];
	if (!ce->will_schedule && !ce->scheduled) {
		//raw_spin_unlock(&_lowest_prio_cpu.lock);
		TRACE("CPU %d (local) is the lowest!\n", ce->cpu);
		return ce->cpu;
	} else {
		TRACE("Local CPU will_schedule=%d, scheduled=(%s/%d)\n", ce->will_schedule, ce->scheduled ? (ce->scheduled)->comm : "null", ce->scheduled ? (ce->scheduled)->pid : 0);
	}

	for_each_online_cpu(cpu) {
		ce = &_lowest_prio_cpu.cpu_entries[cpu];
		/* If a CPU will call schedule() in the near future, we don't
		   return that CPU. */
		TRACE("CPU %d will_schedule=%d, scheduled=(%s/%d:%d)\n", cpu, ce->will_schedule,
	      ce->scheduled ? (ce->scheduled)->comm : "null",
	      ce->scheduled ? (ce->scheduled)->pid : 0,
	      ce->scheduled ? (ce->scheduled)->rt_param.job_params.job_no : 0);
		if (!ce->will_schedule) {
			if (!ce->scheduled) {
				/* Idle cpu, return this. */
				//raw_spin_unlock(&_lowest_prio_cpu.lock);
				TRACE("CPU %d is the lowest!\n", ce->cpu);
				return ce->cpu;
			} else if (ce->lv == CRIT_LEVEL_C && 
			           ce->deadline > latest_deadline) {
				latest_deadline = ce->deadline;
				ret = ce->cpu;
			}
		}
	}		
	
	//raw_spin_unlock(&_lowest_prio_cpu.lock);

	if (priority >= latest_deadline)
		ret = NO_CPU;
	
	TRACE("CPU %d is the lowest!\n", ret);

	return ret;
}

/* mc2_update_time - update time for a given criticality level. 
 *                   caller must hold a proper lock
 *                   (cpu_state lock or global lock)
 */
/* 9/24/2015 temporally not using
static void mc2_update_time(enum crit_level lv, 
                            struct mc2_cpu_state *state, lt_t time)
{
	int global_schedule_now;
	
	if (lv < CRIT_LEVEL_C)
		sup_update_time(&state->sup_env, time);
	else if (lv == CRIT_LEVEL_C) {
		global_schedule_now = gmp_update_time(&_global_env, time);
		while (global_schedule_now--) {
			int cpu = get_lowest_prio_cpu(0);
			if (cpu != NO_CPU) {
				raw_spin_lock(&_lowest_prio_cpu.lock);
				_lowest_prio_cpu.cpu_entries[cpu].will_schedule = true;
				raw_spin_unlock(&_lowest_prio_cpu.lock);
				TRACE("LOWEST CPU = P%d\n", cpu);
				litmus_reschedule(cpu);
			}
		} 
	}
	else
		TRACE("update_time(): Criticality level error!!!!\n");
}
*/

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
	//enum crit_level lv = get_task_crit_level(state->scheduled);
	struct next_timer_event *event, *next;
	int reschedule[NR_CPUS];
	
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
		
	list_for_each_entry_safe(event, next, &_global_env.next_events, list) {
		/* If the event time is already passed, we call schedule() on
		   the lowest priority cpu */
		if (event->next_update >= update) {
			break;
		}
		
		if (event->next_update < litmus_clock()) {
			if (event->timer_armed_on == NO_CPU) {
				struct reservation *res = gmp_find_by_id(&_global_env, event->id);
				int cpu = get_lowest_prio_cpu(res?res->priority:0);
				TRACE("GLOBAL EVENT PASSED!! poking CPU %d to reschedule\n", cpu);
				list_del(&event->list);
				kfree(event);
				if (cpu != NO_CPU) {
					//raw_spin_lock(&_lowest_prio_cpu.lock);
					_lowest_prio_cpu.cpu_entries[cpu].will_schedule = true;
					//raw_spin_unlock(&_lowest_prio_cpu.lock);
					if (cpu == local_cpu_state()->cpu)
						litmus_reschedule_local();
					else
						reschedule[cpu] = 1;
				}
			}
		} else if (event->next_update < update && (event->timer_armed_on == NO_CPU || event->timer_armed_on == state->cpu)) {
			event->timer_armed_on = state->cpu;
			update = event->next_update;
			break;
		}
	}
	
	/* Must drop state lock before calling into hrtimer_start(), which
	 * may raise a softirq, which in turn may wake ksoftirqd. */
	raw_spin_unlock(&_global_env.lock);
	raw_spin_unlock(&state->lock);
		
	if (update <= now || reschedule[state->cpu]) {
		//litmus_reschedule(state->cpu);
		raw_spin_lock(&state->lock);
		preempt_if_preemptable(state->scheduled, state->cpu);
		raw_spin_unlock(&state->lock);
		reschedule[state->cpu] = 0;
	} else if (likely(local && update != SUP_NO_SCHEDULER_UPDATE)) {
		/* Reprogram only if not already set correctly. */
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
			//litmus_reschedule(state->cpu);
			raw_spin_lock(&state->lock);
			preempt_if_preemptable(state->scheduled, state->cpu);
			raw_spin_unlock(&state->lock);
			reschedule[state->cpu] = 0;
		}
	}
	for (cpus = 0; cpus<NR_CPUS; cpus++) {
		if (reschedule[cpus]) {
			//litmus_reschedule(cpus);
			struct mc2_cpu_state *remote_state;

			remote_state = cpu_state_for(cpus);
			raw_spin_lock(&remote_state->lock);
			preempt_if_preemptable(remote_state->scheduled, remote_state->cpu);
			raw_spin_unlock(&remote_state->lock);
		}
	}
}

/* mc2_update_ghost_state - Update crit_entries[] to track ghost jobs
 *                          If the budget of a ghost is exhausted,
 *                          clear is_ghost and reschedule
 */
/*
static lt_t mc2_update_ghost_state(struct mc2_cpu_state *state)
{
	int lv = 0;
	struct crit_entry* ce;
	struct reservation *res;
	struct mc2_task_state *tinfo;
	lt_t ret = ULLONG_MAX;
	
	BUG_ON(!state);
	
	for (lv = 0; lv < NUM_CRIT_LEVELS; lv++) {
		ce = &state->crit_entries[lv];
		if (ce->running != NULL) {
//printk(KERN_ALERT "P%d ce->running : %s/%d\n", state->cpu,  ce->running ? (ce->running)->comm : "null", ce->running ? (ce->running)->pid : 0);
			tinfo = get_mc2_state(ce->running);
			if (!tinfo)
				continue;
			
			res = res_find_by_id(state, tinfo->mc2_param.res_id);
			//BUG_ON(!res);
			if (!res) {
				printk(KERN_ALERT "mc2_update_ghost_state(): R%d not found!\n", tinfo->mc2_param.res_id);			
				return 0;
			}
			
			TRACE("LV %d running id %d budget %llu\n", 
			       lv, tinfo->mc2_param.res_id, res->cur_budget);
			// If the budget is exhausted, clear is_ghost and reschedule 
			if (!res->cur_budget) {
				struct sup_reservation_environment* sup_env = &state->sup_env;
				
				TRACE("GHOST FINISH id %d at %llu\n", 
				      tinfo->mc2_param.res_id, litmus_clock());
				ce->running = NULL;
				res->is_ghost = NO_CPU;
				
				if (lv < CRIT_LEVEL_C) {
					res = list_first_entry_or_null(
					      &sup_env->active_reservations, 
						  struct reservation, list);
					if (res)
						litmus_reschedule_local();
				} else if (lv == CRIT_LEVEL_C) {
					res = list_first_entry_or_null(
					      &_global_env.active_reservations,
						  struct reservation, list);
					if (res)
						litmus_reschedule(state->cpu);
				}
			} else {
				//TRACE("GHOST NOT FINISH id %d budget %llu\n", res->id, res->cur_budget);
				//gmp_add_event_after(&_global_env, res->cur_budget, res->id, EVENT_DRAIN);
				if (ret > res->cur_budget) {
					ret = res->cur_budget;
				}
			}
		}
	}
	
	return ret;
}			
*/

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
	//lt_t remain_budget; // no ghost jobs
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
	//raw_spin_lock_irqsave(&_global_env.lock, flags);
	raw_spin_lock_irqsave(&state->lock, flags);
	now = litmus_clock();
	sup_update_time(&state->sup_env, now);

/* 9/20/2015 fix - no ghost job 	
	remain_budget = mc2_update_ghost_state(state);
*/	
	update = state->sup_env.next_scheduler_update;
	now = state->sup_env.env.current_time;

/* 9/20/2015 fix - no ghost job 
	if (remain_budget != ULLONG_MAX && update > now + remain_budget) {
		update = now + remain_budget;
	}
	
	TRACE_CUR("on_scheduling_timer at %llu, upd:%llu (for cpu=%d) g_schedule_now:%d remain_budget:%llu\n", now, update, state->cpu, global_schedule_now, remain_budget);
*/	

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
			//raw_spin_lock(&_lowest_prio_cpu.lock);
			_lowest_prio_cpu.cpu_entries[cpu].will_schedule = true;
			//raw_spin_unlock(&_lowest_prio_cpu.lock);
			TRACE("LOWEST CPU = P%d\n", cpu);
			if (cpu == state->cpu && update > now)
				litmus_reschedule_local();
			else
				reschedule[cpu] = 1;
		}
	} 
	raw_spin_unlock(&_global_env.lock);
	
	raw_spin_unlock_irqrestore(&state->lock, flags);
	//raw_spin_unlock_irqrestore(&_global_env.lock, flags);
	
	TS_ISR_END;
	
	for (cpus = 0; cpus<NR_CPUS; cpus++) {
		if (reschedule[cpus]) {
			//litmus_reschedule(cpus);
			struct mc2_cpu_state *remote_state;

			remote_state = cpu_state_for(cpus);
			raw_spin_lock(&remote_state->lock);
			preempt_if_preemptable(remote_state->scheduled, remote_state->cpu);
			raw_spin_unlock(&remote_state->lock);
		}
	}
	
	
	return restart;
}

/* mc2_dispatch - Select the next task to schedule.
 */
struct task_struct* mc2_dispatch(struct sup_reservation_environment* sup_env, struct mc2_cpu_state* state)
{
	struct reservation *res, *next;
	struct task_struct *tsk = NULL;
	struct crit_entry *ce;
	enum crit_level lv;
	lt_t time_slice;

	list_for_each_entry_safe(res, next, &sup_env->active_reservations, list) {
		if (res->state == RESERVATION_ACTIVE) {
			tsk = res->ops->dispatch_client(res, &time_slice);
			if (likely(tsk)) {
				lv = get_task_crit_level(tsk);
				if (lv == NUM_CRIT_LEVELS) {
					sup_scheduler_update_after(sup_env, res->cur_budget);
					return tsk;
				} else {
					ce = &state->crit_entries[lv];
					sup_scheduler_update_after(sup_env, res->cur_budget);
					res->blocked_by_ghost = 0;
					res->is_ghost = NO_CPU;
					return tsk;
/* no ghost jobs
					if (likely(!ce->running)) {
						sup_scheduler_update_after(sup_env, res->cur_budget);
						res->blocked_by_ghost = 0;
						res->is_ghost = NO_CPU;
						return tsk;
					} else {
						res->blocked_by_ghost = 1;
						TRACE_TASK(ce->running, " is GHOST\n");
					}
*/
				}
			}
		}
	}
	
	return NULL;
}

struct task_struct* mc2_global_dispatch(struct mc2_cpu_state* state)
{
	struct reservation *res, *next;
	struct task_struct *tsk = NULL;
	//struct crit_entry *ce;
	enum crit_level lv;
	lt_t time_slice;
	
	/* no eligible level A or B tasks exists */
	/* check the ghost job */
	/*
	ce = &state->crit_entries[CRIT_LEVEL_C];
	if (ce->running) {
		TRACE_TASK(ce->running," is GHOST\n");
		return NULL;
	}
	*/
	list_for_each_entry_safe(res, next, &_global_env.active_reservations, list) {
		BUG_ON(!res);
		if (res->state == RESERVATION_ACTIVE && res->scheduled_on == NO_CPU) {
			tsk = res->ops->dispatch_client(res, &time_slice);
			if (likely(tsk)) {
				lv = get_task_crit_level(tsk);
				if (lv == NUM_CRIT_LEVELS) {
#if BUDGET_ENFORCEMENT_AT_C			
					gmp_add_event_after(&_global_env, res->cur_budget, res->id, EVENT_DRAIN);
#endif
					res->event_added = 1;
					res->blocked_by_ghost = 0;
					res->is_ghost = NO_CPU;
					res->scheduled_on = state->cpu;
					return tsk;
				} else if (lv == CRIT_LEVEL_C) {
					//ce = &state->crit_entries[lv];
					//if (likely(!ce->running)) {
#if BUDGET_ENFORCEMENT_AT_C
						gmp_add_event_after(&_global_env, res->cur_budget, res->id, EVENT_DRAIN);
#endif
						res->event_added = 1;
						res->blocked_by_ghost = 0;
						res->is_ghost = NO_CPU;
						res->scheduled_on = state->cpu;
						return tsk;
					//} else {
					//	res->blocked_by_ghost = 1;
					//	TRACE_TASK(ce->running, " is GHOST\n");
					//	return NULL;
					//}
				} else {
					BUG();
				}
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
	if ((!next) || !is_realtime(next))
		return;

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
	lt_t now;
	struct mc2_cpu_state *state = local_cpu_state();
	
	pre_schedule(prev, state->cpu);
	
	/* 9/20/2015 fix
	raw_spin_lock(&_global_env.lock);
	*/
	raw_spin_lock(&state->lock);
	
	//BUG_ON(state->scheduled && state->scheduled != prev);
	//BUG_ON(state->scheduled && !is_realtime(prev));
	if (state->scheduled && state->scheduled != prev)
		; //printk(KERN_ALERT "BUG1!!!!!!!! %s %s\n", state->scheduled ? (state->scheduled)->comm : "null", prev ? (prev)->comm : "null");
	if (state->scheduled && !is_realtime(prev))
		; //printk(KERN_ALERT "BUG2!!!!!!!! \n");

	/* (0) Determine state */
	exists = state->scheduled != NULL;
	blocks = exists && !is_current_running();
	np = exists && is_np(state->scheduled);
	
	/* update time */
	state->sup_env.will_schedule = true;

	now = litmus_clock();
	sup_update_time(&state->sup_env, now);
	/* 9/20/2015 fix
	gmp_update_time(&_global_env, now);
	*/
	/* 9/20/2015 fix 
	mc2_update_ghost_state(state);	
	*/
	
	/* remove task from reservation if it blocks */
	if (is_realtime(prev) && !is_running(prev)) {
		if (get_task_crit_level(prev) == CRIT_LEVEL_C)
			raw_spin_lock(&_global_env.lock);
		task_departs(prev, is_completed(prev));
		if (get_task_crit_level(prev) == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);
	}
	
	/* figure out what to schedule next */
	if (!np)
		state->scheduled = mc2_dispatch(&state->sup_env, state);

	if (!state->scheduled) {
		raw_spin_lock(&_global_env.lock);
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
	
	//raw_spin_lock(&_lowest_prio_cpu.lock);
	//_lowest_prio_cpu.cpu_entries[state->cpu].will_schedule = false;
	//update_cpu_prio(state);
	//raw_spin_unlock(&_lowest_prio_cpu.lock);
	
	/* Notify LITMUS^RT core that we've arrived at a scheduling decision. */
	sched_state_task_picked();

	/* program scheduler timer */
	state->sup_env.will_schedule = false;
		
	/* NOTE: drops state->lock */
	mc2_update_timer_and_unlock(state);

	if (prev != state->scheduled && is_realtime(prev)) {
		struct mc2_task_state* tinfo = get_mc2_state(prev);
		struct reservation* res = tinfo->res_info.client.reservation;
		TRACE_TASK(prev, "PREV JOB scheduled_on = P%d\n", res->scheduled_on);
		res->scheduled_on = NO_CPU;
		TRACE_TASK(prev, "descheduled.\n");
		/* if prev is preempted and a global task, find the lowest cpu and reschedule */
		if (tinfo->has_departed == false && get_task_crit_level(prev) == CRIT_LEVEL_C) {
			int cpu;
			raw_spin_lock(&_global_env.lock);
			cpu = get_lowest_prio_cpu(res?res->priority:0);
			//TRACE("LEVEL-C TASK PREEMPTED!! poking CPU %d to reschedule\n", cpu);
			if (cpu != NO_CPU && _lowest_prio_cpu.cpu_entries[cpu].will_schedule == false) {
				//raw_spin_lock(&_lowest_prio_cpu.lock);
				_lowest_prio_cpu.cpu_entries[cpu].will_schedule = true;
				resched_cpu[cpu] = 1;
				//raw_spin_unlock(&_lowest_prio_cpu.lock);
			}
			raw_spin_unlock(&_global_env.lock);
		}
	}
	if (state->scheduled) {
		TRACE_TASK(state->scheduled, "scheduled.\n");
	}
	
	post_schedule(state->scheduled, state->cpu);
	
	return state->scheduled;
}

static void resume_legacy_task_model_updates(struct task_struct *tsk)
{
	lt_t now;
	if (is_sporadic(tsk)) {
		/* If this sporadic task was gone for a "long" time and woke up past
		 * its deadline, then give it a new budget by triggering a job
		 * release. This is purely cosmetic and has no effect on the
		 * MC2 scheduler. */

		now = litmus_clock();
		if (is_tardy(tsk, now)) {
			//release_at(tsk, now);
			//sched_trace_task_release(tsk);
		}
	}
}

/* mc2_task_resume - Called when the state of tsk changes back to 
 *                   TASK_RUNNING. We need to requeue the task.
 */
static void mc2_task_resume(struct task_struct  *tsk)
{
	unsigned long flags;
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	struct mc2_cpu_state *state;

	TRACE_TASK(tsk, "thread wakes up at %llu\n", litmus_clock());

	local_irq_save(flags);
	if (tinfo->cpu != -1)
		state = cpu_state_for(tinfo->cpu);
	else
		state = local_cpu_state();

	/* 9/20/2015 fix
	raw_spin_lock(&_global_env.lock);
	*/
	/* Requeue only if self-suspension was already processed. */
	if (tinfo->has_departed)
	{
		/* We don't want to consider jobs before synchronous releases */
		if (tsk_rt(tsk)->job_params.job_no > 5) {
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
		}
		
		raw_spin_lock(&state->lock);
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
			
		/* 9/20/2015 fix 
		mc2_update_ghost_state(state);
		*/
		//task_arrives(state, tsk);
		/* NOTE: drops state->lock */
		TRACE_TASK(tsk, "mc2_resume()\n");
		mc2_update_timer_and_unlock(state);	
	} else {
		TRACE_TASK(tsk, "resume event ignored, still scheduled\n");
		//raw_spin_unlock(&_global_env.lock);
	}

	local_irq_restore(flags);
	
	//gmp_free_passed_event();
	resume_legacy_task_model_updates(tsk);
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
	if (tsk_rt(current)->sporadic_release) {
		struct mc2_cpu_state *state;
		struct reservation_environment *env;
		struct mc2_task_state *tinfo;
		struct reservation *res = NULL;
		unsigned long flags;
		enum crit_level lv;

		preempt_disable();
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
/*		
		if (get_task_crit_level(current) == CRIT_LEVEL_A) {
			struct table_driven_reservation *tdres;
			tdres = container_of(res, struct table_driven_reservation, res);
			tdres->next_interval = 0;
			tdres->major_cycle_start = tsk_rt(current)->sporadic_release_time;
			res->next_replenishment += tdres->intervals[0].start;			
		}
*/		
		res->cur_budget = 0;
		res->env->change_state(res->env, res, RESERVATION_DEPLETED);
		
		//TRACE_CUR("CHANGE NEXT_REP = %llu NEXT_UPDATE = %llu\n", res->next_replenishment, state->sup_env.next_scheduler_update);
		
		//if (lv < CRIT_LEVEL_C)
//			raw_spin_unlock(&state->lock);
		//else 
		if (lv == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);
		
		raw_spin_unlock(&state->lock);
		local_irq_restore(flags);
		preempt_enable();
	}
	
	sched_trace_task_completion(current, 0);		
	/* update the next release time and deadline */
	prepare_for_next_period(current);
	sched_trace_task_release(current);
	next_release = ns_to_ktime(get_release(current));
	preempt_disable();
	TRACE_CUR("next_release=%llu\n", get_release(current));
	if (get_release(current) > litmus_clock()) {
		/* sleep until next_release */
		set_current_state(TASK_INTERRUPTIBLE);
		preempt_enable_no_resched();
		err = schedule_hrtimeout(&next_release, HRTIMER_MODE_ABS);
	} else {
		/* release the next job immediately */
		err = 0;
		TRACE_CUR("TARDY: release=%llu now=%llu\n", get_release(current), litmus_clock());
		preempt_enable();
	}

	TRACE_CUR("mc2_complete_job returns at %llu\n", litmus_clock());

	return err;
}

/* mc2_admit_task - Setup mc2 task parameters
 */
static long mc2_admit_task(struct task_struct *tsk)
{
	long err = -ESRCH;
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
		return err;
	}
	
	lv = mp->crit;
	preempt_disable();

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

		raw_spin_unlock_irqrestore(&state->lock, flags);
	} else if (lv == CRIT_LEVEL_C) {
		state = local_cpu_state();
		raw_spin_lock_irqsave(&state->lock, flags);
		raw_spin_lock(&_global_env.lock);
		//state = local_cpu_state();
		
		//raw_spin_lock(&state->lock);
		
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

		raw_spin_unlock(&_global_env.lock);
		raw_spin_unlock_irqrestore(&state->lock, flags);	
	}
	
	preempt_enable();

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

	TRACE_TASK(tsk, "new RT task %llu (on_rq:%d, running:%d)\n",
		   litmus_clock(), on_runqueue, is_running);

	if (tinfo->cpu == -1)
		state = local_cpu_state();
	else 
		state = cpu_state_for(tinfo->cpu);
	
	local_irq_save(flags);
	
	/* acquire the lock protecting the state and disable interrupts */
	//raw_spin_lock(&_global_env.lock);
	//raw_spin_lock(&state->lock);
	if (is_running) {
		state->scheduled = tsk;
		/* make sure this task should actually be running */
		litmus_reschedule_local();
	}
	
	raw_spin_lock(&state->lock);

	if (lv == CRIT_LEVEL_C) {
		raw_spin_lock(&_global_env.lock);
		res = gmp_find_by_id(&_global_env, tinfo->mc2_param.res_id);
	}
	else {
		res = sup_find_by_id(&state->sup_env, tinfo->mc2_param.res_id);
	}
	//res = res_find_by_id(state, tinfo->mc2_param.res_id);
	release = res->next_replenishment;
	
	if (on_runqueue || is_running) {
		/* Assumption: litmus_clock() is synchronized across cores
		 * [see comment in pres_task_resume()] */
		if (lv == CRIT_LEVEL_C) {
			gmp_update_time(&_global_env, litmus_clock());
			//raw_spin_unlock(&_global_env.lock);
		}
		else
			sup_update_time(&state->sup_env, litmus_clock());
		//mc2_update_time(lv, state, litmus_clock());
		/* 9/20/2015 fix 
		mc2_update_ghost_state(state);
		*/
		task_arrives(state, tsk);
		if (lv == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);
		/* NOTE: drops state->lock */
		TRACE("mc2_new()\n");
		
		mc2_update_timer_and_unlock(state);
	} else {
		if (lv == CRIT_LEVEL_C)
			raw_spin_unlock(&_global_env.lock);
		raw_spin_unlock(&state->lock);
		//raw_spin_unlock(&_global_env.lock);
	}
	local_irq_restore(flags);
	
	if (!release) {
		TRACE_TASK(tsk, "mc2_task_new() next_release = %llu\n", release);
		//release_at(tsk, release);
	}
	else
		TRACE_TASK(tsk, "mc2_task_new() next_release = NULL\n");
}

/* mc2_reservation_destroy - reservation_destroy system call backend
 */
static long mc2_reservation_destroy(unsigned int reservation_id, int cpu)
{
	long ret = -EINVAL;
	struct mc2_cpu_state *state;
	struct reservation *res = NULL, *next;
	struct sup_reservation_environment *sup_env;
	int found = 0;
	//enum crit_level lv = get_task_crit_level(current);
	unsigned long flags;
	
	if (cpu == -1) {
		/* if the reservation is global reservation */
		local_irq_save(flags);
		//state = local_cpu_state();
		raw_spin_lock(&_global_env.lock);
		//raw_spin_lock(&state->lock);
		
		list_for_each_entry_safe(res, next, &_global_env.depleted_reservations, list) {
			if (res->id == reservation_id) {
				list_del(&res->list);
				kfree(res);
				found = 1;
				ret = 0;
			}
		}
		if (!found) {
			list_for_each_entry_safe(res, next, &_global_env.inactive_reservations, list) {
				if (res->id == reservation_id) {
					list_del(&res->list);
					kfree(res);
					found = 1;
					ret = 0;
				}
			}
		}
		if (!found) {
			list_for_each_entry_safe(res, next, &_global_env.active_reservations, list) {
				if (res->id == reservation_id) {
					list_del(&res->list);
					kfree(res);
					found = 1;
					ret = 0;
				}
			}
		}

		//raw_spin_unlock(&state->lock);
		raw_spin_unlock(&_global_env.lock);
		local_irq_restore(flags);
	} else {
		/* if the reservation is partitioned reservation */
		state = cpu_state_for(cpu);
		local_irq_save(flags);
		raw_spin_lock(&state->lock);
		
	//	res = sup_find_by_id(&state->sup_env, reservation_id);
		sup_env = &state->sup_env;
		list_for_each_entry_safe(res, next, &sup_env->depleted_reservations, list) {
			if (res->id == reservation_id) {
/*
			if (lv == CRIT_LEVEL_A) {
					struct table_driven_reservation *tdres;
					tdres = container_of(res, struct table_driven_reservation, res);
					kfree(tdres->intervals);
			}
*/
				list_del(&res->list);
				kfree(res);
				found = 1;
				ret = 0;
			}
		}
		if (!found) {
			list_for_each_entry_safe(res, next, &sup_env->inactive_reservations, list) {
				if (res->id == reservation_id) {
/*					if (lv == CRIT_LEVEL_A) {
						struct table_driven_reservation *tdres;
						tdres = container_of(res, struct table_driven_reservation, res);
						kfree(tdres->intervals);
					}
*/
					list_del(&res->list);
					kfree(res);
					found = 1;
					ret = 0;
				}
			}
		}
		if (!found) {
			list_for_each_entry_safe(res, next, &sup_env->active_reservations, list) {
				if (res->id == reservation_id) {
/*					if (lv == CRIT_LEVEL_A) {
						struct table_driven_reservation *tdres;
						tdres = container_of(res, struct table_driven_reservation, res);
						kfree(tdres->intervals);
					}
*/
					list_del(&res->list);
					kfree(res);
					found = 1;
					ret = 0;
				}
			}
		}

		raw_spin_unlock(&state->lock);
		local_irq_restore(flags);
	}
	
	TRACE("Rerservation destroyed ret = %d\n", ret);
	return ret;
}

/* mc2_task_exit - Task became a normal task (not real-time task)
 */
static void mc2_task_exit(struct task_struct *tsk)
{
	unsigned long flags;
	struct mc2_task_state* tinfo = get_mc2_state(tsk);
	struct mc2_cpu_state *state;
	enum crit_level lv = tinfo->mc2_param.crit;
	struct crit_entry* ce;
	int cpu;

	local_irq_save(flags);
	if (tinfo->cpu != -1)
		state = cpu_state_for(tinfo->cpu);
	else 
		state = local_cpu_state();
	
	raw_spin_lock(&state->lock);
	
	if (state->scheduled == tsk)
		state->scheduled = NULL;

	ce = &state->crit_entries[lv];
	if (ce->running == tsk)
		ce->running = NULL;
	
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
			//raw_spin_unlock(&_global_env.lock);
		}
		/* 9/20/2015 fix 
		mc2_update_ghost_state(state);
		*/
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
			
			ce = &state->crit_entries[lv];
			if (ce->running == tsk)
				ce->running = NULL;
			
			raw_spin_unlock(&state->lock);
		}
	}
	
	local_irq_restore(flags);
	
	kfree(tsk_rt(tsk)->plugin_state);
	tsk_rt(tsk)->plugin_state = NULL;
	kfree(tsk_rt(tsk)->mc2_data);
	tsk_rt(tsk)->mc2_data = NULL;
}

/* create_polling_reservation - create a new polling reservation
 */
static long create_polling_reservation(
	int res_type,
	struct reservation_config *config)
{
	struct mc2_cpu_state *state;
	struct reservation* res;
	struct polling_reservation *pres;
	unsigned long flags;
	int use_edf  = config->priority == LITMUS_NO_PRIORITY;
	int periodic =  res_type == PERIODIC_POLLING;
	long err = -EINVAL;

	/* sanity checks */
	if (config->polling_params.budget >
	    config->polling_params.period) {
		printk(KERN_ERR "invalid polling reservation (%u): "
		       "budget > period\n", config->id);
		return -EINVAL;
	}
	if (config->polling_params.budget >
	    config->polling_params.relative_deadline
	    && config->polling_params.relative_deadline) {
		printk(KERN_ERR "invalid polling reservation (%u): "
		       "budget > deadline\n", config->id);
		return -EINVAL;
	}
	if (config->polling_params.offset >
	    config->polling_params.period) {
		printk(KERN_ERR "invalid polling reservation (%u): "
		       "offset > period\n", config->id);
		return -EINVAL;
	}

	/* Allocate before we grab a spin lock.
	 * Todo: would be nice to use a core-local allocation.
	 */
	pres = kzalloc(sizeof(*pres), GFP_KERNEL);
	if (!pres)
		return -ENOMEM;

	if (config->cpu != -1) {
		
		//raw_spin_lock_irqsave(&_global_env.lock, flags);
		state = cpu_state_for(config->cpu);
		raw_spin_lock_irqsave(&state->lock, flags);

		res = sup_find_by_id(&state->sup_env, config->id);
		if (!res) {
			polling_reservation_init(pres, use_edf, periodic,
				config->polling_params.budget,
				config->polling_params.period,
				config->polling_params.relative_deadline,
				config->polling_params.offset);
			pres->res.id = config->id;
			pres->res.blocked_by_ghost = 0;
			pres->res.is_ghost = NO_CPU;
			if (!use_edf)
				pres->res.priority = config->priority;
			sup_add_new_reservation(&state->sup_env, &pres->res);
			err = config->id;
		} else {
			err = -EEXIST;
		}

		raw_spin_unlock_irqrestore(&state->lock, flags);
		//raw_spin_unlock_irqrestore(&_global_env.lock, flags);

	} else {
		raw_spin_lock_irqsave(&_global_env.lock, flags);
		
		res = gmp_find_by_id(&_global_env, config->id);
		if (!res) {
			polling_reservation_init(pres, use_edf, periodic,
				config->polling_params.budget,
				config->polling_params.period,
				config->polling_params.relative_deadline,
				config->polling_params.offset);
			pres->res.id = config->id;
			pres->res.blocked_by_ghost = 0;
			pres->res.scheduled_on = NO_CPU;
			pres->res.is_ghost = NO_CPU;
			if (!use_edf)
				pres->res.priority = config->priority;
			gmp_add_new_reservation(&_global_env, &pres->res);
			err = config->id;
		} else {
			err = -EEXIST;
		}
		raw_spin_unlock_irqrestore(&_global_env.lock, flags);		
	}
	
	if (err < 0)
		kfree(pres);

	return err;
}

#define MAX_INTERVALS 1024

/* create_table_driven_reservation - create a table_driven reservation
 */
static long create_table_driven_reservation(
	struct reservation_config *config)
{
	struct mc2_cpu_state *state;
	struct reservation* res;
	struct table_driven_reservation *td_res = NULL;
	struct lt_interval *slots = NULL;
	size_t slots_size;
	unsigned int i, num_slots;
	unsigned long flags;
	long err = -EINVAL;


	if (!config->table_driven_params.num_intervals) {
		printk(KERN_ERR "invalid table-driven reservation (%u): "
		       "no intervals\n", config->id);
		return -EINVAL;
	}

	if (config->table_driven_params.num_intervals > MAX_INTERVALS) {
		printk(KERN_ERR "invalid table-driven reservation (%u): "
		       "too many intervals (max: %d)\n", config->id, MAX_INTERVALS);
		return -EINVAL;
	}

	num_slots = config->table_driven_params.num_intervals;
	slots_size = sizeof(slots[0]) * num_slots;
	slots = kzalloc(slots_size, GFP_KERNEL);
	if (!slots)
		return -ENOMEM;

	td_res = kzalloc(sizeof(*td_res), GFP_KERNEL);
	if (!td_res)
		err = -ENOMEM;
	else
		err = copy_from_user(slots,
			config->table_driven_params.intervals, slots_size);

	if (!err) {
		/* sanity checks */
		for (i = 0; !err && i < num_slots; i++)
			if (slots[i].end <= slots[i].start) {
				printk(KERN_ERR
				       "invalid table-driven reservation (%u): "
				       "invalid interval %u => [%llu, %llu]\n",
				       config->id, i,
				       slots[i].start, slots[i].end);
				err = -EINVAL;
			}

		for (i = 0; !err && i + 1 < num_slots; i++)
			if (slots[i + 1].start <= slots[i].end) {
				printk(KERN_ERR
				       "invalid table-driven reservation (%u): "
				       "overlapping intervals %u, %u\n",
				       config->id, i, i + 1);
				err = -EINVAL;
			}

		if (slots[num_slots - 1].end >
			config->table_driven_params.major_cycle_length) {
			printk(KERN_ERR
				"invalid table-driven reservation (%u): last "
				"interval ends past major cycle %llu > %llu\n",
				config->id,
				slots[num_slots - 1].end,
				config->table_driven_params.major_cycle_length);
			err = -EINVAL;
		}
	}

	if (!err) {
		state = cpu_state_for(config->cpu);
		raw_spin_lock_irqsave(&state->lock, flags);

		res = sup_find_by_id(&state->sup_env, config->id);
		if (!res) {
			table_driven_reservation_init(td_res,
				config->table_driven_params.major_cycle_length,
				slots, num_slots);
			td_res->res.id = config->id;
			td_res->res.priority = config->priority;
			td_res->res.blocked_by_ghost = 0;
			sup_add_new_reservation(&state->sup_env, &td_res->res);
			err = config->id;
		} else {
			err = -EEXIST;
		}

		raw_spin_unlock_irqrestore(&state->lock, flags);
	}

	if (err < 0) {
		kfree(slots);
		kfree(td_res);
	}

	return err;
}

/* mc2_reservation_create - reservation_create system call backend
 */
static long mc2_reservation_create(int res_type, void* __user _config)
{
	long ret = -EINVAL;
	struct reservation_config config;

	TRACE("Attempt to create reservation (%d)\n", res_type);

	if (copy_from_user(&config, _config, sizeof(config)))
		return -EFAULT;

	if (config.cpu != -1) {
		if (config.cpu < 0 || !cpu_online(config.cpu)) {
			printk(KERN_ERR "invalid polling reservation (%u): "
				   "CPU %d offline\n", config.id, config.cpu);
			return -EINVAL;
		}
	}

	switch (res_type) {
		case PERIODIC_POLLING:
		case SPORADIC_POLLING:
			ret = create_polling_reservation(res_type, &config);
			break;

		case TABLE_DRIVEN:
			ret = create_table_driven_reservation(&config);
			break;

		default:
			return -EINVAL;
	};

	return ret;
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
	int cpu, lv;
	struct mc2_cpu_state *state;
	struct cpu_entry *ce;

	gmp_init(&_global_env);
	raw_spin_lock_init(&_lowest_prio_cpu.lock);
	
	for_each_online_cpu(cpu) {
		TRACE("Initializing CPU%d...\n", cpu);

		resched_cpu[cpu] = 0;
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
		for (lv = 0; lv < NUM_CRIT_LEVELS; lv++) {
			struct crit_entry *cr_entry = &state->crit_entries[lv];
			cr_entry->level = lv;
			cr_entry->running = NULL;
		}
		sup_init(&state->sup_env);

		hrtimer_init(&state->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
		state->timer.function = on_scheduling_timer;
	}

	mc2_setup_domain_proc();

	return 0;
}

static void mc2_finish_switch(struct task_struct *prev)
{
	struct mc2_cpu_state *state = local_cpu_state();
	
	state->scheduled = is_realtime(current) ? current : NULL;
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

		/* Delete all reservations --- assumes struct reservation
		 * is prefix of containing struct. */

		while (!list_empty(&state->sup_env.active_reservations)) {
			res = list_first_entry(
				&state->sup_env.active_reservations,
			        struct reservation, list);
			list_del(&res->list);
			kfree(res);
		}

		while (!list_empty(&state->sup_env.inactive_reservations)) {
			res = list_first_entry(
				&state->sup_env.inactive_reservations,
			        struct reservation, list);
			list_del(&res->list);
			kfree(res);
		}

		while (!list_empty(&state->sup_env.depleted_reservations)) {
			res = list_first_entry(
				&state->sup_env.depleted_reservations,
			        struct reservation, list);
			list_del(&res->list);
			kfree(res);
		}

		raw_spin_unlock(&state->lock);
	}

	raw_spin_lock(&_global_env.lock);
	
	while (!list_empty(&_global_env.active_reservations)) {
		res = list_first_entry(
			&_global_env.active_reservations,
				struct reservation, list);
		list_del(&res->list);
		kfree(res);
	}

	while (!list_empty(&_global_env.inactive_reservations)) {
		res = list_first_entry(
			&_global_env.inactive_reservations,
				struct reservation, list);
		list_del(&res->list);
		kfree(res);
	}

	while (!list_empty(&_global_env.depleted_reservations)) {
		res = list_first_entry(
			&_global_env.depleted_reservations,
				struct reservation, list);
		list_del(&res->list);
		kfree(res);
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
	.plugin_name			= "MC2",
	.schedule				= mc2_schedule,
	.finish_switch			= mc2_finish_switch,
	.task_wake_up			= mc2_task_resume,
	.admit_task				= mc2_admit_task,
	.task_new				= mc2_task_new,
	.task_exit				= mc2_task_exit,
	.complete_job           = mc2_complete_job,
	.get_domain_proc_info   = mc2_get_domain_proc_info,
	.activate_plugin		= mc2_activate_plugin,
	.deactivate_plugin      = mc2_deactivate_plugin,
	.reservation_create     = mc2_reservation_create,
	.reservation_destroy	= mc2_reservation_destroy,
};

static int __init init_mc2(void)
{
	return register_sched_plugin(&mc2_plugin);
}

module_init(init_mc2);

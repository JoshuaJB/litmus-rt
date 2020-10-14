/*
 * litmus/rt_domain.c
 *
 * LITMUS real-time infrastructure. This file contains the
 * functions that manipulate RT domains. RT domains are an abstraction
 * of a ready queue and a release queue.
 */

#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <litmus/litmus.h>
#include <litmus/sched_plugin.h>
#include <litmus/sched_trace.h>
#include <litmus/debug_trace.h>

#include <litmus/rt_domain.h>
#include <litmus/reservations/ext_reservation.h>

#include <litmus/trace.h>

#include <litmus/bheap.h>
#include <litmus/binheap.h>

/* Uncomment when debugging timer races... */
#if 0
#define VTRACE_TASK TRACE_TASK
#define VTRACE TRACE
#else
#define VTRACE_TASK(t, fmt, args...) /* shut up */
#define VTRACE(fmt, args...) /* be quiet already */
#endif

#define NO_FUTURE_RELEASE ULLONG_MAX

static int dummy_resched(rt_domain_t *rt)
{
	return 0;
}

static int dummy_order(struct bheap_node* a, struct bheap_node* b)
{
	return 0;
}

/* default implementation: use default lock */
static void default_release_jobs(rt_domain_t* rt, struct bheap* tasks)
{
	merge_ready(rt, tasks);
}

static unsigned int time2slot(lt_t time)
{
	return (unsigned int) time2quanta(time, FLOOR) % RELEASE_QUEUE_SLOTS;
}

int release_order(struct binheap_node *a, struct binheap_node *b)
{
	return lt_before(binheap_entry(a, struct release_heap, node)->release_time,
					 binheap_entry(b, struct release_heap, node)->release_time);
}

void release_jobs_before_now(rt_domain_t* rt)
{
	unsigned long flags;
	struct release_heap* rh;

	/* remove all heaps with release time earlier than now
	 * from the release queue and call release callback
	 */
	while(!binheap_empty(&rt->release_queue.queue) &&
			lt_before_eq(rt->release_queue.earliest_release, litmus_clock())) {
		raw_spin_lock_irqsave(&rt->release_lock, flags);
		VTRACE("CB has the release_lock 0x%p\n", &rt->release_lock);

		/* O(1) operation */
		rh = binheap_top_entry(&rt->release_queue.queue, struct release_heap, node);
		list_del_init(&rh->list);

		TS_RELEASE_LATENCY(rh->release_time);
		TS_RELEASE_START;

		binheap_delete_root(&rt->release_queue.queue, struct release_heap, node);
		if (binheap_empty(&rt->release_queue.queue)) {
			rt->release_queue.earliest_release = NO_FUTURE_RELEASE;
		} else {
			rt->release_queue.earliest_release =
				binheap_top_entry(&rt->release_queue.queue, struct release_heap, node)
				->release_time;
		}

		raw_spin_unlock_irqrestore(&rt->release_lock, flags);
		VTRACE("CB returned release_lock 0x%p\n", &rt->release_lock);

		rt->release_jobs(rt, &rh->heap);

		TS_RELEASE_END;
	}
}

static enum hrtimer_restart on_release_timer(struct hrtimer *timer)
{
	rt_domain_t* rt;

	rt = container_of(timer, rt_domain_t, timer);

	release_jobs_before_now(rt);

	VTRACE("on_release_timer(0x%p) ends.\n", timer);

	/* when there are no more jobs to release */
	if (rt->release_queue.earliest_release == NO_FUTURE_RELEASE)
		return HRTIMER_NORESTART;
	hrtimer_set_expires(timer, ns_to_ktime(rt->release_queue.earliest_release));

	return HRTIMER_RESTART;
}

void domain_suspend_releases(rt_domain_t* rt)
{
	hrtimer_cancel(&rt->timer);
}

// Resume the release timer on the current CPU
void domain_resume_releases(rt_domain_t* rt)
{
	release_jobs_before_now(rt);
	if (rt->release_queue.earliest_release != NO_FUTURE_RELEASE) {
		hrtimer_start(&rt->timer,
			ns_to_ktime(rt->release_queue.earliest_release),
			HRTIMER_MODE_ABS_PINNED);
	}
}

/* allocated in litmus.c */
struct kmem_cache * release_heap_cache;

struct release_heap* release_heap_alloc(int gfp_flags)
{
	struct release_heap* rh;
	rh= kmem_cache_alloc(release_heap_cache, gfp_flags);
	return rh;
}

void release_heap_free(struct release_heap* rh)
{
	/* make sure timer is no longer in use */
	kmem_cache_free(release_heap_cache, rh);
}

/* For all variants of get_release_heap
 * Caller must hold release lock.
 * Will return heap for given time. If no such heap exists prior to
 * the invocation it will be created.
 */
static struct release_heap* __get_release_heap(rt_domain_t *rt,
					     lt_t release_time,
						 struct release_heap* th,
					     int use_task_heap)
{
	struct list_head* pos;
	struct release_heap* heap = NULL;
	struct release_heap* rh;
	unsigned int slot = time2slot(release_time);

	/* loop is for hash collision, O(1) time complexity */
	/* initialize pos for the case that the list is empty */
	pos = rt->release_queue.slot[slot].next;
	list_for_each(pos, &rt->release_queue.slot[slot]) {
		rh = list_entry(pos, struct release_heap, list);
		if (release_time == rh->release_time) {
			/* perfect match -- this happens on hyperperiod
			 * boundaries
			 */
			heap = rh;
			break;
		} else if (lt_before(release_time, rh->release_time)) {
			/* we need to insert a new node since rh is
			 * already in the future
			 */
			break;
		}
	}
	if (!heap && use_task_heap) {
		/* use pre-allocated release heap */
		rh = th;

		rh->release_time = release_time;

		/* add to release queue */
		list_add(&rh->list, pos->prev);
		/* binheap_add is O(lg n) time complexity. It can't be helped
		 * if we want to be able to have 1 domain timer that we can disable
		 * easily upon domain preemption
		 */
		binheap_add(&rh->node, &rt->release_queue.queue, struct release_heap, node);

		heap = rh;
	}
	return heap;
}

static struct release_heap* get_release_heap_res(rt_domain_t *rt,
						 struct ext_reservation* res,
						 int use_task_heap)
{
	return __get_release_heap(rt, res->replenishment_time, res->rel_heap, use_task_heap);
}

static struct release_heap* get_release_heap(rt_domain_t *rt,
						 struct task_struct *t,
						 int use_task_heap)
{
	return __get_release_heap(rt, get_release(t), tsk_rt(t)->rel_heap, use_task_heap);
}

static void reinit_release_heap(struct task_struct* t)
{
	struct release_heap* rh;

	/* use pre-allocated release heap */
	rh = tsk_rt(t)->rel_heap;
	INIT_LIST_HEAD(&rh->list_head);
	/* initialize */
	bheap_init(&rh->heap);
}

static void reinit_release_heap_res(struct ext_reservation* res)
{
	struct release_heap* rh;

	/* use pre-allocated release heap */
	rh = res->rel_heap;
	INIT_LIST_HEAD(&rh->list_head);
	/* initialize */
	bheap_init(&rh->heap);
}

/* arm_release_timer() - start local release timer or trigger
 *     remote timer (pull timer)
 *
 * Called by add_release() with:
 * - tobe_lock taken
 * - IRQ disabled
 */
#ifdef CONFIG_RELEASE_MASTER
#define arm_release_timer(t) arm_release_timer_on((t), NO_CPU)
static void arm_release_timer_on(rt_domain_t *_rt , int target_cpu)
#else
static void arm_release_timer(rt_domain_t *_rt)
#endif
{
	rt_domain_t *rt = _rt;
	struct list_head list;
	struct list_head *pos, *safe;
	struct task_struct* t;
	struct release_heap* rh;

	VTRACE("arm_release_timer() at %llu\n", litmus_clock());
	list_replace_init(&rt->tobe_released, &list);

	list_for_each_safe(pos, safe, &list) {
		/* pick task of work list */
		t = list_entry(pos, struct task_struct, rt_param.list);
		//sched_trace_task_release(t);
		list_del(pos);

		/* put into release heap while holding release_lock */
		raw_spin_lock(&rt->release_lock);
		VTRACE("acquired the release_lock 0x%p\n", &rt->release_lock);

		rh = get_release_heap(rt, t, 0);
		if (!rh) {
			/* need to use our own, but drop lock first */
			raw_spin_unlock(&rt->release_lock);
			VTRACE("dropped release_lock 0x%p\n",
				    &rt->release_lock);

			reinit_release_heap(t);
			VTRACE("release_heap ready\n");

			raw_spin_lock(&rt->release_lock);
			VTRACE("re-acquired release_lock 0x%p\n",
				    &rt->release_lock);

			rh = get_release_heap(rt, t, 1);
		}
		bheap_insert(rt->order, &rh->heap, tsk_rt(t)->heap_node);
		VTRACE("arm_release_timer(): added to release heap\n");

		rh = binheap_top_entry(&rt->release_queue.queue, struct release_heap, node);
		rt->release_queue.earliest_release = rh->release_time;

		raw_spin_unlock(&rt->release_lock);
		VTRACE("dropped the release_lock 0x%p\n", &rt->release_lock);

		/* To avoid arming the timer multiple times, we only let the
		 * owner of the new earliest release heap do the arming.
		 */
		if (rh == tsk_rt(t)->rel_heap) {
			VTRACE("arming timer 0x%p\n", &rt->timer);

			if (!hrtimer_is_hres_active(&rt->timer)) {
				VTRACE("WARNING: no hires timer!!!\n");
			}

			/* we cannot arm the timer using hrtimer_start()
			 * as it may deadlock on rq->lock
			 *
			 * PINNED mode is ok on both local and remote CPU
			 */
#ifdef CONFIG_RELEASE_MASTER
			if (rt->release_master == NO_CPU &&
			    target_cpu == NO_CPU)
#endif
				hrtimer_start(&rt->timer,
					ns_to_ktime(rh->release_time),
					HRTIMER_MODE_ABS_PINNED);
#ifdef CONFIG_RELEASE_MASTER
			else
				hrtimer_start_on(
					/* target_cpu overrides release master */
					(target_cpu != NO_CPU ?
					 target_cpu : rt->release_master),
					&rt->info, &rt->timer,
					ns_to_ktime(rh->release_time),
					HRTIMER_MODE_ABS_PINNED);
#endif
		} else
			VTRACE("timer 0x%p has been armed for earlier time\n", &rh->timer);
	}
}

/* arm_release_timer_res() - start local release timer or trigger
 *     remote timer (pull timer)
 *
 * Called by add_release_res() with:
 * - tobe_lock taken
 * - IRQ disabled
 *
 * TODO: find some way to combine this with the task version of this fuction
 */
#ifdef CONFIG_RELEASE_MASTER
#define arm_release_timer_res(t, i) arm_release_timer_res_on((t), (i), NO_CPU)
static void arm_release_timer_res_on(rt_domain_t *_rt, int interrupt_release, int target_cpu)
#else
static void arm_release_timer_res(rt_domain_t *_rt, int interrupt_release)
#endif
{
	rt_domain_t *rt = _rt;
	struct list_head list;
	struct list_head *pos, *safe;
	struct ext_reservation* res;
	struct release_heap* rh;

	VTRACE("arm_release_timer() at %llu\n", litmus_clock());
	list_replace_init(&rt->tobe_released, &list);

	list_for_each_safe(pos, safe, &list) {
		/* pick task of work list */
		res = list_entry(pos, struct ext_reservation, ln);
		//sched_trace_task_release(t);
		list_del(pos);

		/* put into release heap while holding release_lock */
		raw_spin_lock(&rt->release_lock);
		VTRACE("acquired the release_lock 0x%p\n", &rt->release_lock);

		rh = get_release_heap_res(rt, res, 0);
		if (!rh) {
			/* need to use our own, but drop lock first */
			raw_spin_unlock(&rt->release_lock);
			VTRACE("dropped release_lock 0x%p\n",
				    &rt->release_lock);

			reinit_release_heap_res(res);
			VTRACE("release_heap ready\n");

			raw_spin_lock(&rt->release_lock);
			VTRACE("re-acquired release_lock 0x%p\n",
				    &rt->release_lock);

			rh = get_release_heap_res(rt, res, 1);
		}
		bheap_insert(rt->order, &rh->heap, res->heap_node);
		list_add_tail(&res->ln, &rh->list_head);
		VTRACE("arm_release_timer(): added to release heap\n");

		rh = binheap_top_entry(&rt->release_queue.queue, struct release_heap, node);
		rt->release_queue.earliest_release = rh->release_time;

		raw_spin_unlock(&rt->release_lock);
		VTRACE("dropped the release_lock 0x%p\n", &rt->release_lock);

		/* To avoid arming the timer multiple times, we only let the
		 * owner of the new earliest release heap do the arming.
		 */
		if (rh == res->rel_heap && interrupt_release) {
			VTRACE("arming timer 0x%p\n", &rt->timer);

			if (!hrtimer_is_hres_active(&rt->timer)) {
				VTRACE("WARNING: no hires timer!!!\n");
			}

			/* we cannot arm the timer using hrtimer_start()
			 * as it may deadlock on rq->lock
			 *
			 * PINNED mode is ok on both local and remote CPU
			 */
#ifdef CONFIG_RELEASE_MASTER
			if (rt->release_master == NO_CPU &&
			    target_cpu == NO_CPU)
#endif
				hrtimer_start(&rt->timer,
					ns_to_ktime(rh->release_time),
					HRTIMER_MODE_ABS_PINNED_HARD);
#ifdef CONFIG_RELEASE_MASTER
			else
				hrtimer_start_on(
					/* target_cpu overrides release master */
					(target_cpu != NO_CPU ?
					 target_cpu : rt->release_master),
					&rt->info, &rt->timer,
					ns_to_ktime(rh->release_time),
					HRTIMER_MODE_ABS_PINNED_HARD);
#endif
		} else
			VTRACE("timer 0x%p has been armed for earlier time\n", &rh->timer);
	}
}

void rt_domain_init(rt_domain_t *rt,
		    bheap_prio_t order,
		    check_resched_needed_t check,
		    release_jobs_t release
		   )
{
	int i;

	BUG_ON(!rt);
	if (!check)
		check = dummy_resched;
	if (!release)
		release = default_release_jobs;
	if (!order)
		order = dummy_order;

#ifdef CONFIG_RELEASE_MASTER
	rt->release_master = NO_CPU;
#endif

	bheap_init(&rt->ready_queue);
	INIT_LIST_HEAD(&rt->tobe_released);
	for (i = 0; i < RELEASE_QUEUE_SLOTS; i++)
		INIT_LIST_HEAD(&rt->release_queue.slot[i]);
	INIT_BINHEAP_HANDLE(&rt->release_queue.queue, release_order);
	rt->release_queue.earliest_release = NO_FUTURE_RELEASE;

	raw_spin_lock_init(&rt->ready_lock);
	raw_spin_lock_init(&rt->release_lock);
	raw_spin_lock_init(&rt->tobe_lock);

	hrtimer_init(&rt->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	rt->timer.function = on_release_timer;

	rt->check_resched 	= check;
	rt->release_jobs	= release;
	rt->order		= order;
}

/* add_ready - add a real-time task to the rt ready queue. It must be runnable.
 * @new:       the newly released task
 */
void __add_ready(rt_domain_t* rt, struct task_struct *new)
{
	TRACE("rt: adding %s/%d (%llu, %llu, %llu) rel=%llu "
		"to ready queue at %llu\n",
		new->comm, new->pid,
		get_exec_cost(new), get_rt_period(new), get_rt_relative_deadline(new),
		get_release(new), litmus_clock());

	BUG_ON(bheap_node_in_heap(tsk_rt(new)->heap_node));

	bheap_insert(rt->order, &rt->ready_queue, tsk_rt(new)->heap_node);
	rt->check_resched(rt);
}

void __add_ready_res(rt_domain_t* rt, struct ext_reservation* new)
{
	BUG_ON(bheap_node_in_heap(new->heap_node));

	bheap_insert(rt->order, &rt->ready_queue, new->heap_node);
}

/* merge_ready - Add a sorted set of tasks to the rt ready queue. They must be runnable.
 * @tasks      - the newly released tasks
 */
void __merge_ready(rt_domain_t* rt, struct bheap* tasks)
{
	bheap_union(rt->order, &rt->ready_queue, tasks);
	rt->check_resched(rt);
}


#ifdef CONFIG_RELEASE_MASTER
void __add_release_on(rt_domain_t* rt, struct task_struct *task,
		      int target_cpu)
{
	TRACE_TASK(task, "add_release_on(), rel=%llu, target=%d\n",
		   get_release(task), target_cpu);
	list_add(&tsk_rt(task)->list, &rt->tobe_released);
	task->rt_param.domain = rt;

	arm_release_timer_on(rt, target_cpu);
}

void __add_release_res_on(rt_domain_t* rt, struct ext_reservation *res,
			   int target_cpu)
{
	list_add(&res->ln, &rt->tobe_released);

	arm_release_timer_res_on(rt, 1, target_cpu);
}
#endif

/* add_release - add a real-time task to the rt release queue.
 * @task:        the sleeping task
 */
void __add_release(rt_domain_t* rt, struct task_struct *task)
{
	TRACE_TASK(task, "add_release(), rel=%llu\n", get_release(task));
	list_add(&tsk_rt(task)->list, &rt->tobe_released);
	task->rt_param.domain = rt;

	arm_release_timer(rt);
}

void __add_release_res(rt_domain_t* rt, struct ext_reservation *res)
{
	list_add(&res->ln, &rt->tobe_released);

	arm_release_timer_res(rt, 1);
}

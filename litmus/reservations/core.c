#include <linux/sched.h>
#include <linux/slab.h>

#include <litmus/litmus.h>
#include <litmus/debug_trace.h>
#include <litmus/reservations/reservation.h>

#define BUDGET_ENFORCEMENT_AT_C 0

void reservation_init(struct reservation *res)
{
	memset(res, 0, sizeof(*res));
	res->state = RESERVATION_INACTIVE;
	INIT_LIST_HEAD(&res->clients);
}

struct task_struct* default_dispatch_client(
	struct reservation *res,
	lt_t *for_at_most)
{
	struct reservation_client *client, *next;
	struct task_struct* tsk;

	BUG_ON(res->state != RESERVATION_ACTIVE);
	*for_at_most = 0;

	list_for_each_entry_safe(client, next, &res->clients, list) {
		tsk = client->dispatch(client);
		if (likely(tsk)) {
			return tsk;
		}
	}
	return NULL;
}

void common_drain_budget(
	struct reservation *res,
	lt_t how_much)
{
	if (how_much >= res->cur_budget)
		res->cur_budget = 0;
	else
		res->cur_budget -= how_much;

	res->budget_consumed += how_much;
	res->budget_consumed_total += how_much;

	switch (res->state) {
		case RESERVATION_DEPLETED:
		case RESERVATION_INACTIVE:
			BUG();
			break;

		case RESERVATION_ACTIVE_IDLE:
		case RESERVATION_ACTIVE:
			if (!res->cur_budget) {
				res->env->change_state(res->env, res,
						RESERVATION_DEPLETED);
			} /* else: stay in current state */
			break;
	}
}

static struct task_struct * task_client_dispatch(struct reservation_client *client)
{
	struct task_client *tc = container_of(client, struct task_client, client);
	return tc->task;
}

void task_client_init(struct task_client *tc, struct task_struct *tsk,
	struct reservation *res)
{
	memset(&tc->client, 0, sizeof(tc->client));
	tc->client.dispatch = task_client_dispatch;
	tc->client.reservation = res;
	tc->task = tsk;
}

static void sup_scheduler_update_at(
	struct sup_reservation_environment* sup_env,
	lt_t when)
{
	if (sup_env->next_scheduler_update > when)
		sup_env->next_scheduler_update = when;
}

void sup_scheduler_update_after(
	struct sup_reservation_environment* sup_env,
	lt_t timeout)
{
	sup_scheduler_update_at(sup_env, sup_env->env.current_time + timeout);
}

static int _sup_queue_depleted(
	struct sup_reservation_environment* sup_env,
	struct reservation *res)
{
	struct list_head *pos;
	struct reservation *queued;
	int passed_earlier = 0;

	list_for_each(pos, &sup_env->depleted_reservations) {
		queued = list_entry(pos, struct reservation, list);
		if (queued->next_replenishment > res->next_replenishment) {
			list_add(&res->list, pos->prev);
			return passed_earlier;
		} else
			passed_earlier = 1;
	}

	list_add_tail(&res->list, &sup_env->depleted_reservations);

	return passed_earlier;
}

static void sup_queue_depleted(
	struct sup_reservation_environment* sup_env,
	struct reservation *res)
{
	int passed_earlier = _sup_queue_depleted(sup_env, res);

	/* check for updated replenishment time */
	if (!passed_earlier)
		sup_scheduler_update_at(sup_env, res->next_replenishment);
}

static int _sup_queue_active(
	struct sup_reservation_environment* sup_env,
	struct reservation *res)
{
	struct list_head *pos;
	struct reservation *queued;
	int passed_active = 0;

	list_for_each(pos, &sup_env->active_reservations) {
		queued = list_entry(pos, struct reservation, list);
		if (queued->priority > res->priority) {
			list_add(&res->list, pos->prev);
			return passed_active;
		} else if (queued->state == RESERVATION_ACTIVE)
			passed_active = 1;
	}

	list_add_tail(&res->list, &sup_env->active_reservations);
	return passed_active;
}

static void sup_queue_active(
	struct sup_reservation_environment* sup_env,
	struct reservation *res)
{
	int passed_active = _sup_queue_active(sup_env, res);

	/* check for possible preemption */
	if (res->state == RESERVATION_ACTIVE && !passed_active)
		sup_env->next_scheduler_update = SUP_RESCHEDULE_NOW;
	else {
		/* Active means this reservation is draining budget => make sure
		 * the scheduler is called to notice when the reservation budget has been
		 * drained completely. */
		sup_scheduler_update_after(sup_env, res->cur_budget);
	}
}

static void sup_queue_reservation(
	struct sup_reservation_environment* sup_env,
	struct reservation *res)
{
	switch (res->state) {
		case RESERVATION_INACTIVE:
			list_add(&res->list, &sup_env->inactive_reservations);
			break;

		case RESERVATION_DEPLETED:
			sup_queue_depleted(sup_env, res);
			break;

		case RESERVATION_ACTIVE_IDLE:
		case RESERVATION_ACTIVE:
			sup_queue_active(sup_env, res);
			break;
	}
}

void sup_add_new_reservation(
	struct sup_reservation_environment* sup_env,
	struct reservation* new_res)
{
	new_res->env = &sup_env->env;
	list_add(&new_res->all_list, &sup_env->all_reservations);
	sup_queue_reservation(sup_env, new_res);
}

struct reservation* sup_find_by_id(struct sup_reservation_environment* sup_env,
	unsigned int id)
{
	struct reservation *res;

	list_for_each_entry(res, &sup_env->all_reservations, all_list) {
		if (res->id == id)
			return res;
	}

	return NULL;
}

static void sup_charge_budget(
	struct sup_reservation_environment* sup_env,
	lt_t delta)
{
	struct list_head *pos, *next;
	struct reservation *res;

	int encountered_active = 0;

	list_for_each_safe(pos, next, &sup_env->active_reservations) {
		/* charge all ACTIVE_IDLE up to the first ACTIVE reservation */
		res = list_entry(pos, struct reservation, list);
		if (res->state == RESERVATION_ACTIVE) {
			TRACE("sup_charge_budget ACTIVE R%u drain %llu\n", res->id, delta);
			if (encountered_active == 0) {
				TRACE("DRAIN !!\n");
				res->ops->drain_budget(res, delta);
				encountered_active = 1;
			}
		} else {
			TRACE("sup_charge_budget INACTIVE R%u drain %llu\n", res->id, delta);
			res->ops->drain_budget(res, delta);
		}
		if (res->state == RESERVATION_ACTIVE ||
			res->state == RESERVATION_ACTIVE_IDLE)
		{
			/* make sure scheduler is invoked when this reservation expires
			 * its remaining budget */
			 TRACE("requesting scheduler update for reservation %u "
				"in %llu nanoseconds\n",
				res->id, res->cur_budget);
			 sup_scheduler_update_after(sup_env, res->cur_budget);
		}
	}
}

static void sup_replenish_budgets(struct sup_reservation_environment* sup_env)
{
	struct list_head *pos, *next;
	struct reservation *res;

	list_for_each_safe(pos, next, &sup_env->depleted_reservations) {
		res = list_entry(pos, struct reservation, list);
		if (res->next_replenishment <= sup_env->env.current_time) {
			res->ops->replenish(res);
		} else {
			/* list is ordered by increasing depletion times */
			break;
		}
	}

	/* request a scheduler update at the next replenishment instant */
	res = list_first_entry_or_null(&sup_env->depleted_reservations,
		struct reservation, list);
	if (res)
		sup_scheduler_update_at(sup_env, res->next_replenishment);
}

void sup_update_time(
	struct sup_reservation_environment* sup_env,
	lt_t now)
{
	lt_t delta;

	/* If the time didn't advance, there is nothing to do.
	 * This check makes it safe to call sup_advance_time() potentially
	 * multiple times (e.g., via different code paths. */
	if (!list_empty(&sup_env->active_reservations))
		TRACE("(sup_update_time) now: %llu, current_time: %llu\n", now,
			sup_env->env.current_time);
	if (unlikely(now <= sup_env->env.current_time))
		return;

	delta = now - sup_env->env.current_time;
	sup_env->env.current_time = now;

	/* check if future updates are required */
	if (sup_env->next_scheduler_update <= sup_env->env.current_time)
		sup_env->next_scheduler_update = SUP_NO_SCHEDULER_UPDATE;

	/* deplete budgets by passage of time */
	sup_charge_budget(sup_env, delta);

	/* check if any budgets were replenished */
	sup_replenish_budgets(sup_env);
}

struct task_struct* sup_dispatch(struct sup_reservation_environment* sup_env)
{
	struct reservation *res, *next;
	struct task_struct *tsk = NULL;
	lt_t time_slice;

	list_for_each_entry_safe(res, next, &sup_env->active_reservations, list) {
		if (res->state == RESERVATION_ACTIVE) {
			tsk = res->ops->dispatch_client(res, &time_slice);
			if (likely(tsk)) {
				if (time_slice)
				    sup_scheduler_update_after(sup_env, time_slice);
				sup_scheduler_update_after(sup_env, res->cur_budget);
				return tsk;
			}
		}
	}

	return NULL;
}

static void sup_res_change_state(
	struct reservation_environment* env,
	struct reservation *res,
	reservation_state_t new_state)
{
	struct sup_reservation_environment* sup_env;

	sup_env = container_of(env, struct sup_reservation_environment, env);

	TRACE("reservation R%d state %d->%d at %llu\n",
		res->id, res->state, new_state, env->current_time);

	list_del(&res->list);
	/* check if we need to reschedule because we lost an active reservation */
	if (res->state == RESERVATION_ACTIVE && !sup_env->will_schedule)
		sup_env->next_scheduler_update = SUP_RESCHEDULE_NOW;
	res->state = new_state;
	sup_queue_reservation(sup_env, res);
}

static void sup_request_replenishment(
	struct reservation_environment* env,
	struct reservation *res)
{
	struct sup_reservation_environment* sup_env;

	sup_env = container_of(env, struct sup_reservation_environment, env);
	sup_queue_depleted(sup_env, res);
}

void sup_init(struct sup_reservation_environment* sup_env)
{
	memset(sup_env, 0, sizeof(*sup_env));

	INIT_LIST_HEAD(&sup_env->all_reservations);
	INIT_LIST_HEAD(&sup_env->active_reservations);
	INIT_LIST_HEAD(&sup_env->depleted_reservations);
	INIT_LIST_HEAD(&sup_env->inactive_reservations);

	sup_env->env.change_state = sup_res_change_state;
	sup_env->env.request_replenishment = sup_request_replenishment;

	sup_env->next_scheduler_update = SUP_NO_SCHEDULER_UPDATE;
}

struct reservation* gmp_find_by_id(struct gmp_reservation_environment* gmp_env,
	unsigned int id)
{
	struct reservation *res;

	list_for_each_entry(res, &gmp_env->all_reservations, all_list) {
		if (res->id == id)
			return res;
	}

	return NULL;
}


struct next_timer_event* gmp_find_event_by_id(struct gmp_reservation_environment* gmp_env,
	unsigned int id)
{
	struct next_timer_event *event;

	list_for_each_entry(event, &gmp_env->next_events, list) {
		if (event->id == id)
			return event;
	}

	return NULL;
}

#define TIMER_RESOLUTION 100000L

static void gmp_add_event(
	struct gmp_reservation_environment* gmp_env,
	lt_t when, unsigned int id, event_type_t type)
{
	struct next_timer_event *nevent, *queued;
	struct list_head *pos;
	int found = 0, update = 0;

	// XXX: This only works because we can have at most two types of timers
	nevent = gmp_find_event_by_id(gmp_env, id);

	if (nevent)
		TRACE("EVENT R%d update prev = %llu, new = %llu\n", nevent->id, nevent->next_update, when);

	if (nevent && nevent->next_update > when) {
		list_del(&nevent->list);
		update = 1;

	}

	if (!nevent || nevent->type != type || update == 1) {
		if (update == 0)
			nevent = kzalloc(sizeof(*nevent), GFP_ATOMIC);
		BUG_ON(!nevent);
		nevent->next_update = when;
		nevent->id = id;
		nevent->type = type;
		nevent->timer_armed_on = NO_CPU;

		list_for_each(pos, &gmp_env->next_events) {
			queued = list_entry(pos, struct next_timer_event, list);
			if (queued->next_update > nevent->next_update) {
				list_add(&nevent->list, pos->prev);
				found = 1;
				TRACE("NEXT_EVENT id=%d type=%d update=%llu ADDED at before %llu\n", nevent->id, nevent->type, nevent->next_update, queued->next_update);
				break;
			}
		}

		if (!found) {
			list_add_tail(&nevent->list, &gmp_env->next_events);
			TRACE("NEXT_EVENT id=%d type=%d update=%llu ADDED at TAIL\n", nevent->id, nevent->type, nevent->next_update);
		}
	} else {
		//TRACE("EVENT FOUND id = %d type=%d when=%llu, NEW EVENT type=%d when=%llu\n", nevent->id, nevent->type, nevent->next_update, type, when);
; //printk(KERN_ALERT "EVENT FOUND id = %d type=%d when=%llu, NEW EVENT type=%d when=%llu\n", nevent->id, nevent->type, nevent->next_update, type, when);
	}

	TRACE("======START PRINTING EVENT LIST======\n");
	gmp_print_events(gmp_env, litmus_clock());
	TRACE("======FINISH PRINTING EVENT LIST======\n");
}

void gmp_add_event_after(
	struct gmp_reservation_environment* gmp_env, lt_t timeout, unsigned int id, event_type_t type)
{
	//printk(KERN_ALERT "ADD_EVENT_AFTER id = %d\n", id);
	gmp_add_event(gmp_env, gmp_env->env.current_time + timeout, id, type);
}

static void gmp_queue_depleted(
	struct gmp_reservation_environment* gmp_env,
	struct reservation *res)
{
	struct list_head *pos;
	struct reservation *queued;
	int found = 0;

//printk(KERN_ALERT "R%d request to enqueue depleted_list\n", res->id);

	list_for_each(pos, &gmp_env->depleted_reservations) {
		queued = list_entry(pos, struct reservation, list);
		if (queued && (queued->next_replenishment > res->next_replenishment)) {
//printk(KERN_ALERT "QUEUED R%d %llu\n", queued->id, queued->next_replenishment);
			list_add(&res->list, pos->prev);
			found = 1;
			break;
		}
	}

	if (!found)
		list_add_tail(&res->list, &gmp_env->depleted_reservations);

	TRACE("R%d queued to depleted_list\n", res->id);
//printk(KERN_ALERT "R%d queued to depleted_list\n", res->id);
	gmp_add_event(gmp_env, res->next_replenishment, res->id, EVENT_REPLENISH);
}

static void gmp_queue_active(
	struct gmp_reservation_environment* gmp_env,
	struct reservation *res)
{
	struct list_head *pos;
	struct reservation *queued;
	int check_preempt = 1, found = 0;

	list_for_each(pos, &gmp_env->active_reservations) {
		queued = list_entry(pos, struct reservation, list);
		if (queued->priority > res->priority) {
			list_add(&res->list, pos->prev);
			found = 1;
			break;
		} else if (queued->scheduled_on == NO_CPU)
			check_preempt = 0;
	}

	if (!found)
		list_add_tail(&res->list, &gmp_env->active_reservations);

	/* check for possible preemption */
	if (res->state == RESERVATION_ACTIVE && check_preempt)
		gmp_env->schedule_now++;

#if BUDGET_ENFORCEMENT_AT_C
	gmp_add_event_after(gmp_env, res->cur_budget, res->id, EVENT_DRAIN);
#endif
	res->event_added = 1;
}

static void gmp_queue_reservation(
	struct gmp_reservation_environment* gmp_env,
	struct reservation *res)
{

//printk(KERN_ALERT "DEBUG: Passed %s %d %p R%d STATE %d\n",__FUNCTION__,__LINE__, gmp_env, res->id, res->state);
	switch (res->state) {
		case RESERVATION_INACTIVE:
			list_add(&res->list, &gmp_env->inactive_reservations);
			break;

		case RESERVATION_DEPLETED:
			gmp_queue_depleted(gmp_env, res);
			break;

		case RESERVATION_ACTIVE_IDLE:
		case RESERVATION_ACTIVE:
			gmp_queue_active(gmp_env, res);
			break;
	}
}

void gmp_add_new_reservation(
	struct gmp_reservation_environment* gmp_env,
	struct reservation* new_res)
{
	new_res->env = &gmp_env->env;
	list_add(&new_res->all_list, &gmp_env->all_reservations);
	gmp_queue_reservation(gmp_env, new_res);
}

#if BUDGET_ENFORCEMENT_AT_C
static void gmp_charge_budget(
	struct gmp_reservation_environment* gmp_env,
	lt_t delta)
{
	struct list_head *pos, *next;
	struct reservation *res;

	list_for_each_safe(pos, next, &gmp_env->active_reservations) {
		int drained = 0;
		/* charge all ACTIVE_IDLE up to the first ACTIVE reservation */
		res = list_entry(pos, struct reservation, list);
		if (res->state == RESERVATION_ACTIVE) {
			TRACE("gmp_charge_budget ACTIVE R%u scheduled_on=%d drain %llu\n", res->id, res->scheduled_on, delta);
			if (res->scheduled_on != NO_CPU) {
				TRACE("DRAIN !!\n");
				drained = 1;
				res->ops->drain_budget(res, delta);
			} else {
				TRACE("NO DRAIN (not scheduled)!!\n");
			}
		} else {
			//BUG_ON(res->state != RESERVATION_ACTIVE_IDLE);
			if (res->state != RESERVATION_ACTIVE_IDLE)
				TRACE("BUG!!!!!!!!!!!! gmp_charge_budget()\n");
			TRACE("gmp_charge_budget INACTIVE R%u drain %llu\n", res->id, delta);
			TRACE("DRAIN !!\n");
			drained = 1;
			res->ops->drain_budget(res, delta);
		}
		if ((res->state == RESERVATION_ACTIVE ||
			res->state == RESERVATION_ACTIVE_IDLE) && (drained == 1))
		{
			/* make sure scheduler is invoked when this reservation expires
			 * its remaining budget */
			 TRACE("requesting gmp_scheduler update for reservation %u in %llu nanoseconds\n", res->id, res->cur_budget);
			 gmp_add_event_after(gmp_env, res->cur_budget, res->id, EVENT_DRAIN);
			 res->event_added = 1;
		}
		//if (encountered_active == 2)
			/* stop at the first ACTIVE reservation */
		//	break;
	}
	//TRACE("finished charging budgets\n");
}
#else // No budget enforcement

static void gmp_charge_budget(
	struct gmp_reservation_environment* gmp_env,
	lt_t delta)
{
	return;
}

#endif

static void gmp_replenish_budgets(struct gmp_reservation_environment* gmp_env)
{
	struct list_head *pos, *next;
	struct reservation *res;

	list_for_each_safe(pos, next, &gmp_env->depleted_reservations) {
		res = list_entry(pos, struct reservation, list);
		if (res->next_replenishment <= gmp_env->env.current_time) {
			res->ops->replenish(res);
			TRACE("R%d replenished! scheduled_on=%d\n", res->id, res->scheduled_on);
		} else {
			/* list is ordered by increasing depletion times */
			break;
		}
	}
	//TRACE("finished replenishing budgets\n");
}

#define EPSILON	50

/* return schedule_now */
int gmp_update_time(
	struct gmp_reservation_environment* gmp_env,
	lt_t now)
{
	struct next_timer_event *event, *next;
	lt_t delta, ret;

	/* If the time didn't advance, there is nothing to do.
	 * This check makes it safe to call sup_advance_time() potentially
	 * multiple times (e.g., via different code paths. */
	//TRACE("(gmp_update_time) now: %llu, current_time: %llu\n", now, gmp_env->env.current_time);
	if (unlikely(now <= gmp_env->env.current_time + EPSILON))
		return 0;

	delta = now - gmp_env->env.current_time;
	gmp_env->env.current_time = now;


	//gmp_print_events(gmp_env, now);
	/* deplete budgets by passage of time */
	//TRACE("CHARGE###\n");
	gmp_charge_budget(gmp_env, delta);

	/* check if any budgets where replenished */
	//TRACE("REPLENISH###\n");
	gmp_replenish_budgets(gmp_env);


	list_for_each_entry_safe(event, next, &gmp_env->next_events, list) {
		if (event->next_update < now) {
			list_del(&event->list);
			//TRACE("EVENT at %llu IS DELETED\n", event->next_update);
			kfree(event);
		} else {
			break;
		}
	}

	//gmp_print_events(gmp_env, litmus_clock());

	ret = min(gmp_env->schedule_now, NR_CPUS);
	gmp_env->schedule_now = 0;

	return ret;
}

void gmp_print_events(struct gmp_reservation_environment* gmp_env, lt_t now)
{
	struct next_timer_event *event, *next;

	TRACE("GLOBAL EVENTS now=%llu\n", now);
	list_for_each_entry_safe(event, next, &gmp_env->next_events, list) {
		TRACE("at %llu type=%d id=%d armed_on=%d\n", event->next_update, event->type, event->id, event->timer_armed_on);
	}
}

static void gmp_res_change_state(
	struct reservation_environment* env,
	struct reservation *res,
	reservation_state_t new_state)
{
	struct gmp_reservation_environment* gmp_env;

	gmp_env = container_of(env, struct gmp_reservation_environment, env);

	TRACE("GMP reservation R%d state %d->%d at %llu\n",
		res->id, res->state, new_state, env->current_time);

	list_del(&res->list);
	/* check if we need to reschedule because we lost an active reservation */
	if (res->state == RESERVATION_ACTIVE)
		gmp_env->schedule_now++;
	res->state = new_state;
	gmp_queue_reservation(gmp_env, res);
}

void gmp_init(struct gmp_reservation_environment* gmp_env)
{
	memset(gmp_env, 0, sizeof(*gmp_env));

	INIT_LIST_HEAD(&gmp_env->all_reservations);
	INIT_LIST_HEAD(&gmp_env->active_reservations);
	INIT_LIST_HEAD(&gmp_env->depleted_reservations);
	INIT_LIST_HEAD(&gmp_env->inactive_reservations);
	INIT_LIST_HEAD(&gmp_env->next_events);

	gmp_env->env.change_state = gmp_res_change_state;

	gmp_env->schedule_now = 0;
	gmp_env->will_schedule = false;

	raw_spin_lock_init(&gmp_env->lock);
}

void destroy_reservation(struct reservation* res) {
	list_del(&res->list);
	list_del(&res->all_list);
	if (res->ops->shutdown)
		res->ops->shutdown(res);
	kfree(res);
}


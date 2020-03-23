#ifndef LITMUS_RESERVATION_H
#define LITMUS_RESERVATION_H

#include <linux/list.h>
#include <linux/hrtimer.h>

#include <litmus/debug_trace.h>
#include <litmus/reservations/budget-notifier.h>

struct reservation_client;
struct reservation_environment;
struct reservation;

typedef enum {
	/* reservation has no clients, is not consuming budget */
	RESERVATION_INACTIVE = 0,

	/* reservation has clients, consumes budget when scheduled */
	RESERVATION_ACTIVE,

	/* reservation has no clients, but may be consuming budget */
	RESERVATION_ACTIVE_IDLE,

	/* Reservation has no budget and waits for
	 * replenishment. May or may not have clients. */
	RESERVATION_DEPLETED,
} reservation_state_t;


/* ************************************************************************** */

/* Select which task to dispatch. If NULL is returned, it means there is nothing
 * to schedule right now and background work can be scheduled. */
typedef struct task_struct * (*dispatch_t)  (
	struct reservation_client *client
);

/* Something that can be managed in a reservation and that can yield
 * a process for dispatching. Contains a pointer to the reservation
 * to which it "belongs". */
struct reservation_client {
	struct list_head list;
	struct reservation* reservation;
	dispatch_t dispatch;
};


/* ************************************************************************** */

/* Called by reservations to request state change. */
typedef void (*reservation_change_state_t)  (
	struct reservation_environment* env,
	struct reservation *res,
	reservation_state_t new_state
);

/* Called by reservations to request replenishment while not DEPLETED.
 * Useful for soft reservations that remain ACTIVE with lower priority. */
typedef void (*request_replenishment_t)(
	struct reservation_environment* env,
	struct reservation *res
);

/* The framework within wich reservations operate. */
struct reservation_environment {
	lt_t time_zero;
	lt_t current_time;

	/* services invoked by reservations */
	reservation_change_state_t change_state;
	request_replenishment_t request_replenishment;
};

/* ************************************************************************** */

/* A new client is added or an existing client resumes. */
typedef void (*client_arrives_t)  (
	struct reservation *reservation,
	struct reservation_client *client
);

/* A client suspends or terminates. */
typedef void (*client_departs_t)  (
	struct reservation *reservation,
	struct reservation_client *client,
	int did_signal_job_completion
);

/* A previously requested replenishment has occurred. */
typedef void (*on_replenishment_timer_t)  (
	struct reservation *reservation
);

/* Update the reservation's budget to reflect execution or idling. */
typedef void (*drain_budget_t) (
	struct reservation *reservation,
	lt_t how_much
);

/* Select a ready task from one of the clients for scheduling. */
typedef struct task_struct* (*dispatch_client_t)  (
	struct reservation *reservation,
	lt_t *time_slice /* May be used to force rescheduling after
	                    some amount of time. 0 => no limit */
);

/* Destructor: called before scheduler is deactivated. */
typedef void (*shutdown_t)(struct reservation *reservation);

struct reservation_ops {
	dispatch_client_t dispatch_client;

	client_arrives_t client_arrives;
	client_departs_t client_departs;

	on_replenishment_timer_t replenish;
	drain_budget_t drain_budget;

	shutdown_t shutdown;
};

#define RESERVATION_BACKGROUND_PRIORITY ULLONG_MAX

struct reservation {
	/* used to queue in environment */
	struct list_head list;

	reservation_state_t state;
	unsigned int id;
	unsigned int kind;

	/* exact meaning defined by impl. */
	lt_t priority;
	lt_t cur_budget;
	lt_t next_replenishment;

	/* budget stats */
	lt_t budget_consumed; /* how much budget consumed in this allocation cycle? */
	lt_t budget_consumed_total;

	/* list of registered budget callbacks */
	struct budget_notifier_list budget_notifiers;

	/* for memory reclamation purposes */
	struct list_head all_list;

	/* interaction with framework */
	struct reservation_environment *env;
	struct reservation_ops *ops;

	struct list_head clients;

	/* for global env. */
	int scheduled_on;
	int event_added;
};

void reservation_init(struct reservation *res);

/* Default implementations */

/* simply select the first client in the list, set *for_at_most to zero */
struct task_struct* default_dispatch_client(
	struct reservation *res,
	lt_t *for_at_most
);

/* drain budget at linear rate, enter DEPLETED state when budget used up */
void common_drain_budget(struct reservation *res, lt_t how_much);

/* "connector" reservation client to hook up tasks with reservations */
struct task_client {
	struct reservation_client client;
	struct task_struct *task;
};

void task_client_init(struct task_client *tc, struct task_struct *task,
	struct reservation *reservation);

#define SUP_RESCHEDULE_NOW (0)
#define SUP_NO_SCHEDULER_UPDATE (ULLONG_MAX)

/* A simple uniprocessor (SUP) flat (i.e., non-hierarchical) reservation
 * environment.
 */
struct sup_reservation_environment {
	struct reservation_environment env;

	/* ordered by priority */
	struct list_head active_reservations;

	/* ordered by next_replenishment */
	struct list_head depleted_reservations;

	/* unordered */
	struct list_head inactive_reservations;

	/* list of all reservations */
	struct list_head all_reservations;

	/* - SUP_RESCHEDULE_NOW means call sup_dispatch() now
	 * - SUP_NO_SCHEDULER_UPDATE means nothing to do
	 * any other value means program a timer for the given time
	 */
	lt_t next_scheduler_update;
	/* set to true if a call to sup_dispatch() is imminent */
	bool will_schedule;
};

/* Contract:
 *  - before calling into sup_ code, or any reservation methods,
 *    update the time with sup_update_time(); and
 *  - after calling into sup_ code, or any reservation methods,
 *    check next_scheduler_update and program timer or trigger
 *    scheduler invocation accordingly.
 */

void sup_init(struct sup_reservation_environment* sup_env);
void sup_add_new_reservation(struct sup_reservation_environment* sup_env,
	struct reservation* new_res);
// We expose this as we need it in the MC^2 scheduler
void sup_scheduler_update_after(struct sup_reservation_environment* sup_env,
	lt_t timeout);
void sup_update_time(struct sup_reservation_environment* sup_env, lt_t now);
struct task_struct* sup_dispatch(struct sup_reservation_environment* sup_env);

struct reservation* sup_find_by_id(struct sup_reservation_environment* sup_env,
	unsigned int id);
void destroy_reservation(struct reservation* res);

/* A global multiprocessor (GMP) reservation environment. */

typedef enum {
	EVENT_REPLENISH = 0,
	EVENT_DRAIN,
} event_type_t;


struct next_timer_event {
	lt_t next_update;
	int timer_armed_on;
	unsigned int id;
	event_type_t type;
	struct list_head list;
};

struct gmp_reservation_environment {
	raw_spinlock_t lock;
	struct reservation_environment env;

	/* ordered by priority */
	struct list_head active_reservations;

	/* ordered by next_replenishment */
	struct list_head depleted_reservations;

	/* unordered */
	struct list_head inactive_reservations;

	/* list of all reservations */
	struct list_head all_reservations;

	/* timer event ordered by next_update */
	struct list_head next_events;

	/* (schedule_now == true) means call gmp_dispatch() now */
	int schedule_now;
	/* set to true if a call to gmp_dispatch() is imminent */
	bool will_schedule;
};

void gmp_init(struct gmp_reservation_environment* gmp_env);
void gmp_add_new_reservation(struct gmp_reservation_environment* gmp_env,
	struct reservation* new_res);
void gmp_add_event_after(struct gmp_reservation_environment* gmp_env,
	lt_t timeout, unsigned int id, event_type_t type);
void gmp_print_events(struct gmp_reservation_environment* gmp_env, lt_t now);
int gmp_update_time(struct gmp_reservation_environment* gmp_env, lt_t now);
struct task_struct* gmp_dispatch(struct gmp_reservation_environment* gmp_env);
struct next_timer_event* gmp_find_event_by_id(struct gmp_reservation_environment* gmp_env, unsigned int id);
struct reservation* gmp_find_by_id(struct gmp_reservation_environment* gmp_env,
	unsigned int id);

#endif

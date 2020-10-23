#ifndef LITMUS_EXT_RESERVATION_H
#define LITMUS_EXT_RESERVATION_H

#include <linux/list.h>
#include <linux/sched.h>

#include <litmus/rt_param.h>
#include <litmus/debug_trace.h>
#include <litmus/reservations/budget-notifier.h>

struct ext_reservation_environment;
struct ext_reservation;

int higher_res_prio(
	struct ext_reservation* first,
	struct ext_reservation* second
);

/* ************************************************************************** */
/* Reservation replenishes its budget. */
typedef void (*replenish_budget_t)  (
	struct ext_reservation *reservation,
	int cpu
);

/* Update the reservation's budget to reflect execution or idling. */
typedef void (*drain_budget_ext_t) (
	struct ext_reservation *reservation,
	lt_t how_much,
	int cpu
);

typedef struct task_struct* (*dispatch_client_ext_t) (
	struct ext_reservation *reservation,
	lt_t* time_slice,
	int cpu
);

/* When reservation is scheduled. */
typedef void (*on_schedule_t) (
	struct ext_reservation *reservation,
	int cpu
);

/* When reservation is preempted. */
typedef void (*on_preempt_t) (
	struct ext_reservation *reservation,
	int cpu
);

typedef int (*is_np_t) (
	struct ext_reservation *reservation,
	int cpu
);

/* Destructor: called before scheduler is deactivated. */
typedef void (*shutdown_ext_t)(
	struct ext_reservation *reservation
);

struct ext_reservation_ops {
	drain_budget_ext_t drain_budget;
	replenish_budget_t replenish_budget;
	dispatch_client_ext_t dispatch_client;
	on_schedule_t on_schedule;
	on_preempt_t on_preempt;
	is_np_t is_np;
	shutdown_ext_t shutdown;
};

struct ext_reservation {
	unsigned int id;

	/* exact meaning defined by impl. */
	lt_t priority;
	lt_t replenishment_time;
	lt_t cur_budget;
	lt_t max_budget;

	/* budget stats */
	lt_t budget_consumed; /* how much budget consumed in this allocation cycle? */
	lt_t budget_consumed_total;

	/* for memory reclamation purposes */
	struct list_head all_list;

	/* interaction with framework */
	struct ext_reservation_ops *ops;
	struct ext_reservation_environment* par_env;

	struct ext_reservation_environment* env;

	/* used to enqueue int rt_domain framework */
	struct bheap_node* heap_node;
	struct release_heap* rel_heap;

	struct list_head ln;
};

void init_ext_reservation(
	struct ext_reservation* res,
	unsigned int id,
	struct ext_reservation_ops* ops);

void clean_up_ext_reservation(struct ext_reservation* res);

/* ************************************************************************** */
typedef void (*env_update_time_t) (
	struct ext_reservation_environment* env,
	lt_t how_much,
	int cpu);

typedef struct task_struct* (*env_dispatch_t) (
	struct ext_reservation_environment* env,
	lt_t* time_slice,
	int cpu);

typedef void (*env_resume_t) (
	struct ext_reservation_environment* env,
	int cpu);

typedef void (*env_suspend_t) (
	struct ext_reservation_environment* env,
	int cpu);

typedef void (*env_add_res_t) (
	struct ext_reservation_environment* env,
	struct ext_reservation* res,
	int cpu);

typedef void (*env_remove_res_t) (
	struct ext_reservation_environment* env,
	struct ext_reservation* res,
	int complete,
	int cpu);

typedef struct ext_reservation* (*env_find_res_t) (
	struct ext_reservation_environment* env,
	int id);

typedef int (*env_is_np_t) (
	struct ext_reservation_environment* env,
	int cpu);

typedef void (*env_shutdown_t) (
	struct ext_reservation_environment* env);

struct ext_reservation_environment_ops {
	env_update_time_t	update_time;
	env_dispatch_t		dispatch;
	env_resume_t		resume;
	env_suspend_t		suspend;
	env_add_res_t		add_res;
	env_remove_res_t	remove_res;
	env_find_res_t		find_res_by_id;
	env_is_np_t			is_np;
	env_shutdown_t		shutdown;
};

struct ext_reservation_environment {
	struct ext_reservation_environment_ops* ops;
	struct ext_reservation* res;
	struct list_head all_reservations;
};

#endif

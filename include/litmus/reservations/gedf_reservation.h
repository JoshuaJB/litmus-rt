#ifndef LITMUS_GEDF_RESERVATION_H
#define LITMUS_GEDF_RESERVATION_H

#include <linux/hrtimer.h>

#include <litmus/bheap.h>
#include <litmus/rt_domain.h>
#include <litmus/reservations/ext_reservation.h>

/* ************************************************************************** */
struct gedf_reservation {
	struct ext_reservation res;
	struct gedf_cpu_entry* linked_on;
	int will_remove;
	int blocked;
};

struct gedf_cpu_entry {
	int id;
	struct bheap_node* hn;
	struct gedf_reservation* linked;
	struct gedf_reservation* scheduled;
};

struct gedf_task_reservation {
	struct gedf_reservation gedf_res;
	struct task_struct* task;
};

struct gedf_container_reservation {
	struct gedf_reservation gedf_res;
	lt_t max_budget;
	lt_t period;
	lt_t relative_deadline;
};

long alloc_gedf_container_reservation(
	struct gedf_container_reservation** _res,
	int id,
	lt_t max_budget,
	lt_t period,
	lt_t relative_deadline
);

long alloc_gedf_task_reservation(
	struct gedf_task_reservation** _res,
	struct task_struct* task,
	lt_t max_budget
);

/* environment for scheduling reservations via gedf */
struct gedf_reservation_environment {
	struct ext_reservation_environment env;

	/* list of all reservations scheduled by environment */
	struct list_head all_reservations;

	/* number of active cpus in reservation */
	volatile int num_cpus;

	/* array of gedf cpu entries */
	struct gedf_cpu_entry* cpu_entries;

	/* used to order cpus for gedf purposes */
	struct bheap cpu_heap;
	struct bheap_node* cpu_node;

	rt_domain_t domain;
};

long alloc_gedf_reservation_environment(
	struct gedf_reservation_environment** _env,
	int max_cpus
);

#endif

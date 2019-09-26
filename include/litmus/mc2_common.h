/*
 * MC^2 common data structures
 */

#ifndef __UNC_MC2_COMMON_H__
#define __UNC_MC2_COMMON_H__

enum crit_level {
	CRIT_LEVEL_A = 0,
	CRIT_LEVEL_B = 1,
	CRIT_LEVEL_C = 2,
	NUM_CRIT_LEVELS = 3,
};

struct mc2_task {
	enum crit_level crit;
	unsigned int res_id;
};

#ifdef __KERNEL__

#include <litmus/reservation.h>

#define tsk_mc2_data(t)		(tsk_rt(t)->mc2_data)

long mc2_task_client_init(struct task_client *tc, struct mc2_task *mc2_param, struct task_struct *tsk,
							struct reservation *res);

#endif /* __KERNEL__ */

#endif

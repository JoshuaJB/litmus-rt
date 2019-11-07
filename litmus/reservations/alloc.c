#include <linux/slab.h>
#include <asm/uaccess.h>

#include <litmus/rt_param.h>

#include <litmus/reservations/alloc.h>
#include <litmus/reservations/polling.h>
#include <litmus/reservations/table-driven.h>


long alloc_polling_reservation(
	int res_type,
	struct reservation_config *config,
	struct reservation **_res)
{
	struct polling_reservation *pres;
	int use_edf  = config->priority == LITMUS_NO_PRIORITY;
	int periodic =  res_type == PERIODIC_POLLING;

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

	/* XXX: would be nice to use a core-local allocation. */
	pres = kzalloc(sizeof(*pres), GFP_KERNEL);
	if (!pres)
		return -ENOMEM;

	polling_reservation_init(pres, use_edf, periodic,
		config->polling_params.budget,
		config->polling_params.period,
		config->polling_params.relative_deadline,
		config->polling_params.offset);
	pres->res.id = config->id;
	pres->res.blocked_by_ghost = 0;
	pres->res.is_ghost = 0xffffffff;//NO_CPU;
	if (!use_edf)
		pres->res.priority = config->priority;

	*_res = &pres->res;
	return 0;
}

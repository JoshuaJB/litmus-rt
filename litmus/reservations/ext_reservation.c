#include <linux/mm.h>
#include <litmus/litmus.h>
#include <litmus/bheap.h>
#include <litmus/rt_domain.h>
#include <litmus/reservations/ext_reservation.h>

struct release_heap* release_heap_alloc(int gfp_flags);
void release_heap_free(struct release_heap* rh);

int higher_res_prio(struct ext_reservation* first,
		    struct ext_reservation* second)
{
	struct ext_reservation *first_task = first;
	struct ext_reservation *second_task = second;

	/* There is no point in comparing a reservation to itself. */
	if (first && first == second) {
		return 0;
	}

	/* check for NULL reservations */
	if (!first || !second)
		return first && !second;

	if (first_task->priority > second_task->priority) {
		return 1;
	}
	else if (first_task->priority == second_task->priority) {
		/* Tie break by pid */
		if (first_task->id < second_task->id) {
			return 1;
		}
	}
	return 0; /* fall-through. prio(second_task) > prio(first_task) */
}

void init_ext_reservation(
	struct ext_reservation* res,
	unsigned int id,
	struct ext_reservation_ops* ops)
{
	res->id = id;
	res->ops = ops;
	res->heap_node = bheap_node_alloc(GFP_ATOMIC);
	res->rel_heap = release_heap_alloc(GFP_ATOMIC);
	bheap_node_init(&res->heap_node, res);
	INIT_LIST_HEAD(&res->ln);
	INIT_LIST_HEAD(&res->all_list);
}

void clean_up_ext_reservation(struct ext_reservation* res)
{
	bheap_node_free(res->heap_node);
	release_heap_free(res->rel_heap);
}

#ifndef __CPT2_TASK_H__
#define __CPT2_TASK_H__

#include <stdbool.h>

#include "cpt-image.h"
#include "context.h"
#include "list.h"

struct task_struct {
	struct hlist_node	hash;
	struct task_struct	*parent;

	struct list_head	list;
	struct list_head	children;
	struct list_head	threads;
	unsigned int		n_threads;

	struct cpt_task_image	ti;
};

extern int read_tasks(context_t *ctx);
extern void free_tasks(context_t *ctx);

extern struct task_struct *root_task;

#endif /* __CPT2_TASK_H__ */

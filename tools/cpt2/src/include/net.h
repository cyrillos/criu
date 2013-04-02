#ifndef __CPT2_NET_H__
#define __CPT2_NET_H__

#include <stdbool.h>

#include "cpt-image.h"
#include "context.h"
#include "types.h"
#include "list.h"

struct task_struct;

struct sock_struct {
	struct hlist_node	hash;

	struct cpt_sock_image	si;
};

extern int read_sockets(context_t *ctx);
extern void free_sockets(context_t *ctx);
extern struct sock_struct *sk_lookup_file(u64 cpt_file);

extern int write_task_route(context_t *ctx, struct task_struct *t);

#endif /* __CPT2_NET_H__ */

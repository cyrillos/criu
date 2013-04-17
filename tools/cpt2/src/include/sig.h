#ifndef __CPT2_SIG_H__
#define __CPT2_SIG_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compiler.h"
#include "context.h"
#include "task.h"
#include "obj.h"

#define SIGMAX 64

struct sighand_struct {
	struct cpt_sighand_image	si;
	unsigned int			nr_signals;

	struct cpt_sighandler_image	sig[SIGMAX];
};

extern void free_sighandlers(context_t *ctx);
extern int read_sighand(context_t *ctx);
extern int write_sighandlers(context_t *ctx, struct task_struct *t);

#endif /* __CPT2_SIG_H__ */

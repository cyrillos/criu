#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>

#include "cpt-image.h"
#include "xmalloc.h"
#include "image.h"
#include "read.h"
#include "log.h"
#include "obj.h"
#include "bug.h"
#include "sig.h"

#include "protobuf.h"
#include "../../../protobuf/sa.pb-c.h"

int write_sighandlers(context_t *ctx, struct task_struct *t)
{
	struct sighand_struct *s;
	int ret = -1, fd = -1;
	unsigned int i;
	SaEntry e;

	s = obj_lookup_to(CPT_OBJ_SIGHAND_STRUCT, t->ti.cpt_sighand);
	if (!s) {
		pr_err("No sighandler found at @%li for task %d\n",
			(long)t->ti.cpt_sighand, t->ti.cpt_pid);
		goto err;
	}

	fd = open_image(ctx, CR_FD_SIGACT, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		goto err;

	for (i = 0; i < ARRAY_SIZE(s->sig); i++) {
		sa_entry__init(&e);

		if (s->sig[i].cpt_handler || s->sig[i].cpt_restorer) {
			e.sigaction	= s->sig[i].cpt_handler;
			e.restorer	= s->sig[i].cpt_restorer;
			e.flags		= s->sig[i].cpt_flags;
			e.mask		= s->sig[i].cpt_flags;
		}

		if (pb_write_one(fd, &e, PB_SIGACT) < 0)
			goto err;
	}

	ret = 0;

err:
	close_safe(&fd);
	return ret;
}

void free_sighandlers(context_t *ctx)
{
	struct sighand_struct *s;

	while ((s = obj_pop_unhash_to(CPT_OBJ_SIGHAND_STRUCT)))
		obj_free_to(s);
}

static void show_sighand_cont(context_t *ctx, struct sighand_struct *s)
{
	unsigned int i;

	pr_debug("\t@%-8li nr-signals %d\n",
		(long)obj_of(s)->o_pos, s->nr_signals);

	for (i = 0; i < ARRAY_SIZE(s->sig); i++) {
		if (!s->sig[i].cpt_handler && !s->sig[i].cpt_restorer)
			continue;
		pr_debug("\t\t%3d: %#-16lx %#-16lx %#-16lx %#-16lx\n",
			s->sig[i].cpt_signo,
			(long)s->sig[i].cpt_handler,
			(long)s->sig[i].cpt_restorer,
			(long)s->sig[i].cpt_flags,
			(long)s->sig[i].cpt_mask);
	}
}

static int read_sighandlers(context_t *ctx, struct sighand_struct *s,
			    off_t start, off_t end)
{
	int ret = -1;

	while (start < end) {
		struct cpt_sighandler_image si;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_SIGHANDLER, &si, start)) {
			pr_err("Can't read sighandler struct at @%li\n", (long)start);
			goto err;
		}

		if (si.cpt_signo >= SIGMAX) {
			pr_err("Unexpected signal number %d at @%li\n",
			       si.cpt_signo, (long)start);
			goto err;
		}

		if (s->sig[si.cpt_signo].cpt_handler == 0)
			s->nr_signals++;

		s->sig[si.cpt_signo] = si;

		start += si.cpt_next;
	}
	ret = 0;
err:
	return ret;
}

int read_sighand(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_debug("Signal handlers\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_SIGHAND_STRUCT, &start, &end);

	while (start < end) {
		struct sighand_struct *s;

		s = obj_alloc_to(struct sighand_struct, si);
		if (!s)
			goto err;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_SIGHAND_STRUCT, &s->si, start)) {
			obj_free_to(s);
			pr_err("Can't read sighand struct at @%li\n", (long)start);
			goto err;
		}

		/*
		 * Init to zero means here two things:
		 *
		 * - it indeed zero all date thus we don't
		 *   have any heap trash in
		 *
		 * - zero entry means default signal handler,
		 *   note the handlers in image are optional
		 */
		memzero(s->sig, sizeof(s->sig));
		s->nr_signals = 0;

		if (s->si.cpt_next > s->si.cpt_hdrlen) {
			if (read_sighandlers(ctx, s,
					     start + s->si.cpt_hdrlen,
					     start + s->si.cpt_next)) {
				obj_free_to(s);
				pr_err("Can't read sighandlers at @%li\n", (long)start);
				goto err;
			}
		}

		obj_push_hash_to(s, CPT_OBJ_SIGHAND_STRUCT, start);
		show_sighand_cont(ctx, s);
		start += s->si.cpt_next;
	}

	pr_debug("------------------------------\n\n");

	ret = 0;
err:
	return ret;
}

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <linux/futex.h>

#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "image.h"
#include "files.h"
#include "read.h"
#include "task.h"
#include "log.h"
#include "obj.h"
#include "bug.h"
#include "mm.h"
#include "ns.h"

#include "protobuf.h"
#include "../../../protobuf/pstree.pb-c.h"

static unsigned int max_threads;
static LIST_HEAD(task_list);
struct task_struct *root_task;

#define PID_HASH_BITS		10
static DEFINE_HASHTABLE(pids_hash, PID_HASH_BITS);

struct task_struct *task_lookup_pid(u32 pid)
{
	struct task_struct *task;

	hash_for_each_key(pids_hash, task, hash, pid) {
		if (task->ti.cpt_pid == pid)
			return task;
	}

	return NULL;
}

static int __write_task_images(context_t *ctx, struct task_struct *t)
{
	int ret;

	ret = write_task_files(ctx, t);
	if (ret) {
		pr_err("Failed writing fdinfo for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_mm(ctx, t->ti.cpt_pid, t->ti.cpt_mm);
	if (ret) {
		pr_err("Failed writing mm for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_vmas(ctx, t->ti.cpt_pid, t->ti.cpt_mm);
	if (ret) {
		pr_err("Failed writing vmas for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_pages(ctx, t->ti.cpt_pid, t->ti.cpt_mm);
	if (ret) {
		pr_err("Failed writing vmas for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_fs(ctx, t);
	if (ret) {
		pr_err("Failed writing fs for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_mountpoints(ctx, t);
	if (ret) {
		pr_err("Failed writing mountpoints for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

out:
	return ret;
}

int write_task_images(context_t *ctx)
{
	struct task_struct *child, *task;
	int ret = 0;

	list_for_each_entry(task, &task_list, list) {
		ret = __write_task_images(ctx, task);
		if (ret)
			goto out;
		list_for_each_entry(child, &task->children, list) {
			ret = __write_task_images(ctx, child);
			if (ret)
				goto out;
		}
	}
out:
	return ret;
}

static int __write_pstree_items(int fd, struct task_struct *t,
				PstreeEntry *e, void *threads_buf,
				unsigned int nr_max)
{
	struct task_struct *thread;
	unsigned int i = 0;
	int ret = 0;

	pstree_entry__init(e);

	e->pid		= t->ti.cpt_pid;
	e->ppid		= t->ti.cpt_ppid;
	e->pgid		= t->ti.cpt_pgrp;
	e->sid		= t->ti.cpt_session;
	e->threads	= threads_buf;
	e->n_threads	= t->n_threads + 1;

	e->threads[i++] = t->ti.cpt_pid;

	list_for_each_entry(thread, &t->threads, list) {
		BUG_ON(i >= nr_max);
		e->threads[i++] = thread->ti.cpt_pid;
	}

	ret = pb_write_one(fd, e, PB_PSTREE);
	if (!ret) {
		struct task_struct *child;

		list_for_each_entry(child, &t->children, list) {
			ret = __write_pstree_items(fd, child, e,
						   threads_buf, nr_max);
			if (ret)
				break;
		}
	}

	return ret;
}

int write_pstree(context_t *ctx)
{
	struct task_struct *task;
	int pstree_fd = -1, ret = 0;
	PstreeEntry e;
	void *threads;

	threads = xmalloc(sizeof(e.threads[0]) * (max_threads + 1));
	if (!threads)
		return -1;

	pstree_fd = open_image(ctx, CR_FD_PSTREE, O_DUMP);
	if (pstree_fd < 0) {
		ret = -1;
		goto out;
	}

	list_for_each_entry(task, &task_list, list) {
		ret = __write_pstree_items(pstree_fd, task, &e,
					   threads, max_threads);
		if (ret)
			break;
	}

out:
	close_safe(&pstree_fd);
	xfree(threads);
	return ret;
}

static void connect_task(struct task_struct *task)
{
	struct task_struct *t;

	/*
	 * We don't care if there is some of PIDs
	 * are screwed, the crtools will refuse to
	 * restore if someone pass us coeeupted data.
	 *
	 * Thus we only collect threads and children.
	 */
	t = task_lookup_pid(task->ti.cpt_ppid);
	if (t) {
		task->parent = t;
		list_move(&task->list, &t->children);
		return;
	}

	t = task_lookup_pid(task->ti.cpt_rppid);
	if (t) {
		list_move(&task->list, &t->threads);
		t->n_threads++;

		if (max_threads < t->n_threads)
			max_threads = t->n_threads;
		return;
	}
}

void free_tasks(context_t *ctx)
{
	struct task_struct *task;

	while ((task = obj_pop_unhash_to(CPT_OBJ_TASK)))
		obj_free_to(task);
}

static void show_task_cont(context_t *ctx, struct task_struct *t)
{
	struct cpt_task_image *ti = &t->ti;

	pr_debug("\t@%-8li pid %6d tgid %6d ppid %6d rppid %6d pgrp %6d\n"
		 "\t\tcomm '%s' session %d leader %d 64bit %d\n"
		 "\t\tmm @%-8ld files @%-8ld fs @%-8ld signal @%-8ld\n",
		 (long)obj_of(t)->o_pos, ti->cpt_pid, ti->cpt_tgid, ti->cpt_ppid,
		 ti->cpt_rppid, ti->cpt_pgrp, ti->cpt_comm, ti->cpt_session,
		 ti->cpt_leader,ti->cpt_64bit, (long)ti->cpt_mm,
		 (long)ti->cpt_files, (long)ti->cpt_fs, (long)ti->cpt_signal);
}

int read_tasks(context_t *ctx)
{
	struct task_struct *task, *tmp;
	off_t start, end;

	pr_debug("Tasks\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_TASKS, &start, &end);

	while (start < end) {
		task = obj_alloc_to(struct task_struct, ti);
		if (!task)
			return -1;
		INIT_LIST_HEAD(&task->list);
		INIT_LIST_HEAD(&task->children);
		INIT_LIST_HEAD(&task->threads);
		task->n_threads = 0;
		task->parent = NULL;

		if (read_obj(ctx->fd, CPT_OBJ_TASK, &task->ti, sizeof(task->ti), start)) {
			obj_free_to(task);
			pr_err("Can't read task object at %li\n", (long)start);
			return -1;
		}

		hash_add(pids_hash, &task->hash, task->ti.cpt_pid);
		list_add_tail(&task->list, &task_list);

		obj_push_hash_to(task, CPT_OBJ_TASK, start);

		if (likely(root_task)) {
			if (root_task->ti.cpt_pid > task->ti.cpt_pid)
				root_task = task;
		} else
			root_task = task;

		start += task->ti.cpt_next;
		show_task_cont(ctx, task);
	}
	pr_debug("------------------------------\n\n");

	/*
	 * Create a process tree we will need to dump.
	 * Because in CRIU protobuf task file there is
	 * a set of threads associated with every task,
	 * we've had to collect all tasks first then
	 * build a process tree.
	 */
	list_for_each_entry_safe(task, tmp, &task_list, list)
		connect_task(task);

	return 0;
}

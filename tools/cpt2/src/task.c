#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <linux/futex.h>

#include "asm/fpu.h"

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
#include "net.h"
#include "sig.h"
#include "mm.h"
#include "ns.h"

#include "protobuf.h"
#include "../../../protobuf/pstree.pb-c.h"
#include "../../../protobuf/itimer.pb-c.h"
#include "../../../protobuf/creds.pb-c.h"
#include "../../../protobuf/core.pb-c.h"
#include "../../../protobuf/sa.pb-c.h"

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

static u32 decode_segment(u32 segno)
{
	if (segno == CPT_SEG_ZERO)
		return 0;

	if (segno <= CPT_SEG_TLS3)
		return ((GDT_ENTRY_TLS_MIN + segno - CPT_SEG_TLS1) << 3) + 3;

	if (segno >= CPT_SEG_LDT)
		return ((segno - CPT_SEG_LDT) << 3) | 7;

	if (segno == CPT_SEG_USER32_DS)
		return __USER32_DS;
	if (segno == CPT_SEG_USER32_CS)
		return __USER32_CS;
	if (segno == CPT_SEG_USER64_DS)
		return __USER_DS;
	if (segno == CPT_SEG_USER64_CS)
		return __USER_CS;

	pr_err("Invalid segment register %d\n", segno);
	return 0;
}

static int read_core_data(context_t *ctx, struct task_struct *t, CoreEntry *core)
{
	union {
		struct cpt_object_hdr		h;
		struct cpt_obj_bits		bits;
		struct cpt_x86_64_regs		regs;
		struct cpt_task_aux_image	aux;
		struct cpt_signal_image		sig;
	} u;

	struct xsave_struct xsave;

	off_t start;
	int ret = -1;

#define __copy_fpu_state()								\
	do {										\
		core->thread_info->fpregs->cwd		= xsave.i387.cwd;		\
		core->thread_info->fpregs->swd		= xsave.i387.swd;		\
		core->thread_info->fpregs->twd		= xsave.i387.twd;		\
		core->thread_info->fpregs->fop		= xsave.i387.fop;		\
		core->thread_info->fpregs->rip		= xsave.i387.rip;		\
		core->thread_info->fpregs->rdp		= xsave.i387.rdp;		\
		core->thread_info->fpregs->mxcsr	= xsave.i387.mxcsr;		\
		core->thread_info->fpregs->mxcsr_mask	= xsave.i387.mxcsr_mask;	\
											\
		memcpy(core->thread_info->fpregs->st_space,				\
		       xsave.i387.st_space, sizeof(xsave.i387.st_space));		\
		memcpy(core->thread_info->fpregs->xmm_space,				\
		       xsave.i387.xmm_space, sizeof(xsave.i387.xmm_space));		\
	} while (0)

	for (start = obj_of(t)->o_pos + t->ti.cpt_hdrlen;
	     start < obj_of(t)->o_pos + t->ti.cpt_next;
	     start += u.h.cpt_next) {
		if (read_obj_cpt(ctx->fd, -1, &u.h, start)) {
			pr_err("Can't read task data header at %li\n", (long)start);
			goto out;
		}

		if (u.h.cpt_object == CPT_OBJ_BITS) {
			if (read_obj_cpt_cont(ctx->fd, &u.bits)) {
				pr_err("Can't read bits at %li\n", (long)start);
				goto out;
			}
			switch (u.h.cpt_content) {
			case CPT_CONTENT_STACK:
				/* skip it */
				continue;
			case CPT_CONTENT_X86_FPUSTATE:
				if (u.bits.cpt_size != sizeof(xsave.i387)) {
					pr_err("Inconsistent fxsave frame "
					       "size %d(%d) at %li\n",
					       (int)u.bits.cpt_size, (int)sizeof(xsave.i387),
					       (long)start);
					goto out;
				}
				if (read_data(ctx->fd, &xsave.i387, sizeof(xsave.i387), false)) {
					pr_err("Can't read bits at %li\n", (long)start);
					goto out;
				}

				__copy_fpu_state();

				/*
				 * Don't forget to drop xsave frame, it can't be
				 * two frames in one pass.
				 */
				core->thread_info->fpregs->xsave = NULL;

				break;
			case CPT_CONTENT_X86_XSAVE:
				if (!core->thread_info->fpregs->xsave) {
					pr_err("Dump corrupted, two FPU frames detected "
					       "while only one is allowed at %li\n", (long)start);
					goto out;
				}
				if (u.bits.cpt_size != sizeof(xsave)) {
					pr_err("Inconsistent xsave frame "
					       "size %d(%d) at %li\n",
					       (int)u.bits.cpt_size, (int)sizeof(xsave),
					       (long)start);
					goto out;
				}
				if (read_data(ctx->fd, &xsave, sizeof(xsave), false)) {
					pr_err("Can't read bits at %li\n", (long)start);
					goto out;
				}

				__copy_fpu_state();

				core->thread_info->fpregs->xsave->xstate_bv = xsave.xsave_hdr.xstate_bv;

				memcpy(core->thread_info->fpregs->xsave->ymmh_space,
				       xsave.ymmh.ymmh_space, sizeof(xsave.ymmh.ymmh_space));

				break;
			default:
				goto unknown_obj;
			}
		} else if (u.h.cpt_object == CPT_OBJ_X86_64_REGS) {
			if (read_obj_cpt_cont(ctx->fd, &u.regs)) {
				pr_err("Can't read task registers at %li\n", (long)start);
				goto out;
			}

			core->thread_info->gpregs->r15		= u.regs.cpt_r15;
			core->thread_info->gpregs->r14		= u.regs.cpt_r14;
			core->thread_info->gpregs->r13		= u.regs.cpt_r13;
			core->thread_info->gpregs->r12		= u.regs.cpt_r12;
			core->thread_info->gpregs->bp		= u.regs.cpt_rbp;
			core->thread_info->gpregs->bx		= u.regs.cpt_rbx;
			core->thread_info->gpregs->r11		= u.regs.cpt_r11;
			core->thread_info->gpregs->r10		= u.regs.cpt_r10;
			core->thread_info->gpregs->r9		= u.regs.cpt_r9;
			core->thread_info->gpregs->r8		= u.regs.cpt_r8;
			core->thread_info->gpregs->ax		= u.regs.cpt_rax;
			core->thread_info->gpregs->cx		= u.regs.cpt_rcx;
			core->thread_info->gpregs->dx		= u.regs.cpt_rdx;
			core->thread_info->gpregs->si		= u.regs.cpt_rsi;
			core->thread_info->gpregs->di		= u.regs.cpt_rdi;
			core->thread_info->gpregs->orig_ax	= u.regs.cpt_orig_rax;
			core->thread_info->gpregs->ip		= u.regs.cpt_rip;
			core->thread_info->gpregs->cs		= decode_segment(u.regs.cpt_cs);
			core->thread_info->gpregs->flags	= u.regs.cpt_eflags;
			core->thread_info->gpregs->sp		= u.regs.cpt_rsp;
			core->thread_info->gpregs->ss		= decode_segment(u.regs.cpt_ss);
			core->thread_info->gpregs->fs_base	= u.regs.cpt_fsbase;
			core->thread_info->gpregs->gs_base	= u.regs.cpt_gsbase;
			core->thread_info->gpregs->ds		= decode_segment(u.regs.cpt_ds);
			core->thread_info->gpregs->es		= decode_segment(u.regs.cpt_es);
			core->thread_info->gpregs->fs		= decode_segment(u.regs.cpt_fsindex);
			core->thread_info->gpregs->gs		= decode_segment(u.regs.cpt_gsindex);

		} else if (u.h.cpt_object == CPT_OBJ_TASK_AUX) {
			if (read_obj_cpt_cont(ctx->fd, &u.aux)) {
				pr_err("Can't read task aux data at %li\n", (long)start);
				goto out;
			}
			/* See note at FUTEX_RLA_LEN definition */
			core->thread_core->futex_rla		= u.aux.cpt_robust_list;
			core->thread_core->futex_rla_len	= FUTEX_RLA_LEN;
		} else if (u.h.cpt_object == CPT_OBJ_SIGNAL_STRUCT)
			continue;
		else
			goto unknown_obj;
	}
	ret = 0;
out:
	return ret;

unknown_obj:
	pr_err("Unexpected object %d at %li\n",
	       u.h.cpt_object, (long)start);
	goto out;

#undef __copy_fpu_state
}

/*
 * No threads yet.
 */
static int write_task_core(context_t *ctx, struct task_struct *t)
{
	ThreadCoreEntry thread_core = THREAD_CORE_ENTRY__INIT;
	ThreadInfoX86 thread_info = THREAD_INFO_X86__INIT;
	TaskCoreEntry tc = TASK_CORE_ENTRY__INIT;
	CoreEntry core = CORE_ENTRY__INIT;

	UserX86RegsEntry gpregs = USER_X86_REGS_ENTRY__INIT;
	UserX86FpregsEntry fpregs = USER_X86_FPREGS_ENTRY__INIT;
	UserX86XsaveEntry xsave = USER_X86_XSAVE_ENTRY__INIT;

	struct xsave_struct x;

	int core_fd = -1, ret = -1;

	core_fd = open_image(ctx, CR_FD_CORE, O_DUMP, t->ti.cpt_pid);
	if (core_fd < 0)
		return -1;

	/*
	 * Bind core topology, the callee may maodify it so don't
	 * assume it's immutable.
	 */
	core.mtype			= CORE_ENTRY__MARCH__X86_64;
	core.thread_info		= &thread_info;
	core.tc				= &tc;

	core.thread_core		= &thread_core;

	thread_info.gpregs		= &gpregs;
	thread_info.fpregs		= &fpregs;

	BUILD_BUG_ON(sizeof(x.i387.st_space[0]) != sizeof(fpregs.st_space[0]));
	BUILD_BUG_ON(sizeof(x.i387.xmm_space[0]) != sizeof(fpregs.xmm_space[0]));
	BUILD_BUG_ON(sizeof(x.ymmh.ymmh_space[0]) != sizeof(xsave.ymmh_space[0]));

	xsave.n_ymmh_space		= ARRAY_SIZE(x.ymmh.ymmh_space);
	xsave.ymmh_space		= x.ymmh.ymmh_space;

	fpregs.xsave			= &xsave;

	fpregs.n_st_space		= ARRAY_SIZE(x.i387.st_space);
	fpregs.st_space			= x.i387.st_space;
	fpregs.n_xmm_space		= ARRAY_SIZE(x.i387.xmm_space);
	fpregs.xmm_space		= x.i387.xmm_space;

	if (read_core_data(ctx, t, &core)) {
		pr_err("Failed to read core data for task %d\n",
		       t->ti.cpt_pid);
			goto out;
	}

	/*
	 * FIXME For a while set it as TASK_ALIVE
	 */

	/* tc.task_state			= t->ti.cpt_state; */
	tc.task_state			= 1;
	tc.exit_code			= t->ti.cpt_exit_code;
	tc.personality			= t->ti.cpt_personality;
	tc.flags			= t->ti.cpt_flags;
	tc.blk_sigset			= t->ti.cpt_sigrblocked;
	tc.comm				= (char *)t->ti.cpt_comm;

	ret = pb_write_one(core_fd, &core, PB_CORE);

#if 0
	/*
	 * FIXME No sched entries in image yet.
	 */
	thread_core.sched_nice		= 0;
	thread_core.sched_policy	= 0;
	thread_core.sched_prio		= 0;
#endif
out:
	close_safe(&core_fd);
	return ret;
}

static int write_task_kids(context_t *ctx, struct task_struct *t)
{
	TaskKobjIdsEntry kids = TASK_KOBJ_IDS_ENTRY__INIT;
	int fd, ret = -1;
	obj_t *obj;

	fd = open_image(ctx, CR_FD_IDS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	/*
	 * FIXME In crtools we use 32 bit kids, while
	 * openvz is using 64 bit ones.
	 */

	obj = obj_hash_lookup(CPT_OBJ_MM, t->ti.cpt_mm);
	if (!obj) {
		pr_err("Can't find mm at @%li\n", (long)t->ti.cpt_mm);
		goto out;
	}
	kids.vm_id	= t->ti.cpt_mm;

	obj = obj_hash_lookup(CPT_OBJ_FILES, t->ti.cpt_files);
	if (!obj) {
		pr_err("Can't find files at @%li\n", (long)t->ti.cpt_files);
		goto out;
	}
	kids.files_id		= t->ti.cpt_files;

	kids.fs_id		= t->ti.cpt_fs;
	kids.sighand_id		= t->ti.cpt_sighand;

	kids.has_pid_ns_id	= true;
	kids.has_net_ns_id	= true;
	kids.has_ipc_ns_id	= true;
	kids.has_uts_ns_id	= true;
	kids.has_mnt_ns_id	= true;

	/*
	 * FIXME See write_inventory() routine.
	 * There IDs are taken for debug purpose
	 * only!
	 */

	kids.pid_ns_id		= 1;
	kids.net_ns_id		= 2;
	kids.ipc_ns_id		= 2;
	kids.uts_ns_id		= 2;
	kids.mnt_ns_id		= 2;
	kids.mnt_ns_id		= t->ti.cpt_namespace;

	ret = pb_write_one(fd, &kids, PB_IDS);
out:
	close(fd);
	return ret;
}

static int write_task_itimers(context_t *ctx, struct task_struct *t)
{
	int ret = 0, fd = -1;
	ItimerEntry ie;

	fd = open_image(ctx, CR_FD_ITIMERS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	/*
	 * FIXME
	 *
	 * No real data yet
	 */

	/* real */
	itimer_entry__init(&ie);
	ret = pb_write_one(fd, &ie, PB_ITIMERS);
	if (ret)
		goto err;

	/* virt */
	itimer_entry__init(&ie);
	ret = pb_write_one(fd, &ie, PB_ITIMERS);
	if (ret)
		goto err;

	/* prof */
	itimer_entry__init(&ie);
	ret = pb_write_one(fd, &ie, PB_ITIMERS);
	if (ret)
		goto err;
err:
	close_safe(&fd);
	return ret;
}

static int write_task_creds(context_t *ctx, struct task_struct *t)
{
	CredsEntry ce = CREDS_ENTRY__INIT;
	int ret = 0, fd = -1;
	u64 bset = ~0;

	fd = open_image(ctx, CR_FD_CREDS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	ce.uid		= t->ti.cpt_uid;
	ce.gid		= t->ti.cpt_gid;
	ce.euid		= t->ti.cpt_euid;
	ce.egid		= t->ti.cpt_egid;
	ce.suid		= t->ti.cpt_suid;
	ce.sgid		= t->ti.cpt_sgid;
	ce.fsuid	= t->ti.cpt_fsuid;
	ce.fsgid	= t->ti.cpt_fsgid;

	ce.n_cap_inh	= sizeof(t->ti.cpt_icap) / sizeof(ce.cap_inh[0]);
	ce.cap_inh	= (u32 *)&t->ti.cpt_icap;

	ce.n_cap_prm	= sizeof(t->ti.cpt_pcap) / sizeof(ce.cap_prm[0]);
	ce.cap_prm	= (u32 *)&t->ti.cpt_pcap;

	ce.n_cap_eff	= sizeof(t->ti.cpt_ecap) / sizeof(ce.cap_eff[0]);
	ce.cap_eff	= (u32 *)&t->ti.cpt_ecap;

	/*
	 * FIXME bset is container wide, yet not found where.
	 */
	ce.n_cap_bnd	= sizeof(bset) / sizeof(ce.cap_bnd[0]);
	ce.cap_bnd	= (u32 *)&bset;

	ce.secbits	= t->ti.cpt_keepcap;

	ce.n_groups	= t->ti.cpt_ngids;
	ce.groups	= t->ti.cpt_gids;

	ret = pb_write_one(fd, &ce, PB_CREDS);

	close_safe(&fd);
	return ret;
}

static int write_task_utsns(context_t *ctx, struct task_struct *t)
{
	int ret = 0;
	int fd = -1;

	fd = open_image(ctx, CR_FD_UTSNS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;
	goto out;
out:
	close_safe(&fd);
	return ret;
}

static int write_task_ipc(context_t *ctx, struct task_struct *t)
{
	int ret = -1;
	int fd_ipc_var = -1, fd_ipc_shm = -1;
	int fd_ipc_msg = -1, fd_ipc_sem = -1;

	fd_ipc_var = open_image(ctx, CR_FD_IPCNS_VAR, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_var < 0)
		goto out;
	fd_ipc_shm = open_image(ctx, CR_FD_IPCNS_SHM, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_shm < 0)
		goto out;
	fd_ipc_msg = open_image(ctx, CR_FD_IPCNS_MSG, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_msg < 0)
		goto out;
	fd_ipc_sem = open_image(ctx, CR_FD_IPCNS_SEM, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_sem < 0)
		goto out;
	ret = 0;
out:
	close_safe(&fd_ipc_var);
	close_safe(&fd_ipc_shm);
	close_safe(&fd_ipc_msg);
	close_safe(&fd_ipc_sem);
	return ret;
}


static int write_task_flocks(context_t *ctx, struct task_struct *t)
{
	int ret = 0;
	int fd = -1;

	fd = open_image(ctx, CR_FD_FILE_LOCKS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;
	goto out;
out:
	close_safe(&fd);
	return ret;
}

static int write_task_netdev(context_t *ctx, struct task_struct *t)
{
	int ret = 0;
	int fd = -1;

	fd = open_image(ctx, CR_FD_NETDEV, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;
	goto out;
out:
	close_safe(&fd);
	return ret;
}

static int write_task_ifaddr(context_t *ctx, struct task_struct *t)
{
	int ret = 0;
	int fd = -1;

	fd = open_image(ctx, CR_FD_IFADDR, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;
	goto out;
out:
	close_safe(&fd);
	return ret;
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

	ret = write_task_core(ctx, t);
	if (ret) {
		pr_err("Failed writing core for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_kids(ctx, t);
	if (ret) {
		pr_err("Failed writing kernel-ids for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_sighandlers(ctx, t);
	if (ret) {
		pr_err("Failed writing sighandlers for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_itimers(ctx, t);
	if (ret) {
		pr_err("Failed writing itimers for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_creds(ctx, t);
	if (ret) {
		pr_err("Failed writing creds for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_utsns(ctx, t);
	if (ret) {
		pr_err("Failed writing utsns for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_ipc(ctx, t);
	if (ret) {
		pr_err("Failed writing ipc for task %d\n",
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

	ret = write_task_flocks(ctx, t);
	if (ret) {
		pr_err("Failed writing file locks for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_netdev(ctx, t);
	if (ret) {
		pr_err("Failed writing netdev for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_ifaddr(ctx, t);
	if (ret) {
		pr_err("Failed writing ifaddr for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_route(ctx, t);
	if (ret) {
		pr_err("Failed writing route for task %d\n",
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

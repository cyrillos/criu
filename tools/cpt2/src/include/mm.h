#ifndef __CPT2_MM_H__
#define __CPT2_MM_H__

#include <stdbool.h>
#include <sys/types.h>

#include "context.h"
#include "types.h"
#include "list.h"

struct file_struct;

struct mm_struct {
	struct list_head	vma_list;

	bool			has_auxv;
	off_t			auxv_at;

	struct vma_struct	*exec_vma;

	struct cpt_mm_image	mmi;
};

struct vma_struct {
	struct list_head	list;

	struct file_struct	*file;
	u32			status;

	struct cpt_vma_image	vmai;
};

struct shmem_struct {
	struct hlist_node	hash;

	u64			shmid;
	struct vma_struct	*vma;

	unsigned long		size;
	pid_t			pid;
};

#define _calc_vm_trans(x, bit1, bit2)				\
  ((bit1) <= (bit2) ? ((x) & (bit1)) * ((bit2) / (bit1))	\
   : ((x) & (bit1)) / ((bit1) / (bit2)))

#define VM_READ		0x00000001
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_MAYREAD	0x00000010
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */

#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */

#define VM_EXECUTABLE	0x00001000
#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */

#define VSYSCALL_START	(-10UL << 20)
#define VSYSCALL_SIZE	1024
#define VSYSCALL_END	(-2UL << 20)

/*
 * FIXME Dup'ed from crtools.
 */
#define VMA_AREA_NONE		(0 <<  0)
#define VMA_AREA_REGULAR	(1 <<  0)	/* Dumpable area */
#define VMA_AREA_STACK		(1 <<  1)
#define VMA_AREA_VSYSCALL	(1 <<  2)
#define VMA_AREA_VDSO		(1 <<  3)
#define VMA_FORCE_READ		(1 <<  4)	/* VMA changed to be readable */
#define VMA_AREA_HEAP		(1 <<  5)

#define VMA_FILE_PRIVATE	(1 <<  6)
#define VMA_FILE_SHARED		(1 <<  7)
#define VMA_ANON_SHARED		(1 <<  8)
#define VMA_ANON_PRIVATE	(1 <<  9)

#define VMA_AREA_SYSVIPC	(1 <<  10)
#define VMA_AREA_SOCKET		(1 <<  11)

#define __vma_is(status, flags)	((status) & (flags))
#define vma_is(vma, flags)	__vma_is((vma)->status, flags)
#define vma_is_shared(vma)	vma_is(vma, VMA_FILE_SHARED | VMA_ANON_SHARED)

#define vmai_is(vma, flags)	__vma_is((vma)->vmai.cpt_flags, flags)
#define vmai_is_shared(vma)	vmai_is(vma, VM_SHARED | VM_MAYSHARE)

extern int read_mm(context_t *ctx);
extern void free_mm(context_t *ctx);

extern int write_mm(context_t *ctx, pid_t pid, off_t cpt_mm);
extern int write_vmas(context_t *ctx, pid_t pid, off_t cpt_mm);
extern int write_pages(context_t *ctx, pid_t pid, off_t cpt_mm);
extern int write_shmem(context_t *ctx);

#endif /* __CPT2_MM_H__ */

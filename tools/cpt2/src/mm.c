#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/mman.h>

#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "image.h"
#include "files.h"
#include "read.h"
#include "log.h"
#include "obj.h"
#include "bug.h"
#include "mm.h"

void free_mm(context_t *ctx)
{
	struct mm_struct *mm;

	while ((mm = obj_pop_unhash_to(CPT_OBJ_MM))) {
		struct vma_struct *vma, *n;

		list_for_each_entry_safe(vma, n, &mm->vma_list, list) {
			obj_unhash_to(vma);
			obj_free_to(vma);
		}
		obj_free_to(mm);
	}


}

static void show_mmi_cont(context_t *ctx, struct cpt_mm_image *mmi)
{
	pr_debug("\tstart_code 0x%-16lx end_code  0x%-16lx "
		 "start_data 0x%-16lx  end_data 0x%-16lx mm_flags 0x%-16lx\n",
		 (long)mmi->cpt_start_code, (long)mmi->cpt_end_code,
		 (long)mmi->cpt_start_data, (long)mmi->cpt_end_data,
		 (long)mmi->cpt_mm_flags);
}

static bool is_dev_zero(struct cpt_inode_image *inode, struct file_struct *file)
{
	if (!inode || inode->cpt_sb != TMPFS_MAGIC || !file->name)
		return false;

	return (strcmp(file->name, "/dev/zero (deleted)") == 0 ||
		strcmp(file->name, " (deleted)/dev/zero") == 0 ||
		strcmp(file->name, "/dev/zero") == 0);
}

static char *vma_name(struct vma_struct *vma)
{
	if (vma_is(vma, VMA_AREA_STACK))
		return "stack";
	else if (vma_is(vma, VMA_AREA_VSYSCALL))
		return "vsyscall";
	else if (vma_is(vma, VMA_AREA_VDSO))
		return "vdso";
	else if (vma_is(vma, VMA_AREA_HEAP))
		return "heap";
	else if (vma_is(vma, VMA_AREA_SYSVIPC))
		return "sysvipc";
	else if (vma_is(vma, VMA_AREA_SOCKET))
		return "socket";
	else if (vma_is(vma, VMA_FILE_PRIVATE))
		return "file private mmap";
	else if (vma_is(vma, VMA_FILE_SHARED))
		return "file shared mmap";
	else if (vma_is(vma, VMA_ANON_SHARED))
		return "anon shared mmap";
	else if (vma_is(vma, VMA_ANON_PRIVATE))
		return "anon private mmap";

	return "unknown";
}

static void show_vma_cont(context_t *ctx, struct vma_struct *vma)
{
	pr_debug("\t\tvma @%-8li file @%-8li type %2d start %#16lx end %#16lx\n"
		 "\t\t\tflags %#8lx pgprot %#16lx pgoff %#10lx\n"
		 "\t\t\tanonvma %#8x anonvmaid %#8lx\n"
		 "\t\t\t(%c%c%c) (%c) (%#x -> [%s])\n"
		 "\t\t\t(%li payload bytes)\n",
		 obj_of(vma)->o_pos, (long)vma->vmai.cpt_file,
		 vma->vmai.cpt_type, (long)vma->vmai.cpt_start,
		 (long)vma->vmai.cpt_end, (long)vma->vmai.cpt_flags,
		 (long)vma->vmai.cpt_pgprot, (long)vma->vmai.cpt_pgoff,
		 vma->vmai.cpt_anonvma, (long)vma->vmai.cpt_anonvmaid,

		 vmai_is(vma, VM_READ) ? 'r' : '-',
		 vmai_is(vma, VM_WRITE) ? 'w' : '-',

		 vmai_is(vma, VM_EXEC | VM_EXECUTABLE) ? 'x' : '-',
		 vmai_is_shared(vma) ? 's' : 'p',

		 vma->status, vma_name(vma),
		 (long)(vma->vmai.cpt_next - vma->vmai.cpt_hdrlen));
}

static int vma_parse(context_t *ctx, struct mm_struct *mm,
		     struct vma_struct *vma)
{
	struct cpt_inode_image *inode = NULL;
	struct file_struct *file = NULL;

	if (vma->vmai.cpt_file != -1) {
		file = obj_lookup_to(CPT_OBJ_FILE, vma->vmai.cpt_file);
		if (!file)
			goto err;

		if (file->fi.cpt_inode != -1) {
			inode = obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
			if (!inode)
				goto err;
		}

		vma->file = file;
	}

	vma->status = VMA_AREA_REGULAR;

	switch (vma->vmai.cpt_type) {
	case CPT_VMA_TYPE_0:
		if (file) {
			if (is_dev_zero(inode, file)) {
				if (!vmai_is_shared(vma)) {
					pr_err("Private mapping on share entry\n");
					goto err;
				}
				vma->status |= VMA_ANON_SHARED;
			} else {
				if (vmai_is_shared(vma))
					vma->status |= VMA_FILE_SHARED;
				else
					vma->status |= VMA_FILE_PRIVATE;
			}
		} else {
			/*
			 * No file associated -- anonymous private
			 */
			if (vmai_is_shared(vma)) {
				pr_err("No file associated on shared memory\n");
				goto err;
			}
			vma->status |= VMA_ANON_PRIVATE;
		}
		break;
	case CPT_VMA_TYPE_SHM:
		if (!file) {
			pr_err("SysV shmem area without file found\n");
			goto err;
		}
		vma->status |= VMA_ANON_SHARED | VMA_AREA_SYSVIPC;
		break;
	case CPT_VMA_VDSO:
	case CPT_VMA_VDSO_OLD:
		if (file) {
			pr_err("VDSO area with file found\n");
			goto err;
		}
		vma->status |= VMA_ANON_PRIVATE | VMA_AREA_VDSO;
		break;
	}

	if (vma->vmai.cpt_start <= mm->mmi.cpt_start_brk &&
	    vma->vmai.cpt_end >= mm->mmi.cpt_brk) {
		vma->status |= VMA_AREA_HEAP;
	} else if (vma->vmai.cpt_start <= mm->mmi.cpt_start_stack
		   && vma->vmai.cpt_end >= mm->mmi.cpt_start_stack) {
		vma->status |= VMA_AREA_STACK;
	} else if (vma->vmai.cpt_start >= VSYSCALL_START &&
		 vma->vmai.cpt_end <= VSYSCALL_END) {
		/*
		 * cpt image do not tell us if vma is
		 * vsyscall area so we need to figure it
		 * out by self
		 *
		 * FIXME It's valid for x86-64 only
		 */
		vma->status &= ~VMA_AREA_REGULAR;
		vma->status |= VMA_AREA_VSYSCALL;
	}

	return 0;

err:
	pr_err("Error while parsing VMA %lx-%lx\n",
	       (long)vma->vmai.cpt_start, (long)vma->vmai.cpt_end);
	return -1;
}

static int read_vmas(context_t *ctx, struct mm_struct *mm,
		     off_t start, off_t end)
{
	struct cpt_object_hdr h;
	int ret = -1;

	for (; start < end; start += h.cpt_next) {
		struct vma_struct *vma;

		if (read_obj_hdr(ctx->fd, &h, start)) {
			pr_err("Can't read VMA header at %li\n", (long)start);
			return -1;
		}

		switch (h.cpt_object) {
		case CPT_OBJ_VMA:
			break;
		case CPT_OBJ_MM_AUXV:
			mm->has_auxv = true;
			mm->auxv_at = start;
			continue;
		default:
			continue;
		}

		vma = obj_alloc_to(struct vma_struct, vmai);
		if (!vma)
			goto out;
		INIT_LIST_HEAD(&vma->list);
		vma->status = 0;
		vma->file = NULL;

		if (read_obj_cpt_cont(ctx->fd, &vma->vmai))
			goto out;

		memcpy(&vma->vmai, &h, sizeof(h));
		list_add_tail(&vma->list, &mm->vma_list);

		if (vma->vmai.cpt_file != -1 &&
		    (vma->vmai.cpt_flags & VM_EXECUTABLE)) {
			mm->exec_vma = vma;
		}

		obj_hash_typed_to(vma, CPT_OBJ_VMA, start);

		if (vma_parse(ctx, mm, vma)) {
			pr_err("Can't parse VMA at @%li\n",
			       start);
			goto out;
		}

		show_vma_cont(ctx, vma);
	}

	if (!mm->exec_vma) {
		pr_err("No self-exe vma found for MM at @%li\n",
		       (long)obj_of(mm)->o_pos);
		goto out;
	} else if (!mm->has_auxv) {
		pr_err("No auxv found for MM at @%li\n",
		       (long)obj_of(mm)->o_pos);
		goto out;
	}

	ret = 0;
out:
	return ret;
}

int read_mm(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_debug("MM\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_MM, &start, &end);

	while (start < end) {
		struct mm_struct *mm = obj_alloc_to(struct mm_struct, mmi);
		if (!mm)
			return -1;
		INIT_LIST_HEAD(&mm->vma_list);
		mm->has_auxv = false;
		mm->auxv_at = 0;
		mm->exec_vma = NULL;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_MM, &mm->mmi, start)) {
			obj_free_to(mm);
			pr_err("Can't read task mm at %li\n", (long)start);
			return -1;
		}

		obj_push_hash_to(mm, CPT_OBJ_MM, start);
		show_mmi_cont(ctx, &mm->mmi);

		if (read_vmas(ctx, mm, start + mm->mmi.cpt_hdrlen, start + mm->mmi.cpt_next))
			goto out;

		start += mm->mmi.cpt_next;
	}
	pr_debug("------------------------------\n\n");

	ret = 0;
out:
	return ret;
}

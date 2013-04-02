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

#include "protobuf.h"
#include "../../../protobuf/regfile.pb-c.h"
#include "../../../protobuf/pagemap.pb-c.h"
#include "../../../protobuf/fdinfo.pb-c.h"
#include "../../../protobuf/fown.pb-c.h"
#include "../../../protobuf/vma.pb-c.h"
#include "../../../protobuf/mm.pb-c.h"

static u32 pages_ids = 1;

#define SHMEM_HASH_BITS	10
static DEFINE_HASHTABLE(shmem_hash, SHMEM_HASH_BITS);

static struct shmem_struct *shmem_lookup(u64 shmid)
{
	struct shmem_struct *shmem;

	hash_for_each_key(shmem_hash, shmem, hash, shmid) {
		if (shmem->shmid == shmid)
			return shmem;
	}

	return NULL;
}

static int shmem_add(struct vma_struct *vma, u64 shmid, pid_t pid)
{
	struct shmem_struct *shmem;
	unsigned long size;

	BUG_ON(!vma->file || !(vma_is(vma, VMA_ANON_SHARED)));

	size  = (vma->vmai.cpt_pgoff << PAGE_SHIFT);
	size += (vma->vmai.cpt_end - vma->vmai.cpt_start);

	shmem = shmem_lookup(shmid);
	if (shmem) {
		if (shmem->size < size) {
			shmem->size = size;
			return 0;
		}
	}

	shmem = xmalloc(sizeof(*shmem));
	if (!shmem) {
		pr_err("Failed handling shmem\n");
		return -1;
	}

	INIT_HLIST_NODE(&shmem->hash);
	shmem->shmid	= shmid;
	shmem->vma	= vma;
	shmem->pid	= pid;

	hash_add(shmem_hash, &shmem->hash, shmem->shmid);
	return 0;
}

void free_mm(context_t *ctx)
{
	struct shmem_struct *shmem;
	struct hlist_node *n;
	unsigned long bucket;
	struct mm_struct *mm;

	hash_for_each_safe(shmem_hash, bucket, n, shmem, hash)
		xfree(shmem);

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

static u32 vma_flags_to_prot(u64 flags)
{
	return	_calc_vm_trans(flags, VM_READ,		PROT_READ)	|
		_calc_vm_trans(flags, VM_WRITE,		PROT_WRITE)	|
		_calc_vm_trans(flags, VM_EXEC,		PROT_EXEC)	|
		_calc_vm_trans(flags, VM_EXECUTABLE,	PROT_EXEC);
}

static bool is_dev_zero(struct cpt_inode_image *inode, struct file_struct *file)
{
	if (!inode || inode->cpt_sb != TMPFS_MAGIC || !file->name)
		return false;

	return (strcmp(file->name, "/dev/zero (deleted)") == 0 ||
		strcmp(file->name, " (deleted)/dev/zero") == 0 ||
		strcmp(file->name, "/dev/zero") == 0);
}

static bool vma_has_payload(struct vma_struct *vma)
{
	return vma->vmai.cpt_hdrlen < vma->vmai.cpt_next;
}

static bool should_dump_vma(struct vma_struct *vma)
{
	/* Special areas are not dumped */
	if (!vma_is(vma, VMA_AREA_REGULAR))
		return false;

	/* No dumps for file-shared mappings */
	if (vma_is(vma, VMA_FILE_SHARED))
		return false;

	/* Always dump vDSO */
	if (vma_is(vma, VMA_AREA_VDSO))
		return true;

	/* No dumps for SYSV IPC mappings */
	if (vma_is(vma, VMA_AREA_SYSVIPC))
		return false;

	/* Anon shared is dumped separately */
	if (vma_is(vma, VMA_ANON_SHARED))
		return false;

	if (!vma_is(vma, VMA_ANON_PRIVATE | VMA_FILE_PRIVATE)) {
		pr_warn("Unexpected VMA area found (@%li %#x)\n",
			obj_of(vma)->o_pos, vma->status);
		return false;
	}

	if (vma->vmai.cpt_end > TASK_SIZE)
		return false;

	return true;
}

static int write_vma_pages(context_t *ctx, int pagemap_fd, int page_fd,
			   struct vma_struct *vma)
{
	union {
		struct cpt_object_hdr	h;
		struct cpt_page_block	pb;
	} u;

	u8 page[PAGE_SIZE];

	unsigned long nr_pages, i;
	off_t start, end;
	PagemapEntry pe;
	int ret = -1;

	start	= obj_of(vma)->o_pos + vma->vmai.cpt_hdrlen;
	end	= obj_of(vma)->o_pos + vma->vmai.cpt_next;

	for (; start < end; start += u.h.cpt_next) {
		if (read_obj_cpt(ctx->fd, OBJ_ANY, &u.h, start)) {
			pr_err("Can't read page header at %li\n", (long)start);
			goto err;
		}

		/*
		 * We support only regular pages for now.
		 */
		switch (u.h.cpt_object) {
		case CPT_OBJ_PAGES:
			break;
		case CPT_OBJ_REMAPPAGES:
		case CPT_OBJ_COPYPAGES:
		case CPT_OBJ_LAZYPAGES:
		case CPT_OBJ_ITERPAGES:
		case CPT_OBJ_ITERYOUNGPAGES:
		default:
			pr_err("Unexpected object %d at %li\n",
			       u.h.cpt_object, (long)start);
			goto err;
		}

		if (read_obj_cont(ctx->fd, &u.pb)) {
			pr_err("Can't read page at %li\n", (long)start);
			goto err;
		}

		if (u.h.cpt_content != CPT_CONTENT_DATA) {
			pr_err("Unexpected object content %d at %li\n",
			       u.h.cpt_content, (long)start);
			goto err;
		}

		/*
		 * Nothing to write.
		 */
		if (u.h.cpt_hdrlen == u.h.cpt_next)
			continue;

		nr_pages = PAGES(u.h.cpt_next - u.h.cpt_hdrlen);
		i = PAGES(u.pb.cpt_end - u.pb.cpt_start);
		if (nr_pages != i) {
			pr_err("Broken pages count (%li/%li)at %li\n",
			       nr_pages, i, (long)start);
			goto err;
		}

		pagemap_entry__init(&pe);

		pe.vaddr	= u.pb.cpt_start;
		pe.nr_pages	= nr_pages;

		if (pb_write_one(pagemap_fd, &pe, PB_PAGEMAP) < 0)
			goto err;

		for (i = 0; i < nr_pages; i++) {
			if (__read(ctx->fd, page, sizeof(page))) {
				pr_err("Can't read page at %li\n",
				       (long)start);
					goto err;
				}
			if (__write(page_fd, page, sizeof(page))) {
				pr_err("Can't write page at %li\n",
				       (long)start);
				goto err;
			}
		}
	}
	ret = 0;
err:
	return ret;
}

int write_shmem(context_t *ctx)
{
	int pagemap_fd = -1, page_fd = -1;
	struct shmem_struct *shmem;
	unsigned long bucket;
	int ret = -1;

	hash_for_each(shmem_hash, bucket, shmem, hash) {
		PagemapHead h = PAGEMAP_HEAD__INIT;

		if (!vma_has_payload(shmem->vma))
			continue;

		pagemap_fd = open_image(ctx, CR_FD_SHMEM_PAGEMAP, O_DUMP, shmem->shmid);
		if (pagemap_fd < 0)
			return -1;

		h.pages_id = shmem->shmid;

		page_fd = open_image(ctx, CR_FD_PAGES, O_DUMP, h.pages_id);
		if (page_fd < 0)
			goto err;

		if (pb_write_one(pagemap_fd, &h, PB_PAGEMAP_HEAD) < 0)
			goto err;

		ret = write_vma_pages(ctx, pagemap_fd, page_fd, shmem->vma);
		if (ret) {
			pr_err("Can't write pages header at %li\n",
			       (long)obj_of(shmem->vma)->o_pos);
			goto err;
		}

		close_safe(&pagemap_fd);
		close_safe(&page_fd);
	}
	ret = 0;

err:
	close_safe(&pagemap_fd);
	close_safe(&page_fd);
	return ret;
}

int write_pages(context_t *ctx, pid_t pid, off_t cpt_mm)
{
	PagemapHead h = PAGEMAP_HEAD__INIT;
	struct vma_struct *vma;
	struct mm_struct *mm;

	int pagemap_fd = -1;
	int page_fd = -1;
	int ret = -1;

	mm = obj_lookup_to(CPT_OBJ_MM, cpt_mm);
	if (!mm)
		return -1;

	pagemap_fd = open_image(ctx, CR_FD_PAGEMAP, O_DUMP, pid);
	if (pagemap_fd < 0)
		goto err;

	h.pages_id = pages_ids++;

	page_fd = open_image(ctx, CR_FD_PAGES, O_DUMP, h.pages_id);
	if (page_fd < 0)
		goto err;

	if (pb_write_one(pagemap_fd, &h, PB_PAGEMAP_HEAD) < 0)
		goto err;

	list_for_each_entry(vma, &mm->vma_list, list) {
		if (!should_dump_vma(vma) || !vma_has_payload(vma))
			continue;

		ret = write_vma_pages(ctx, pagemap_fd, page_fd, vma);
		if (ret) {
			pr_err("Can't write pages header at %li\n",
			       (long)obj_of(vma)->o_pos);
			goto err;
		}
	}
	ret = 0;
err:
	close_safe(&pagemap_fd);
	close_safe(&page_fd);
	return ret;
}

static int write_file_map(context_t *ctx, pid_t pid, struct vma_struct *vma)
{
	int rfd = fdset_fd(ctx->fdset_glob, CR_FD_REG_FILES);
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	int ret;

	if (vma->file->dumped)
		return 0;

	fill_fown(&fown, vma->file);

	rfe.id		= obj_id_of(vma->file);
	rfe.pos		= vma->file->fi.cpt_pos;
	rfe.fown	= &fown;
	rfe.name	= vma->file->name;

	if (vmai_is(vma, VM_WRITE) && vma_is(vma, VMA_FILE_SHARED))
		rfe.flags = O_RDWR;
	else
		rfe.flags = O_RDONLY;

	ret = pb_write_one(rfd, &rfe, PB_REG_FILES);
	if (!ret)
		vma->file->dumped = 1;

	return ret;
}

int write_vmas(context_t *ctx, pid_t pid, off_t cpt_mm)
{
	VmaEntry e = VMA_ENTRY__INIT;
	int fd_vmas = -1, ret = -1;
	struct vma_struct *vma;
	struct mm_struct *mm;

	mm = obj_lookup_to(CPT_OBJ_MM, cpt_mm);
	if (!mm)
		return -1;

	fd_vmas = open_image(ctx, CR_FD_VMAS, O_DUMP, pid);
	if (fd_vmas < 0)
		return -1;

	list_for_each_entry(vma, &mm->vma_list, list) {

		if (!vma_is(vma, VMA_AREA_REGULAR))
			continue;

		e.start		= vma->vmai.cpt_start;
		e.end		= vma->vmai.cpt_end;
		e.pgoff		= vma->vmai.cpt_pgoff << PAGE_SHIFT;
		e.prot		= vma_flags_to_prot(vma->vmai.cpt_flags);
		e.status	= vma->status;
		e.fd		= -1;

		if (vma_is_shared(vma))
			e.flags = MAP_SHARED;
		else
			e.flags = MAP_PRIVATE;

		if (vma_is(vma, VMA_ANON_SHARED | VMA_ANON_PRIVATE))
			e.flags |= MAP_ANONYMOUS;

		if (vmai_is(vma, VM_GROWSDOWN))
			e.flags |= MAP_GROWSDOWN;

		if (vmai_is(vma, VM_DENYWRITE))
			e.flags |= MAP_DENYWRITE;

		if (vmai_is(vma, VM_ACCOUNT))
			e.flags |= MAP_NORESERVE;

		if (vma_is(vma, VMA_FILE_SHARED | VMA_FILE_PRIVATE)) {
			e.shmid = obj_id_of(vma->file);
			if (write_file_map(ctx, pid, vma))
				goto err;
		} else if (vma_is(vma, VMA_ANON_SHARED)) {
			e.shmid = vma->file ? obj_id_of(vma->file) : -1;
			if (shmem_add(vma, e.shmid, pid))
				goto err;
		} else if (vma_is(vma, VMA_AREA_SOCKET)) {
			pr_err("Sockets are not yet supported\n");
			goto err;
		}

		if (pb_write_one(fd_vmas, &e, PB_VMAS)) {
			pr_err("Can't write VMA at %li\n",
			       (long)obj_of(vma)->o_pos);
			goto err;
		}
	}
	ret = 0;

out:
	close_safe(&fd_vmas);
	return ret;

err:
	pr_err("Error while handling VMA %lx-%lx\n",
	       (long)vma->vmai.cpt_start, (long)vma->vmai.cpt_end);
	goto out;
}

int write_mm(context_t *ctx, pid_t pid, off_t cpt_mm)
{
	struct {
		u64	cpt_next;
		u32	cpt_object;
		u16	cpt_hdrlen;
		u16	cpt_content;

		u64	vector[AT_VECTOR_SIZE];
	} auxv;

	MmEntry e = MM_ENTRY__INIT;
	struct mm_struct *mm;
	int fd, ret = -1;

	mm = obj_lookup_to(CPT_OBJ_MM, cpt_mm);
	if (!mm)
		return -1;

	fd = open_image(ctx, CR_FD_MM, O_DUMP, pid);
	if (fd < 0)
		return -1;

	e.mm_start_code		= mm->mmi.cpt_start_code;
	e.mm_end_code		= mm->mmi.cpt_end_code;
	e.mm_start_data		= mm->mmi.cpt_start_data;
	e.mm_end_data		= mm->mmi.cpt_end_data;
	e.mm_start_stack	= mm->mmi.cpt_start_stack;
	e.mm_start_brk		= mm->mmi.cpt_start_brk;
	e.mm_brk		= mm->mmi.cpt_brk;
	e.mm_arg_start		= mm->mmi.cpt_start_arg;
	e.mm_arg_end		= mm->mmi.cpt_end_arg;
	e.mm_env_start		= mm->mmi.cpt_start_env;
	e.mm_env_end		= mm->mmi.cpt_end_env;

	memzero(&auxv, sizeof(auxv));
	if (read_obj_cpt(ctx->fd, CPT_OBJ_MM_AUXV, &auxv, mm->auxv_at))
		goto out;

	e.exe_file_id		= obj_id_of(mm->exec_vma->file);
	e.n_mm_saved_auxv	= AT_VECTOR_SIZE;
	e.mm_saved_auxv		= (void *)auxv.vector;

	if (write_reg_file_entry(ctx, mm->exec_vma->file)) {
		pr_err("Can't add exe_file_id link\n");
		goto out;
	}

	ret = pb_write_one(fd, &e, PB_MM);
out:
	close(fd);
	return ret;
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

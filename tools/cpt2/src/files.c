#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <linux/major.h>

#include "cpt-image.h"
#include "magicfs.h"
#include "xmalloc.h"
#include "files.h"
#include "image.h"
#include "task.h"
#include "read.h"
#include "log.h"
#include "net.h"
#include "obj.h"
#include "bug.h"

#include "protobuf.h"
#include "../../../protobuf/fdinfo.pb-c.h"
#include "../../../protobuf/regfile.pb-c.h"
#include "../../../protobuf/pipe.pb-c.h"
#include "../../../protobuf/fs.pb-c.h"

static int type_from_name(FdinfoEntry *e, struct file_struct *file)
{
	if (!file->name)
		return -1;

	if (strcmp(file->name, "inotify") == 0) {
		e->type = FD_TYPES__INOTIFY;
		return 0;
	} else if (strcmp(file->name, "[fanotify]") == 0) {
		e->type = FD_TYPES__FANOTIFY;
		return 0;
	} else if (strcmp(file->name, "[eventpoll]") == 0) {
		e->type = FD_TYPES__EVENTPOLL;
		return 0;
	} else if (strcmp(file->name, "[eventfd]") == 0) {
		e->type = FD_TYPES__EVENTFD;
		return 0;
	} else if (strcmp(file->name, "[signalfd]") == 0) {
		e->type = FD_TYPES__SIGNALFD;
		return 0;
	}

	return -1;
}

static int set_fdinfo_type(FdinfoEntry *e, struct file_struct *file,
			   struct cpt_inode_image *inode)
{
	if (S_ISSOCK(file->fi.cpt_i_mode)) {
		struct sock_struct *sk;

		sk = sk_lookup_file(obj_of(file)->o_pos);
		if (!sk) {
			pr_err("Can't find socket for @%li\n",
			       (long)obj_of(file)->o_pos);
			return -1;
		}
		switch (sk->si.cpt_family) {
		case PF_INET:
		case PF_INET6:
			e->type = FD_TYPES__INETSK;
			break;
		case PF_UNIX:
			e->type = FD_TYPES__UNIXSK;
			break;
		case PF_PACKET:
			e->type = FD_TYPES__PACKETSK;
			break;
		default:
			pr_err("File at @%li with unsupported sock family %d\n",
			       (long)obj_of(file)->o_pos, (int)sk->si.cpt_family);
			return -1;
		}
	} else if (S_ISCHR(file->fi.cpt_i_mode)) {
		if (!inode) {
			pr_err("Character file without inode at @%li\n",
			       (long)obj_of(file)->o_pos);
			return -1;
		}
		switch (kdev_major(inode->cpt_rdev)) {
		case MEM_MAJOR:
			e->type = FD_TYPES__REG;
			break;
		case TTYAUX_MAJOR:
		case UNIX98_PTY_MASTER_MAJOR ... (UNIX98_PTY_MASTER_MAJOR + UNIX98_PTY_MAJOR_COUNT - 1):
		case UNIX98_PTY_SLAVE_MAJOR:
			e->type = FD_TYPES__TTY;
			break;
		default:
			pr_err("Character file with maj %d inode at @%li\n",
			       major(inode->cpt_rdev), (long)obj_of(file)->o_pos);
			return -1;
		}
	} else if (S_ISREG(file->fi.cpt_i_mode) || S_ISDIR(file->fi.cpt_i_mode)) {
		e->type = FD_TYPES__REG;
	} else if (S_ISFIFO(file->fi.cpt_i_mode)) {
		if (!inode) {
			pr_err("Fifo file without inode at @%li\n",
			       (long)obj_of(file)->o_pos);
			return -1;
		}
		if (inode->cpt_sb == PIPEFS_MAGIC)
			e->type = FD_TYPES__PIPE;
		else
			e->type = FD_TYPES__FIFO;
	} else {
		if (type_from_name(e, file) == 0)
			return 0;

		pr_err("File with unknown type at @%li\n",
			(long)obj_of(file)->o_pos);
		return -1;
	}

	return 0;
}

enum pid_type {
	PIDTYPE_PID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX
};

void fill_fown(FownEntry *e, struct file_struct *file)
{
	e->uid		= file->fi.cpt_fown_uid;
	e->euid		= file->fi.cpt_fown_euid;
	e->signum	= file->fi.cpt_fown_signo;

	/*
	 * FIXME
	 * No info about pid type in OpenVZ image, use
	 * type PID for a while.
	 */
	e->pid_type	= PIDTYPE_PID;
	e->pid		= file->fi.cpt_fown_pid;
}

int write_reg_file_entry(context_t *ctx, struct file_struct *file)
{
	int rfd = fdset_fd(ctx->fdset_glob, CR_FD_REG_FILES);
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	int ret = -1;

	if (file->dumped)
		return 0;

	fill_fown(&fown, file);

	rfe.id		= obj_id_of(file);
	rfe.flags	= file->fi.cpt_flags;
	rfe.pos		= file->fi.cpt_pos;
	rfe.fown	= &fown;
	rfe.name	= file->name;

	ret = pb_write_one(rfd, &rfe, PB_REG_FILES);
	if (!ret)
		file->dumped = true;

	return ret;
}

static int write_pipe_entry(context_t *ctx, struct file_struct *file)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_PIPES);
	PipeEntry pe = PIPE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	struct cpt_inode_image *inode;
	int ret = -1;

	if (file->dumped)
		return 0;

	if (file->fi.cpt_flags & O_DIRECT) {
		pr_err("The packetized mode for pipes is not supported yet\n");
		return -1;
	}

	inode = obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("No inode for pipe on file @%li\n",
		       (long)obj_of(file)->o_pos);
		return -1;
	}

	fill_fown(&fown, file);

	pe.id		= obj_id_of(file);
	pe.pipe_id	= obj_id_of(inode);
	pe.flags	= file->fi.cpt_flags;
	pe.fown		= &fown;

	ret = pb_write_one(fd, &pe, PB_PIPES);
	if (!ret)
		file->dumped = true;

	/*
	 * FIXME Where is the pipe data?
	 */

	return ret;
}

int write_task_files(context_t *ctx, struct task_struct *t)
{
	FdinfoEntry e = FDINFO_ENTRY__INIT;
	struct files_struct *files;
	struct fd_struct *fd;
	int image_fd = -1;
	int ret = -1;

	/*
	 * If we share fdtable with parent then simply
	 * get out early.
	 */
	if (t->parent) {
		if (t->parent->ti.cpt_files == t->ti.cpt_files)
			return 0;
	}

	files = obj_lookup_to(CPT_OBJ_FILES, t->ti.cpt_files);
	if (!files) {
		pr_err("Can't find files associated with task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	image_fd = open_image(ctx, CR_FD_FDINFO, O_DUMP, t->ti.cpt_pid);
	if (image_fd < 0)
		goto out;

	list_for_each_entry(fd, &files->fd_list, list) {
		struct cpt_inode_image *inode;
		struct file_struct *file;

		file = obj_lookup_to(CPT_OBJ_FILE, fd->fdi.cpt_file);
		if (!file)
			goto out;

		if (file->fi.cpt_inode != -1) {
			inode = obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
			if (!inode)
				return -1;
		} else
			inode = NULL;

		if (set_fdinfo_type(&e, file, inode)) {
			pr_err("Can't find file type for  @%li\n",
			       (long)fd->fdi.cpt_file);
			goto out;
		}

		e.id	= obj_id_of(file);
		e.flags	= fd->fdi.cpt_flags;
		e.fd	= fd->fdi.cpt_fd;

		ret = pb_write_one(image_fd, &e, PB_FDINFO);
		if (ret)
			goto out;

		switch (e.type) {
		case FD_TYPES__REG:
			ret = write_reg_file_entry(ctx, file);
			break;
		case FD_TYPES__PIPE:
			ret = write_pipe_entry(ctx, file);
			break;
		default:
			pr_err("Unsupported file found (type = %d)\n", e.type);
			ret = -1;
			break;
		}

		if (ret)
			goto out;
	}
	ret = 0;

out:
	close_safe(&image_fd);
	return ret;
}

void free_inodes(context_t *ctx)
{
	obj_t *obj;

	while ((obj = obj_pop_unhash(CPT_OBJ_INODE)))
		obj_free(obj);
}

static void show_inode_cont(context_t *ctx, obj_t *obj)
{
	struct cpt_inode_image *inode = obj->o_image;

	pr_debug("\t@%-8li dev %10li ino %10li mode %6d nlink %6d "
		 "rdev %10li sb %10li vfsmount @%-8li\n",
		 (long)obj->o_pos, (long)inode->cpt_dev, (long)inode->cpt_ino,
		 inode->cpt_mode, inode->cpt_nlink, (long)inode->cpt_rdev,
		 (long)inode->cpt_sb, (long)inode->cpt_vfsmount);
}

int read_inodes(context_t *ctx)
{
	off_t start, end;

	pr_debug("Inodes\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_INODE, &start, &end);

	while (start < end) {
		struct cpt_inode_image *inode;
		obj_t *obj;

		obj = obj_alloc(sizeof(struct cpt_inode_image));
		if (!obj)
			return -1;
		inode = obj->o_image;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_INODE, inode, start)) {
			obj_free(obj);
			pr_err("Can't read inode object at @%li\n", (long)start);
			return -1;
		}

		obj_push_hash(obj, CPT_OBJ_INODE, start);
		start += inode->cpt_next;
		show_inode_cont(ctx, obj);
	}

	pr_debug("------------------------------\n\n");

	return 0;
}

static void show_file_cont(context_t *ctx, struct file_struct *file)
{
	pr_debug("\t@%-8li flags %8d mode %6d pos %16li\n"
		 "\t\ti_mode %6d lflags %6d inode @%-8li vfsmount @%-8li --> %s\n",
		(long)obj_of(file)->o_pos, file->fi.cpt_flags, file->fi.cpt_mode,
		(long)file->fi.cpt_pos, file->fi.cpt_i_mode,
		file->fi.cpt_lflags, (long)file->fi.cpt_inode,
		(long)file->fi.cpt_vfsmount, file->name);
}

static struct file_struct *read_file(context_t *ctx, off_t start, off_t *next)
{
	struct file_struct *file;

	file = obj_alloc_to(struct file_struct, fi);
	if (!file)
		return NULL;

	file->name = NULL;
	file->dumped = false;

	if (read_obj_cpt(ctx->fd, CPT_OBJ_FILE, &file->fi, start)) {
		obj_free_to(file);
		pr_err("Can't read file object at @%li\n", (long)start);
		return NULL;
	}

	obj_push_hash_to(file, CPT_OBJ_FILE, start);
	*next = start + file->fi.cpt_next;

	if (file->fi.cpt_next > file->fi.cpt_hdrlen) {
		file->name = read_name(ctx->fd, obj_of(file)->o_pos + file->fi.cpt_hdrlen, NULL);
		if (IS_ERR(file->name)) {
			obj_free_to(file);
			return NULL;
		}
	}

	return file;
}

void free_files(context_t *ctx)
{
	struct files_struct *files;
	struct file_struct *file;
	struct fd_struct *fd, *n;

	while ((file = obj_pop_unhash_to(CPT_OBJ_FILE))) {
		xfree(file->name);
		obj_free_to(file);
	}

	while ((files = obj_pop_unhash_to(CPT_OBJ_FILES))) {
		list_for_each_entry_safe(fd, n, &files->fd_list, list) {
			obj_unhash_to(fd);
			obj_free_to(fd);
		}
		obj_free_to(files);
	}
}

static void show_fd_cont(context_t *ctx, struct fd_struct *fd)
{
	struct file_struct *file = obj_lookup_to(CPT_OBJ_FILE, fd->fdi.cpt_file);
	obj_t *obj = file ? obj_of(file) : NULL;

	pr_debug("\t\t@%-8li fd %8d flags %6x file @%-8li (name --> %s)\n",
		obj ? (long)obj->o_pos : -1, fd->fdi.cpt_fd, fd->fdi.cpt_flags,
		(long)fd->fdi.cpt_file, file ? file->name : "");
}

static void show_files_cont(context_t *ctx, struct files_struct *files)
{
	pr_debug("\t@%-8li index %8d cpt_max_fds %6d cpt_next_fd %6d\n",
		(long)obj_of(files)->o_pos, files->fsi.cpt_index,
		files->fsi.cpt_max_fds, files->fsi.cpt_next_fd);
}

int read_files(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_debug("Files\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_FILES, &start, &end);

	while (start < end) {
		struct file_struct *file;

		file = read_file(ctx, start, &start);
		if (!file)
			goto out;

		show_file_cont(ctx, file);
	}

	pr_debug("------------------------------\n\n");

	pr_debug("Files descriptors\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_FILES_STRUCT, &start, &end);

	while (start < end) {
		struct files_struct *files;
		struct fd_struct *fd;
		off_t from, to;

		files = obj_alloc_to(struct files_struct, fsi);
		if (!files)
			return -1;
		INIT_LIST_HEAD(&files->fd_list);

		if (read_obj_cpt(ctx->fd, CPT_OBJ_FILES, &files->fsi, start)) {
			obj_free_to(files);
			pr_err("Can't read files object at @%li\n", (long)start);
			return -1;
		}

		obj_push_hash_to(files, CPT_OBJ_FILES, start);
		start += files->fsi.cpt_next;

		show_files_cont(ctx, files);

		if (files->fsi.cpt_next <= files->fsi.cpt_hdrlen)
			continue;

		/*
		 * Read underlied file descriptors.
		 */
		for (from = obj_of(files)->o_pos + files->fsi.cpt_hdrlen,
		     to = obj_of(files)->o_pos + files->fsi.cpt_next;
		     from < to;
		     from += fd->fdi.cpt_next) {

			fd = obj_alloc_to(struct fd_struct, fdi);
			if (!fd)
				return -1;
			INIT_LIST_HEAD(&fd->list);

			if (read_obj_cpt(ctx->fd, CPT_OBJ_FILEDESC, &fd->fdi, from)) {
				obj_free_to(fd);
				pr_err("Can't read files object at @%li\n", (long)from);
				return -1;
			}

			obj_hash_to(fd, from);
			list_add_tail(&fd->list, &files->fd_list);

			show_fd_cont(ctx, fd);
		}
	}
	pr_debug("------------------------------\n\n");

	ret = 0;
out:
	return ret;
}

void free_fs(context_t *ctx)
{
	struct fs_struct *fs;

	while ((fs = obj_pop_unhash_to(CPT_OBJ_FS)))
		obj_free_to(fs);
}

int write_task_fs(context_t *ctx, struct task_struct *t)
{
	FsEntry e = FS_ENTRY__INIT;
	int ret = -1, fd = -1;
	struct fs_struct *fs;

	fs = obj_lookup_to(CPT_OBJ_FS, t->ti.cpt_fs);
	if (!fs) {
		pr_err("No FS object found for task %d at @%li\n",
			t->ti.cpt_pid, (long)t->ti.cpt_fs);
		goto out;
	}

	fd = open_image(ctx, CR_FD_FS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		goto out;

	e.has_umask	= true;
	e.umask		= fs->fsi.cpt_umask;
	e.root_id	= obj_id_of(fs->root);
	e.cwd_id	= obj_id_of(fs->cwd);

	if (write_reg_file_entry(ctx, fs->root)) {
		pr_err("Failed to write reg file for FS root\n");
		goto out;
	}

	if (write_reg_file_entry(ctx, fs->cwd)) {
		pr_err("Failed to write reg file for FS cwd\n");
		goto out;
	}

	ret = pb_write_one(fd, &e, PB_FS);
out:
	close_safe(&fd);

	return ret;
}

static void show_fs_cont(context_t *ctx, struct fs_struct *fs)
{
	pr_debug("\t@%-8li cpt_umask %#6x\n"
		 "\t\troot @%-8li (name --> %s)\n"
		 "\t\tcwd  @%-8li (name --> %s)\n",
		 (long)obj_of(fs)->o_pos, fs->fsi.cpt_umask,
		 (long)obj_of(fs->root)->o_pos, fs->root->name,
		 (long)obj_of(fs->cwd)->o_pos, fs->cwd->name);
}

int read_fs(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_debug("FS\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_FS, &start, &end);

	while (start < end) {
		struct fs_struct *fs;
		off_t file_off;

		fs = obj_alloc_to(struct fs_struct, fsi);
		if (!fs)
			return -1;
		fs->root = fs->cwd = NULL;

		/* fs itself */
		if (read_obj_cpt(ctx->fd, CPT_OBJ_FS, &fs->fsi, start)) {
			obj_free_to(fs);
			pr_err("Can't read fs object at @%li\n", (long)start);
			return -1;
		}

		obj_push_hash_to(fs, CPT_OBJ_FS, start);

		if (fs->fsi.cpt_hdrlen >= fs->fsi.cpt_next) {
			pr_err("FS entry corrupted at @%li\n", (long)start);
			goto out;
		}

		file_off = start + fs->fsi.cpt_hdrlen;

		fs->root = read_file(ctx, file_off, &file_off);
		if (!fs->root) {
			pr_err("FS root entry corrupted at @%li\n", (long)file_off);
			goto out;
		}

		fs->cwd = read_file(ctx, file_off, &file_off);
		if (!fs->cwd) {
			pr_err("FS cwd entry corrupted at @%li\n", (long)file_off);
			goto out;
		}

		start += fs->fsi.cpt_next;
		show_fs_cont(ctx, fs);
	}

	ret = 0;

	pr_debug("------------------------------\n\n");

out:
	return ret;
}

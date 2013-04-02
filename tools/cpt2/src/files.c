#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <linux/major.h>

#include "cpt-image.h"
#include "xmalloc.h"
#include "files.h"
#include "read.h"
#include "log.h"
#include "obj.h"

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

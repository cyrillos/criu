#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <syscall.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <limits.h>

#include "cpt-image.h"
#include "hashtable.h"
#include "fsnotify.h"
#include "xmalloc.h"
#include "string.h"
#include "files.h"
#include "image.h"
#include "read.h"
#include "log.h"
#include "obj.h"
#include "ns.h"

#include "protobuf.h"
#include "../../../protobuf/fsnotify.pb-c.h"

#define INOTIFY_HASH_BITS		10
static DEFINE_HASHTABLE(inotify_hash, INOTIFY_HASH_BITS);
static LIST_HEAD(inotify_list);

struct inotify_struct *inotify_lookup_file(u64 cpt_file)
{
	struct inotify_struct *inotify;

	hash_for_each_key(inotify_hash, inotify, hash, cpt_file) {
		if (inotify->ii.cpt_file == cpt_file)
			return inotify;
	}

	return NULL;
}

static int alloc_fhandle(FhEntry *fh)
{
	fh->n_handle = FH_ENTRY_SIZES__min_entries;
	fh->handle = xmalloc(pb_repeated_size(fh, handle));

	return fh->handle == NULL ? -1 : 0;
}

static void free_fhandle(FhEntry *fh)
{
	xfree(fh->handle);
}

static int write_inotify_fdinfo(context_t *ctx,
				struct file_struct *file,
				struct inotify_struct *inotify)
{
	InotifyWdEntry we = INOTIFY_WD_ENTRY__INIT;
	FhEntry f_handle = FH_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_INOTIFY_WD);
	struct inotify_wd_struct *wd;
	char origin[PATH_MAX];
	int ret = -1;

	if (alloc_fhandle(&f_handle))
		return -1;

	strlcpy(origin, ctx->root, sizeof(origin));

	list_for_each_entry(wd, &inotify->wd_list, list) {
		struct stat st;
		int mnt_id;

		struct {
			unsigned int	handle_bytes;
			int		handle_type;
			unsigned char	f_handle[128];
		} fh;

		fh.handle_bytes	= sizeof(fh.f_handle);

		strlcat(&origin[ctx->root_len], wd->file->name,
			sizeof(origin) - ctx->root_len);

		if (stat(origin, &st)) {
			pr_perror("Failed to stat on %s", origin);
			goto err;
		}

		if (syscall(__NR_name_to_handle_at, AT_FDCWD,
			    origin, &fh, &mnt_id, 0) < 0) {
			pr_perror("name_to_handle_at failed");
			goto err;
		}

		f_handle.type	= fh.handle_type;
		f_handle.bytes	= fh.handle_bytes;

		memcpy(f_handle.handle, fh.f_handle, fh.handle_bytes);

		we.id			= obj_id_of(file);
		we.wd			= wd->wdi.cpt_wd;
		we.mask			= wd->wdi.cpt_mask;
		we.i_ino		= st.st_ino;
		we.s_dev		= root_ns->root->s_dev;
		we.ignored_mask		= 0;		/* FIXME No @ignored_mask in image */
		we.f_handle		= &f_handle;
	}

	ret = pb_write_one(fd, &we, PB_INOTIFY_WD);

err:
	free_fhandle(&f_handle);
	return ret;
}

int write_inotify(context_t *ctx, struct file_struct *file)
{
	InotifyFileEntry ie = INOTIFY_FILE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_INOTIFY);
	struct inotify_struct *inotify;
	int ret = -1;

	if (file->dumped)
		return 0;

	inotify = inotify_lookup_file(obj_pos_of(file));
	if (!inotify) {
		pr_err("No inotify found for file @%li\n",
		       obj_pos_of(file));
		return -1;
	}

	fill_fown(&fown, file);

	ie.id		= obj_id_of(file);
	ie.flags	= file->fi.cpt_flags;
	ie.fown		= &fown;

	ret = write_inotify_fdinfo(ctx, file, inotify);
	if (!ret) {
		ret = pb_write_one(fd, &ie, PB_INOTIFY);
		if (!ret)
			file->dumped = true;
	}

	return ret;
}

void free_inotify(context_t *ctx)
{
	struct inotify_struct *inotify, *n;
	struct inotify_wd_struct *wd, *t;

	list_for_each_entry_safe(inotify, n, &inotify_list, list) {
		list_for_each_entry_safe(wd, t, &inotify->wd_list, list) {
			if (wd->file) {
				xfree(wd->file->name);
				obj_unhash_to(wd->file);
				obj_free_to(wd->file);
			}
			obj_free_to(wd);
		}
		obj_unhash_to(inotify);
		obj_free_to(inotify);
	}
}

static void show_inotify_cont(context_t *ctx, struct inotify_struct *inotify)
{
	struct inotify_wd_struct *wd;

	pr_debug("\t@%-8li file %8li user %d max_events %d last_wd %d\n",
		 (long)obj_of(inotify)->o_pos, (long)inotify->ii.cpt_file,
		 inotify->ii.cpt_user, inotify->ii.cpt_max_events,
		 inotify->ii.cpt_last_wd);

	list_for_each_entry(wd, &inotify->wd_list, list) {
		pr_debug("\t\twd %d mask %x\n",
			 wd->wdi.cpt_wd, wd->wdi.cpt_mask);
		pr_debug("\t\t\tfile @%-8li --> %s\n",
			 (long)obj_of(wd->file)->o_pos,
			 wd->file->name);
	}
}

static int read_inotify_watch(context_t *ctx, off_t start, off_t end, struct inotify_struct *inotify)
{
	while (start < end) {
		struct inotify_wd_struct *wd;
		struct cpt_object_hdr *h;
		struct file_struct *file;
		off_t at;

		wd = obj_alloc_to(struct inotify_wd_struct, wdi);
		if (!wd)
			return -1;
		INIT_LIST_HEAD(&wd->list);
		wd->file = NULL;

		h = (void *)&wd->wdi;
		if (read_obj_cpt(ctx->fd, -1, h, start)) {
			obj_free_to(wd);
			pr_err("Can't read wd object header at @%li\n", (long)start);
			return -1;
		}

		/*
		 * The structure is that: inotify-watch + file series and
		 * queued events then, thus once we met events -- get out,
		 * since we don't support them.
		 */
		if (h->cpt_object == CPT_OBJ_INOTIFY_EVENT) {
			obj_free_to(wd);
			return 0;
		}

		if (read_obj_cpt(ctx->fd, CPT_OBJ_INOTIFY_WATCH, &wd->wdi, start)) {
			obj_free_to(wd);
			pr_err("Can't read wd object at @%li\n", (long)start);
			return -1;
		}

		obj_settype_to(wd, CPT_OBJ_INOTIFY_WATCH);
		obj_setpos_to(wd, start);
		start += wd->wdi.cpt_next;

		file = obj_alloc_to(struct file_struct, fi);
		if (!file)
			return -1;
		file->name = NULL;

		at = obj_of(wd)->o_pos + wd->wdi.cpt_hdrlen;
		if (read_obj_cpt(ctx->fd, CPT_OBJ_FILE, &file->fi, at)) {
			obj_free_to(file);
			pr_err("Can't read file object at %li\n", (long)at);
			return -1;
		}

		obj_hash_typed_to(file, CPT_OBJ_FILE, at);
		wd->file = file;

		if (file->fi.cpt_next <= file->fi.cpt_hdrlen) {
			pr_err("File name expected at @%li\n",
				obj_of(file)->o_pos + file->fi.cpt_hdrlen);
			return -1;
		}

		list_add_tail(&wd->list, &inotify->wd_list);

		at = obj_of(file)->o_pos + file->fi.cpt_hdrlen;
		file->name = read_name(ctx->fd, at, NULL);
		if (IS_ERR(file->name)) {
			file->name = NULL;
			return -1;
		}
	}
	return 0;
}

int read_inotify(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_debug("Inotify\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_INOTIFY, &start, &end);

	while (start < end) {
		struct inotify_struct *inotify;
		off_t from, to;

		inotify = obj_alloc_to(struct inotify_struct, ii);
		if (!inotify)
			return -1;
		INIT_LIST_HEAD(&inotify->list);
		INIT_LIST_HEAD(&inotify->wd_list);

		if (read_obj_cpt(ctx->fd, CPT_OBJ_INOTIFY, &inotify->ii, start)) {
			obj_free_to(inotify);
			pr_err("Can't read file object at %li\n", (long)start);
			return -1;
		}

		hash_add(inotify_hash, &inotify->hash, inotify->ii.cpt_file);
		obj_hash_typed_to(inotify, CPT_OBJ_INOTIFY, start);
		list_add_tail(&inotify->list, &inotify_list);

		start += inotify->ii.cpt_next;

		from = obj_of(inotify)->o_pos + inotify->ii.cpt_hdrlen;
		to = obj_of(inotify)->o_pos + inotify->ii.cpt_next;

		/*
		 * FIXME What about event queue? This is CPT_CONTENT_ARRAY
		 * data, so we need to be ready.
		 */

		ret = read_inotify_watch(ctx, from, to, inotify);
		if (ret) {
			pr_err("Failed readin inotify wds at @%li\n",
				(long)from);
			goto out;
		}

		show_inotify_cont(ctx, inotify);
	}
	ret = 0;

	pr_debug("------------------------------\n\n");
out:
	return ret;
}

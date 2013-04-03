#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <termios.h>

#include <linux/major.h>

#include "cpt-image.h"
#include "xmalloc.h"
#include "files.h"
#include "image.h"
#include "read.h"
#include "log.h"
#include "obj.h"
#include "tty.h"

#include "protobuf.h"
#include "../../../protobuf/fdinfo.pb-c.h"
#include "../../../protobuf/creds.pb-c.h"
#include "../../../protobuf/tty.pb-c.h"

void free_ttys(context_t *ctx)
{
	struct tty_struct *tty;

	while ((tty = obj_pop_unhash_to(CPT_OBJ_TTY)))
		obj_free_to(tty);
}

static int write_tty_info_entry(context_t *ctx, u32 id,
				struct file_struct *file,
				struct cpt_inode_image *inode,
				struct tty_struct *tty)
{
	TtyInfoEntry info		= TTY_INFO_ENTRY__INIT;
	TermiosEntry termios		= TERMIOS_ENTRY__INIT;
	TermiosEntry termios_locked	= TERMIOS_ENTRY__INIT;
	WinsizeEntry winsize		= WINSIZE_ENTRY__INIT;
	TtyPtyEntry pty			= TTY_PTY_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_TTY_INFO);
	int ret = -1;

	struct termios t;
	struct winsize w;

	BUILD_BUG_ON(sizeof(t.c_cc) != sizeof(tty->ti.cpt_c_cc));

	if (file->dumped || tty->dumped)
		return 0;

	info.id			= id;
	info.type		= TTY_TYPE__PTY;
	info.sid		= tty->ti.cpt_session;
	info.pgrp		= tty->ti.cpt_pgrp;
	info.rdev		= inode->cpt_rdev;
	info.pty		= &pty;

	info.locked		= !!tty_flag(tty, TTY_PTY_LOCK);
	info.exclusive		= !!tty_flag(tty, TTY_EXCLUSIVE);
	info.packet_mode	= tty->ti.cpt_packet;

	pty.index		= tty->ti.cpt_index;

	/*
	 * Nothing more on hupp[ed|ing] terminal. A simple case.
	 */
	if (tty_flag(tty, TTY_HUPPING) || tty_flag(tty, TTY_HUPPED)) {
		ret = pb_write_one(fd, &info, PB_TTY_INFO);
		goto out;
	}

	info.termios		= &termios;
	info.termios_locked	= &termios_locked;
	info.winsize		= &winsize;

	termios.n_c_cc		= TERMIOS_NCC;
	termios.c_cc		= xmalloc(pb_repeated_size(&termios, c_cc));

	termios_locked.n_c_cc	= TERMIOS_NCC;
	termios_locked.c_cc	= xmalloc(pb_repeated_size(&termios_locked, c_cc));

	if (!termios.c_cc || !termios_locked.c_cc)
		goto out;

	memzero(&t, sizeof(t));

	memcpy(t.c_cc, tty->ti.cpt_c_cc, sizeof(tty->ti.cpt_c_cc));
	t.c_iflag	= tty->ti.cpt_c_iflag;
	t.c_oflag	= tty->ti.cpt_c_oflag;
	t.c_cflag	= tty->ti.cpt_c_cflag;
	t.c_lflag	= tty->ti.cpt_c_lflag;
	t.c_line	= tty->ti.cpt_c_line;

	/*
	 * FIXME No locked termios in cpt image :(
	 */

	memzero(&w, sizeof(w));
	w.ws_row	= tty->ti.cpt_ws_row;
	w.ws_col	= tty->ti.cpt_ws_col;
	w.ws_xpixel	= tty->ti.cpt_ws_pcol;
	w.ws_ypixel	= tty->ti.cpt_ws_prow;

	ret = pb_write_one(fd, &info, PB_TTY_INFO);

out:
	if (!ret) {
		file->dumped = true;
		tty->dumped = 1;
	}
	xfree(termios.c_cc);
	xfree(termios_locked.c_cc);
	return ret;
}

static int tty_gen_id(int major, int index)
{
	return (index << 1) + (major == TTYAUX_MAJOR);
}

int write_tty_entry(context_t *ctx, struct file_struct *file)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_TTY);
	struct cpt_inode_image *inode;
	struct tty_struct *tty;

	TtyFileEntry e = TTY_FILE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	int ret = -1;

	if (file->dumped)
		return 0;

	inode = obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("Can't find inode for file at @%li\n",
		       (long)obj_of(file)->o_pos);
		return -1;
	}

	tty = obj_lookup_to(CPT_OBJ_TTY, file->fi.cpt_priv);
	if (!tty) {
		pr_err("Can't find tty @%li for file at @%li\n",
		       (long)obj_of(file)->o_pos, (long)file->fi.cpt_priv);
		return -1;
	}

	fill_fown(&fown, file);

	e.id		= obj_id_of(file);
	e.tty_info_id	= tty_gen_id(major(inode->cpt_rdev), tty->ti.cpt_index);
	e.flags		= file->fi.cpt_flags;
	e.fown		= (FownEntry *)&fown;

	ret = write_tty_info_entry(ctx, e.tty_info_id, file, inode, tty);
	if (!ret)
		ret = pb_write_one(fd, &e, PB_TTY);

	return ret;
}

static void show_tty_cont(context_t *ctx, struct tty_struct *tty)
{
	pr_debug("\t@%-8li flags %#16lx link %#8x index %#8x type %#8x subtype %#8x\n"
		 "\t\tpgrp %8d session %8d name %s\n",
		 (long)obj_of(tty)->o_pos, (long)tty->ti.cpt_flags,
		 tty->ti.cpt_link, tty->ti.cpt_index,
		 tty->ti.cpt_drv_type, tty->ti.cpt_drv_subtype,
		 tty->ti.cpt_pgrp, tty->ti.cpt_session, tty->ti.cpt_name);
}

static int is_supported_tty(struct tty_struct *tty)
{
	return ((tty->ti.cpt_drv_type == TTY_DRIVER_TYPE_PTY)	&&
		(tty->ti.cpt_drv_subtype == PTY_TYPE_MASTER	||
		 tty->ti.cpt_drv_subtype == PTY_TYPE_SLAVE));
}

int read_ttys(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_debug("TTYs\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_TTY, &start, &end);

	while (start < end) {
		struct tty_struct *tty;

		tty = obj_alloc_to(struct tty_struct, ti);
		if (!tty)
			goto out;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_TTY, &tty->ti, start)) {
			obj_free_to(tty);
			pr_err("Can't read tty object at @%li\n", (long)start);
			goto out;
		}

		if (!is_supported_tty(tty)) {
			obj_free_to(tty);
			pr_err("Usupported tty object at @%li\n", (long)start);
			goto out;
		}

		obj_push_hash_to(tty, CPT_OBJ_TTY, start);

		start += tty->ti.cpt_hdrlen;
		show_tty_cont(ctx, tty);
	}

	ret = 0;

	pr_debug("------------------------------\n\n");

out:
	return ret;
}

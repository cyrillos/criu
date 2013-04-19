#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/limits.h>

#include "compiler.h"
#include "image.h"

#define GEN_DUMMY_SHOW(_name)			\
	void _name(int fd, struct cr_options *o) { }

GEN_DUMMY_SHOW(show_inventory);
GEN_DUMMY_SHOW(show_files);
GEN_DUMMY_SHOW(show_pagemap);
GEN_DUMMY_SHOW(show_reg_files);
GEN_DUMMY_SHOW(show_eventfds);
GEN_DUMMY_SHOW(show_eventpoll);
GEN_DUMMY_SHOW(show_eventpoll_tfd);
GEN_DUMMY_SHOW(show_signalfd);

GEN_DUMMY_SHOW(show_inotify);
GEN_DUMMY_SHOW(show_inotify_wd);
GEN_DUMMY_SHOW(show_fanotify);
GEN_DUMMY_SHOW(show_fanotify_mark);
GEN_DUMMY_SHOW(show_core);
GEN_DUMMY_SHOW(show_ids);
GEN_DUMMY_SHOW(show_mm);
GEN_DUMMY_SHOW(show_vmas);
GEN_DUMMY_SHOW(show_pipes);
GEN_DUMMY_SHOW(show_pipes_data);
GEN_DUMMY_SHOW(show_fifo);
GEN_DUMMY_SHOW(show_fifo_data);
GEN_DUMMY_SHOW(show_pstree);
GEN_DUMMY_SHOW(show_sigacts);
GEN_DUMMY_SHOW(show_unixsk);
GEN_DUMMY_SHOW(show_inetsk);
GEN_DUMMY_SHOW(show_packetsk);
GEN_DUMMY_SHOW(show_netlinksk);
GEN_DUMMY_SHOW(show_sk_queues);
GEN_DUMMY_SHOW(show_itimers);
GEN_DUMMY_SHOW(show_creds);
GEN_DUMMY_SHOW(show_utsns);
GEN_DUMMY_SHOW(show_ipc_var);
GEN_DUMMY_SHOW(show_ipc_shm);
GEN_DUMMY_SHOW(show_ipc_msg);
GEN_DUMMY_SHOW(show_ipc_sem);
GEN_DUMMY_SHOW(show_fs);
GEN_DUMMY_SHOW(show_remap_files);
GEN_DUMMY_SHOW(show_ghost_file);
GEN_DUMMY_SHOW(show_tcp_stream);
GEN_DUMMY_SHOW(show_mountpoints);
GEN_DUMMY_SHOW(show_netdevices);
GEN_DUMMY_SHOW(show_raw_image);
GEN_DUMMY_SHOW(show_tty);
GEN_DUMMY_SHOW(show_tty_info);
GEN_DUMMY_SHOW(show_file_locks);
GEN_DUMMY_SHOW(show_rlimit);
GEN_DUMMY_SHOW(show_siginfo);

int open_image(context_t *ctx, int type, int flags, ...)
{
	char path[PATH_MAX];
	va_list args;
	int ret = -1;

	va_start(args, flags);
	vsnprintf(path, PATH_MAX, fdset_template[type].fmt, args);
	va_end(args);

	if (flags & O_EXCL) {
		ret = unlinkat(ctx->dfd, path, 0);
		if (ret && errno != ENOENT) {
			pr_perror("Unable to unlink %s", path);
			return -1;
		}
	}

	ret = openat(ctx->dfd, path, flags, CR_FD_PERM);
	if (ret < 0) {
		pr_perror("Unable to open %s", path);
		goto err;
	}

	if (fdset_template[type].magic == RAW_IMAGE_MAGIC)
		goto skip_magic;

	if (flags == O_RDONLY) {
		u32 magic;

		if (read_img(ret, &magic) < 0)
			goto err;
		if (magic != fdset_template[type].magic) {
			pr_err("Magic doesn't match for %s\n", path);
			goto err;
		}
	} else {
		if (write_img(ret, &fdset_template[type].magic))
			goto err;
	}

skip_magic:
	return ret;
err:
	close_safe(&ret);
	return -1;
}

int open_image_fdset(context_t *ctx, struct fdset *fdset, pid_t pid,
		     unsigned int from, unsigned int to, int flags)
{
	unsigned int i;
	int ret;

	for (i = from + 1; i < to; i++) {
		ret = open_image(ctx, i, flags, pid);
		if (ret < 0) {
			if (!(flags & O_CREAT))
				/* caller should check himself */
				continue;
			goto err;
		}
		*fdset_fd_ptr(fdset, i) = ret;
	}

	return 0;

err:
	return -1;
}

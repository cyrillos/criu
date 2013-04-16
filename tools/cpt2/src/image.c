#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/limits.h>

#include "image.h"

#define FD_ENTRY(_name, _fmt)			\
	[CR_FD_##_name] = {			\
		.fmt	= _fmt ".img",		\
		.magic	= _name##_MAGIC,	\
	}

struct cr_fd_desc_tmpl template[CR_FD_MAX] = {
	FD_ENTRY(INVENTORY,		"inventory"),
	FD_ENTRY(FDINFO,		"fdinfo-%d"),
	FD_ENTRY(PAGEMAP,		"pagemap-%ld"),
	FD_ENTRY(SHMEM_PAGEMAP,		"pagemap-shmem-%ld"),
	FD_ENTRY(REG_FILES,		"reg-files"),
	FD_ENTRY(EVENTFD,		"eventfd"),
	FD_ENTRY(EVENTPOLL,		"eventpoll"),
	FD_ENTRY(EVENTPOLL_TFD,		"eventpoll-tfd"),
	FD_ENTRY(SIGNALFD,		"signalfd"),
	FD_ENTRY(INOTIFY,		"inotify"),
	FD_ENTRY(INOTIFY_WD,		"inotify-wd"),
	FD_ENTRY(FANOTIFY,		"fanotify"),
	FD_ENTRY(FANOTIFY_MARK,		"fanotify-mark"),
	FD_ENTRY(CORE,			"core-%d"),
	FD_ENTRY(IDS,			"ids-%d"),
	FD_ENTRY(MM,			"mm-%d"),
	FD_ENTRY(VMAS,			"vmas-%d"),
	FD_ENTRY(PIPES,			"pipes"),
	FD_ENTRY(PIPES_DATA,		"pipes-data"),
	FD_ENTRY(FIFO,			"fifo"),
	FD_ENTRY(FIFO_DATA,		"fifo-data"),
	FD_ENTRY(PSTREE,		"pstree"),
	FD_ENTRY(SIGACT,		"sigacts-%d"),
	FD_ENTRY(UNIXSK,		"unixsk"),
	FD_ENTRY(INETSK,		"inetsk"),
	FD_ENTRY(PACKETSK,		"packetsk"),
	FD_ENTRY(NETLINKSK,		"netlinksk"),
	FD_ENTRY(SK_QUEUES,		"sk-queues"),
	FD_ENTRY(ITIMERS,		"itimers-%d"),
	FD_ENTRY(CREDS,			"creds-%d"),
	FD_ENTRY(UTSNS,			"utsns-%d"),
	FD_ENTRY(IPCNS_VAR,		"ipcns-var-%d"),
	FD_ENTRY(IPCNS_SHM,		"ipcns-shm-%d"),
	FD_ENTRY(IPCNS_MSG,		"ipcns-msg-%d"),
	FD_ENTRY(IPCNS_SEM,		"ipcns-sem-%d"),
	FD_ENTRY(FS,			"fs-%d"),
	FD_ENTRY(REMAP_FPATH,		"remap-fpath"),
	FD_ENTRY(GHOST_FILE,		"ghost-file-%x"),
	FD_ENTRY(TCP_STREAM,		"tcp-stream-%x"),
	FD_ENTRY(MOUNTPOINTS,		"mountpoints-%d"),
	FD_ENTRY(NETDEV,		"netdev-%d"),
	FD_ENTRY(IFADDR,		"ifaddr-%d"),
	FD_ENTRY(ROUTE,			"route-%d"),
	FD_ENTRY(TMPFS,			"tmpfs-%d.tar.gz"),
	FD_ENTRY(TTY,			"tty"),
	FD_ENTRY(TTY_INFO,		"tty-info"),
	FD_ENTRY(FILE_LOCKS,		"filelocks-%d"),
	FD_ENTRY(RLIMIT,		"rlimit"),
	FD_ENTRY(PAGES,			"pages-%u"),
	FD_ENTRY(PAGES_OLD,		"pages-%d"),
	FD_ENTRY(SHM_PAGES_OLD,		"pages-shmem-%ld"),
	FD_ENTRY(SIGNAL,		"signal-s-%d"),
	FD_ENTRY(PSIGNAL,		"signal-p-%d"),
};

int open_image(context_t *ctx, int type, int flags, ...)
{
	char path[PATH_MAX];
	va_list args;
	int ret = -1;

	va_start(args, flags);
	vsnprintf(path, PATH_MAX, template[type].fmt, args);
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

	if (template[type].magic == RAW_IMAGE_MAGIC)
		goto skip_magic;

	if (flags == O_RDONLY) {
		u32 magic;

		if (read_img(ret, &magic) < 0)
			goto err;
		if (magic != template[type].magic) {
			pr_err("Magic doesn't match for %s\n", path);
			goto err;
		}
	} else {
		if (write_img(ret, &template[type].magic))
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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "protobuf.h"
#include "context.h"
#include "convert.h"
#include "image.h"
#include "read.h"
#include "task.h"
#include "cpt2.h"
#include "log.h"

static int write_stubs(context_t *ctx)
{
	int fd;

#define gen_stub(type)						\
	do {							\
		fd = open_image(ctx, CR_FD_##type, O_DUMP);	\
		if (fd < 0)					\
			return -1;				\
		close(fd);					\
	} while (0)

	gen_stub(EVENTFD);
	gen_stub(EVENTPOLL);
	gen_stub(EVENTPOLL_TFD);
	gen_stub(SIGNALFD);
	gen_stub(INOTIFY);
	gen_stub(INOTIFY_WD);
	gen_stub(FANOTIFY);
	gen_stub(FANOTIFY_MARK);
	gen_stub(PIPES);
	gen_stub(PIPES_DATA);
	gen_stub(FIFO);
	gen_stub(FIFO_DATA);
	gen_stub(UNIXSK);
	gen_stub(INETSK);
	gen_stub(PACKETSK);
	gen_stub(SK_QUEUES);
	gen_stub(REMAP_FPATH);
	gen_stub(TTY);
	gen_stub(TTY_INFO);
	gen_stub(RLIMIT);
	gen_stub(NETLINKSK);
#undef gen_stub

	return 0;
}

int convert(void)
{
	context_t ctx;
	int ret = -1;

	context_init(&ctx);
	pb_init();

	ctx.dfd = open(global_opts.criu_dirname, O_RDONLY);
	if (ctx.dfd < 0) {
		pr_perror("Can't open directory %s\n",
			  global_opts.criu_dirname);
		goto out;
	}

	ctx.fd = open(global_opts.cpt_filename, O_RDONLY);
	if (ctx.fd < 0) {
		pr_perror("Can't open checkpoint file %s\n",
			  global_opts.cpt_filename);
		goto out;
	}

	ret = context_init_fdset_glob(&ctx);
	if (ret)
		goto out;

	ret = read_dumpfile(&ctx);
	if (ret) {
		pr_err("Failed reading dumpfile %s\n",
		       global_opts.cpt_filename);
		goto out;
	}

	ret = write_task_images(&ctx);
	if (ret) {
		pr_err("Failed to write task images\n");
		goto out;
	}

	ret = write_pstree(&ctx);
	if (ret) {
		pr_err("Failed writting process tree\n");
		goto out;
	}

	ret = write_stubs(&ctx);
	if (ret) {
		pr_err("Failed writting stubs\n");
		goto out;
	}

	pr_err("Conversion is not yet implemented\n");
	ret = -1;
out:
	read_fini(&ctx);
	context_fini(&ctx);
	return ret;
}

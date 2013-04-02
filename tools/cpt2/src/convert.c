#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "protobuf.h"
#include "context.h"
#include "convert.h"
#include "read.h"
#include "cpt2.h"
#include "log.h"

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

	pr_err("Conversion is not yet implemented\n");
	ret = -1;
out:
	read_fini(&ctx);
	context_fini(&ctx);
	return ret;
}

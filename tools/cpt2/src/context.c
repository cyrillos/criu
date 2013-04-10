#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "compiler.h"
#include "context.h"
#include "xmalloc.h"
#include "image.h"
#include "types.h"
#include "io.h"

int context_init_fdset_glob(context_t *ctx)
{
	struct fdset *fdset;

	fdset = fdset_alloc(_CR_FD_GLOB_FROM,
			    _CR_FD_GLOB_TO - _CR_FD_GLOB_FROM);
	if (!fdset) {
		pr_err("Can't allocate glob fdset\n");
		return -1;
	}
	ctx->fdset_glob = fdset;

	if (open_image_fdset(ctx, fdset, -1,
			     _CR_FD_GLOB_FROM,
			     _CR_FD_GLOB_TO, O_DUMP)) {
		pr_err("Failed to open glob fdset\n");
		return -1;
	}

	return 0;
}

void context_fini_fdset_glob(context_t *ctx)
{
	if (ctx->fdset_glob) {
		fdset_close(ctx->fdset_glob, _CR_FD_GLOB_FROM, _CR_FD_GLOB_TO);
		fdset_free(&ctx->fdset_glob);
	}
}

void context_init(context_t *ctx)
{
	memzero(ctx, sizeof(*ctx));
	ctx->fd = ctx->dfd = -1;
}

void context_fini(context_t *ctx)
{
	close_safe(&ctx->fd);
	close_safe(&ctx->dfd);
	context_fini_fdset_glob(ctx);
}

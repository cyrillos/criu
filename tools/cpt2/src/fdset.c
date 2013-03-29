#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "xmalloc.h"
#include "fdset.h"
#include "io.h"

struct fdset *fdset_alloc(unsigned int offset, unsigned int number)
{
	unsigned long len = sizeof(int) * number;
	struct fdset *p = xmalloc(sizeof(*p) + len);

	if (p) {
		p->offset	= offset;
		p->number	= number;

		memset(p->__fd, 0xff, len);
	}

	return p;
}

void fdset_close(struct fdset *fdset, unsigned int from, unsigned int to)
{
	unsigned int i;

	for (i = from; i < to; i++) {
		int *fd = fdset_fd_ptr(fdset, i);
		if (!fd)
			break;
		close_safe(fd);
	}
}

static inline void __fdset_free(struct fdset *fdset)
{
	fdset_close(fdset, fdset->offset, fdset->number);
	xfree(fdset);
}

void fdset_free(struct fdset **fdset)
{
	if (fdset) {
		__fdset_free(*fdset);
		*fdset = NULL;
	}
}

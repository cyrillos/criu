/*
 * FIXME
 *
 * These fdset operations are close to ones used in crtools
 * code so need to retrieve fdset ops from crtools sources
 * and make them shared.
 */
#ifndef __CPT2_FDSET_H__
#define __CPT2_FDSET_H__

#include "compiler.h"

struct fdset {
	unsigned int	offset;		/* which offset caller prefer to count fd from */
	unsigned int	number;		/* amount of fd in a set */

	char __fd[0]	__aligned(8);
};

static inline int *fdset_fd_ptr(struct fdset *fdset, unsigned int offset)
{
	if ((offset - fdset->offset) < fdset->number)
		return &((int *)fdset->__fd)[offset - fdset->offset];
	return NULL;
}

static inline int fdset_fd(struct fdset *fdset, unsigned int offset)
{
	int *fd = fdset_fd_ptr(fdset, offset);

	return fd ? *fd : -1;
}

extern struct fdset *fdset_alloc(unsigned int offset, unsigned int number);
extern void fdset_close(struct fdset *fdset, unsigned int from, unsigned int to);
extern void fdset_free(struct fdset **fdset);

#endif /* __CPT2_FDSET_H__ */

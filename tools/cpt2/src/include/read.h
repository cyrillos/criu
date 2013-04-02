#ifndef __CPT2_READ_H__
#define __CPT2_READ_H__

#include <sys/types.h>

#include "context.h"

extern void get_section_bounds(context_t *ctx, int type, off_t *start, off_t *end);
extern char *read_name(int fd, off_t pos, off_t *next);
extern int read_dumpfile(context_t *ctx);
extern void read_fini(context_t *ctx);

#endif /* __CPT2_READ_H__ */

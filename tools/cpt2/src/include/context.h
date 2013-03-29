#ifndef __CPT2_CONTEXT_H__
#define __CPT2_CONTEXT_H__

#include <unistd.h>

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <limits.h>

#include "cpt-image.h"
#include "fdset.h"
#include "list.h"

typedef struct context {
	int			fd;		/* dumpfile */
	int			dfd;		/* output dir */
	struct stat		st;		/* stat on @fd */

	int			rootfd;		/* where container's root fs lives */
	struct stat		stroot;

	char			root[PATH_MAX];
	size_t			root_len;

	struct cpt_major_hdr	h;
	struct cpt_major_tail	t;
	struct cpt_veinfo_image	veinfo;

	/*
	 * This represents offsets for data inside
	 * section, ie the section header itself
	 * is not counter here.
	 */
	off_t			sections[CPT_SECT_MAX][2];

	struct fdset		*fdset_glob;
} context_t;

extern void context_init(context_t *ctx);
extern void context_fini(context_t *ctx);

extern int context_init_fdset_glob(context_t *ctx);
extern void context_fini_fdset_glob(context_t *ctx);

#endif /* __CPT2_CONTEXT_H__ */

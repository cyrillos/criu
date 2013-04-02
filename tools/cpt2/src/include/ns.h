#ifndef __CPT2_NS_H__
#define __CPT2_NS_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compiler.h"
#include "context.h"

struct vfsmnt_struct {
	struct list_head		list;

	int				s_dev;
	char				*mnt_dev;
	char				*mnt_point;
	char				*mnt_type;

	struct cpt_vfsmount_image	vfsmnt;
};


struct ns_struct {
	struct list_head		list;

	struct vfsmnt_struct		*root;

	struct cpt_object_hdr		nsi;
};

extern int read_ns(context_t *ctx);
extern void free_ns(context_t *ctx);

#endif /* __CPT2_NS_H__ */

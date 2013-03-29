#ifndef __CPT2_FSNOTIFY_H__
#define __CPT2_FSNOTIFY_H__

#include <stdbool.h>

#include "cpt-image.h"
#include "context.h"
#include "list.h"
#include "obj.h"

struct inotify_struct {
	struct list_head		list;

	struct hlist_node		hash;
	struct list_head		wd_list;

	struct cpt_inotify_image	ii;
};

struct inotify_wd_struct {
	struct list_head		list;

	struct cpt_inotify_wd_image	wdi;
	struct file_struct		*file;
};

extern struct inotify_struct *inotify_lookup_file(u64 cpt_file);

extern int read_inotify(context_t *ctx);
extern void free_inotify(context_t *ctx);

extern int write_inotify(context_t *ctx, struct file_struct *file);

#endif /* __CPT2_FSNOTIFY_H__ */

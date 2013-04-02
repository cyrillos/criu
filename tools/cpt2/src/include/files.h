#ifndef __CPT2_FILES_H__
#define __CPT2_FILES_H__

#include <stdbool.h>

#include "cpt-image.h"
#include "context.h"
#include "types.h"
#include "list.h"
#include "obj.h"

#include "../../../../protobuf/fown.pb-c.h"
#include "../../../../protobuf/fdinfo.pb-c.h"

struct task_struct;

struct file_struct {
	bool				dumped;
	char				*name;

	struct cpt_file_image		fi;
};

struct files_struct {
	struct list_head		fd_list;

	struct cpt_files_struct_image	fsi;
};

struct fd_struct {
	struct list_head		list;

	struct cpt_fd_image		fdi;
};

struct fs_struct {
	struct file_struct		*root;
	struct file_struct		*cwd;

	struct cpt_fs_struct_image	fsi;
};

extern int read_files(context_t *ctx);
extern void free_files(context_t *ctx);

extern int read_inodes(context_t *ctx);
extern void free_inodes(context_t *ctx);

extern int read_fs(context_t *ctx);
extern void free_fs(context_t *ctx);

#endif /* __CPT2_FILES_H__ */

#ifndef __CPT2_OBJ_H__
#define __CPT2_OBJ_H__

#include <sys/types.h>

#include "cpt-image.h"
#include "compiler.h"
#include "types.h"
#include "list.h"
#include "bug.h"
#include "err.h"

#define OBJ_ANY			-1

typedef struct obj_s {
	off_t			o_pos;		/* object position */
	struct hlist_node	o_hash;		/* for hashing */
	struct list_head	o_list;		/* for linear linking */
	int			o_type;		/* object type */
	u32			o_id;		/* object unique id */

	void			*o_image;	/* might point somewhere inside payload */

	size_t			o_size;		/* payload size */
	char			__payload[0] __aligned(8);
} obj_t;

static inline void obj_setpos(obj_t *obj, off_t pos)
{
	obj->o_pos = pos;
}

static inline void obj_settype(obj_t *obj, int objtype)
{
	obj->o_type = objtype;
}

extern obj_t *obj_hash_lookup(int objtype, off_t pos);
extern void obj_hash(obj_t *obj, off_t pos);
extern void obj_hash_typed(obj_t *obj, int objtype, off_t pos);
extern void obj_unhash(obj_t *obj);

extern char *obj_name(int objtype);

extern void obj_push(obj_t *obj, int objtype);
extern obj_t *pop_obj(int objtype);

extern obj_t *obj_alloc(size_t size);
extern void obj_free(obj_t *obj);
extern void obj_free_safe(obj_t **obj);

extern int read_obj(int fd, int objtype, void *p, size_t size, off_t pos);

/*
 * Object read image data helpers
 */

#define read_obj_hdr(fd, p, pos)					\
	read_obj(fd, OBJ_ANY, p, sizeof(struct cpt_object_hdr), pos)

#define read_obj_cpt(fd, objtype, p, pos)				\
	read_obj(fd, objtype, p, sizeof(*(p)), pos)

#define read_obj_cont(fd, p)						\
({									\
	int __ret = -1;							\
	void *__p = (void *)(p) + sizeof(struct cpt_object_hdr);	\
	u64 __size = sizeof(*p) - sizeof(struct cpt_object_hdr);	\
									\
	if (read_data(fd, __p, __size, false) == 0)			\
		__ret = 0;						\
	else								\
		pr_err("Can't read object payload\n");			\
									\
	__ret;								\
})

#define read_obj_cpt_cont(fd, p)					\
({									\
	int __ret = -1;							\
	void *__p = (void *)(p) + sizeof(struct cpt_object_hdr);	\
	u64 __size = sizeof(*(p)) - sizeof(struct cpt_object_hdr);	\
									\
	if (read_data(fd, __p, __size, false) == 0)			\
		__ret = 0;						\
	else								\
		pr_err("Can't read object payload\n");			\
									\
	__ret;								\
})

/*
 * General object helpers
 */

#define obj_push_hash(obj, objtype, pos)				\
	do {								\
		obj_push(obj, objtype);					\
		obj_hash(obj, pos);					\
	} while (0)

#define obj_pop_unhash(objtype)						\
({									\
	obj_t *__o = pop_obj(objtype);					\
	if (__o)							\
		obj_unhash(__o);					\
	__o;								\
})

/*
 * Compound object helpers. It's implied that composite type
 * is declared as
 *
 * struct name {
 *	arbitrary member
 *	arbitrary member
 *	...
 *	cpt_image member
 * }
 *
 * _to() helpers work with poiter to compoun type
 * _of() helpers work with pointer to obj_t
 */

#define obj_of(ptr)							\
	((obj_t *)((void *)ptr - sizeof(obj_t)))

#define obj_to(obj)							\
	((void *)((void *)obj + sizeof(obj_t)))

#define obj_set_image_to(obj, type, img_member)				\
do {									\
	__obj->o_image = (void *)__obj->__payload +			\
		offsetof(type, img_member);				\
} while (0)

#define obj_set_image_of(ptr, img_member)				\
do {									\
	obj_t *__obj = obj_of(ptr);					\
	obj_set_image_to(__obj, typeof(*ptr), img_member);		\
} while (0)

#define obj_alloc_to(type, img_member)					\
({									\
	obj_t *__obj = obj_alloc(sizeof(type));				\
	type *__ptr;							\
									\
	if (__obj) {							\
		__ptr = obj_to(__obj);					\
		obj_set_image_to(__obj, type, img_member);		\
	} else								\
		__ptr = NULL;						\
	__ptr;								\
})

#define obj_free_to(ptr)						\
	obj_free(obj_of(ptr))

#define obj_push_hash_to(ptr, objtype, pos)				\
	obj_push_hash(obj_of(ptr), objtype, pos)

#define obj_hash_typed_to(ptr, objtype, pos)				\
	obj_hash_typed(obj_of(ptr), objtype, pos)

#define obj_hash_to(ptr, pos)						\
	obj_hash(obj_of(ptr), pos)

#define obj_unhash_to(ptr)						\
	obj_unhash(obj_of(ptr))

#define obj_settype_to(ptr, objtype)					\
	obj_settype(obj_of(ptr), objtype)

#define obj_setpos_to(ptr, pos)						\
	obj_setpos(obj_of(ptr), pos)

#define obj_pop_unhash_to(objtype)					\
({									\
	obj_t *__obj = obj_pop_unhash(objtype);				\
	void *__ptr;							\
									\
	if (__obj)							\
		__ptr = obj_to(__obj);					\
	else								\
		__ptr = NULL;						\
	__ptr;								\
})

#define obj_lookup_to(objtype, pos)					\
({									\
	obj_t *__obj = obj_hash_lookup(objtype, pos);			\
	void *__ptr;							\
									\
	if (__obj)							\
		__ptr = obj_to(__obj);					\
	else {								\
		__ptr = NULL;						\
		pr_err("Can't find `%s' at @%li\n",			\
		       obj_name(objtype), (long)pos);			\
	}								\
	__ptr;								\
})

#define obj_lookup_img(objtype, pos)					\
({									\
	obj_t *__obj = obj_hash_lookup(objtype, pos);			\
	void *__ptr;							\
									\
	if (__obj)							\
		__ptr = __obj->o_image;					\
	else {								\
		__ptr = NULL;						\
		pr_err("Can't find `%s' at @%li\n",			\
		       obj_name(objtype), (long)pos);			\
	}								\
	__ptr;								\
})

#define obj_id_of(ptr)							\
	obj_of((ptr))->o_id

#define obj_pos_of(ptr)							\
	((long)(obj_of(ptr)->o_pos))

#define obj_set_eos(str)						\
	do {								\
		((char *)str)[sizeof(str) - 1] = '\0';			\
	} while (0)

#endif /* __CPT2_OBJ_H__ */

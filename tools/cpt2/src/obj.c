#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>

#include "xmalloc.h"
#include "types.h"

#include "hashtable.h"
#include "image.h"
#include "bug.h"
#include "obj.h"

static u32 obj_ids = 1;

/*
 * 16K hash should be more than enough.
 */
#define OBJS_HASH_BITS		14
static DEFINE_HASHTABLE(objs_hash, OBJS_HASH_BITS);

static struct list_head objects[CPT_OBJ_MAX] = {
#define __obj_list_init(objtype) [objtype] = LIST_HEAD_INIT(objects[objtype])
	__obj_list_init(CPT_OBJ_TASK),
	__obj_list_init(CPT_OBJ_MM),
	__obj_list_init(CPT_OBJ_FS),
	__obj_list_init(CPT_OBJ_FILES),
	__obj_list_init(CPT_OBJ_FILE),
	__obj_list_init(CPT_OBJ_SIGHAND_STRUCT),
	__obj_list_init(CPT_OBJ_SIGNAL_STRUCT),
	__obj_list_init(CPT_OBJ_TTY),
	__obj_list_init(CPT_OBJ_SOCKET),
	__obj_list_init(CPT_OBJ_SYSVSEM_UNDO),
	__obj_list_init(CPT_OBJ_NAMESPACE),
	__obj_list_init(CPT_OBJ_SYSV_SHM),
	__obj_list_init(CPT_OBJ_INODE),
	__obj_list_init(CPT_OBJ_UBC),
	__obj_list_init(CPT_OBJ_SLM_SGREG),
	__obj_list_init(CPT_OBJ_SLM_REGOBJ),
	__obj_list_init(CPT_OBJ_SLM_MM),
	__obj_list_init(CPT_OBJ_VFSMOUNT_REF),
	__obj_list_init(CPT_OBJ_CGROUP),
	__obj_list_init(CPT_OBJ_CGROUPS),
	__obj_list_init(CPT_OBJ_POSIX_TIMER_LIST),
#undef __obj_list_init
};

char *obj_name(int objtype)
{
#define __obj_name(name)	case name: return __stringify_1(name);
	switch (objtype) {
	case OBJ_ANY: return "ANY";

	__obj_name(CPT_OBJ_TASK)
	__obj_name(CPT_OBJ_MM)
	__obj_name(CPT_OBJ_FS)
	__obj_name(CPT_OBJ_FILES)
	__obj_name(CPT_OBJ_FILE)
	__obj_name(CPT_OBJ_SIGHAND_STRUCT)
	__obj_name(CPT_OBJ_SIGNAL_STRUCT)
	__obj_name(CPT_OBJ_TTY)
	__obj_name(CPT_OBJ_SOCKET)
	__obj_name(CPT_OBJ_SYSVSEM_UNDO)
	__obj_name(CPT_OBJ_NAMESPACE)
	__obj_name(CPT_OBJ_SYSV_SHM)
	__obj_name(CPT_OBJ_INODE)
	__obj_name(CPT_OBJ_UBC)
	__obj_name(CPT_OBJ_SLM_SGREG)
	__obj_name(CPT_OBJ_SLM_REGOBJ)
	__obj_name(CPT_OBJ_SLM_MM)
	__obj_name(CPT_OBJ_VFSMOUNT_REF)
	__obj_name(CPT_OBJ_CGROUP)
	__obj_name(CPT_OBJ_CGROUPS)
	__obj_name(CPT_OBJ_POSIX_TIMER_LIST)

	__obj_name(CPT_OBJ_MAX)

	__obj_name(CPT_OBJ_VMA)
	__obj_name(CPT_OBJ_FILEDESC)
	__obj_name(CPT_OBJ_SIGHANDLER)
	__obj_name(CPT_OBJ_SIGINFO)
	__obj_name(CPT_OBJ_LASTSIGINFO)
	__obj_name(CPT_OBJ_SYSV_SEM)
	__obj_name(CPT_OBJ_SKB)
	__obj_name(CPT_OBJ_FLOCK)
	__obj_name(CPT_OBJ_OPENREQ)
	__obj_name(CPT_OBJ_VFSMOUNT)
	__obj_name(CPT_OBJ_TRAILER)
	__obj_name(CPT_OBJ_SYSVSEM_UNDO_REC)
	__obj_name(CPT_OBJ_NET_DEVICE)
	__obj_name(CPT_OBJ_NET_IFADDR)
	__obj_name(CPT_OBJ_NET_ROUTE)
	__obj_name(CPT_OBJ_NET_CONNTRACK)
	__obj_name(CPT_OBJ_NET_CONNTRACK_EXPECT)
	__obj_name(CPT_OBJ_AIO_CONTEXT)
	__obj_name(CPT_OBJ_VEINFO)
	__obj_name(CPT_OBJ_EPOLL)
	__obj_name(CPT_OBJ_EPOLL_FILE)
	__obj_name(CPT_OBJ_SKFILTER)
	__obj_name(CPT_OBJ_SIGALTSTACK)
	__obj_name(CPT_OBJ_SOCK_MCADDR)
	__obj_name(CPT_OBJ_BIND_MNT)
	__obj_name(CPT_OBJ_SYSVMSG)
	__obj_name(CPT_OBJ_SYSVMSG_MSG)
	__obj_name(CPT_OBJ_MM_AUXV)
	__obj_name(CPT_OBJ_X86_REGS)
	__obj_name(CPT_OBJ_X86_64_REGS)
	__obj_name(CPT_OBJ_PAGES)
	__obj_name(CPT_OBJ_COPYPAGES)
	__obj_name(CPT_OBJ_REMAPPAGES)
	__obj_name(CPT_OBJ_LAZYPAGES)
	__obj_name(CPT_OBJ_NAME)
	__obj_name(CPT_OBJ_BITS)
	__obj_name(CPT_OBJ_REF)
	__obj_name(CPT_OBJ_ITERPAGES)
	__obj_name(CPT_OBJ_ITERYOUNGPAGES)
	__obj_name(CPT_OBJ_VSYSCALL)
	__obj_name(CPT_OBJ_IA64_REGS)
	__obj_name(CPT_OBJ_INOTIFY)
	__obj_name(CPT_OBJ_INOTIFY_WATCH)
	__obj_name(CPT_OBJ_INOTIFY_EVENT)
	__obj_name(CPT_OBJ_TASK_AUX)
	__obj_name(CPT_OBJ_NET_TUNTAP)
	__obj_name(CPT_OBJ_NET_HWADDR)
	__obj_name(CPT_OBJ_NET_VETH)
	__obj_name(CPT_OBJ_NET_STATS)
	__obj_name(CPT_OBJ_NET_IPIP_TUNNEL)
	__obj_name(CPT_OBJ_TIMERFD)
	__obj_name(CPT_OBJ_EVENTFD)
	__obj_name(CPT_OBJ_NET_BR)
	__obj_name(CPT_OBJ_NET_BR_DEV)
	__obj_name(CPT_OBJ_POSIX_TIMER)
	__obj_name(CPT_OBJ_NET_TAP_FILTER)
	}
#undef __obj_name

	return "UNKNOWN";
}

obj_t *obj_hash_lookup(int objtype, off_t pos)
{
	obj_t *obj;

	hash_for_each_key(objs_hash, obj, o_hash, pos) {
		if (obj->o_pos == pos &&
		    obj->o_type == objtype)
			return obj;
	}

	return NULL;
}

void obj_hash(obj_t *obj, off_t pos)
{
	obj_setpos(obj, pos);
	hash_add(objs_hash, &obj->o_hash, obj->o_pos);
}

void obj_hash_typed(obj_t *obj, int objtype, off_t pos)
{
	obj_setpos(obj, pos);
	obj_settype(obj, objtype);

	hash_add(objs_hash, &obj->o_hash, obj->o_pos);
}

void obj_unhash(obj_t *obj)
{
	hlist_del_init(&obj->o_hash);
}

void obj_push(obj_t *obj, int objtype)
{
	BUG_ON(objtype >= CPT_OBJ_MAX);

	obj_settype(obj, objtype);
	list_add(&obj->o_list, &objects[objtype]);
}

obj_t *pop_obj(int objtype)
{
	struct list_head *head;
	obj_t *obj = NULL;

	BUG_ON(objtype >= CPT_OBJ_MAX);
	head = &objects[objtype];
	if (!list_empty(head)) {
		obj = list_first_entry(head, obj_t, o_list);
		list_del(&obj->o_list);
	}

	return obj;
}

static void obj_reset(obj_t *obj, size_t size)
{
	memzero(obj, sizeof(*obj));

	INIT_LIST_HEAD(&obj->o_list);
	INIT_HLIST_NODE(&obj->o_hash);

	obj->o_id	= obj_ids++;
	obj->o_size	= size;
	obj->o_image	= obj->__payload;
}

obj_t *obj_alloc(size_t size)
{
	obj_t *obj = xmalloc(sizeof(*obj) + size);
	if (obj)
		obj_reset(obj, size);
	return obj;
}

void obj_free(obj_t *obj)
{
	if (obj)
		xfree(obj);
}

void obj_free_safe(obj_t **obj)
{
	if (obj) {
		obj_free(*obj);
		*obj = NULL;
	}
}

int read_obj(int fd, int objtype, void *p, size_t size, off_t pos)
{
	struct cpt_object_hdr *h = p;

	if (size < sizeof(*h)) {
		pr_err("Buffer is too small: %ld (required: %ld) at %ld\n",
		       (long)size, sizeof(*h), (long)pos);
		return -1;
	} else if (__read_ptr_at(fd, h, pos)) {
		pr_err("Can't read object header type %d (%s) at %ld\n",
		       objtype, obj_name(objtype), (long)pos);
		return -1;
	} else if (objtype > OBJ_ANY && objtype != h->cpt_object) {
		pr_err("Wrong object type %d (%s) but %d (%s) expected at %ld\n",
		       h->cpt_object, obj_name(h->cpt_object),
		       objtype, obj_name(objtype), (long)pos);
		return -1;
	} else if (h->cpt_hdrlen > h->cpt_next) {
		pr_err("Bad object size: %d (next object in %ld) at %ld\n",
		       (int)h->cpt_hdrlen, (long)h->cpt_next, (long)pos);
		return -1;
	} else if (h->cpt_hdrlen < sizeof(*h)) {
		pr_err("Bad header length: %d (object size: %ld) at %ld\n",
		       h->cpt_hdrlen, (long)h->cpt_next, (long)pos);
		return -1;
	} else if (size > h->cpt_hdrlen) {
		memzero(p + h->cpt_hdrlen, size - h->cpt_hdrlen);
		size = h->cpt_hdrlen;
	}

	if (size > sizeof(*h)) {
		if (__read(fd, &h[1], size - sizeof(*h))) {
			pr_err("Reading object type %d (%s) failed at %ld\n",
			       objtype, obj_name(objtype), (long)pos);
			return -1;
		}
	}

	return 0;
}

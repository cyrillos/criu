#ifndef __CR_SERVICE_FD_H__
#define __CR_SERVICE_FD_H__

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "criu-log.h"

enum sfd_type {
	SERVICE_FD_MIN,

	LOG_FD_OFF,
	IMG_FD_OFF,
	PROC_FD_OFF,		/* fd with /proc for all proc_ calls */
	PROC_PID_FD_OFF,
	CR_PROC_FD_OFF,		/* some other's proc fd:
				 *  - For dump -- target ns' proc
				 *  - For restore -- CRIU ns' proc
				 */
	ROOT_FD_OFF,		/* Root of the namespace we dump/restore */
	CGROUP_YARD,
	USERNSD_SK,		/* Socket for usernsd */
	NS_FD_OFF,		/* Node's net namespace fd */
	TRANSPORT_FD_OFF,	/* to transfer file descriptors */
	RPC_SK_OFF,
	FDSTORE_SK_OFF,

	SERVICE_FD_MAX
};

struct pstree_item;
extern bool sfds_protected;

#define sfd_verify_targtet(_type, _old_fd, _new_fd)					\
	do {										\
		char self_path[64];							\
											\
		snprintf(self_path, sizeof(self_path), "/proc/self/fd/%d", _new_fd);	\
		if (!access(self_path, F_OK)) {						\
			pr_warn("%s busy target %d -> %d\n",				\
				sfd_type_name(_type), _old_fd, _new_fd);		\
		}									\
	} while (0)

extern const char *sfd_type_name(enum sfd_type type);
extern int init_service_fd(void);
extern int get_service_fd(enum sfd_type type);
extern bool is_any_service_fd(int fd);
extern bool is_service_fd(int fd, enum sfd_type type);
extern int service_fd_min_fd(struct pstree_item *item);
extern int install_service_fd(enum sfd_type type, int fd);
extern int close_service_fd(enum sfd_type type);
extern int clone_service_fd(struct pstree_item *me);

#endif /* __CR_SERVICE_FD_H__ */

#ifndef __CR_EVENTPOLL_H__
#define __CR_EVENTPOLL_H__

#include "files.h"

extern int is_eventpoll_link(char *link);
extern int flush_eventpoll_dinfo_queue(void);
extern int eventpoll_init(void);

extern int eventpoll_notify_pre_open(pid_t pid, int tfd);
extern int eventpoll_notify_open(pid_t pid, int tfd);

extern const struct fdtype_ops eventpoll_dump_ops;
extern struct collect_image_info epoll_tfd_cinfo;
extern struct collect_image_info epoll_cinfo;

#endif /* __CR_EVENTPOLL_H__ */

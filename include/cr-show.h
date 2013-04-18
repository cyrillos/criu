#ifndef __CR_SHOW_H__
#define __CR_SHOW_H__

struct cr_options;

extern void show_inventory(int fd, struct cr_options *o);
extern void show_files(int fd_files, struct cr_options *o);
extern void show_pagemap(int fd, struct cr_options *o);
extern void show_reg_files(int fd_reg_files, struct cr_options *o);
extern void show_eventfds(int fd, struct cr_options *o);
extern void show_eventpoll(int fd, struct cr_options *o);
extern void show_eventpoll_tfd(int fd, struct cr_options *o);
extern void show_signalfd(int fd, struct cr_options *o);

extern void show_inotify(int fd, struct cr_options *o);
extern void show_inotify_wd(int fd, struct cr_options *o);
extern void show_fanotify(int fd, struct cr_options *o);
extern void show_fanotify_mark(int fd, struct cr_options *o);
extern void show_core(int fd, struct cr_options *o);
extern void show_ids(int fd, struct cr_options *o);
extern void show_mm(int fd, struct cr_options *o);
extern void show_vmas(int fd, struct cr_options *o);
extern void show_pipes(int fd, struct cr_options *o);
extern void show_pipes_data(int fd, struct cr_options *o);
extern void show_fifo(int fd, struct cr_options *o);
extern void show_fifo_data(int fd, struct cr_options *o);
extern void show_pstree(int fd, struct cr_options *o);
extern void show_sigacts(int fd, struct cr_options *o);
extern void show_unixsk(int fd, struct cr_options *o);
extern void show_inetsk(int fd, struct cr_options *o);
extern void show_packetsk(int fd, struct cr_options *o);
extern void show_netlinksk(int fd, struct cr_options *o);
extern void show_sk_queues(int fd, struct cr_options *o);
extern void show_itimers(int fd, struct cr_options *o);
extern void show_creds(int fd, struct cr_options *o);
extern void show_utsns(int fd, struct cr_options *o);
extern void show_ipc_var(int fd, struct cr_options *o);
extern void show_ipc_shm(int fd, struct cr_options *o);
extern void show_ipc_msg(int fd, struct cr_options *o);
extern void show_ipc_sem(int fd, struct cr_options *o);
extern void show_fs(int fd, struct cr_options *o);
extern void show_remap_files(int fd, struct cr_options *o);
extern void show_ghost_file(int fd, struct cr_options *o);
extern void show_tcp_stream(int fd, struct cr_options *o);
extern void show_mountpoints(int fd, struct cr_options *o);
extern void show_netdevices(int fd, struct cr_options *o);
extern void show_raw_image(int fd, struct cr_options *o);
extern void show_tty(int fd, struct cr_options *o);
extern void show_tty_info(int fd, struct cr_options *o);
extern void show_file_locks(int fd, struct cr_options *o);
extern void show_rlimit(int fd, struct cr_options *o);
extern void show_siginfo(int fd, struct cr_options *o);

#endif /* __CR_SHOW_H__ */

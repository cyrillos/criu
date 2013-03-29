#ifndef __CPT2_PROTOBUF_H__
#define __CPT2_PROTOBUF_H__

/*
 * FIXME Code duplication
 */
enum {
	PB_INVENTORY,
	PB_FDINFO,
	PB_CORE,
	PB_MM,
	PB_VMAS,
	PB_SIGACT,
	PB_ITIMERS,
	PB_CREDS,
	PB_FS,
	PB_UTSNS,
	PB_IPCNS_VAR,
	PB_IPCNS_SHM,
	PB_IPCNS_MSG,
	PB_IPCNS_MSG_ENT,
	PB_IPCNS_SEM,
	PB_MOUNTPOINTS,
	PB_NETDEV,
	PB_PSTREE,
	PB_GHOST_FILE,
	PB_TCP_STREAM,
	PB_SK_QUEUES,
	PB_REG_FILES,
	PB_INETSK,
	PB_UNIXSK,
	PB_PACKETSK,
	PB_NETLINKSK,
	PB_PIPES,
	PB_FIFO,
	PB_PIPES_DATA,
	PB_REMAP_FPATH,
	PB_EVENTFD,
	PB_EVENTPOLL,
	PB_EVENTPOLL_TFD,
	PB_SIGNALFD,
	PB_INOTIFY,
	PB_INOTIFY_WD,
	PB_FANOTIFY,
	PB_FANOTIFY_MARK,
	PB_TTY,
	PB_TTY_INFO,
	PB_FILE_LOCK,
	PB_RLIMIT,
	PB_IDS,
	PB_PAGEMAP_HEAD,
	PB_PAGEMAP,
	PB_SIGINFO,

	PB_MAX
};

#define pb_pksize(__obj, __proto_message_name)						\
	(__proto_message_name ##__get_packed_size(__obj) + sizeof(u32))

#define pb_repeated_size(__obj, __member)						\
	((size_t)(sizeof(*(__obj)->__member) * (__obj)->n_ ##__member))

#define pb_msg(__base, __type)								\
	container_of(__base, __type, base)

extern void pb_init(void);
extern int pb_write_one(int fd, void *obj, int type);

#endif /* __CPT2_PROTOBUF_H__ */

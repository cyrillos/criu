#ifndef __CR_PROTOBUF_H__
#define __CR_PROTOBUF_H__

#include "asm/types.h"
#include "compiler.h"
#include "util.h"

#include "protobuf-defs.h"

extern void cr_pb_init(void);
extern int do_pb_read_one(int fd, void **objp, int type, bool eof);

#define pb_read_one(fd, objp, type) do_pb_read_one(fd, (void **)objp, type, false)
#define pb_read_one_eof(fd, objp, type) do_pb_read_one(fd, (void **)objp, type, true)

extern int pb_write_one(int fd, void *obj, int type);

#include <google/protobuf-c/protobuf-c.h>

extern void do_pb_show_plain(int fd, int type, int single_entry,
		void (*payload_hadler)(int fd, void *obj, int flags),
		int flags, const char *pretty_fmt);

/* Don't have objects at hands to also do typechecking here */
#define pb_show_plain_payload_pretty(__fd, __type, payload_hadler, flags, pretty)	\
	do_pb_show_plain(__fd, __type, 0, payload_hadler, flags, pretty)

#define pb_show_plain_payload(__fd, __proto_message_name, payload_hadler, flags)	\
	pb_show_plain_payload_pretty(__fd, __proto_message_name, payload_hadler, flags, NULL)

#define pb_show_plain_pretty(__fd, __proto_message_name, __pretty)		\
	pb_show_plain_payload_pretty(__fd, __proto_message_name, NULL, 0, __pretty)

#define pb_show_plain(__fd, __type)							\
	pb_show_plain_payload(__fd, __type, NULL, 0)

#define pb_show_vertical(__fd, __type)							\
	do_pb_show_plain(__fd, __type, 1, NULL, 0, NULL)

int collect_image(int fd_t, int obj_t, unsigned size,
		int (*collect)(void *obj, ProtobufCMessage *msg));
int collect_image_sh(int fd_t, int obj_t, unsigned size,
		int (*collect)(void *obj, ProtobufCMessage *msg));

#endif /* __CR_PROTOBUF_H__ */

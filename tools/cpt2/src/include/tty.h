#ifndef __CPT2_TTY_H__
#define __CPT2_TTY_H__

#include <stdbool.h>

#include "cpt-image.h"
#include "context.h"
#include "types.h"
#include "files.h"

#define TERMIOS_NCC			19

#define TTY_DRIVER_TYPE_SYSTEM		0x0001
#define TTY_DRIVER_TYPE_CONSOLE		0x0002
#define TTY_DRIVER_TYPE_SERIAL		0x0003
#define TTY_DRIVER_TYPE_PTY		0x0004
#define TTY_DRIVER_TYPE_SCC		0x0005
#define TTY_DRIVER_TYPE_SYSCONS		0x0006

#define PTY_TYPE_MASTER			0x0001
#define PTY_TYPE_SLAVE			0x0002


#define TTY_THROTTLED			0
#define TTY_IO_ERROR			1
#define TTY_OTHER_CLOSED		2
#define TTY_EXCLUSIVE			3
#define TTY_DEBUG			4
#define TTY_DO_WRITE_WAKEUP		5
#define TTY_PUSH			6
#define TTY_CLOSING			7
#define TTY_LDISC			9
#define TTY_LDISC_CHANGING		10
#define TTY_LDISC_OPEN			11
#define TTY_HW_COOK_OUT			14
#define TTY_HW_COOK_IN			15
#define TTY_PTY_LOCK			16
#define TTY_NO_WRITE_SPLIT		17
#define TTY_HUPPED			18
#define TTY_FLUSHING			19
#define TTY_FLUSHPENDING		20
#define TTY_CHARGED			21
#define TTY_EXTRA_REFERENCE		22
#define TTY_HUPPING			23

#define tty_flag(tty, flag)		\
	((tty)->ti.cpt_flags & (1 << (flag)))

struct tty_struct {
	bool			dumped;
	struct cpt_tty_image	ti;
};

extern int read_ttys(context_t *ctx);
extern void free_ttys(context_t *ctx);
extern int write_tty_entry(context_t *ctx, struct file_struct *file);

#endif /* __CPT2_TTY_H__ */

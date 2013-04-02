#ifndef __CPT2_TYPES_H__
#define __CPT2_TYPES_H__

#include <linux/types.h>
#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

#include "asm/bitsperlong.h"
#include "asm/int.h"

#if defined(CONFIG_X86_64)
# define AT_VECTOR_SIZE 44
#else
# define AT_VECTOR_SIZE 22
#endif

#define KDEV_MINORBITS		20
#define KDEV_MINORMASK		((1UL << KDEV_MINORBITS) - 1)
#define MKKDEV(ma, mi)		(((ma) << KDEV_MINORBITS) | (mi))

#define kdev_major(kdev)	((kdev) >> KDEV_MINORBITS)
#define kdev_minor(kdev)	((kdev) & KDEV_MINORMASK)
#define kdev_to_odev(kdev)	(kdev_major(kdev) << 8) | kdev_minor(kdev)

#define PAGE_SHIFT		(12)
#define PAGE_SIZE		(1 << PAGE_SHIFT)
#define PAGES(len)		((len) >> PAGE_SHIFT)

#define TASK_SIZE		((1UL << 47) - PAGE_SIZE)

/*
 * FIXME robust list length is actually a kernel
 * internal sttructure, which size may vary between
 * kernel versions. Thus for a while stick with
 * precalculated value. If one day kernel change it
 * we need to update this code as well.
 */
#ifdef CONFIG_X86_64
# define FUTEX_RLA_LEN 24
#else
# define FUTEX_RLA_LEN 12
#endif

/* For registers convention */
#define GDT_ENTRY_KERNEL32_CS		1
#define GDT_ENTRY_KERNEL_CS		2
#define GDT_ENTRY_KERNEL_DS		3

#define __KERNEL32_CS			(GDT_ENTRY_KERNEL32_CS * 8)
#define GDT_ENTRY_DEFAULT_USER32_CS	4
#define GDT_ENTRY_DEFAULT_USER_DS	5
#define GDT_ENTRY_DEFAULT_USER_CS	6
#define __USER32_CS			(GDT_ENTRY_DEFAULT_USER32_CS * 8 + 3)
#define __USER32_DS			__USER_DS

#define GDT_ENTRY_TSS			8
#define GDT_ENTRY_LDT			10
#define GDT_ENTRY_TLS_MIN		12
#define GDT_ENTRY_TLS_MAX		14

#define GDT_ENTRY_PER_CPU		15
#define __PER_CPU_SEG			(GDT_ENTRY_PER_CPU * 8 + 3)

#define FS_TLS				0
#define GS_TLS				1

#define GS_TLS_SEL			((GDT_ENTRY_TLS_MIN+GS_TLS) * 8 + 3)
#define FS_TLS_SEL			((GDT_ENTRY_TLS_MIN+FS_TLS) * 8 + 3)

#define GDT_ENTRIES			16

#define __KERNEL_CS			(GDT_ENTRY_KERNEL_CS * 8)
#define __KERNEL_DS			(GDT_ENTRY_KERNEL_DS * 8)
#define __USER_DS			(GDT_ENTRY_DEFAULT_USER_DS * 8 + 3)
#define __USER_CS			(GDT_ENTRY_DEFAULT_USER_CS * 8 + 3)

#endif /* __CPT2_TYPES_H__ */

#ifndef __CPT2_TYPES_H__
#define __CPT2_TYPES_H__

#include <linux/types.h>
#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

#include "asm/bitsperlong.h"
#include "asm/int.h"

#define KDEV_MINORBITS		20
#define KDEV_MINORMASK		((1UL << KDEV_MINORBITS) - 1)
#define MKKDEV(ma, mi)		(((ma) << KDEV_MINORBITS) | (mi))

#define kdev_major(kdev)	((kdev) >> KDEV_MINORBITS)
#define kdev_minor(kdev)	((kdev) & KDEV_MINORMASK)
#define kdev_to_odev(kdev)	(kdev_major(kdev) << 8) | kdev_minor(kdev)

#endif /* __CPT2_TYPES_H__ */

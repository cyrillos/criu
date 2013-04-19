#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>

#include "compiler.h"
#include "xmalloc.h"
#include "types.h"
#include "log.h"

#include "protobuf.h"

/*
 * Writes PB record (header + packed object pointed by @obj)
 * to file @fd, using @getpksize to get packed size and @pack
 * to implement packing
 *
 *  0 on success
 * -1 on error
 */
int pb_write_one(int fd, void *obj, int type)
{
	u8 local[1024];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}

	size = cr_pb_descs[type].getpksize(obj);
	if (size > (u32)sizeof(local)) {
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	packed = cr_pb_descs[type].pack(obj, buf);
	if (packed != size) {
		pr_err("Failed packing PB object %p\n", obj);
		goto err;
	}

	ret = write(fd, &size, sizeof(size));
	if (ret != sizeof(size)) {
		ret = -1;
		pr_perror("Can't write %d bytes", (int)sizeof(size));
		goto err;
	}

	ret = write(fd, buf, size);
	if (ret != size) {
		ret = -1;
		pr_perror("Can't write %d bytes", size);
		goto err;
	}

	ret = 0;
err:
	if (buf != (void *)&local)
		xfree(buf);
	return ret;
}

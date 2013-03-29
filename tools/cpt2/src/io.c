#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "io.h"
#include "log.h"

int read_data(int fd, void *ptr, size_t size, bool eof)
{
	ssize_t ret;

	ret = read(fd, ptr, size);
	if (ret == size)
		return 0;
	if (ret == 0) {
		if (eof)
			return 0;
		else
			return 1;
	}

	if (ret < 0)
		pr_perror("Can't read record from the file");
	else
		pr_err("Record trimmed %d/%d\n", (int)ret, (int)size);

	return -1;
}

int read_data_at(int fd, void *ptr, size_t size, off_t pos, bool eof)
{
	off_t cur = lseek(fd, pos, SEEK_SET);
	if (cur < 0) {
		pr_perror("Can't move file position\n");
		return -1;
	}

	return read_data(fd, ptr, size, eof);
}

int write_data(int fd, void *ptr, size_t size)
{
	ssize_t ret;

	ret = write(fd, ptr, size);
	if (ret == size)
		return 0;

	if (ret < 0)
		pr_perror("Can't write data to a file");
	else
		pr_err("Record has been trimmed %d/%d\n", (int)ret, (int)size);

	return -1;
}

/*
 * We don't use pwrite here simply because we can reuse error
 * messages from write_data() helper.
 */
int write_data_at(int fd, void *ptr, size_t size, off_t pos)
{
	off_t cur = lseek(fd, pos, SEEK_SET);
	if (cur < 0) {
		pr_perror("Can't move file position\n");
		return -1;
	}

	return write_data(fd, ptr, size);
}


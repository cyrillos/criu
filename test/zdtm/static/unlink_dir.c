#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check cleanup order of ghost directory and files inside";
const char *test_author	= "Cyrill Gorcunov <gorcunov@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char ** argv)
{
	char path_dir1[PATH_MAX];
	char path_dir2[PATH_MAX];
	char path_dir3[PATH_MAX];
	char path_dir4[PATH_MAX];

	/* Order does matter */
	char *path_dirs[] = {
		path_dir4,
		path_dir3,
		path_dir2,
		path_dir1,
	};

	char path[PATH_MAX];
	int fds[4], dfds[4], i;

	int lo = ARRAY_SIZE(fds) / 2;
	int hi = ARRAY_SIZE(fds);

	test_init(argc, argv);

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't create directory %s", dirname);
		return 1;
	}

	ssprintf(path_dir1, "%s/%s", dirname, "gd1");
	if (mkdir(path_dir1, 0700) < 0) {
		pr_perror("Can't create directory %s", path_dir1);
		return 1;
	}

	ssprintf(path_dir2, "%s/%s/%s", dirname, "gd1", "gd2");
	if (mkdir(path_dir2, 0700) < 0) {
		pr_perror("Can't create directory %s", path_dir2);
		return 1;
	}

	ssprintf(path_dir3, "%s/%s/%s/%s", dirname, "gd1", "gd2", "gd3");
	if (mkdir(path_dir3, 0700) < 0) {
		pr_perror("Can't create directory %s", path_dir3);
		return 1;
	}

	ssprintf(path_dir4, "%s/%s/%s/%s/%s", dirname, "gd1", "gd2", "gd3", "gd4");
	if (mkdir(path_dir4, 0700) < 0) {
		pr_perror("Can't create directory %s", path_dir4);
		return 1;
	}

	for (i = 0; i < lo; i++) {
		ssprintf(path, "%s/%d", path_dir1, i);
		fds[i] = open(path, O_RDONLY | O_CREAT | O_TRUNC);
		if (fds[i] < 0) {
			pr_perror("Can't open %s", path);
			return 1;
		}
		if (unlink(path)) {
			pr_perror("Can't unlink %s", path);
			return 1;
		}
	}

	for (i = lo; i < hi; i++) {
		ssprintf(path, "%s/%d", path_dir2, i);
		fds[i] = open(path, O_RDONLY | O_CREAT | O_TRUNC);
		if (fds[i] < 0) {
			pr_perror("Can't open %s", path);
			return 1;
		}
		if (unlink(path)) {
			pr_perror("Can't unlink %s", path);
			return 1;
		}
	}

	for (i = 0; i < ARRAY_SIZE(path_dirs); i++) {
		dfds[i] =  open(path_dirs[i], O_RDONLY | O_DIRECTORY);
		if (dfds[i] < 0) {
			pr_perror("Can't open %s", path_dirs[i]);
			return 1;
		}
		if (rmdir(path_dirs[i])) {
			pr_perror("Can't rmdir %s", path_dirs[i]);
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < ARRAY_SIZE(path_dirs); i++) {
		if (access(path_dirs[i], F_OK)) {
			if (errno == ENOENT)
				continue;
			fail("Unexpected error on %s", path_dirs[i]);
			exit(1);
		}
	}
	pass();
	return 0;
}

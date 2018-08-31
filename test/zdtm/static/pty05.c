#define _XOPEN_SOURCE 500

#include <termios.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc	= "Test multiple PTYs with different session leaders";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int pty_get_index(int fd)
{
	int index;

	if (ioctl(fd, TIOCGPTN, &index)) {
		pr_perror("Can't fetch ptmx index");
		return -1;
	}

	return index;
}

static int open_pty_pair(char *dir, int *fdm, int *fds)
{
	char path[PATH_MAX];
	int index;

	snprintf(path, sizeof(path), "%s/ptmx", dir);
	*fdm = open(path, O_RDWR);
	if (*fdm < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	grantpt(*fdm);
	unlockpt(*fdm);

	index = pty_get_index(*fdm);
	if (index < 0) {
		close(*fdm);
		return -1;
	}

	snprintf(path, sizeof(path), "%s/%d", dir, index);
	*fds = open(path, O_RDWR);
	if (*fds < 0) {
		pr_perror("Can't open %s\n", path);
		close(*fdm);
		return -1;
	}

	test_msg("Created pair %d/%d index %d\n", *fdm, *fds, index);
	return 0;
}

int main(int argc, char *argv[])
{
	char path[PATH_MAX], *dir1, *dir2;
	struct peer_s {
		char	*str;
		int	size;
		int	fdm;
		int	fds;
	} peers[2] = {
		{ .str = "hello1\n", .size = 7, },
		{ .str = "hello2\n", .size = 7, } };
	int ret, retval = 1, i;
	char buf[64];

	test_init(argc, argv);

	if (mkdir(dirname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		pr_perror("Can't create testing directory %s", dirname);
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", dirname, "lvl1");
	dir1 = strdup(path);

	if (!dir1 || mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		pr_perror("Can't create testing directory %s", path);
		exit(1);
	}
	test_msg("Mounting first devpts at %s\n", dir1);
	if (mount("devpts", path, "devpts", 0, "newinstance,ptmxmode=0666")) {
		pr_perror("Can't mount testing directory %s", path);
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s", dirname, "lvl2");
	dir2 = strdup(path);
	if (!dir2 || mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
		umount2(dir1, MNT_DETACH);
		pr_perror("Can't create testing directory %s", path);
		exit(1);
	}
	test_msg("Mounting second devpts at %s\n", dir2);
	if (mount("devpts", path, "devpts", 0, "newinstance,ptmxmode=0666")) {
		umount2(dir1, MNT_DETACH);
		pr_perror("Can't mount testing directory %s", path);
		exit(1);
	}

	if (open_pty_pair(dir1, &peers[0].fdm, &peers[0].fds) ||
	    open_pty_pair(dir2, &peers[1].fdm, &peers[1].fds)) {
		umount2(dir1, MNT_DETACH);
		umount2(dir2, MNT_DETACH);
		exit(1);
	}

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		test_msg("Writting %d bytes into fds %d\n", peers[i].size, peers[i].fds);
		ret = write(peers[i].fds, peers[i].str, peers[i].size);
		if (ret != peers[i].size) {
			pr_perror("Can't write into fds %d, "
				  "%d bytes but %d expected",
				  peers[i].fds, ret, peers[i].size);
			exit(1);
		}
	}

	test_daemon();
	test_waitsig();

	signal(SIGHUP, SIG_IGN);

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		memset(buf, 0, sizeof(buf));
		test_msg("Reading %d bytes from fdm %d\n", peers[i].size, peers[i].fdm);
		ret = read(peers[i].fdm, buf, peers[i].size);
		if (ret != peers[i].size) {
			fail("Can't read from fdm %d, "
			     "got %d bytes but %d expected",
			     peers[i].fdm, ret, peers[i].size);
			goto out;
		}

		if (strncmp(buf, peers[i].str, peers[i].size - 1)) {
			fail("Data mismatch on fdm %d (got %s but %s expected)",
			     peers[i].fdm, buf, peers[i].str);
			goto out;
		}
	}

	retval = 0;
out:
	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		close(peers[i].fds);
		close(peers[i].fdm);
	}

	if (umount2(dir1, MNT_DETACH))
		pr_perror("Can't unmount %s\n", dir1);
	if (umount2(dir2, MNT_DETACH))
		pr_perror("Can't unmount %s\n", dir2);
	if (rmdir(dir1))
		pr_perror("Can't remove %s", dir1);
	if (rmdir(dir2))
		pr_perror("Can't remove %s", dir2);
	if (rmdir(dirname))
		pr_perror("Can't remove %s", dirname);

	free(dir1);
	free(dir2);

	if (retval == 0)
		pass();

	return retval;
}

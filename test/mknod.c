/* SPDX-License-Identifier: MIT */
/*
 * Description: test io_uring mknodat handling
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include "liburing.h"

static int do_mknodat(struct io_uring *ring, const char *fn, mode_t mode, dev_t dev)
{
	int ret;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "sqe get failed\n");
		goto err;
	}
	io_uring_prep_mknodat(sqe, AT_FDCWD, fn, mode, dev);

	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqes(ring, &cqe, 1, 0, 0);
	if (ret) {
		fprintf(stderr, "wait_cqe failed: %d\n", ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
err:
	return 1;
}

int check_fifo(const char* fn)
{
	char buf[4];
	int fd = open(fn, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "failed to open fifo: %s\n", strerror(errno));
		return 1;
	}
	if (write(fd, "42", 2) != 2) {
		fprintf(stderr, "short write to fifo\n");
		return 1;
	}
	if (read(fd, buf, 2) != 2) {
		fprintf(stderr, "short read from fifo\n");
		return 1;
	}
	buf[3] = 0;
	if (strncmp(buf, "42", 2)) {
		fprintf(stderr, "read unexpected data from fifo: %s\n", buf);
		return 1;
	}

	return 0;
}

int test_device(struct io_uring *ring, const char* fn)
{
	// 1, 3 is /dev/null
	struct stat sb;
	dev_t dev = makedev(1, 3);
	int ret = do_mknodat(ring, fn, 0600 | S_IFCHR, dev);
	if (ret < 0) {
		fprintf(stderr, "mknodat device: %s\n", strerror(-ret));
		return ret;
	} else if (ret) {
		return ret;
	}
	ret = stat(fn, &sb);
	if (ret) {
		perror("stat");
		return ret;
	}
	if (sb.st_rdev != dev) {
		fprintf(stderr, "unexpected device number: %d, %d\n",
			major(sb.st_rdev), minor(sb.st_rdev));
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	static const char fn[] = "io_uring-mknodat-test";
	int ret;
	struct io_uring ring;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return ret;
	}

	ret = do_mknodat(&ring, fn, 0600 | S_IFIFO, 0);
	if (ret < 0) {
		if (ret == -EBADF || ret == -EINVAL) {
			fprintf(stdout, "mknodat not supported, skipping\n");
			goto out;
		}
		fprintf(stderr, "mknodat: %s\n", strerror(-ret));
		goto err;
	} else if (ret) {
		goto err;
	}


	if (check_fifo(fn))
		goto err1;

	ret = do_mknodat(&ring, fn, 0600 | S_IFIFO, 0);
	if (ret != -EEXIST) {
		fprintf(stderr, "do_mknodat already exists failed: %d\n", ret);
		goto err1;
	}

	ret = do_mknodat(&ring, "surely/this/wont/exist", 0600 | S_IFIFO, 0);
	if (ret != -ENOENT) {
		fprintf(stderr, "do_mkdirat no parent failed: %d\n", ret);
		goto err1;
	}

	unlinkat(AT_FDCWD, fn, 0);

	if (!geteuid()) {
		if (test_device(&ring, fn))
			goto err1;
	}
	else
		fprintf(stdout, "skipping the device test which needs root perms\n");

out:
	unlinkat(AT_FDCWD, fn, 0);
	io_uring_queue_exit(&ring);
	return 0;
err1:
	unlinkat(AT_FDCWD, fn, 0);
err:
	io_uring_queue_exit(&ring);
	return 1;
}


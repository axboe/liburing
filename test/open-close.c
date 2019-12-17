/*
 * Description: run various openat(2) tests
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"

static int create_file(const char *file, size_t size)
{
	ssize_t ret;
	char *buf;
	int fd;

	buf = malloc(size);
	memset(buf, 0xaa, size);

	fd = open(file, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror("open file");
		return 1;
	}
	ret = write(fd, buf, size);
	close(fd);
	return ret != size;
}

static int test_close(struct io_uring *ring, int fd)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}
	io_uring_prep_close(sqe, fd);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
err:
	return -1;
}

static int test_openat(struct io_uring *ring, const char *path)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}
	io_uring_prep_openat(sqe, -1, path, 0, O_RDONLY);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
err:
	return -1;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	const char *fname;
	int ret, do_unlink;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed\n");
		return 1;
	}

	if (argc > 1) {
		fname = argv[1];
		do_unlink = 0;
	} else {
		fname = "/tmp/.open.close";
		do_unlink = 0;
	}

	if (create_file(fname, 4096)) {
		fprintf(stderr, "file create failed\n");
		return 1;
	}

	ret = test_openat(&ring, fname);
	if (ret < 0) {
		if (ret == -EINVAL) {
			fprintf(stdout, "Open not supported, skipping\n");
			goto done;
		}
		fprintf(stderr, "test_openat failed: %d\n", ret);
		goto err;
	}

	ret = test_close(&ring, ret);
	if (ret) {
		fprintf(stderr, "test_close normal failed\n");
		goto err;
	}

	ret = test_close(&ring, ring.ring_fd);
	if (ret != -EBADF) {
		fprintf(stderr, "test_close ring_fd failed\n");
		goto err;
	}

done:
	if (do_unlink)
		unlink(fname);
	return 0;
err:
	if (do_unlink)
		unlink(fname);
	return 1;
}

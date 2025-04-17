/* SPDX-License-Identifier: MIT */
/*
 * Description: test various offset of fixed buffer read
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "liburing.h"
#include "helpers.h"

static struct iovec vec;

static int read_it(struct io_uring *ring, int fd, int len, int off)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_read_fixed(sqe, fd, vec.iov_base + off, len, 0, 0);
	sqe->user_data = 1;

	io_uring_submit(ring);

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait %d\n", ret);
		return 1;
	}
	if (cqe->res < 0) {
		fprintf(stderr, "cqe res %s\n", strerror(-cqe->res));
		return 1;
	}
	if (cqe->res != len) {
		fprintf(stderr, "Bad read amount: %d\n", cqe->res);
		return 1;
	}
	io_uring_cqe_seen(ring, cqe);
	return 0;
}

static int test(struct io_uring *ring, int fd, int vec_off)
{
	struct iovec v = vec;
	int ret;

	v.iov_base += vec_off;
	v.iov_len -= vec_off;
	ret = io_uring_register_buffers(ring, &v, 1);
	if (ret) {
		fprintf(stderr, "Vec register: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = read_it(ring, fd, 4096, vec_off);
	if (ret) {
		fprintf(stderr, "4096 0 failed\n");
		return T_EXIT_FAIL;
	}
	ret = read_it(ring, fd, 8192, 4096);
	if (ret) {
		fprintf(stderr, "8192 4096 failed\n");
		return T_EXIT_FAIL;
	}
	ret = read_it(ring, fd, 4096, 4096);
	if (ret) {
		fprintf(stderr, "4096 4096 failed\n");
		return T_EXIT_FAIL;
	}
	
	io_uring_unregister_buffers(ring);
	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	const char *fname;
	char buf[256];
	int fd, ret;

	if (argc > 1) {
		fname = argv[1];
	} else {
		srand((unsigned)time(NULL));
		snprintf(buf, sizeof(buf), ".fixed-seg-%u-%u", (unsigned) rand(),
				(unsigned)getpid());
		fname = buf;
		t_create_file(fname, 128*1024);
	}

	fd = open(fname, O_RDONLY | O_DIRECT);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	if (posix_memalign(&vec.iov_base, 4096, 512*1024))
		goto err;
	vec.iov_len = 512*1024;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue_init: %d\n", ret);
		goto err;
	}

	ret = test(&ring, fd, 0);
	if (ret) {
		fprintf(stderr, "test 0 failed\n");
		goto err;
	}

	ret = test(&ring, fd, 512);
	if (ret) {
		fprintf(stderr, "test 512 failed\n");
		goto err;
	}

	ret = test(&ring, fd, 3584);
	if (ret) {
		fprintf(stderr, "test 3584 failed\n");
		goto err;
	}

	close(fd);
	io_uring_queue_exit(&ring);
	if (fname != argv[1])
		unlink(fname);
	return T_EXIT_PASS;
err:
	if (fname != argv[1])
		unlink(fname);
	return T_EXIT_FAIL;
}

/* SPDX-License-Identifier: MIT */
/*
 * Description: test IORING_OP_FILES_UPDATE can support io_uring
 * allocates an available direct descriptor instead of having the
 * application pass one.
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/uio.h>

#include "helpers.h"
#include "liburing.h"

int main(int argc, char *argv[])
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	char wbuf[1] = { 0xef }, rbuf[1] = {0x0};
	struct io_uring ring;
	int i, ret, pipe_fds[2], fds[2] = { -1, -1};

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed\n");
		return -1;
	}

	ret = io_uring_register_files(&ring, fds, 2);
	if (ret) {
		fprintf(stderr, "%s: register ret=%d\n", __func__, ret);
		return -1;
	}

	if (pipe2(pipe_fds, O_NONBLOCK)) {
		fprintf(stderr, "pipe() failed\n");
		return -1;
	}

	/*
	 * Pass IORING_FILE_INDEX_ALLOC, so io_uring in kernel will allocate
	 * available direct descriptors.
	 */
	fds[0] = pipe_fds[0];
	fds[1] = pipe_fds[1];
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_files_update(sqe, fds, 2, IORING_FILE_INDEX_ALLOC);
	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return -1;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait files update completion failed: %d\n", ret);
		return ret;
	}

	if (cqe->res < 0) {
		if (cqe->res == -EINVAL) {
			fprintf(stdout, "files update(IORING_FILE_INDEX_ALLOC) not "
				"supported, skipping\n");
			return 0;
		}
		fprintf(stderr, "files update(IORING_FILE_INDEX_ALLOC) failed: %d\n", ret);
		return ret;
	}
	ret = cqe->res;
	if (ret != 2) {
		fprintf(stderr, "should allocate 2 direct descriptors, but get:%d\n", ret);
		return -1;
	}
	if (fds[0] != 0 || fds[1] != 1) {
		fprintf(stderr, "allocate wrong direct descriptors:%d %d\n",
			fds[0], fds[1]);
		return -1;
	}
	io_uring_cqe_seen(&ring, cqe);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_write(sqe, fds[1], wbuf, sizeof(wbuf), 0);
	sqe->flags |= IOSQE_FIXED_FILE;
	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return -1;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0 || cqe->res < 0) {
		fprintf(stderr, "write failed %d\n", ret);
		return ret;
	}
	io_uring_cqe_seen(&ring, cqe);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_read(sqe, fds[0], rbuf, sizeof(rbuf), 0);
	sqe->flags |= IOSQE_FIXED_FILE;
	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return -1;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0 || cqe->res < 0) {
		fprintf(stderr, "read failed %d\n", ret);
		return ret;
	}
	if (rbuf[0] != (char)0xef) {
		fprintf(stderr, "read wrong data %x\n", rbuf[0]);
		return ret;
	}
	io_uring_cqe_seen(&ring, cqe);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_close_all(sqe, pipe_fds[0], fds[0]);
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_close_all(sqe, pipe_fds[1], fds[1]);
	ret = io_uring_submit(&ring);
	if (ret != 2) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return -1;
	}

	for (i = 0; i < 2; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0 || cqe->res < 0) {
			fprintf(stderr, "wait close completion %d\n", ret);
			return ret;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	io_uring_queue_exit(&ring);
	return 0;
}

/* SPDX-License-Identifier: MIT */
/*
 * Description: Test IORING_ASYNC_CANCEL_{ALL,FD}
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include "liburing.h"

int main(int argc, char *argv[])
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int ret, i, fd[2];

	if (argc > 1)
		return 0;

	if (pipe(fd) < 0) {
		perror("pipe");
		return 1;
	}

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "child: ring setup failed: %d\n", ret);
		return 1;
	}

	for (i = 0; i < 8; i++) {
		sqe = io_uring_get_sqe(&ring);
		if (!sqe) {
			fprintf(stderr, "get sqe failed\n");
			return 1;
		}

		io_uring_prep_poll_add(sqe, fd[0], POLLIN);
		sqe->user_data = i + 1;
	}

	ret = io_uring_submit(&ring);
	if (ret < 8) {
		fprintf(stderr, "child: sqe submit failed: %d\n", ret);
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		return 1;
	}

	/*
	 * Mark CANCEL_ALL to cancel all matching the key, and use
	 * CANCEL_FD to cancel requests matching the specified fd.
	 * This should cancel all the pending poll requests on the pipe
	 * input.
	 */
	io_uring_prep_cancel_fd(sqe, fd[0], IORING_ASYNC_CANCEL_ALL);
	sqe->user_data = 100;

	ret = io_uring_submit(&ring);
	if (ret < 1) {
		fprintf(stderr, "child: sqe submit failed: %d\n", ret);
		return 1;
	}

	for (i = 0; i < 9; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait=%d\n", ret);
			return 1;
		}
		switch (cqe->user_data) {
		case 100:
			if (cqe->res != 8) {
				fprintf(stderr, "canceled %d\n", cqe->res);
				return 1;
			}
			break;
		case 1 ... 8:
			if (cqe->res != -ECANCELED) {
				fprintf(stderr, "poll res %d\n", cqe->res);
				return 1;
			}
			break;
		default:
			fprintf(stderr, "invalid user_data %lu\n",
					(unsigned long) cqe->user_data);
			return 1;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	return 0;
}

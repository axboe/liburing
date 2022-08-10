/* SPDX-License-Identifier: MIT */
/*
 * Description: test disable/enable notifications through eventfd
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>

#include "liburing.h"
#include "helpers.h"

int main(int argc, char *argv[])
{
	struct io_uring_params p = {};
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	uint64_t ptr = 0;
	struct iovec vec = {
		.iov_base = &ptr,
		.iov_len = sizeof(ptr)
	};
	int ret, evfd, i;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = io_uring_queue_init_params(64, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	evfd = eventfd(0, EFD_CLOEXEC);
	if (evfd < 0) {
		perror("eventfd");
		return T_EXIT_FAIL;
	}

	ret = io_uring_register_eventfd(&ring, evfd);
	if (ret) {
		fprintf(stderr, "failed to register evfd: %d\n", ret);
		return T_EXIT_FAIL;
	}

	if (!io_uring_cq_eventfd_enabled(&ring)) {
		fprintf(stderr, "eventfd disabled\n");
		return T_EXIT_FAIL;
	}

	ret = io_uring_cq_eventfd_toggle(&ring, false);
	if (ret) {
		fprintf(stdout, "Skipping, CQ flags not available!\n");
		return T_EXIT_SKIP;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_readv(sqe, evfd, &vec, 1, 0);
	sqe->user_data = 1;

	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (i = 0; i < 63; i++) {
		sqe = io_uring_get_sqe(&ring);
		io_uring_prep_nop(sqe);
		sqe->user_data = 2;
	}

	ret = io_uring_submit(&ring);
	if (ret != 63) {
		fprintf(stderr, "submit: %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (i = 0; i < 63; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait: %d\n", ret);
			return T_EXIT_FAIL;
		}

		switch (cqe->user_data) {
		case 1: /* eventfd */
			fprintf(stderr, "eventfd unexpected: %d\n", (int)ptr);
			return T_EXIT_FAIL;
		case 2:
			if (cqe->res) {
				fprintf(stderr, "nop: %d\n", cqe->res);
				return T_EXIT_FAIL;
			}
			break;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	ret = io_uring_cq_eventfd_toggle(&ring, true);
	if (ret) {
		fprintf(stderr, "io_uring_cq_eventfd_toggle: %d\n", ret);
		return T_EXIT_FAIL;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 2;

	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (i = 0; i < 2; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait: %d\n", ret);
			return T_EXIT_FAIL;
		}

		switch (cqe->user_data) {
		case 1: /* eventfd */
			if (cqe->res != sizeof(ptr)) {
				fprintf(stderr, "read res: %d\n", cqe->res);
				return T_EXIT_FAIL;
			}

			if (ptr != 1) {
				fprintf(stderr, "eventfd: %d\n", (int)ptr);
				return T_EXIT_FAIL;
			}
			break;
		case 2:
			if (cqe->res) {
				fprintf(stderr, "nop: %d\n", cqe->res);
				return T_EXIT_FAIL;
			}
			break;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	return T_EXIT_PASS;
}

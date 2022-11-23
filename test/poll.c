/* SPDX-License-Identifier: MIT */
/*
 * Description: test io_uring poll handling
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <sys/wait.h>

#include "helpers.h"
#include "liburing.h"

static int test_basic(void)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int pipe1[2];
	pid_t p;
	int ret;

	if (pipe(pipe1) != 0) {
		perror("pipe");
		return 1;
	}

	p = fork();
	if (p == -1) {
		perror("fork");
		exit(2);
	} else if (p == 0) {
		ret = io_uring_queue_init(1, &ring, 0);
		if (ret) {
			fprintf(stderr, "child: ring setup failed: %d\n", ret);
			return 1;
		}

		sqe = io_uring_get_sqe(&ring);
		if (!sqe) {
			fprintf(stderr, "get sqe failed\n");
			return 1;
		}

		io_uring_prep_poll_add(sqe, pipe1[0], POLLIN);
		io_uring_sqe_set_data(sqe, sqe);

		ret = io_uring_submit(&ring);
		if (ret <= 0) {
			fprintf(stderr, "child: sqe submit failed: %d\n", ret);
			return 1;
		}

		do {
			ret = io_uring_wait_cqe(&ring, &cqe);
			if (ret < 0) {
				fprintf(stderr, "child: wait completion %d\n", ret);
				break;
			}
			io_uring_cqe_seen(&ring, cqe);
		} while (ret != 0);

		if (ret < 0)
			return 1;
		if (cqe->user_data != (unsigned long) sqe) {
			fprintf(stderr, "child: cqe doesn't match sqe\n");
			return 1;
		}
		if ((cqe->res & POLLIN) != POLLIN) {
			fprintf(stderr, "child: bad return value %ld\n",
							(long) cqe->res);
			return 1;
		}

		io_uring_queue_exit(&ring);
		exit(0);
	}

	do {
		errno = 0;
		ret = write(pipe1[1], "foo", 3);
	} while (ret == -1 && errno == EINTR);

	if (ret != 3) {
		fprintf(stderr, "parent: bad write return %d\n", ret);
		return 1;
	}
	close(pipe1[0]);
	close(pipe1[1]);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test_basic();
	if (ret) {
		fprintf(stderr, "test_basic() failed %i\n", ret);
		return T_EXIT_FAIL;
	}
	return 0;
}

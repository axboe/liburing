/* SPDX-License-Identifier: MIT */
/*
 * Description: Test flagging of IORING_CQE_F_POLLED on both read and write
 *		side of a pipe.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

#include "liburing.h"
#include "helpers.h"

static bool set_nonblock(int fd)
{
	int fl;

	fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0) {
		perror("fcntl get");
		return false;
	}
	fl |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, fl) < 0) {
		perror("fcntl set");
		return false;
	}

	return true;
}

static int test_write(struct io_uring *ring, int *fds)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	unsigned fl1, fl2;
	char buf[32];
	int ret;

	if (!set_nonblock(fds[0]) || !set_nonblock(fds[1]))
		return T_EXIT_FAIL;

	memset(buf, 0x5a, sizeof(buf));
	do {
		ret = write(fds[1], buf, sizeof(buf));
		if (ret < 0) {
			if (errno == EAGAIN)
				break;
			perror("write pipe");
			return T_EXIT_FAIL;
		}
	} while (1);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_write(sqe, fds[1], buf, sizeof(buf), 0);
	io_uring_submit(ring);

	/* drain read side so our write can complete */
	do {
		ret = read(fds[0], buf, sizeof(buf));
		if (ret < 0) {
			if (errno == EAGAIN)
				break;
			perror("read pipe");
			return T_EXIT_FAIL;
		} else if (!ret) {
			break;
		}
	} while (1);

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe: %d\n", ret);
		return T_EXIT_FAIL;
	}
	fl1 = cqe->flags;
	io_uring_cqe_seen(ring, cqe);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_write(sqe, fds[1], buf, sizeof(buf), 0);
	io_uring_submit(ring);

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe: %d\n", ret);
		return T_EXIT_FAIL;
	}
	fl2 = cqe->flags;
	io_uring_cqe_seen(ring, cqe);

	if (!(fl1 & IORING_CQE_F_POLLED) && (fl2 & IORING_CQE_F_POLLED)) {
		fprintf(stderr, "write test odd POLLED flags\n");
		return T_EXIT_FAIL;
	}
	if (fl1 & IORING_CQE_F_POLLED)
		fprintf(stdout, "Pipe write side sets IORING_CQE_F_POLLED\n");
	return 0;
}

static int test_read(struct io_uring *ring, int *fds)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	unsigned int fl1, fl2;
	char buf[32];
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_read(sqe, fds[0], buf, sizeof(buf), 0);
	io_uring_submit(ring);

	ret = write(fds[1], "foo", 3);
	if (ret < 0) {
		perror("write pipe");
		return T_EXIT_FAIL;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe: %d\n", ret);
		return T_EXIT_FAIL;
	}
	fl1 = cqe->flags;
	io_uring_cqe_seen(ring, cqe);

	ret = write(fds[1], "foo", 3);
	if (ret < 0) {
		perror("write pipe");
		return T_EXIT_FAIL;
	}

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_read(sqe, fds[0], buf, sizeof(buf), 0);
	io_uring_submit(ring);

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe: %d\n", ret);
		return T_EXIT_FAIL;
	}
	fl2 = cqe->flags;
	io_uring_cqe_seen(ring, cqe);

	if (!(fl1 & IORING_CQE_F_POLLED) && (fl2 & IORING_CQE_F_POLLED)) {
		fprintf(stderr, "read test odd POLLED flags\n");
		return T_EXIT_FAIL;
	}
	if (fl1 & IORING_CQE_F_POLLED)
		fprintf(stdout, "Pipe read side sets IORING_CQE_F_POLLED\n");
	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret, fds[2];

	if (argc > 1)
		return T_EXIT_SKIP;

	if (pipe(fds) < 0) {
		perror("pipe");
		return T_EXIT_FAIL;
	}

	io_uring_queue_init(4, &ring, 0);

	ret = test_read(&ring, fds);
	if (ret)
		return ret;

	ret = test_write(&ring, fds);
	if (ret)
		return ret;

	close(fds[0]);
	close(fds[1]);
	io_uring_queue_exit(&ring);
	return 0;
}

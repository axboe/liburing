/*
 * Description: test io_uring poll cancel handling
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include "../src/liburing.h"

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int pipe1[2];
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long addr;
	int ret;

	if (pipe(pipe1) != 0) {
		printf("pipe failed\n");
		return 1;
	}

	ret = io_uring_queue_init(2, &ring, 0);
	if (ret) {
		printf("child: ring setup failed\n");
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		printf("child: get sqe failed\n");
		return 1;
	}
	sqe->opcode = IORING_OP_POLL;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = pipe1[0];
	sqe->addr = POLLIN;
	sqe->off = 0;
	sqe->len = 0;
	sqe->buf_index = 0;
	sqe->user_data = addr = (unsigned long) &sqe;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		printf("child: sqe submit failed\n");
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		printf("child: get sqe failed\n");
		return 1;
	}
	sqe->opcode = IORING_OP_POLL_CANCEL;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = 0;
	sqe->addr = addr;
	sqe->off = 0;
	sqe->len = 0;
	sqe->buf_index = 0;
	sqe->user_data = (unsigned long) &sqe;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		printf("child: sqe submit failed\n");
		return 1;
	}

	ret = io_uring_wait_completion(&ring, &cqe);
	if (ret < 0) {
		printf("child: get cqe failed\n");
		return 1;
	}

	if (cqe->user_data != addr) {
		printf("first complete not poll\n");
		return 1;
	}

	ret = io_uring_wait_completion(&ring, &cqe);
	if (ret < 0) {
		printf("parent: get failed\n");
		return 1;
	}
	if (cqe->user_data != (unsigned long) &sqe) {
		printf("second not cancel\n");
		return 1;
	}

	return 0;
}

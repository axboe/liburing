/*
 * Description: test io_uring poll handling
 *
 * Based on 22.t from libaio
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include "../src/liburing.h"

int main(int argc, char *argv[])
{
	pid_t parent = getpid(), p;
	int pipe1[2], pipe2[2];
	struct io_uring cring, pring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	if (pipe(pipe1) != 0 || pipe(pipe2) != 0) {
		printf("pipe failed\n");
		return 1;
	}

	p = fork();
	switch (p) {
	case -1:
		printf("fork failed\n");
		exit(2);
	case 0:
		close(pipe1[1]);
		close(pipe2[0]);

		ret = io_uring_queue_init(1, &cring, 0);
		if (ret) {
			printf("child: ring setup failed\n");
			return 1;
		}

		sqe = io_uring_get_sqe(&cring);
		if (!sqe) {
			printf("child: get sqe failed\n");
			return 1;
		}

		memset(sqe, 0, sizeof(*sqe));
		sqe->opcode = IORING_OP_POLL;
		sqe->fd = pipe1[0];
		sqe->poll_events = POLLIN;
		sqe->user_data = (unsigned long) &sqe;

		ret = io_uring_submit(&cring);
		if (ret <= 0) {
			printf("child: sqe submit failed\n");
			return 1;
		}

		do {
			if (getppid() != parent) {
				printf("parent died\n");
				exit(2);
			}
			ret = io_uring_wait_completion(&cring, &cqe);
		} while (ret != 0);

		if (ret < 0) {
			printf("child: completion get failed\n");
			return 1;
		}

		do {
			errno = 0;
			ret = write(pipe2[1], "foo", 3);
		} while (ret == -1 && errno == EINTR);

		exit(0);
	default:
		close(pipe1[0]);
		close(pipe2[1]);

		ret = io_uring_queue_init(1, &pring, 0);
		if (ret) {
			printf("parent: ring setup failed\n");
			return 1;
		}

		sqe = io_uring_get_sqe(&pring);
		if (!sqe) {
			printf("parent: get sqe failed\n");
			return 1;
		}

		memset(sqe, 0, sizeof(*sqe));
		sqe->opcode = IORING_OP_POLL;
		sqe->fd = pipe2[0];
		sqe->poll_events = POLLIN;
		sqe->user_data = (unsigned long) &sqe;

		ret = io_uring_submit(&pring);
		if (ret <= 0) {
			printf("parent: sqe submit failed\n");
			return 1;
		}

		kill(p, SIGUSR1);

		ret = io_uring_wait_completion(&pring, &cqe);
		if (ret < 0) {
			printf("parent: cqe get failed\n");
			return 1;
		}
		if (cqe->user_data != (unsigned long) &sqe) {
			printf("parent: cqe wrong fd\n");
			return 1;
		}
		if ((cqe->res & POLLIN) != POLLIN) {
			printf("parent: cqe did not report readable fd\n");
			return 1;
		}

		return 0;
	}
}

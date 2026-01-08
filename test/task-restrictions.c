/* SPDX-License-Identifier: MIT */
/*
 * Description: test task registered restrictions
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>

#include "liburing.h"
#include "helpers.h"

static int test_restrictions(int should_work)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	uint64_t ptr;
	struct iovec vec = {
		.iov_base = &ptr,
		.iov_len = sizeof(ptr)
	};
	int ret, fds[2];

	if (pipe(fds) != 0) {
		perror("pipe");
		return T_EXIT_FAIL;
	}

	ret = io_uring_queue_init(8, &ring, IORING_SETUP_SUBMIT_ALL);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_writev(sqe, fds[1], &vec, 1, 0);
	sqe->user_data = 1;

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_readv(sqe, fds[0], &vec, 1, 0);
	sqe->user_data = 2;

	ret = io_uring_submit(&ring);
	if (ret != 2) {
		fprintf(stderr, "submit: %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (int i = 0; i < 2; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait: %d\n", ret);
			return T_EXIT_FAIL;
		}

		switch (cqe->user_data) {
		case 1: /* writev */
			if (cqe->res != sizeof(ptr)) {
				fprintf(stderr, "write res: %d\n", cqe->res);
				return T_EXIT_FAIL;
			}

			break;
		case 2: /* readv should be denied */
			if (should_work) {
				if (cqe->res != sizeof(ptr)) {
					fprintf(stderr, "read res: %d\n", cqe->res);
					return T_EXIT_FAIL;
				}
			} else {
				if (cqe->res != -EACCES) {
					fprintf(stderr, "read res: %d\n", cqe->res);
					return T_EXIT_FAIL;
				}
			}
			break;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	io_uring_queue_exit(&ring);
	close(fds[0]);
	close(fds[1]);
	return T_EXIT_PASS;
}

static void *thread_fn(void *unused)
{
	int ret;

	ret = test_restrictions(0);
	if (ret) {
		fprintf(stderr, "thread restrictions test failed\n");
		return (void *) (uintptr_t) ret;
	}

	ret = io_uring_register_task_restrictions(NULL);
	if (!ret) {
		fprintf(stderr, "thread restrictions unregister worked?!\n");
		return (void *) (uintptr_t) 1;
	}

	return NULL;
}

static int test_restrictions_task(void)
{
	struct io_uring_task_restriction *res;
	pthread_t thread;
	void *tret;
	int ret;

	res = calloc(1, sizeof(*res) + 3 * sizeof(struct io_uring_restriction));

	res->restrictions[0].opcode = IORING_RESTRICTION_SQE_OP;
	res->restrictions[0].sqe_op = IORING_OP_WRITEV;
	res->restrictions[1].opcode = IORING_RESTRICTION_SQE_OP;
	res->restrictions[1].sqe_op = IORING_OP_WRITE;
	res->restrictions[1].opcode = IORING_RESTRICTION_SQE_OP;
	res->restrictions[1].sqe_op = IORING_OP_READV;
	res->nr_res = 3;

	ret = io_uring_register_task_restrictions(res);
	if (ret) {
		if (ret == -EINVAL)
			return T_EXIT_SKIP;
		fprintf(stderr, "Failed to register task restrictions: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/*
	 * Should all work at this point, all allowed opcodes
	 */
	ret = test_restrictions(1);
	if (ret)
		return ret;

	/*
	 * Disallow READV and retest
	 */
	res->restrictions[0].opcode = IORING_RESTRICTION_SQE_OP;
	res->restrictions[0].sqe_op = IORING_OP_READV;
	res->nr_res = 1;
	res->flags = IORING_REG_RESTRICTIONS_MASK;

	ret = io_uring_register_task_restrictions(res);
	if (ret) {
		fprintf(stderr, "Failed to register task restrictions: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = test_restrictions(0);
	if (ret)
		return ret;

	/*
	 * Do an update that fails, should fall back to old set
	 */
	res->restrictions[0].opcode = IORING_RESTRICTION_SQE_OP;
	res->restrictions[0].sqe_op = IORING_OP_WRITEV;
	res->restrictions[1].opcode = IORING_RESTRICTION_SQE_OP;
	res->restrictions[1].sqe_op = 255;
	res->nr_res = 2;
	res->flags = IORING_REG_RESTRICTIONS_MASK;

	ret = io_uring_register_task_restrictions(res);
	if (ret != -EINVAL) {
		fprintf(stderr, "Failed to register task restrictions: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = test_restrictions(0);
	if (ret)
		return ret;

	/*
	 * Now create a thread and have it setup a ring and run the same
	 * test. This should be subject to the same restrictions that we set.
	 */
	pthread_create(&thread, NULL, thread_fn, NULL);
	pthread_join(thread, &tret);
	if (tret)
		 return T_EXIT_FAIL;

	ret = io_uring_register_task_restrictions(NULL);
	if (ret) {
		fprintf(stderr, "thread restrictions unregister failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

static int test_restrictions_task_invalid(void)
{
	struct io_uring_task_restriction *res;
	int ret;

	res = calloc(1, sizeof(*res) + 2 * sizeof(struct io_uring_restriction));

	res->restrictions[0].opcode = IORING_RESTRICTION_SQE_OP;
	res->restrictions[0].sqe_op = IORING_OP_WRITEV;
	res->restrictions[1].opcode = IORING_RESTRICTION_SQE_OP;
	res->restrictions[1].sqe_op = IORING_OP_WRITE;
	res->nr_res = 2;
	res->flags = 0x5a5a;

	ret = io_uring_register_task_restrictions(res);
	if (ret == -EINVAL) {
		free(res);
		return T_EXIT_PASS;
	}

	fprintf(stderr, "Invalid task restrictions: %d\n", ret);
	return T_EXIT_FAIL;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = test_restrictions_task_invalid();
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test_restrictions_resv failed\n");
		return ret;
	}

	ret = test_restrictions_task();
	if (ret == T_EXIT_SKIP) {
		printf("test_restrictions_resv: skipped\n");
		return T_EXIT_SKIP;
	} else if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test_restrictions_resv failed\n");
		return ret;
	}

	return T_EXIT_PASS;
}

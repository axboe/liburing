// SPDX-License-Identifier: MIT
/*
 * Description: test reserving multiple SQEs
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "helpers.h"
#include "liburing.h"

#define QD	8

static int __test(struct io_uring *ring)
{
	struct io_uring_sqe_iter iter;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	unsigned head;
	int i = 0;

	/* reserve half */
	if (!io_uring_reserve_sqes(ring, QD / 2, &iter)) {
		fprintf(stderr, "Failed reserving\n");
		return 1;
	}

	while ((sqe = io_uring_sqe_iter_next(&iter)) != NULL) {
		io_uring_prep_nop(sqe);
		sqe->user_data = ++i;
	}

	io_uring_commit_sqes(ring, &iter);
	io_uring_submit(ring);

	i = 0;
	io_uring_for_each_cqe(ring, head, cqe) {
		i++;
		if (cqe->user_data != i) {
			fprintf(stderr, "user_data mismatch\n");
			return 1;
		}
	}
	if (i != QD / 2) {
		fprintf(stderr, "Found fewer CQEs\n");
		return 1;
	}
	io_uring_cq_advance(ring, i);

	/* reserve all of them */
	if (!io_uring_reserve_sqes(ring, QD, &iter)) {
		fprintf(stderr, "Failed reserving\n");
		return 1;
	}

	i = 0;
	while ((sqe = io_uring_sqe_iter_next(&iter)) != NULL) {
		io_uring_prep_nop(sqe);
		sqe->user_data = ++i;
	}

	io_uring_commit_sqes(ring, &iter);
	io_uring_submit(ring);

	i = 0;
	io_uring_for_each_cqe(ring, head, cqe) {
		i++;
		if (cqe->user_data != i) {
			fprintf(stderr, "user_data mismatch\n");
			return 1;
		}
	}
	if (i != QD) {
		fprintf(stderr, "Found fewer CQEs\n");
		return 1;
	}
	io_uring_cq_advance(ring, i);

	/* reserve more than we have, should fail */
	if (io_uring_reserve_sqes(ring, QD + 1, &iter)) {
		fprintf(stderr, "Failed reserving\n");
		return 1;
	}

	/* reserve 1 and prep it, but unreserve */
	if (!io_uring_reserve_sqes(ring, 1, &iter)) {
		fprintf(stderr, "Failed reserving\n");
		return 1;
	}

	i = 0;
	while ((sqe = io_uring_sqe_iter_next(&iter)) != NULL) {
		io_uring_prep_nop(sqe);
		sqe->user_data = ++i;
	}
	io_uring_unreserve_sqes(1, &iter);
	io_uring_submit(ring);

	i = 0;
	io_uring_for_each_cqe(ring, head, cqe)
		i++;
	if (i) {
		fprintf(stderr, "Found unreserved requests\n");
		return 1;
	}

	/* test nesting inside a current pending get_sqe() region */
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 1;

	if (!io_uring_reserve_sqes(ring, 3, &iter)) {
		fprintf(stderr, "Failed reserving\n");
		return 1;
	}

	i = 1;
	while ((sqe = io_uring_sqe_iter_next(&iter)) != NULL) {
		io_uring_prep_nop(sqe);
		sqe->user_data = ++i;
	}
	io_uring_commit_sqes(ring, &iter);
	io_uring_submit(ring);

	i = 0;
	io_uring_for_each_cqe(ring, head, cqe) {
		i++;
		if (cqe->user_data != i) {
			fprintf(stderr, "user_data mismatch\n");
			return 1;
		}
	}
	if (i != 4) {
		fprintf(stderr, "Found fewer CQEs\n");
		return 1;
	}
	io_uring_cq_advance(ring, i);

	/* test nesting inside a current pending get_sqe() region */
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 1;

	if (io_uring_reserve_sqes(ring, QD, &iter)) {
		fprintf(stderr, "1 Failed reserving\n");
		return 1;
	}

	if (!io_uring_reserve_sqes(ring, QD - 1, &iter)) {
		fprintf(stderr, "2 Failed reserving\n");
		return 1;
	}

	return 0;
}

static int test(void)
{
	struct io_uring ring;
	int ret;

	io_uring_queue_init(QD, &ring, 0);
	ret = __test(&ring);
	io_uring_queue_exit(&ring);
	if (ret) {
		fprintf(stderr, "test 0 failed\n");
		return T_EXIT_FAIL;
	}

	ret = io_uring_queue_init(QD, &ring, IORING_SETUP_SQE128);
	if (ret == -EINVAL)
		return T_EXIT_PASS;
	ret = __test(&ring);
	io_uring_queue_exit(&ring);
	return ret;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		return T_EXIT_SKIP;

	return test();
}

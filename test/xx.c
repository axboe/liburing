/* SPDX-License-Identifier: MIT */
/*
 * Description: run various nop tests
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"
#include "test.h"

#define NR_NOPS		100000000UL
#define NR_BATCH	16

static int seq;

static int test(struct io_uring *ring, int nr)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret, i;

	for (i = 0; i < nr; i++) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			fprintf(stderr, "get sqe failed at %d\n", i);
			goto err;
		}
		io_uring_prep_nop(sqe);
		sqe->user_data = ++seq;
	}

	ret = io_uring_submit(ring);
	if (ret != nr) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	for (i = 0; i < nr; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait completion %d\n", ret);
			goto err;
		}
		if (!cqe->user_data) {
			fprintf(stderr, "Unexpected 0 user_data\n");
			goto err;
		}
		io_uring_cqe_seen(ring, cqe);
	}
	return 0;
err:
	return 1;
}

static int test_ring(void)
{
	struct io_uring ring;
	struct io_uring_params p = { };
	int ret, i;

	p.flags = 0;
	ret = io_uring_queue_init_params(NR_BATCH, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	for (i = 0; i < NR_NOPS / NR_BATCH; i++) {
		ret = test(&ring, NR_BATCH);
		if (ret) {
			fprintf(stderr, "test failed at loop %d\n", i);
			goto err;
		}
	}
err:
	io_uring_queue_exit(&ring);
	return ret;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		return 0;

	return test_ring();
}

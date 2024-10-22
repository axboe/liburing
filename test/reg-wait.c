/* SPDX-License-Identifier: MIT */
/*
 * Description: Test that registered waits work
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>

#include "liburing.h"
#include "helpers.h"
#include "test.h"

static int test(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct timeval tv;
	struct io_uring_reg_wait *arg;
	void *buf;
	int ret;

	if (posix_memalign(&buf, 4096, 4096))
		return T_EXIT_FAIL;

	arg = buf;
	memset(arg, 0, sizeof(*arg));
	arg->ts.tv_sec = 1;
	arg->ts.tv_nsec = 0;
	arg->flags = IORING_REG_WAIT_TS;

	ret = io_uring_register_cqwait_reg(ring, arg, 64);
	if (ret == -EINVAL)
		return T_EXIT_SKIP;

	gettimeofday(&tv, NULL);
	ret = io_uring_submit_and_wait_reg(ring, &cqe, 2, 0);
	if (ret != -ETIME) {
		fprintf(stderr, "submit_and_wait_reg: %d\n", ret);
		goto err;
	}
	ret = mtime_since_now(&tv);
	/* allow some slack, should be around 1s */
	if (ret < 900 || ret > 1100) {
		fprintf(stderr, "wait took too long: %d\n", ret);
		goto err;
	}
	return T_EXIT_PASS;
err:
	return T_EXIT_FAIL;
}

static int test_ring(void)
{
	struct io_uring ring;
	struct io_uring_params p = { };
	int ret;

	p.flags = 0;
	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	ret = test(&ring);
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test failed\n");
		goto err;
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

/* SPDX-License-Identifier: MIT */
/*
 * Description: Test that io_uring_submit_and_wait_timeout() returns the
 * right value (submit count) and that it doesn't end up waiting twice.
 *
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
	struct io_uring_sqe *sqe;
	struct __kernel_timespec ts;
	struct timeval tv;
	int ret, i;

	for (i = 0; i < 1; i++) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			fprintf(stderr, "get sqe failed at %d\n", i);
			goto err;
		}
		io_uring_prep_nop(sqe);
	}

	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	gettimeofday(&tv, NULL);
	ret = io_uring_submit_and_wait_timeout(ring, &cqe, 2, &ts, NULL);
	if (ret < 0) {
		fprintf(stderr, "submit_and_wait_timeout: %d\n", ret);
		goto err;
	}
	ret = mtime_since_now(&tv);
	/* allow some slack, should be around 1s */
	if (ret > 1200) {
		fprintf(stderr, "wait took too long: %d\n", ret);
		goto err;
	}
	return 0;
err:
	return 1;
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
	if (ret) {
		fprintf(stderr, "test failed\n");
		goto err;
	}
err:
	io_uring_queue_exit(&ring);
	return ret;
}

static int test_sqpoll_timeout_consumed(void)
{
	struct io_uring_params p = {
		.flags = IORING_SETUP_SQPOLL,
		.sq_thread_idle = 10,
	};
	struct __kernel_timespec ts = { .tv_sec = 1 };
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	unsigned i;
	int ret;

	ret = t_create_ring_params(32768, &ring, &p);
	if (ret == T_SETUP_SKIP)
		return 0;
	if (ret != T_SETUP_OK)
		return 1;

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		ret = 1;
		goto out;
	}
	io_uring_prep_nop(sqe);
	ret = io_uring_submit(&ring);
	if (ret < 0)
		goto out;
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret)
		goto out;

	for (i = 0; i < 1000; i++) {
		if (IO_URING_READ_ONCE(*ring.sq.kflags) &
		    IORING_SQ_NEED_WAKEUP)
			break;
		usleep(1000);
	}
	if (i == 1000) {
		fprintf(stderr, "SQPOLL thread did not go idle\n");
		ret = 1;
		goto out;
	}

	/*
	 * Fill the ring without publishing the SQEs.  Waking the idle SQ
	 * thread below then leaves a deterministic window where the timeout
	 * SQE has been published but not consumed.
	 */
	for (i = 0; i < ring.sq.ring_entries - 1; i++) {
		sqe = io_uring_get_sqe(&ring);
		if (!sqe) {
			fprintf(stderr, "failed to fill SQ ring at %u\n", i);
			ret = 1;
			goto out;
		}
		io_uring_prep_nop(sqe);
	}

	/* Exercise the pre-IORING_FEAT_EXT_ARG timeout fallback. */
	ring.features &= ~IORING_FEAT_EXT_ARG;
	ret = io_uring_wait_cqes(&ring, &cqe, 1, &ts, NULL);
	if (ret) {
		fprintf(stderr, "wait_cqes: %d\n", ret);
		goto out;
	}
	if (io_uring_sq_ready(&ring)) {
		fprintf(stderr, "returned with %u unconsumed SQEs\n",
			io_uring_sq_ready(&ring));
		ret = 1;
	} else {
		ret = 0;
	}
out:
	io_uring_queue_exit(&ring);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test_ring();
	if (ret)
		return ret;
	return test_sqpoll_timeout_consumed();
}

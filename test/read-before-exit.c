/* SPDX-License-Identifier: MIT */
/*
 * Description: test if issuing IO from thread and immediately exiting will
 * proceed correctly.
 *
 * Original test case from: https://github.com/axboe/liburing/issues/582
 */
#include <unistd.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <string.h>
#include <stdio.h>

#include "liburing.h"
#include "helpers.h"

static int no_iopoll;

struct data {
        struct io_uring *ring;
        int timer_fd1;
        int timer_fd2;
        uint64_t buf1;
        uint64_t buf2;
};

static void *submit(void *data)
{
	struct io_uring_sqe *sqe;
	struct data *d = data;
	int ret;

	sqe = io_uring_get_sqe(d->ring);
	io_uring_prep_read(sqe, d->timer_fd1, &d->buf1, sizeof(d->buf1), 0);

	sqe = io_uring_get_sqe(d->ring);
	io_uring_prep_read(sqe, d->timer_fd2, &d->buf2, sizeof(d->buf2), 0);

	ret = io_uring_submit(d->ring);
	if (ret != 2) {
		struct io_uring_cqe *cqe;

		/*
		 * Kernels without submit-all-on-error behavior will
		 * fail submitting all, check if that's the case and
		 * don't error
		 */
		ret = io_uring_peek_cqe(d->ring, &cqe);
		if (!ret && cqe->res == -EOPNOTSUPP) {
			no_iopoll = 1;
			return NULL;
		}
		return (void *) (uintptr_t) 1;
	}

	/* Exit suddenly. */
	return NULL;
}

/*
 * Without CAP_IPC_LOCK, ring memory counts against RLIMIT_MEMLOCK. Every
 * ring here exits with requests still pending, which makes the kernel free
 * it asynchronously, and the loops below create rings faster than those
 * frees complete. Give them time to catch up rather than failing on
 * -ENOMEM.
 */
static enum t_setup_ret create_ring(struct io_uring *ring, int flags)
{
	struct io_uring_params params;
	int i, ret;

	for (i = 0; i < 100; i++) {
		memset(&params, 0, sizeof(params));
		params.flags = flags;
		ret = io_uring_queue_init_params(8, ring, &params);
		if (ret != -ENOMEM || !geteuid())
			break;
		usleep(10000);
	}
	if (!ret)
		return T_SETUP_OK;

	/* let the helper handle skips and report the error */
	memset(&params, 0, sizeof(params));
	params.flags = flags;
	return t_create_ring_params(8, ring, &params);
}

static int test(int flags)
{
	struct io_uring ring;
	struct data d = { .ring = &ring, };
	pthread_t thread;
	void *res;
	int ret;

	ret = create_ring(&ring, flags);
	if (ret == T_SETUP_SKIP)
		return 0;
	else if (ret != T_SETUP_OK)
		return 1;

	d.timer_fd1 = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (d.timer_fd1 < 0) {
		perror("timerfd_create");
		return 1;
	}
	d.timer_fd2 = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (d.timer_fd2 < 0) {
		perror("timerfd_create");
		return 1;
	}

	pthread_create(&thread, NULL, submit, &d);
	pthread_join(thread, &res);

	/** Wait for completions and do stuff ...  **/

	io_uring_queue_exit(&ring);

	close(d.timer_fd1);
	close(d.timer_fd2);
	return !!res;
}

int main(int argc, char *argv[])
{
	int ret, i;

	for (i = 0; i < 1000; i++) {
		ret = test(0);
		if (ret) {
			fprintf(stderr, "Test failed\n");
			return ret;
		}
	}

	for (i = 0; i < 1000; i++) {
		ret = test(IORING_SETUP_IOPOLL);
		if (ret) {
			fprintf(stderr, "Test IOPOLL failed loop %d\n", i);
			return ret;
		}
		if (no_iopoll)
			break;
	}

	for (i = 0; i < 100; i++) {
		ret = test(IORING_SETUP_SQPOLL);
		if (ret) {
			fprintf(stderr, "Test SQPOLL failed\n");
			return ret;
		}
	}

	return 0;
}

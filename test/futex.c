/* SPDX-License-Identifier: MIT */
/*
 * Description: exercise futex wait/wake/waitv
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <linux/futex.h>

#include "liburing.h"
#include "helpers.h"

#define LOOPS	500
#define NFUTEX	8

static int no_futex;

static void *fwake(void *data)
{
	unsigned int *futex = data;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init: %d\n", ret);
		return NULL;
	}

	*futex = 1;
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_futex_wake(sqe, futex, 1, FUTEX_BITSET_MATCH_ANY);
	sqe->user_data = 3;

	io_uring_submit(&ring);

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait: %d\n", ret);
		return NULL;
	}
	io_uring_cqe_seen(&ring, cqe);
	io_uring_queue_exit(&ring);
	return NULL;
}

static int __test(struct io_uring *ring, int vectored, int async,
		  int async_cancel)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct futex_waitv fw[NFUTEX];
	unsigned int *futex;
	pthread_t threads[NFUTEX];
	void *tret;
	int ret, i, nfutex;

	nfutex = NFUTEX;
	if (!vectored)
		nfutex = 1;

	futex = calloc(nfutex, sizeof(*futex));
	for (i = 0; i < nfutex; i++) {
		fw[i].val = 0;
		fw[i].uaddr = (unsigned long) &futex[i];
		fw[i].flags = FUTEX_32;
		fw[i].__reserved = 0;
	}

	sqe = io_uring_get_sqe(ring);
	if (vectored)
		io_uring_prep_futex_waitv(sqe, fw, nfutex, 0, FUTEX_BITSET_MATCH_ANY);
	else
		io_uring_prep_futex_wait(sqe, futex, 0, FUTEX_BITSET_MATCH_ANY);
	if (async)
		sqe->flags |= IOSQE_ASYNC;
	sqe->user_data = 1;

	io_uring_submit(ring);

	for (i = 0; i < nfutex; i++)
		pthread_create(&threads[i], NULL, fwake, &futex[i]);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_cancel64(sqe, 1, 0);
	if (async_cancel)
		sqe->flags |= IOSQE_ASYNC;
	sqe->user_data = 2;

	io_uring_submit(ring);

	for (i = 0; i < 2; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret) {
			fprintf(stderr, "parent wait %d\n", ret);
			return 1;
		}

		if (cqe->res == -EINVAL || cqe->res == -EOPNOTSUPP) {
			no_futex = 1;
			break;
		}
		io_uring_cqe_seen(ring, cqe);
	}

	for (i = 0; i < nfutex; i++)
		pthread_join(threads[i], &tret);

	return 0;
}

static int test(int flags, int vectored)
{
	struct io_uring ring;
	int ret, i;

	ret = io_uring_queue_init(8, &ring, flags);
	if (ret)
		return ret;
	
	for (i = 0; i < LOOPS; i++) {
		int async_cancel = (!i % 2);
		int async_wait = !(i % 3);
		ret = __test(&ring, vectored, async_wait, async_cancel);
		if (ret) {
			fprintf(stderr, "flags=%x, failed=%d\n", flags, i);
			break;
		}
	}

	io_uring_queue_exit(&ring);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = test(0, 0);
	if (ret)
		return T_EXIT_FAIL;
	if (no_futex)
		return T_EXIT_SKIP;

	ret = test(0, 1);
	if (ret)
		return T_EXIT_FAIL;

	ret = test(IORING_SETUP_SQPOLL, 0);
	if (ret)
		return T_EXIT_FAIL;

	ret = test(IORING_SETUP_SQPOLL, 1);
	if (ret)
		return T_EXIT_FAIL;

	ret = test(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN, 0);
	if (ret)
		return T_EXIT_FAIL;

	ret = test(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN, 1);
	if (ret)
		return T_EXIT_FAIL;

	ret = test(IORING_SETUP_COOP_TASKRUN, 0);
	if (ret)
		return T_EXIT_FAIL;

	ret = test(IORING_SETUP_COOP_TASKRUN, 1);
	if (ret)
		return T_EXIT_FAIL;

	return T_EXIT_PASS;
}

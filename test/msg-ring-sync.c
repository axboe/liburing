/* SPDX-License-Identifier: MIT */
/*
 * Description: test ring messaging command
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

static int no_msg;

struct data {
	struct io_uring *ring;
	unsigned int flags;
	pthread_barrier_t startup;
	pthread_barrier_t barrier;
};

static void *wait_cqe_fn(void *__data)
{
	struct data *d = __data;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(4, &ring, d->flags);
	d->ring = &ring;
	pthread_barrier_wait(&d->startup);

	pthread_barrier_wait(&d->barrier);

	if (ret == -EINVAL)
		goto skip;

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait cqe %d\n", ret);
		goto err_no_cqe;
	}

	if (cqe->user_data != 0x5aa5) {
		fprintf(stderr, "user_data %llx\n", (long long) cqe->user_data);
		goto err;
	}
	if (cqe->res != 0x20) {
		fprintf(stderr, "len %x\n", cqe->res);
		goto err;
	}

	io_uring_cqe_seen(&ring, cqe);
skip:
	io_uring_queue_exit(&ring);
	return NULL;
err:
	io_uring_cqe_seen(&ring, cqe);
err_no_cqe:
	io_uring_queue_exit(&ring);
	return (void *) (unsigned long) 1;
}

static int test_remote(unsigned int ring_flags)
{
	struct io_uring *target;
	pthread_t thread;
	void *tret;
	struct io_uring_sqe sqe = { };
	struct data d;
	int ret;

	d.flags = ring_flags;
	pthread_barrier_init(&d.barrier, NULL, 2);
	pthread_barrier_init(&d.startup, NULL, 2);
	pthread_create(&thread, NULL, wait_cqe_fn, &d);

	pthread_barrier_wait(&d.startup);
	target = d.ring;

	io_uring_prep_msg_ring(&sqe, target->ring_fd, 0x20, 0x5aa5, 0);
	sqe.user_data = 1;

	ret = io_uring_register_sync_msg_ring(&sqe);
	if (ret == -EINVAL) {
		no_msg = 1;
		return T_EXIT_SKIP;
	}
	if (ret < 0) {
		fprintf(stderr, "send_msg_ring_sync %d\n", ret);
		goto err;
	}

	pthread_barrier_wait(&d.barrier);

	if (ret != 0) {
		fprintf(stderr, "res %d\n", ret);
		return -1;
	}
	pthread_join(thread, &tret);
	return 0;
err:
	return 1;
}

static int test_invalid(void)
{
	struct io_uring_sqe sqe = { };
	int ret;

	io_uring_prep_msg_ring(&sqe, 1, 0, 0x8989, 0);
	sqe.user_data = 1;

	ret = io_uring_register_sync_msg_ring(&sqe);
	
	if (ret != -EBADFD) {
		fprintf(stderr, "res %d\n", ret);
		return -1;
	}

	return 0;
}

static int test_disabled_ring(int flags)
{
	struct io_uring_sqe sqe = { };
	struct io_uring disabled_ring;
	int ret;

	flags |= IORING_SETUP_R_DISABLED;
	ret = io_uring_queue_init(8, &disabled_ring, flags);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	io_uring_prep_msg_ring(&sqe, disabled_ring.ring_fd, 0x10, 0x1234, 0);
	sqe.user_data = 1;

	ret = io_uring_register_sync_msg_ring(&sqe);
	if (ret != 0 && ret != -EBADFD) {
		fprintf(stderr, "res %d\n", ret);
		return 1;
	}

	return 0;
}

static int test(int ring_flags)
{
	int ret;

	ret = test_invalid();
	if (ret) {
		fprintf(stderr, "test_invalid failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_remote(ring_flags);
	if (ret) {
		fprintf(stderr, "test_remote failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_remote(ring_flags | IORING_SETUP_IOPOLL);
	if (ret) {
		fprintf(stderr, "test_remote failed\n");
		return T_EXIT_FAIL;
	}

	if (test_disabled_ring(0)) {
		fprintf(stderr, "test_disabled_ring failed\n");
		return T_EXIT_FAIL;
	}

	if (test_disabled_ring(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN)) {
		fprintf(stderr, "test_disabled_ring defer failed\n");
		return T_EXIT_FAIL;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = test(0);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "ring flags 0 failed\n");
		return ret;
	}
	if (no_msg)
		return T_EXIT_SKIP;

	ret = test(IORING_SETUP_SINGLE_ISSUER|IORING_SETUP_DEFER_TASKRUN);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "ring flags defer failed\n");
		return ret;
	}

	return ret;
}

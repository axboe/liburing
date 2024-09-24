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
	int with_io;
	pthread_barrier_t startup;
	pthread_barrier_t barrier;
};

#define FILE_SIZE	(512 * 1024)
#define BS		4096
#define BUFFERS		(FILE_SIZE / BS)

static void *wait_cqe_fn(void *__data)
{
	struct iovec *vecs;
	char fname[256];
	struct data *d = __data;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int ret, i, fd = -1, to_wait;

	srand((unsigned)time(NULL));
	snprintf(fname, sizeof(fname), ".basic-rw-%u-%u",
			(unsigned)rand(), (unsigned)getpid());
	if (d->with_io) {
		t_create_file(fname, FILE_SIZE);
		vecs = t_create_buffers(BUFFERS, BS);
	} else {
		vecs = NULL;
	}

	ret = io_uring_queue_init(BUFFERS, &ring, d->flags);
	if (ret) {
up_skip:
		pthread_barrier_wait(&d->startup);
		pthread_barrier_wait(&d->barrier);
		goto skip;
	}

	if (d->with_io) {
		off_t off = 0;

		fd = open(fname, O_RDONLY | O_DIRECT);
		if (fd < 0)
			goto up_skip;

		for (i = 0; i < BUFFERS; i++) {
			struct io_uring_sqe *sqe;

			sqe = io_uring_get_sqe(&ring);
			io_uring_prep_read(sqe, fd, vecs[i].iov_base,
						vecs[i].iov_len, off);
			sqe->user_data = 1;
			io_uring_submit(&ring);
			off += vecs[i].iov_len;
		}
	}

	d->ring = &ring;
	pthread_barrier_wait(&d->startup);
	pthread_barrier_wait(&d->barrier);

	to_wait = 1;
	if (d->with_io)
		to_wait += BUFFERS;

	for (i = 0; i < to_wait; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait cqe %d\n", ret);
			goto err_no_cqe;
		}
		if (cqe->user_data != 0x5aa5 && cqe->user_data != 1) {
			fprintf(stderr, "user_data %llx\n", (long long) cqe->user_data);
			goto err;
		}
		if (cqe->user_data == 0x5aa5) {
			if (cqe->res != 0x20) {
				fprintf(stderr, "msg len %x\n", cqe->res);
				goto err;
			}
		} else {
			if (cqe->res != BS && cqe->res != -EINVAL &&
			    cqe->res != -EOPNOTSUPP) {
				fprintf(stderr, "rw len %d\n", cqe->res);
				goto err;
			}
		}
		io_uring_cqe_seen(&ring, cqe);
	}
skip:
	if (fd != -1)
		close(fd);
	if (d->with_io) {
		t_destroy_buffers(vecs, BUFFERS);
		unlink(fname);
	}
	io_uring_queue_exit(&ring);
	return NULL;
err:
	io_uring_cqe_seen(&ring, cqe);
err_no_cqe:
	if (fd != -1)
		close(fd);
	if (d->with_io) {
		t_destroy_buffers(vecs, BUFFERS);
		unlink(fname);
	}
	io_uring_queue_exit(&ring);
	return (void *) (unsigned long) 1;
}

static int test_remote(unsigned int ring_flags, int with_io)
{
	struct io_uring *target;
	pthread_t thread;
	void *tret;
	struct io_uring_sqe sqe = { };
	struct data d = { };
	int ret;

	d.flags = ring_flags;
	d.with_io = with_io;
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
	if (ret != -EBADFD) {
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

	ret = test_remote(ring_flags, 0);
	if (ret) {
		fprintf(stderr, "test_remote 0 failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_remote(ring_flags, 1);
	if (ret) {
		fprintf(stderr, "test_remote 1 failed\n");
		return T_EXIT_FAIL;
	}


	ret = test_remote(ring_flags | IORING_SETUP_IOPOLL, 0);
	if (ret) {
		fprintf(stderr, "test_remote poll 0 failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_remote(ring_flags | IORING_SETUP_IOPOLL, 1);
	if (ret) {
		fprintf(stderr, "test_remote poll 1 failed\n");
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
	int ret, i;

	if (argc > 1)
		return T_EXIT_SKIP;

	for (i = 0; i < 5; i++) {
		ret = test(0);
		if (ret != T_EXIT_PASS) {
			fprintf(stderr, "ring flags 0 failed\n");
			return ret;
		}
		if (no_msg)
			return T_EXIT_SKIP;
	}

	for (i = 0; i < 5; i++) {
		ret = test(IORING_SETUP_SINGLE_ISSUER|IORING_SETUP_DEFER_TASKRUN);
		if (ret != T_EXIT_PASS) {
			fprintf(stderr, "ring flags defer failed\n");
			return ret;
		}
	}

	return T_EXIT_PASS;
}

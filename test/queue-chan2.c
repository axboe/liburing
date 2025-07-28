/* SPDX-License-Identifier: MIT */
/*
 * Description: test queue -> queue channel comms
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "liburing.h"

struct data {
	pthread_t thread;
	pthread_barrier_t startup;
	pthread_barrier_t run;
	int do_wait;
	int index;
	int done;
	int ring_fd;
	int ncqes;
};

static void *thread_fn(void *data)
{
	struct io_uring_cqe *cqe;
	struct data *d = data;
	struct io_uring dst;
	int i, ret;

	printf("thread%d: up\n", d->index);

	io_uring_queue_init(128, &dst, IORING_SETUP_DEFER_TASKRUN|IORING_SETUP_SINGLE_ISSUER|IORING_SETUP_CQE32);
	d->ring_fd = dst.ring_fd;
	pthread_barrier_wait(&d->startup);

	pthread_barrier_wait(&d->run);
	if (d->do_wait) {
		printf("thread%d: waiting on CQEs\n", d->index);
		for (i = 0; i < d->ncqes; i++) {
			if (d->done)
				break;
			io_uring_wait_cqe(&dst, &cqe);
			printf("thread%d: got cqe\n", d->index);
			io_uring_cqe_seen(&dst, cqe);
		}
	} else {
		printf("thread%d: sleeping\n", d->index);
		while (!d->done) {
			ret = io_uring_peek_cqe(&dst, &cqe);
			if (!ret) {
				printf("thread%d: unexpected cqe!\n", d->index);
				io_uring_cqe_seen(&dst, cqe);
			}
			usleep(10000);
		}
	}

	printf("thread%d: exit\n", d->index);
	io_uring_queue_exit(&dst);
	return NULL;
}

static int flush_cqes(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	int extras = 0;

	do {
		int ret;

		ret = io_uring_peek_cqe(ring, &cqe);
		if (ret)
			break;
		if (cqe->res < 0)
			extras++;
		io_uring_cqe_seen(ring, cqe);
	} while (1);

	return extras;
}

#define NTHREADS		8

int main(int argc, char *argv[])
{
	struct io_uring_sqe *sqe;
	struct io_uring src;
	struct data d[NTHREADS];
	void *tret;
	int ret, i;
	int to_submit, dupes = 0;

	if (argc > 1)
		return 0;

	io_uring_queue_init(128, &src, 0);

	for (i = 0; i < NTHREADS; i++) {
		d[i].ncqes = 10;
		d[i].done = 0;
		d[i].index = i + 1;
		if (i == 3 || i == 5)
			d[i].do_wait = 1;
		else
			d[i].do_wait = 0;
		pthread_barrier_init(&d[i].startup, NULL, 2);
		pthread_barrier_init(&d[i].run, NULL, 2);
	}

	for (i = 0; i < NTHREADS; i++)
		pthread_create(&d[i].thread, NULL, thread_fn, &d[i]);
	
	for (i = 0; i < NTHREADS; i++)
		pthread_barrier_wait(&d[i].startup);

	for (i = 0; i < NTHREADS; i++) {
		struct io_uring_chan_reg reg = { };

		reg.dst_fd = d[i].ring_fd;
		reg.nentries = 32;
		ret = io_uring_register_queue_chan(&src, &reg);
		printf("thread%d: ret=%d\n", d[i].index, ret);
	}

	for (i = 0; i < NTHREADS; i++)
		pthread_barrier_wait(&d[i].run);

	to_submit = d[0].ncqes;
	for (i = 0; i < to_submit; i++) {
		int extras;

		sqe = io_uring_get_sqe(&src);
		io_uring_prep_chan_post(sqe, 1, 0x1234, 0xdeadbeef, IORING_CHAN_POST_IDLE);
		sqe->user_data = 0x5aa55aa5;

		io_uring_submit(&src);
		extras = flush_cqes(&src);
		dupes += extras;
		to_submit += extras;
	}
	printf("submitter done, %d dupes\n", dupes);

	for (i = 0; i < NTHREADS; i++) {
		d[i].done = 1;
		pthread_join(d[i].thread, &tret);
	}

	io_uring_queue_exit(&src);
	return 0;
}

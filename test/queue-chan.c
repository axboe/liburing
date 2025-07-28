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
	int ring_fd;
	int ncqes;
};

static void *thread_fn(void *data)
{
	struct io_uring_cqe *cqe;
	struct data *d = data;
	struct io_uring dst;
	int i;

	io_uring_queue_init(1024, &dst, IORING_SETUP_DEFER_TASKRUN|IORING_SETUP_SINGLE_ISSUER|IORING_SETUP_CQE32);
	//io_uring_queue_init(8, &dst, 0);
	d->ring_fd = dst.ring_fd;
	pthread_barrier_wait(&d->startup);

	pthread_barrier_wait(&d->run);
	for (i = 0; i < d->ncqes; i++) {
		io_uring_wait_cqe(&dst, &cqe);
		io_uring_cqe_seen(&dst, cqe);
	}
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

int main(int argc, char *argv[])
{
	struct io_uring_chan_reg reg = { };
	struct io_uring_sqe *sqe;
	struct io_uring src;
	struct data d = { };
	void *tret;
	int ret, i;
	int to_submit, dupes = 0;

	if (argc > 1)
		return 0;

	io_uring_queue_init(128, &src, 0);

	d.ncqes = 10000000;
	//d.ncqes = 1000;
	pthread_barrier_init(&d.startup, NULL, 2);
	pthread_barrier_init(&d.run, NULL, 2);

	pthread_create(&d.thread, NULL, thread_fn, &d);
	pthread_barrier_wait(&d.startup);

	reg.dst_fd = d.ring_fd;
	reg.nentries = 256;
	//reg.nentries = 32;
	ret = io_uring_register_queue_chan(&src, &reg);
	printf("ret=%d\n", ret);

	pthread_barrier_wait(&d.run);

	to_submit = d.ncqes;
	for (i = 0; i < to_submit; i++) {
		int extras;

		sqe = io_uring_get_sqe(&src);
		if (!sqe) {
			io_uring_submit(&src);
			extras = flush_cqes(&src);
			dupes += extras;
			to_submit += extras;
			sqe = io_uring_get_sqe(&src);
		}

		io_uring_prep_chan_post(sqe, 1, 0x1234, 0xdeadbeef, 0);
		sqe->flags = IOSQE_CQE_SKIP_SUCCESS;
		sqe->user_data = 0x5aa55aa5;
		if (i + 1 == to_submit) {
			io_uring_submit(&src);
			extras = flush_cqes(&src);
			if (!extras)
				break;
			to_submit += extras;
		}
	}
	printf("submitter done, %d dupes\n", dupes);

	pthread_join(d.thread, &tret);

	io_uring_queue_exit(&src);
	return 0;
}

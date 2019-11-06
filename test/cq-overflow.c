/*
 * Description: run various CQ ring overflow tests
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"

static int reap_events(struct io_uring *ring, unsigned nr_events, int do_wait)
{
	struct io_uring_cqe *cqe;
	int i, ret = 0, seq = 0;

	for (i = 0; i < nr_events; i++) {
		if (do_wait)
			ret = io_uring_wait_cqe(ring, &cqe);
		else
			ret = io_uring_peek_cqe(ring, &cqe);
		if (ret) {
			if (ret != -EAGAIN)
				fprintf(stderr, "cqe peek failed: %d\n", ret);
			break;
		}
		if (cqe->user_data != seq) {
			fprintf(stderr, "cqe sequence out-of-order\n");
			fprintf(stderr, "got %d, wanted %d\n", (int) cqe->user_data,
					seq);
			return -EINVAL;
		}
		seq++;
		io_uring_cqe_seen(ring, cqe);
	}

	return i ? i : ret;
}

/*
 * Setup ring with CQ_NODROP and check we get -EBUSY on trying to submit new IO
 * on an overflown ring, and that we get all the events (even overflows) when
 * we finally reap them.
 */
static int test_overflow_nodrop(void)
{
	struct __kernel_timespec ts;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	unsigned pending;
	int ret, i, j;

	ret = io_uring_queue_init(4, &ring, IORING_SETUP_CQ_NODROP);
	if (ret) {
		if (ret == -EINVAL) {
			fprintf(stdout, "CQ_NODROP not supported, skipped\n");
			return 0;
		}
		fprintf(stderr, "io_uring_queue_init failed %d\n", ret);
		return 1;
	}

	ts.tv_sec = 0;
	ts.tv_nsec = 10000000;

	/* submit 4x4 SQEs, should overflow the ring by 8 */
	pending = 0;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			sqe = io_uring_get_sqe(&ring);
			if (!sqe) {
				fprintf(stderr, "get sqe failed\n");
				goto err;
			}

			io_uring_prep_timeout(sqe, &ts, -1U, 0);
			sqe->user_data = (i * 4) + j;
		}

		ret = io_uring_submit(&ring);
		if (ret != 4) {
			fprintf(stderr, "sqe submit failed: %d, %d\n", ret, pending);
			goto err;
		}
	}

	/* wait for timers to fire */
	usleep(2 * 10000);

	/*
	 * We should have 16 pending CQEs now, 8 of them in the overflow list. Any
	 * attempt to queue more IO should return -EBUSY
	 */
	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}

	io_uring_prep_nop(sqe);
	ret = io_uring_submit(&ring);
	if (ret != -EBUSY) {
		fprintf(stderr, "expected sqe submit busy: %d\n", ret);
		goto err;
	}

	/* reap the 16 events we should have available */
	ret = reap_events(&ring, 16, 1);
	if (ret < 0) {
		fprintf(stderr, "ret=%d\n", ret);
		goto err;
	}

	if (*ring.cq.koverflow) {
		fprintf(stderr, "cq ring overflow %d, expected 0\n",
				*ring.cq.koverflow);
		goto err;
	}

	io_uring_queue_exit(&ring);
	return 0;
err:
	io_uring_queue_exit(&ring);
	return 1;
}

/*
 * Submit some NOPs and watch if the overflow is correct
 */
static int test_overflow(void)
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	int ret, i, j;

	ret = io_uring_queue_init(4, &ring, 0);
	if (ret) {
		fprintf(stderr, "io_uring_queue_init failed %d\n", ret);
		return 1;
	}

	/* submit 4x4 SQEs, should overflow the ring by 8 */
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			sqe = io_uring_get_sqe(&ring);
			if (!sqe) {
				fprintf(stderr, "get sqe failed\n");
				goto err;
			}

			io_uring_prep_nop(sqe);
			sqe->user_data = (i * 4) + j;
		}

		ret = io_uring_submit(&ring);
		if (ret != 4) {
			fprintf(stderr, "sqe submit failed: %d\n", ret);
			goto err;
		}
	}

	/* we should now have 8 completions ready */
	ret = reap_events(&ring, 8, 0);
	if (ret < 0)
		goto err;

	if (*ring.cq.koverflow != 8) {
		fprintf(stderr, "cq ring overflow %d, expected 8\n",
				*ring.cq.koverflow);
		goto err;
	}
	io_uring_queue_exit(&ring);
	return 0;
err:
	io_uring_queue_exit(&ring);
	return 1;
}

int main(int argc, char *argv[])
{
	int ret;

	ret = test_overflow();
	if (ret) {
		printf("test_overflow failed\n");
		return ret;
	}

	ret = test_overflow_nodrop();
	if (ret) {
		printf("test_overflow_nodrop failed\n");
		return ret;
	}

	return 0;
}

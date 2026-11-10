/* SPDX-License-Identifier: MIT */
/*
 * Description: test that the second entry of a 128b SQE on an SQE_MIXED
 *		ring isn't treated as an SQE of its own, and that a 128b
 *		opcode with no second entry queued fails without anything
 *		stepping past the SQ tail.
 *
 * With --enable-sanitizer, liburing checks the pointers in each queued SQE
 * before submitting. It must not check the second entry of a 128b SQE as
 * an SQE: a stale 64b SQE left there, pointing to memory that has been
 * freed since, would be reported as a use-after-free.
 *
 * See https://github.com/axboe/liburing/issues/1671
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "liburing.h"
#include "helpers.h"

#define NENTRIES	8
#define BUF_SIZE	64

static int wait_one(struct io_uring *ring, __u64 user_data, int res)
{
	struct io_uring_cqe *cqe;
	int ret;

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait cqe: %d\n", ret);
		return T_EXIT_FAIL;
	}

	if (cqe->user_data != user_data || cqe->res != res) {
		fprintf(stderr, "cqe %llu res %d, wanted %llu res %d\n",
			(unsigned long long)cqe->user_data, cqe->res,
			(unsigned long long)user_data, res);
		return T_EXIT_FAIL;
	}
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

/*
 * NOP128 in slots 0 and 1, with slot 1 still holding an earlier write from
 * a buffer that has been freed since. Fails if the sanitizer checks slot 1
 * as an SQE, or if the kernel runs the stale write.
 */
static int test_stale_entry(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int fds[2], ret, i;
	char *buf;

	if (pipe(fds) < 0) {
		perror("pipe");
		return T_EXIT_FAIL;
	}
	buf = t_malloc(BUF_SIZE);
	memset(buf, 0x5F, BUF_SIZE);

	/*
	 * Slot 0 is a nop, slot 1 a write from buf. A write and not a read,
	 * so that if the stale copy ever ran, it would only read buf, not
	 * scribble on it.
	 */
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 1;
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_write(sqe, fds[1], buf, BUF_SIZE, 0);
	sqe->user_data = 2;
	io_uring_submit(ring);
	if (wait_one(ring, 1, 0) || wait_one(ring, 2, BUF_SIZE))
		return T_EXIT_FAIL;
	/* the write is done, so buf can go, but slot 1 still points at it */
	free(buf);

	/* fill slots 2..7, so the next SQE wraps around to slot 0 */
	for (i = 2; i < NENTRIES; i++) {
		sqe = io_uring_get_sqe(ring);
		io_uring_prep_nop(sqe);
		sqe->user_data = 3;
	}

	io_uring_submit(ring);
	for (i = 2; i < NENTRIES; i++)
		if (wait_one(ring, 3, 0))
			return T_EXIT_FAIL;

	/* NOP128 takes slots 0 and 1, prep_nop128() only fills in slot 0 */
	sqe = io_uring_get_sqe128(ring);
	if (sqe != &ring->sq.sqes[0]) {
		fprintf(stderr, "NOP128 not in slot 0\n");
		return T_EXIT_FAIL;
	}
	io_uring_prep_nop128(sqe);
	sqe->user_data = 4;

	/* a sanitizer build that checks slot 1 as an SQE exits here */
	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "submit: %d\n", ret);
		return T_EXIT_FAIL;
	}
	if (wait_one(ring, 4, 0))
		return T_EXIT_FAIL;

	/* the stale write in slot 1 must not have run either */
	if (!io_uring_peek_cqe(ring, &cqe)) {
		fprintf(stderr, "unexpected cqe %llu res %d\n",
			(unsigned long long)cqe->user_data, cqe->res);
		return T_EXIT_FAIL;
	}

	close(fds[0]);
	close(fds[1]);
	return T_EXIT_PASS;
}

/*
 * NOP128 in a single 64b entry, with nothing queued behind it. The kernel
 * fails it with -EINVAL and consumes only that entry. The sanitizer must
 * stop at the tail as well, rather than step over a second entry that
 * isn't there.
 */
static int test_128b_at_tail(struct io_uring *ring)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	/* a 128b SQE in the last slot is covered by sqe-mixed-bad-wrap */
	if (sqe == &ring->sq.sqes[NENTRIES - 1]) {
		fprintf(stderr, "SQE in last slot\n");
		return T_EXIT_FAIL;
	}
	io_uring_prep_nop128(sqe);
	sqe->user_data = 5;

	/* skipping a second entry here takes the sanitizer past the tail */
	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "submit: %d\n", ret);
		return T_EXIT_FAIL;
	}
	return wait_one(ring, 5, -EINVAL);
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = io_uring_queue_init(NENTRIES, &ring, IORING_SETUP_SQE_MIXED);
	if (ret) {
		if (ret == -EINVAL)
			return T_EXIT_SKIP;
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = test_stale_entry(&ring);
	if (ret) {
		fprintf(stderr, "test_stale_entry failed\n");
		goto done;
	}

	ret = test_128b_at_tail(&ring);
	if (ret)
		fprintf(stderr, "test_128b_at_tail failed\n");
done:
	io_uring_queue_exit(&ring);
	return ret;
}

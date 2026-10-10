/* SPDX-License-Identifier: MIT */
/*
 * Verify optional requeueing after a short SQ_REWIND submission.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "liburing.h"
#include "helpers.h"

static void prep_partial_batch(struct io_uring *ring)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 1;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	sqe->opcode = 0xff;
	sqe->user_data = 2;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 3;
}

static int consume_cqe(struct io_uring *ring, struct io_uring_cqe *cqe,
		       unsigned *seen, unsigned *count)
{
	unsigned bit;

	if (cqe->user_data < 1 || cqe->user_data > 3) {
		fprintf(stderr, "unexpected user_data: %llu\n",
			(unsigned long long) cqe->user_data);
		return T_EXIT_FAIL;
	}
	bit = 1U << cqe->user_data;
	if (*seen & bit) {
		fprintf(stderr, "duplicate completion for user_data %llu\n",
			(unsigned long long) cqe->user_data);
		return T_EXIT_FAIL;
	}
	*seen |= bit;
	(*count)++;
	io_uring_cqe_seen(ring, cqe);
	return T_EXIT_PASS;
}

static int test_partial_submit(unsigned flags, bool timed, bool requeue)
{
	struct __kernel_timespec ts = { .tv_sec = 1 };
	struct io_uring_cqe *cqe = NULL;
	struct io_uring ring;
	unsigned submitted, seen = 0, count = 0, expected_count;
	bool pending;
	int ret;

	ret = io_uring_queue_init(8, &ring, flags);
	if (ret == -EINVAL && (flags & IORING_SETUP_SQ_REWIND))
		return T_EXIT_SKIP;
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	prep_partial_batch(&ring);
	submitted = io_uring_sq_ready(&ring);

	if (timed)
		ret = io_uring_submit_and_wait_timeout(&ring, &cqe, 2, &ts,
						       NULL);
	else
		ret = io_uring_submit(&ring);
	if (ret != 2) {
		fprintf(stderr, "first submit with flags %#x returned %d, expected 2\n",
			flags, ret);
		goto fail;
	}

	if (flags & IORING_SETUP_SQ_REWIND) {
		if (io_uring_sq_ready(&ring) != 0) {
			fprintf(stderr,
				"SQ_REWIND kept a short submit without opt-in\n");
			goto fail;
		}
		if (requeue)
			io_uring_sq_requeue(&ring, submitted, ret);
	}

	pending = requeue || !(flags & IORING_SETUP_SQ_REWIND);
	if (io_uring_sq_ready(&ring) != pending) {
		fprintf(stderr,
			"pending SQEs with flags %#x after partial submit: %u, expected %u\n",
			flags, io_uring_sq_ready(&ring), pending);
		goto fail;
	}
	if (cqe) {
		if (consume_cqe(&ring, cqe, &seen, &count))
			goto fail;
	}

	if (pending) {
		ret = io_uring_submit(&ring);
		if (ret != 1) {
			fprintf(stderr,
				"retry submit with flags %#x returned %d, expected 1\n",
				flags, ret);
			goto fail;
		}
	}

	expected_count = pending ? 3 : 2;
	while (count != expected_count) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait failed: %d\n", ret);
			goto fail;
		}
		if (consume_cqe(&ring, cqe, &seen, &count))
			goto fail;
	}
	if (seen != (expected_count == 3 ? 0xe : 0x6)) {
		fprintf(stderr, "unexpected completion set: %#x\n", seen);
		goto fail;
	}
	ret = io_uring_peek_cqe(&ring, &cqe);
	if (!ret) {
		fprintf(stderr, "unexpected extra completion after short submit\n");
		goto fail;
	}
	if (ret != -EAGAIN) {
		fprintf(stderr, "peek after short submit failed: %d\n", ret);
		goto fail;
	}

	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
fail:
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

static int test_failed_submit(void)
{
	struct io_uring_params p = {
		.flags = IORING_SETUP_R_DISABLED | IORING_SETUP_SQ_REWIND,
	};
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	unsigned submitted;
	int ret;

	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret == -EINVAL)
		return T_EXIT_SKIP;
	if (ret) {
		fprintf(stderr, "disabled queue init failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 1;
	submitted = io_uring_sq_ready(&ring);

	ret = io_uring_submit(&ring);
	if (ret != -EBADFD) {
		fprintf(stderr, "disabled submit returned %d, expected %d\n",
			ret, -EBADFD);
		goto fail;
	}
	if (io_uring_sq_ready(&ring) != 0) {
		fprintf(stderr, "failed submit was requeued without opt-in\n");
		goto fail;
	}
	io_uring_sq_requeue(&ring, submitted, ret);
	if (io_uring_sq_ready(&ring) != 1) {
		fprintf(stderr, "pending SQEs after failed submit: %u, expected 1\n",
			io_uring_sq_ready(&ring));
		goto fail;
	}

	ret = io_uring_enable_rings(&ring);
	if (ret) {
		fprintf(stderr, "ring enable failed: %d\n", ret);
		goto fail;
	}
	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "submit after enable returned %d, expected 1\n", ret);
		goto fail;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret || cqe->user_data != 1 || cqe->res) {
		fprintf(stderr, "unexpected completion after retry: ret=%d\n", ret);
		goto fail;
	}
	io_uring_cqe_seen(&ring, cqe);

	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
fail:
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

static int test_wait_preserves_pending(void)
{
	struct __kernel_timespec ts = { .tv_nsec = 1000000 };
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(8, &ring, IORING_SETUP_SQ_REWIND);
	if (ret == -EINVAL)
		return T_EXIT_SKIP;
	if (ret)
		return T_EXIT_FAIL;

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	ret = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);
	if (ret != -ETIME || io_uring_sq_ready(&ring) != 1) {
		fprintf(stderr, "timed wait lost a pending SQE: ret=%d ready=%u\n",
			ret, io_uring_sq_ready(&ring));
		goto fail;
	}

	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "submit after timed wait failed: %d\n", ret);
		goto fail;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait after timed wait failed: %d\n", ret);
		goto fail;
	}
	io_uring_cqe_seen(&ring, cqe);
	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
fail:
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = test_partial_submit(0, false, false);
	if (ret)
		return ret;

	ret = test_partial_submit(IORING_SETUP_SQ_REWIND, false, false);
	if (ret)
		return ret;

	ret = test_partial_submit(IORING_SETUP_SQ_REWIND, false, true);
	if (ret)
		return ret;

	ret = test_partial_submit(IORING_SETUP_SQ_REWIND |
				  IORING_SETUP_SQE128, false, true);
	if (ret)
		return ret;

	ret = test_partial_submit(IORING_SETUP_SQ_REWIND, true, true);
	if (ret)
		return ret;

	ret = test_wait_preserves_pending();
	if (ret)
		return ret;

	return test_failed_submit();
}

/* SPDX-License-Identifier: MIT */
/*
 * Test io_uring_register with a registered ring (IORING_REGISTER_USE_REGISTERED_RING)
 *
 */
#include <stdio.h>

#include "helpers.h"

/* resize needs the ring fd to mmap, so it must fail before resizing */
static int test_resize_closed(void)
{
	struct io_uring_params p = { };
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(8, &ring, IORING_SETUP_SINGLE_ISSUER |
					    IORING_SETUP_DEFER_TASKRUN);
	if (ret == -EINVAL)
		return T_EXIT_SKIP;
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	if (io_uring_register_ring_fd(&ring) != 1 ||
	    io_uring_close_ring_fd(&ring) != 1) {
		fprintf(stderr, "closing ring fd failed\n");
		goto err;
	}

	p.sq_entries = 16;
	p.cq_entries = 32;
	ret = io_uring_resize_rings(&ring, &p);
	if (ret != -EBADF) {
		fprintf(stderr, "resize with closed ring fd: %d\n", ret);
		goto err;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	ret = io_uring_submit_and_wait(&ring, 1);
	if (ret != 1) {
		fprintf(stderr, "submit after failed resize: %d\n", ret);
		goto err;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe after failed resize: %d\n", ret);
		goto err;
	}
	io_uring_cqe_seen(&ring, cqe);

	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
err:
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	unsigned values[2];
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed\n");
		return T_EXIT_FAIL;
	}

	if (!(ring.features & IORING_FEAT_REG_REG_RING)) {
		fprintf(stderr, "IORING_FEAT_REG_REG_RING not available in kernel\n");
		io_uring_queue_exit(&ring);
		return T_EXIT_SKIP;
	}

	ret = io_uring_close_ring_fd(&ring);
	if (ret != -EINVAL) {
		fprintf(stderr, "closing ring fd should EINVAL before register\n");
		goto err;
	}

	ret = io_uring_unregister_ring_fd(&ring);
	if (ret != -EINVAL) {
		fprintf(stderr, "unregistering not-registered ring fd should fail\n");
		goto err;
	}

	ret = io_uring_register_ring_fd(&ring);
	if (ret != 1) {
		fprintf(stderr, "registering ring fd failed\n");
		goto err;
	}

	ret = io_uring_register_ring_fd(&ring);
	if (ret != -EEXIST) {
		fprintf(stderr, "registering already-registered ring fd should fail\n");
		goto err;
	}

	/* Test a simple io_uring_register operation expected to work.
	 * io_uring_register_iowq_max_workers is arbitrary.
	 */
	values[0] = values[1] = 0;
	ret = io_uring_register_iowq_max_workers(&ring, values);
	if (ret || (values[0] == 0 && values[1] == 0)) {
		fprintf(stderr, "io_uring_register operation failed before closing ring fd\n");
		goto err;
	}

	ret = io_uring_close_ring_fd(&ring);
	if (ret != 1) {
		fprintf(stderr, "closing ring fd failed\n");
		goto err;
	}

	values[0] = values[1] = 0;
	ret = io_uring_register_iowq_max_workers(&ring, values);
	if (ret || (values[0] == 0 && values[1] == 0)) {
		fprintf(stderr, "io_uring_register operation failed after closing ring fd\n");
		goto err;
	}

	ret = io_uring_close_ring_fd(&ring);
	if (ret != -EBADF) {
		fprintf(stderr, "closing already-closed ring fd should fail\n");
		goto err;
	}

	io_uring_queue_exit(&ring);
	return test_resize_closed() == T_EXIT_FAIL ? T_EXIT_FAIL : T_EXIT_PASS;

err:
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

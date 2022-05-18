/* SPDX-License-Identifier: MIT */
/*
 * Description: run various shared buffer ring sanity checks
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"
#include "helpers.h"

static int no_buf_ring;

/* test trying to register classic group when ring group exists */
static int test_mixed_reg2(int bgid)
{
	struct io_uring_buf_reg reg = { };
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	void *ptr, *bufs;
	int ret;

	ret = t_create_ring(1, &ring, 0);
	if (ret == T_SETUP_SKIP)
		return 0;
	else if (ret != T_SETUP_OK)
		return 1;

	if (posix_memalign(&ptr, 4096, 4096))
		return 1;

	reg.ring_addr = (unsigned long) ptr;
	reg.ring_entries = 32;
	reg.bgid = bgid;

	ret = io_uring_register_buf_ring(&ring, &reg, 0);
	if (ret) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	/* provide classic buffers, group 1 */
	bufs = malloc(8 * 1024);
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_provide_buffers(sqe, bufs, 1024, 8, bgid, 0);
	io_uring_submit(&ring);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe %d\n", ret);
		return 1;
	}
	if (cqe->res != -EEXIST && cqe->res != -EINVAL) {
		fprintf(stderr, "cqe res %d\n", cqe->res);
		return 1;
	}
	io_uring_cqe_seen(&ring, cqe);

	io_uring_queue_exit(&ring);
	return 0;
}

/* test trying to register ring group when  classic group exists */
static int test_mixed_reg(int bgid)
{
	struct io_uring_buf_reg reg = { };
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	void *ptr, *bufs;
	int ret;

	ret = t_create_ring(1, &ring, 0);
	if (ret == T_SETUP_SKIP)
		return 0;
	else if (ret != T_SETUP_OK)
		return 1;

	/* provide classic buffers, group 1 */
	bufs = malloc(8 * 1024);
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_provide_buffers(sqe, bufs, 1024, 8, bgid, 0);
	io_uring_submit(&ring);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe %d\n", ret);
		return 1;
	}
	if (cqe->res) {
		fprintf(stderr, "cqe res %d\n", cqe->res);
		return 1;
	}
	io_uring_cqe_seen(&ring, cqe);

	if (posix_memalign(&ptr, 4096, 4096))
		return 1;

	reg.ring_addr = (unsigned long) ptr;
	reg.ring_entries = 32;
	reg.bgid = bgid;

	ret = io_uring_register_buf_ring(&ring, &reg, 0);
	if (ret != -EEXIST) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	io_uring_queue_exit(&ring);
	return 0;
}

static int test_double_reg_unreg(int bgid)
{
	struct io_uring_buf_reg reg = { };
	struct io_uring ring;
	void *ptr;
	int ret;

	ret = t_create_ring(1, &ring, 0);
	if (ret == T_SETUP_SKIP)
		return 0;
	else if (ret != T_SETUP_OK)
		return 1;

	if (posix_memalign(&ptr, 4096, 4096))
		return 1;

	reg.ring_addr = (unsigned long) ptr;
	reg.ring_entries = 32;
	reg.bgid = bgid;

	ret = io_uring_register_buf_ring(&ring, &reg, 0);
	if (ret) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	/* check that 2nd register with same bgid fails */
	reg.ring_addr = (unsigned long) ptr;
	reg.ring_entries = 32;
	reg.bgid = bgid;

	ret = io_uring_register_buf_ring(&ring, &reg, 0);
	if (ret != -EEXIST) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	ret = io_uring_unregister_buf_ring(&ring, bgid);
	if (ret) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	ret = io_uring_unregister_buf_ring(&ring, bgid);
	if (ret != -EINVAL && ret != -ENOENT) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	io_uring_queue_exit(&ring);
	return 0;
}

static int test_reg_unreg(int bgid)
{
	struct io_uring_buf_reg reg = { };
	struct io_uring ring;
	void *ptr;
	int ret;

	ret = t_create_ring(1, &ring, 0);
	if (ret == T_SETUP_SKIP)
		return 0;
	else if (ret != T_SETUP_OK)
		return 1;

	if (posix_memalign(&ptr, 4096, 4096))
		return 1;

	reg.ring_addr = (unsigned long) ptr;
	reg.ring_entries = 32;
	reg.bgid = bgid;

	ret = io_uring_register_buf_ring(&ring, &reg, 0);
	if (ret) {
		if (ret == -EINVAL) {
			no_buf_ring = 1;
			return 0;
		}
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	ret = io_uring_unregister_buf_ring(&ring, bgid);
	if (ret) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	io_uring_queue_exit(&ring);
	return 0;
}

int main(int argc, char *argv[])
{
	int bgids[] = { 1, 127, -1 };
	int ret, i;

	if (argc > 1)
		return 0;

	for (i = 0; bgids[i] != -1; i++) {
		ret = test_reg_unreg(bgids[i]);
		if (ret) {
			fprintf(stderr, "test_reg_unreg failed\n");
			return 1;
		}
		if (no_buf_ring)
			break;

		ret = test_double_reg_unreg(bgids[i]);
		if (ret) {
			fprintf(stderr, "test_double_reg_unreg failed\n");
			return 1;
		}

		ret = test_mixed_reg(bgids[i]);
		if (ret) {
			fprintf(stderr, "test_mixed_reg failed\n");
			return 1;
		}

		ret = test_mixed_reg2(bgids[i]);
		if (ret) {
			fprintf(stderr, "test_mixed_reg2 failed\n");
			return 1;
		}
	}

	return 0;
}

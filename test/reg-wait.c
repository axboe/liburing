/* SPDX-License-Identifier: MIT */
/*
 * Description: Test that registered waits work
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>

#include "liburing.h"
#include "helpers.h"
#include "test.h"

static struct io_uring_reg_wait *reg;

static int test_invalid_reg2(void)
{
	struct io_uring ring;
	void *buf, *ptr;
	int ret;

	io_uring_queue_init(1, &ring, 0);

	if (posix_memalign(&buf, 4096, 4096))
		return T_EXIT_FAIL;
	memset(buf, 0, 4096);
	ptr = buf + 4096 - 32;

	ret = io_uring_register_wait_reg(&ring, ptr, 1);
	if (ret != -EINVAL) {
		fprintf(stderr, "register cqwait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ptr = buf + (sizeof(struct io_uring_reg_wait) / 2);
	ret = io_uring_register_wait_reg(&ring, ptr, 1);
	if (ret != -EINVAL) {
		fprintf(stderr, "register cqwait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	free(buf);
	buf = (void *) 0x1000;
	ret = io_uring_register_wait_reg(&ring, buf, 1);
	if (ret != -EFAULT) {
		fprintf(stderr, "register cqwait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	buf = (void *) 0x1240;
	ret = io_uring_register_wait_reg(&ring, buf, 1);
	if (ret != -EFAULT) {
		fprintf(stderr, "register cqwait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	buf = (void *) 0x1241;
	ret = io_uring_register_wait_reg(&ring, buf, 1);
	if (ret != -EINVAL) {
		fprintf(stderr, "register cqwait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
}

static int test_invalid_reg(void)
{
	struct io_uring_reg_wait *ireg;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	struct timeval tv;
	void *buf, *ptr;
	int ret;

	io_uring_queue_init(1, &ring, 0);

	if (posix_memalign(&buf, 4096, 4096))
		return T_EXIT_FAIL;
	memset(buf, 0, 4096);
	ptr = buf + 512;
	ireg = ptr;

	ret = io_uring_register_wait_reg(&ring, ireg, 56);
	if (ret) {
		fprintf(stderr, "register cqwait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ireg = ptr;
	memset(ireg, 0, sizeof(*ireg));
	ireg->ts.tv_sec = 1;
	ireg->ts.tv_nsec = 0;
	ireg->flags = IORING_REG_WAIT_TS;

	gettimeofday(&tv, NULL);
	ret = io_uring_submit_and_wait_reg(&ring, &cqe, 1, 0);
	if (ret != -ETIME) {
		fprintf(stderr, "wait_reg failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = mtime_since_now(&tv);
	/* allow some slack, should be around 1.1s */
	if (ret < 1000 || ret > 1200) {
		fprintf(stderr, "wait too long or short: %d\n", ret);
		goto err;
	}

	memset(ireg, 0, sizeof(*ireg));
	ireg->ts.tv_sec = 1;
	ireg->ts.tv_nsec = 0;
	ireg->flags = IORING_REG_WAIT_TS;

	gettimeofday(&tv, NULL);
	ret = io_uring_submit_and_wait_reg(&ring, &cqe, 1, 56);
	if (ret != -EFAULT) {
		fprintf(stderr, "out-of-range reg_wait failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	free(buf);
	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
err:
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

static int test_invalid_sig(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	sigset_t sig;
	int ret;

	memset(reg, 0, sizeof(*reg));
	reg->ts.tv_sec = 1;
	reg->ts.tv_nsec = 0;
	reg->sigmask = (unsigned long) &sig;
	reg->sigmask_sz = 1;

	ret = io_uring_submit_and_wait_reg(ring, &cqe, 1, 0);
	if (ret != -EINVAL) {
		fprintf(stderr, "sigmask_sz failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	memset(reg, 0, sizeof(*reg));
	reg->ts.tv_sec = 1;
	reg->ts.tv_nsec = 0;
	reg->sigmask = 100;
	reg->sigmask_sz = 8;

	ret = io_uring_submit_and_wait_reg(ring, &cqe, 1, 0);
	if (ret != -EFAULT) {
		fprintf(stderr, "sigmask invalid failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

static int test_basic(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct timeval tv;
	int ret;

	memset(reg, 0, sizeof(*reg));
	reg->ts.tv_sec = 1;
	reg->ts.tv_nsec = 100000000ULL;
	reg->flags = IORING_REG_WAIT_TS;

	gettimeofday(&tv, NULL);
	ret = io_uring_submit_and_wait_reg(ring, &cqe, 2, 0);
	if (ret != -ETIME) {
		fprintf(stderr, "submit_and_wait_reg: %d\n", ret);
		goto err;
	}
	ret = mtime_since_now(&tv);
	/* allow some slack, should be around 1.1s */
	if (ret < 1000 || ret > 1200) {
		fprintf(stderr, "wait too long or short: %d\n", ret);
		goto err;
	}
	return T_EXIT_PASS;
err:
	return T_EXIT_FAIL;
}

static int test_ring(void)
{
	struct io_uring ring;
	struct io_uring_params p = { };
	int ret;

	p.flags = 0;
	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	reg = io_uring_setup_reg_wait(&ring, 64, &ret);
	if (!reg) {
		if (ret == -EINVAL)
			return T_EXIT_SKIP;
		fprintf(stderr, "setup_reg_wait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = test_basic(&ring);
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test failed\n");
		goto err;
	}

	ret = test_invalid_sig(&ring);
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test_invalid sig failed\n");
		goto err;
	}

	ret = test_invalid_reg();
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test_invalid_reg failed\n");
		goto err;
	}

	ret = test_invalid_reg2();
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test_invalid_reg2 failed\n");
		goto err;
	}

err:
	io_uring_queue_exit(&ring);
	return ret;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		return 0;

	return test_ring();
}

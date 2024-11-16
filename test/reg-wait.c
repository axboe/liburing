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
#include "../src/syscall.h"

static const struct io_uring_reg_wait brief_wait = {
	.flags = IORING_REG_WAIT_TS,
	.ts.tv_sec = 0,
	.ts.tv_nsec = 1000,
};

static int test_wait_reg_offset(struct io_uring *ring,
				 unsigned wait_nr, unsigned long offset)
{
	return __sys_io_uring_enter2(ring->ring_fd, 0, wait_nr,
				     IORING_ENTER_GETEVENTS |
				     IORING_ENTER_EXT_ARG |
				     IORING_ENTER_EXT_ARG_REG,
				     (void *)offset,
				     sizeof(struct io_uring_reg_wait));
}

static int page_size;
static struct io_uring_reg_wait *reg;

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

static int test_offsets(struct io_uring *ring, struct io_uring_reg_wait *base,
			size_t size, bool overallocated)
{
	struct io_uring_cqe *cqe;
	int max_index = size / sizeof(struct io_uring_reg_wait);
	struct io_uring_reg_wait *rw;
	unsigned long offset;
	int copy_size;
	int ret;

	if (overallocated) {
		rw = base + max_index;
		memcpy(rw, &brief_wait, sizeof(brief_wait));
	}
	ret = io_uring_submit_and_wait_reg(ring, &cqe, 1, max_index);
	if (ret != -EFAULT) {
		fprintf(stderr, "max+1 index failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	rw = base + max_index - 1;
	memcpy(rw, &brief_wait, sizeof(brief_wait));
	ret = io_uring_submit_and_wait_reg(ring, &cqe, 1, max_index - 1);
	if (ret != -ETIME) {
		fprintf(stderr, "last index failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	offset = 0UL - sizeof(long);
	ret = test_wait_reg_offset(ring, 1, offset);
	if (ret != -EFAULT) {
		fprintf(stderr, "overflow offset failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	offset = page_size - sizeof(long);
	rw = (void *)base + offset;
	copy_size = overallocated ? sizeof(brief_wait) : sizeof(long);
	memcpy(rw, &brief_wait, copy_size);

	ret = test_wait_reg_offset(ring, 1, offset);
	if (ret != -EFAULT) {
		fprintf(stderr, "OOB offset failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	offset = 1;
	rw = (void *)base + offset;
	memcpy(rw, &brief_wait, sizeof(brief_wait));
	/* undefined behaviour, check the kernel doesn't crash */
	(void)test_wait_reg_offset(ring, 1, offset);

	return 0;
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

static int test_wait_arg(void)
{
	struct io_uring_region_desc rd = {};
	struct io_uring_mem_region_reg mr = {};
	struct io_uring ring;
	void *buffer;
	int ret;

	ret = io_uring_queue_init(8, &ring, IORING_SETUP_R_DISABLED);
	if (ret) {
		if (ret == -EINVAL) {
			printf("IORING_SETUP_R_DISABLED not supported, skip\n");
			return 0;
		}
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	buffer = aligned_alloc(page_size, page_size * 4);
	if (!buffer) {
		fprintf(stderr, "allocation failed\n");
		return T_EXIT_FAIL;
	}

	rd.user_addr = (__u64)(unsigned long)buffer;
	rd.size = page_size;
	rd.flags = IORING_MEM_REGION_TYPE_USER;
	mr.region_uptr = (__u64)(unsigned long)&rd;
	mr.flags = IORING_MEM_REGION_REG_WAIT_ARG;

	ret = io_uring_register_region(&ring, &mr);
	if (ret) {
		fprintf(stderr, "region reg failed %i\n", ret);
		return 1;
	}

	ret = io_uring_enable_rings(&ring);
	if (ret) {
		fprintf(stderr, "io_uring_enable_rings failure %i\n", ret);
		return T_EXIT_FAIL;
	}

	reg = buffer;

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

	ret = test_offsets(&ring, buffer, page_size, true);
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test_offsets failed\n");
		goto err;
	}
err:
	free(buffer);
	io_uring_queue_exit(&ring);
	return ret;
}

static int test_try_register_region(struct io_uring_mem_region_reg *pr,
				    bool disabled)
{
	struct io_uring ring;
	int flags = 0;
	int ret;

	if (disabled)
		flags = IORING_SETUP_R_DISABLED;

	ret = io_uring_queue_init(8, &ring, flags);
	if (ret) {
		if (ret != -EINVAL)
			fprintf(stderr, "ring setup failed: %d\n", ret);
		return ret;
	}

	ret = io_uring_register_region(&ring, pr);
	if (ret)
		goto err;

	if (disabled) {
		ret = io_uring_enable_rings(&ring);
		if (ret)
			fprintf(stderr, "io_uring_enable_rings failure %i\n", ret);
	}
err:
	io_uring_queue_exit(&ring);
	return ret;
}

static int test_regions(void)
{
	struct io_uring_region_desc rd = {};
	struct io_uring_mem_region_reg mr = {};
	void *buffer;
	int ret;

	buffer = aligned_alloc(page_size, page_size * 4);
	if (!buffer) {
		fprintf(stderr, "allocation failed\n");
		return T_EXIT_FAIL;
	}

	rd.user_addr = (__u64)(unsigned long)buffer;
	rd.size = page_size;
	rd.flags = IORING_MEM_REGION_TYPE_USER;

	mr.region_uptr = (__u64)(unsigned long)&rd;
	mr.flags = IORING_MEM_REGION_REG_WAIT_ARG;

	ret = test_try_register_region(&mr, true);
	if (ret == -EINVAL)
		return T_EXIT_SKIP;
	if (ret) {
		fprintf(stderr, "region: register normal fail %i\n", ret);
		return T_EXIT_FAIL;
	}

	ret = test_try_register_region(&mr, false);
	if (ret != -EINVAL) {
		fprintf(stderr, "region: register with !R_DISABLED fail %i\n", ret);
		return T_EXIT_FAIL;
	}

	rd.size = page_size * 4;
	ret = test_try_register_region(&mr, true);
	if (ret) {
		fprintf(stderr, "test_try_register_region() 16KB fail %i\n", ret);
		return T_EXIT_FAIL;
	}
	rd.size = page_size;

	rd.user_addr = 0;
	ret = test_try_register_region(&mr, true);
	if (ret != -EFAULT) {
		fprintf(stderr, "test_try_register_region() null uptr fail %i\n", ret);
		return T_EXIT_FAIL;
	}
	rd.user_addr = (__u64)(unsigned long)buffer;

	rd.flags = 0;
	ret = test_try_register_region(&mr, true);
	if (!ret) {
		fprintf(stderr, "test_try_register_region() kernel alloc with uptr fail %i\n", ret);
		return T_EXIT_FAIL;
	}
	rd.flags = IORING_MEM_REGION_TYPE_USER;

	rd.size = 0;
	ret = test_try_register_region(&mr, true);
	if (!ret) {
		fprintf(stderr, "test_try_register_region() 0-size fail %i\n", ret);
		return T_EXIT_FAIL;
	}
	rd.size = page_size;

	mr.region_uptr = 0;
	ret = test_try_register_region(&mr, true);
	if (!ret) {
		fprintf(stderr, "test_try_register_region() NULL region %i\n", ret);
		return T_EXIT_FAIL;
	}
	mr.region_uptr = (__u64)(unsigned long)&rd;

	rd.user_addr += 16;
	ret = test_try_register_region(&mr, true);
	if (!ret) {
		fprintf(stderr, "test_try_register_region() misaligned region %i\n", ret);
		return T_EXIT_FAIL;
	}

	rd.user_addr = 0x1000;
	ret = test_try_register_region(&mr, true);
	if (!ret) {
		fprintf(stderr, "test_try_register_region() bogus uptr %i\n", ret);
		return T_EXIT_FAIL;
	}
	rd.user_addr = (__u64)(unsigned long)buffer;

	free(buffer);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}

	ret = test_regions();
	if (ret == T_EXIT_SKIP) {
		printf("regions are not supported, skip\n");
		return 0;
	} else if (ret) {
		fprintf(stderr, "test_region failed\n");
		return 1;
	}

	ret = test_wait_arg();
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test_wait_arg failed\n");
		return 1;
	}
	return 0;
}

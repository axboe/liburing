/* SPDX-License-Identifier: MIT */
/*
 * Description: verify io_uring_mmap() rejects oversized SQE arithmetic
 *		before issuing mmap() calls with the caller-provided fd.
 */
#include <stdio.h>
#include <string.h>

#include "liburing.h"
#include "helpers.h"

static int test_sqes_size_overflow(void)
{
	struct io_uring_params p;
	struct io_uring_sq sq;
	struct io_uring_cq cq;
	int ret;

	memset(&p, 0, sizeof(p));
	memset(&sq, 0, sizeof(sq));
	memset(&cq, 0, sizeof(cq));

	/*
	 * sizeof(struct io_uring_sqe) is 64, and 2^26 entries yields 2^32 bytes,
	 * which cannot fit in sq->sqes_sz (unsigned int).
	 */
	p.sq_entries = 1U << 26;
	p.cq_entries = 1;

	ret = io_uring_mmap(-1, &p, &sq, &cq);
	if (ret != -EINVAL) {
		fprintf(stderr, "io_uring_mmap ret=%d, wanted -EINVAL\n", ret);
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		return T_EXIT_SKIP;

	return test_sqes_size_overflow();
}

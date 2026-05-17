/* SPDX-License-Identifier: MIT */
/*
 * Description: regression test for the size_t multiplication overflow
 * guards on size-sensitive call sites in src/setup.c.
 *
 * The contract is encoded in __size_mul(). This test pins both layers
 * of that contract:
 *
 *   1. The helper itself: direct exercises with boundary inputs on
 *      every supported architecture.
 *
 *   2. End-to-end: io_uring_setup_buf_ring() with an adversarial
 *      nentries returns NULL with a non-zero error code, no crash and
 *      no half-initialised ring left behind.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include "liburing.h"
#include "helpers.h"

static int test_size_mul_helper(void)
{
	size_t out;
	int ret;

	ret = __size_mul(2, 3, &out);
	if (ret || out != 6) {
		fprintf(stderr, "__size_mul(2,3) -> ret=%d out=%zu\n", ret, out);
		return 1;
	}

	ret = __size_mul(SIZE_MAX, 0, &out);
	if (ret || out != 0) {
		fprintf(stderr, "__size_mul(SIZE_MAX,0) -> ret=%d out=%zu\n",
			ret, out);
		return 1;
	}

	ret = __size_mul(0, SIZE_MAX, &out);
	if (ret || out != 0) {
		fprintf(stderr, "__size_mul(0,SIZE_MAX) -> ret=%d out=%zu\n",
			ret, out);
		return 1;
	}

	ret = __size_mul(SIZE_MAX, 1, &out);
	if (ret || out != SIZE_MAX) {
		fprintf(stderr, "__size_mul(SIZE_MAX,1) -> ret=%d out=%zu\n",
			ret, out);
		return 1;
	}

	ret = __size_mul(SIZE_MAX, 2, &out);
	if (ret != -EOVERFLOW) {
		fprintf(stderr, "__size_mul(SIZE_MAX,2) -> ret=%d (want -EOVERFLOW)\n",
			ret);
		return 1;
	}

	ret = __size_mul(SIZE_MAX / 2 + 1, 2, &out);
	if (ret != -EOVERFLOW) {
		fprintf(stderr,
			"__size_mul(SIZE_MAX/2+1,2) -> ret=%d (want -EOVERFLOW)\n",
			ret);
		return 1;
	}

	ret = __size_mul(SIZE_MAX / 2, 2, &out);
	if (ret) {
		fprintf(stderr, "__size_mul(SIZE_MAX/2,2) -> ret=%d (want 0)\n",
			ret);
		return 1;
	}

	/*
	 * The exact shape callers depend on: count * sizeof(elem).
	 * sizeof(struct io_uring_buf) is 16, so UINT_MAX * 16 overflows
	 * 32-bit size_t but fits in 64-bit size_t. Both outcomes are
	 * valid for the contract, but the helper must never return
	 * silent garbage.
	 */
	ret = __size_mul(UINT_MAX, sizeof(struct io_uring_buf), &out);
	if (ret && ret != -EOVERFLOW) {
		fprintf(stderr,
			"__size_mul(UINT_MAX,sizeof buf) -> ret=%d (want 0 or -EOVERFLOW)\n",
			ret);
		return 1;
	}
	if (ret == 0 && out != (size_t)UINT_MAX * sizeof(struct io_uring_buf)) {
		fprintf(stderr,
			"__size_mul(UINT_MAX,sizeof buf) silent wrap: out=%zu\n",
			out);
		return 1;
	}

	return 0;
}

static int test_setup_buf_ring_huge(void)
{
	struct io_uring_buf_ring *br;
	struct io_uring ring;
	int ret, err = 0;

	ret = t_create_ring(1, &ring, 0);
	if (ret == T_SETUP_SKIP)
		return T_EXIT_SKIP;
	if (ret != T_SETUP_OK)
		return 1;

	/*
	 * UINT_MAX entries is far above any kernel cap and, on 32-bit
	 * size_t, overflows the count * sizeof(struct io_uring_buf)
	 * product. The library must turn either failure mode into a
	 * clean NULL return with a non-zero err — no crash, no partial
	 * registration left for the caller to leak.
	 */
	br = io_uring_setup_buf_ring(&ring, UINT_MAX, 0, 0, &err);
	if (br != NULL) {
		fprintf(stderr, "setup_buf_ring(UINT_MAX) returned %p\n", br);
		io_uring_free_buf_ring(&ring, br, UINT_MAX, 0);
		io_uring_queue_exit(&ring);
		return 1;
	}
	if (err == 0) {
		fprintf(stderr, "setup_buf_ring(UINT_MAX) NULL but err == 0\n");
		io_uring_queue_exit(&ring);
		return 1;
	}

	/*
	 * Sanity: a legitimate setup at the same bgid still works after
	 * the failed call — no state was leaked.
	 */
	err = 0;
	br = io_uring_setup_buf_ring(&ring, 32, 0, 0, &err);
	if (!br) {
		fprintf(stderr, "follow-up setup_buf_ring(32) failed: %d\n", err);
		io_uring_queue_exit(&ring);
		return 1;
	}
	io_uring_free_buf_ring(&ring, br, 32, 0);

	io_uring_queue_exit(&ring);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	if (test_size_mul_helper()) {
		fprintf(stderr, "size_mul helper test failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_setup_buf_ring_huge();
	if (ret == T_EXIT_SKIP)
		return T_EXIT_SKIP;
	if (ret) {
		fprintf(stderr, "setup_buf_ring huge nentries test failed\n");
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

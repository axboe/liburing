/* SPDX-License-Identifier: MIT */
/*
 * Description: test file descriptor cloning between rings
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "liburing.h"
#include "helpers.h"

#define NR_FILES 64

static int no_file_clone;
static int no_file_offset;

/* * Helper to test if a file is successfully registered at the given index.
 * A 0-byte read using IOSQE_FIXED_FILE will return 0 if valid, or -EBADF if invalid.
 */
static int use_file(struct io_uring *ring, int index)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	char buf[1];
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_read(sqe, 0, buf, 0, 0); // 0-byte read
	sqe->fd = index;
	sqe->flags |= IOSQE_FIXED_FILE;
	io_uring_submit(ring);

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe: %d\n", ret);
		return ret;
	}

	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int test_offsets(void)
{
	struct io_uring src, dst;
	int fds[NR_FILES];
	unsigned int i, offset, nr;
	int ret;

	ret = io_uring_queue_init(1, &src, 0);
	if (ret) {
		fprintf(stderr, "ring_init: %d\n", ret);
		return T_EXIT_FAIL;
	}
	ret = io_uring_queue_init(1, &dst, 0);
	if (ret) {
		fprintf(stderr, "ring_init: %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (i = 0; i < NR_FILES; i++) {
		int pipe_fds[2];
		if (pipe(pipe_fds) < 0)
			return T_EXIT_FAIL;
		fds[i] = pipe_fds[0]; // Register the read end
		close(pipe_fds[1]);   // Close write end, we only need to test FD existence
	}

	ret = io_uring_register_files(&src, fds, NR_FILES);
	if (ret < 0) {
		fprintf(stderr, "register files failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* clone half the files, src offset 0, but ask for too many */
	offset = NR_FILES / 2;
	nr = NR_FILES;
	ret = io_uring_clone_files_offset(&dst, &src, 0, offset, nr, 0);
	if (ret != -EINVAL) {
		if (ret == -EBADF || ret == -ENOSYS) {
			no_file_offset = 1;
			return T_EXIT_SKIP;
		}
		fprintf(stderr, "Offset and too big total failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* ask for too many files */
	nr = NR_FILES + 1;
	ret = io_uring_clone_files_offset(&dst, &src, 0, 0, nr, 0);
	if (ret != -EINVAL) {
		fprintf(stderr, "Too many files total failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* clone half the files into start of dst offset */
	nr = NR_FILES / 2;
	ret = io_uring_clone_files_offset(&dst, &src, 0, nr, nr, 0);
	if (ret) {
		fprintf(stderr, "Half clone with offset failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* 'nr' offset should be 0 on the src side, valid on dst */
	ret = use_file(&dst, 0);
	if (ret < 0) {
		fprintf(stderr, "1 use_file=%d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = io_uring_unregister_files(&dst);
	if (ret) {
		fprintf(stderr, "Failed to unregister partial dst: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = use_file(&dst, 0);
	if (ret != -EBADF) {
		fprintf(stderr, "2 use_file=%d\n", ret);
		return T_EXIT_FAIL;
	}

	/* clone half the files into middle of dst offset */
	nr = NR_FILES / 2;
	ret = io_uring_clone_files_offset(&dst, &src, nr, nr, nr, 0);
	if (ret) {
		fprintf(stderr, "Half files and middle offset failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = use_file(&dst, 0);
	if (ret != -EBADF) {
		fprintf(stderr, "3 use_file=%d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = use_file(&dst, nr);
	if (ret < 0) {
		fprintf(stderr, "4 use_file=%d\n", ret);
		return T_EXIT_FAIL;
	}

	/* should get -EBUSY now, REPLACE not set */
	nr = NR_FILES / 2;
	ret = io_uring_clone_files_offset(&dst, &src, nr, nr, nr, 0);
	if (ret != -EBUSY) {
		fprintf(stderr, "Replace files failed (expected -EBUSY): %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* now replace the initial 0..n in dst (which are dummy/empty nodes) */
	ret = io_uring_clone_files_offset(&dst, &src, 0, 0, nr, IORING_REGISTER_DST_REPLACE);
	if (ret) {
		fprintf(stderr, "File replace failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = use_file(&dst, 0);
	if (ret < 0) {
		fprintf(stderr, "5 use_file=%d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = io_uring_unregister_files(&dst);
	if (ret) {
		fprintf(stderr, "Failed to unregister partial dst: %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (i = 0; i < NR_FILES; i++)
		close(fds[i]);

	io_uring_queue_exit(&src);
	io_uring_queue_exit(&dst);
	return T_EXIT_PASS;
}

static int test(int reg_src, int reg_dst)
{
	struct io_uring src, dst;
	int fds[NR_FILES];
	int ret, i;

	ret = io_uring_queue_init(1, &src, 0);
	if (ret) return T_EXIT_FAIL;
	
	ret = io_uring_queue_init(1, &dst, 0);
	if (ret) return T_EXIT_FAIL;
	
	if (reg_src) {
		ret = io_uring_register_ring_fd(&src);
		if (ret < 0 && ret != -EINVAL) return T_EXIT_FAIL;
	}
	if (reg_dst) {
		ret = io_uring_register_ring_fd(&dst);
		if (ret < 0 && ret != -EINVAL) return T_EXIT_FAIL;
	}

	/* test fail with no files in src */
	ret = io_uring_clone_files(&dst, &src);
	if (ret == -EINVAL) {
		no_file_clone = 1;
		return T_EXIT_SKIP;
	} else if (ret != -ENXIO) {
		fprintf(stderr, "empty copy: %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (i = 0; i < NR_FILES; i++) {
		int pipe_fds[2];
		if (pipe(pipe_fds) < 0) return T_EXIT_FAIL;
		fds[i] = pipe_fds[0];
		close(pipe_fds[1]);
	}

	ret = io_uring_register_files(&src, fds, NR_FILES);
	if (ret < 0) return T_EXIT_FAIL;

	ret = use_file(&src, 0);
	if (ret < 0) return T_EXIT_FAIL;

	ret = use_file(&dst, 0);
	if (ret != -EBADF) return T_EXIT_FAIL;

	/* copy should work now */
	ret = io_uring_clone_files(&dst, &src);
	if (ret) {
		fprintf(stderr, "file copy: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = use_file(&dst, NR_FILES / 2);
	if (ret < 0) return T_EXIT_FAIL;

	ret = io_uring_clone_files(&dst, &src);
	if (ret != -EBUSY) {
		fprintf(stderr, "busy copy: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = io_uring_unregister_files(&dst);
	if (ret) return T_EXIT_FAIL;

	ret = io_uring_unregister_files(&src);
	if (ret) return T_EXIT_FAIL;

	for (i = 0; i < NR_FILES; i++)
		close(fds[i]);

	io_uring_queue_exit(&src);
	io_uring_queue_exit(&dst);
	return T_EXIT_PASS;
}

static int test_same(void)
{
	struct io_uring src;
	int fds[2] = { -1, -1 }; /* sparse files */
	int ret;

	ret = io_uring_queue_init(1, &src, 0);
	if (ret) {
		fprintf(stderr, "ring_init: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = io_uring_register_files(&src, fds, 2);
	if (ret) {
		fprintf(stderr, "reg files: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* Self-cloning MUST fail with -EINVAL due to our kernel patch */
	ret = io_uring_clone_files_offset(&src, &src, 1, 0, 2, IORING_REGISTER_DST_REPLACE);
	if (ret != -EINVAL) {
		fprintf(stderr, "clone offset on same ring: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = io_uring_unregister_files(&src);
	if (ret) {
		fprintf(stderr, "src unregister files: %d\n", ret);
		return T_EXIT_FAIL;
	}

	io_uring_queue_exit(&src);
	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = test(0, 0);
	if (ret == T_EXIT_SKIP) {
		return T_EXIT_SKIP;
	} else if (ret != T_EXIT_PASS) {
		fprintf(stderr, "test 0 0 failed\n");
		return T_EXIT_FAIL;
	}
	if (no_file_clone)
		return T_EXIT_SKIP;

	ret = test(0, 1);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "test 0 1 failed\n");
		return T_EXIT_FAIL;
	}

	ret = test(1, 0);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "test 1 0 failed\n");
		return T_EXIT_FAIL;
	}

	ret = test(1, 1);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "test 1 1 failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_offsets();
	if (ret == T_EXIT_SKIP) {
		return T_EXIT_PASS;
	} else if (ret != T_EXIT_PASS) {
		fprintf(stderr, "test_offset failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_same();
	if (ret == T_EXIT_SKIP) {
		return T_EXIT_PASS;
	} else if (ret != T_EXIT_PASS) {
		fprintf(stderr, "test_same failed\n");
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

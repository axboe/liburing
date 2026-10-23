/* SPDX-License-Identifier: MIT */
/*
 * Description: test that io_uring_ring_dontfork() also covers the SQ/CQ ring
 *		region when the ring was set up on application provided memory
 *		via io_uring_queue_init_mem() (IORING_SETUP_NO_MMAP).
 *
 * io_uring_alloc_huge() zeroes sq->ring_sz for that case, because
 * io_uring_unmap_rings() uses it as a "we own this mapping" marker. As
 * io_uring_ring_dontfork() reads the very same field as a *length*, the
 * madvise() call for the ring region degenerates into a zero length no-op
 * and still reports success, leaving the SQ/CQ region shared with a child.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "liburing.h"
#include "helpers.h"

/* returns 1 if a forked child can still read *addr, 0 if it cannot */
static int child_can_read(volatile unsigned char *addr)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(T_EXIT_FAIL);
	}
	if (pid == 0) {
		struct rlimit rl = { 0, 0 };
		volatile unsigned char v;

		/* the read is expected to fault, don't leave a core file */
		setrlimit(RLIMIT_CORE, &rl);
		v = *addr;
		(void) v;
		_exit(0);
	}
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		exit(T_EXIT_FAIL);
	}
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int test_dontfork(struct io_uring *ring, const char *what)
{
	int ret;

	ret = io_uring_ring_dontfork(ring);
	if (ret) {
		fprintf(stderr, "%s: dontfork failed: %d\n", what, ret);
		return T_EXIT_FAIL;
	}
	if (child_can_read((volatile unsigned char *) ring->sq.sqes)) {
		fprintf(stderr, "%s: sqes still readable in child\n", what);
		return T_EXIT_FAIL;
	}
	if (child_can_read((volatile unsigned char *) ring->sq.ring_ptr)) {
		fprintf(stderr, "%s: sq/cq ring still readable in child\n", what);
		return T_EXIT_FAIL;
	}
	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct io_uring_params p;
	size_t buf_size = 2 * 1024 * 1024;
	void *buf;
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;
	(void) argv;

	/* control: library allocated ring */
	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		if (ret == -ENOSYS || ret == -EPERM)
			return T_EXIT_SKIP;
		fprintf(stderr, "queue_init: %d\n", ret);
		return T_EXIT_FAIL;
	}
	ret = test_dontfork(&ring, "queue_init");
	io_uring_queue_exit(&ring);
	if (ret != T_EXIT_PASS)
		return ret;

	/* application provided memory */
	buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		return T_EXIT_FAIL;
	}
	memset(&p, 0, sizeof(p));
	ret = io_uring_queue_init_mem(8, &ring, &p, buf, buf_size);
	if (ret < 0) {
		if (ret == -EINVAL)
			return T_EXIT_SKIP;
		fprintf(stderr, "queue_init_mem: %d\n", ret);
		return T_EXIT_FAIL;
	}
	ret = test_dontfork(&ring, "queue_init_mem");
	io_uring_queue_exit(&ring);
	munmap(buf, buf_size);
	return ret;
}

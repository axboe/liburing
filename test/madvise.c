/* SPDX-License-Identifier: MIT */
/*
 * Description: basic madvise test
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>

#include "helpers.h"
#include "liburing.h"

#define FILE_SIZE    (8ULL * 1024ULL * 1024ULL * 1024ULL)

static int do_madvise(struct io_uring *ring, void *addr, off_t len, int advice)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "failed to get sqe\n");
		return 1;
	}

	io_uring_prep_madvise(sqe, addr, len, advice);
	sqe->user_data = advice;
	ret = io_uring_submit_and_wait(ring, 1);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait: %d\n", ret);
		return 1;
	}

	ret = cqe->res;
	if (ret == -EINVAL || ret == -EBADF) {
		fprintf(stdout, "Madvise not supported, skipping\n");
		unlink(".madvise.tmp");
		exit(0);
	} else if (ret) {
		fprintf(stderr, "cqe->res=%d (%s)\n", cqe->res,
			strerror(-cqe->res));
	}
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int test_madvise(struct io_uring *ring, const char *filename)
{
	size_t page_size;
	unsigned char contents;
	int fd, ret;
	unsigned char *ptr;

	page_size = sysconf(_SC_PAGE_SIZE);

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	ret =
	    fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, page_size,
		      page_size);
	if (ret == -1 && errno == EOPNOTSUPP)
		return 3;

	ptr = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	ret =
	    do_madvise(ring, ptr + 2 * page_size, FILE_SIZE - page_size,
		       MADV_REMOVE);
	if (ret)
		return 1;

	for (size_t i = 0; i < FILE_SIZE; i++) {
		contents = ptr[i];
		if (contents && i > page_size) {
			fprintf(stderr,
				"In removed page at %lu but contents=%x\n", i,
				contents);
			return 2;
		} else if (contents != 0xaa && i < page_size) {
			fprintf(stderr,
				"In non-removed page at %lu but contents=%x\n",
				i, contents);
			return 2;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret = 0;
	char *fname;

	if (argc > 1) {
		fname = argv[1];
	} else {
		fname = ".madvise.tmp";
		t_create_file(fname, FILE_SIZE);
	}

	if (io_uring_queue_init(8, &ring, 0)) {
		fprintf(stderr, "ring creation failed\n");
		goto err;
	}

	ret = test_madvise(&ring, fname);
	if (ret) {
		fprintf(stderr, "test_madvise failed\n");
		goto err;
	}

	if (fname != argv[1])
		unlink(fname);
	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
err:
	if (fname != argv[1])
		unlink(fname);
	if (ret == 3)
		return T_EXIT_SKIP;
	return T_EXIT_FAIL;
}

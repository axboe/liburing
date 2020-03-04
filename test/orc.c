/* SPDX-License-Identifier: MIT */
/*
 * Description: open+read+close link sequence with fd passing
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"

#ifndef O_SPECIFIC_FD
#define O_SPECIFIC_FD	01000000000
#endif

#define USE_FD	89

static int test_orc(struct io_uring *ring, const char *fname)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct open_how how;
	char buf[32];
	int ret, i;
	int nr = 0;

	how.flags = O_RDONLY | O_SPECIFIC_FD;
	how.mode = 0;
	how.resolve = 0;
	how.fd = USE_FD;
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_openat2(sqe, AT_FDCWD, fname, &how);
	sqe->flags |= IOSQE_IO_LINK;
	sqe->user_data = IORING_OP_OPENAT2;
	nr++;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_read(sqe, USE_FD, buf, sizeof(buf), 0);
	sqe->flags |= IOSQE_IO_LINK;
	sqe->user_data = IORING_OP_READ;
	nr++;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_close(sqe, USE_FD);
	sqe->user_data = IORING_OP_CLOSE;
	nr++;

	ret = io_uring_submit(ring);
	if (ret != nr) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	for (i = 0; i < nr; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait completion %d\n", ret);
			goto err;
		}

		printf("%d: op=%u, res=%d\n", i, (unsigned) cqe->user_data, cqe->res);
		if (cqe->user_data == IORING_OP_OPENAT2 && cqe->res != USE_FD)
			printf("openat2 got fd %d, wanted %d\n", cqe->res, USE_FD);
		io_uring_cqe_seen(ring, cqe);
	}

	return 0;
err:
	return 1;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret;

	if (argc < 2) {
		fprintf(stderr, "%s: <file>\n", argv[0]);
		return 0;
	}

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	ret = test_orc(&ring, argv[1]);
	if (ret) {
		fprintf(stderr, "test_orc failed\n");
		return ret;
	}

	return 0;
}

/*
 * Description: run various timeout tests
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"

static int test_single_timeout(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct timespec ts;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		printf("get sqe failed\n");
		goto err;
	}

	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	io_uring_prep_timeout(sqe, &ts);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		printf("sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		printf("wait completion %d\n", ret);
		goto err;
	}
	if (cqe->res == -EINVAL)
		printf("Timeout not supported, ignored\n");
	else if (cqe->res != 0) {
		printf("Timeout: %s\n", strerror(-cqe->res));
		goto err;
	}

	io_uring_cqe_seen(ring, cqe);
	return 0;
err:
	return 1;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		printf("ring setup failed\n");
		return 1;

	}

	ret = test_single_timeout(&ring);
	if (ret) {
		printf("test_single_timeout failed\n");
		return ret;
	}

	return 0;
}

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
#include <sys/time.h>

#include "liburing.h"

static unsigned long long mtime_since(const struct timeval *s,
				      const struct timeval *e)
{
	long long sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = (e->tv_usec - s->tv_usec);
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	sec *= 1000;
	usec /= 1000;
	return sec + usec;
}

static unsigned long long mtime_since_now(struct timeval *tv)
{
	struct timeval end;

	gettimeofday(&end, NULL);
	return mtime_since(tv, &end);
}

static int test_single_timeout(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long long exp;
	struct timespec ts;
	struct timeval tv;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		printf("get sqe failed\n");
		goto err;
	}
#define TIMEOUT_MSEC	1000

	ts.tv_sec = TIMEOUT_MSEC / 1000;
	ts.tv_nsec = 0;
	io_uring_prep_timeout(sqe, &ts);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		printf("sqe submit failed: %d\n", ret);
		goto err;
	}

	gettimeofday(&tv, NULL);
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

	exp = mtime_since_now(&tv);
	if (exp >= TIMEOUT_MSEC / 2 && exp <= (TIMEOUT_MSEC * 3) / 2)
		return 0;
	printf("Timeout seems wonky (got %llu)\n", exp);
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

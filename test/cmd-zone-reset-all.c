/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "liburing.h"
#include "helpers.h"

static const char *filename;

static int queue_zone_reset_all(struct io_uring *ring, int bdev_fd)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int err;

	sqe = io_uring_get_sqe(ring);
	assert(sqe != NULL);
	io_uring_prep_cmd_zone_reset_all(sqe, bdev_fd);

	err = io_uring_submit_and_wait(ring, 1);
	if (err != 1) {
		fprintf(stderr, "io_uring_submit_and_wait failed %d\n", err);
		exit(1);
	}

	err = io_uring_wait_cqe(ring, &cqe);
	if (err) {
		fprintf(stderr, "io_uring_wait_cqe failed %d\n", err);
		exit(1);
	}

	err = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return err;
}


static int basic_cmd_test(struct io_uring *ring)
{
	int ret, fd;

	fd = open(filename, O_DIRECT | O_RDWR | O_EXCL);
	if (fd < 0) {
		if (errno == EINVAL || errno == EBUSY)
			return T_EXIT_SKIP;
		fprintf(stderr, "open failed %i\n", errno);
		return T_EXIT_FAIL;
	}

	ret = queue_zone_reset_all(ring, fd);
	if (ret) {
		if (ret == -EINVAL || ret == -EOPNOTSUPP) {
			printf("cmd not supported, skip\n");
			ret = T_EXIT_SKIP;
		} else {
			fprintf(stderr, "cmd_issue_verify fail ret %i\n", ret);
			fprintf(stderr, "cmd fail\n");
			ret = T_EXIT_FAIL;
		}
	}

	close(fd);
	return ret;
}

static int test_rdonly(struct io_uring *ring)
{
	int ret, fd;
	int ro;

	fd = open(filename, O_DIRECT | O_RDONLY | O_EXCL);
	if (fd < 0) {
		if (errno == EINVAL || errno == EBUSY)
			return T_EXIT_SKIP;
		fprintf(stderr, "open failed %i\n", errno);
		return T_EXIT_FAIL;
	}

	ret = queue_zone_reset_all(ring, fd);
	if (ret >= 0) {
		fprintf(stderr, "discarded with O_RDONLY %i\n", ret);
		return 1;
	}
	close(fd);

	fd = open(filename, O_DIRECT | O_RDWR | O_EXCL);
	if (fd < 0) {
		if (errno == EINVAL || errno == EBUSY)
			return T_EXIT_SKIP;
		fprintf(stderr, "open failed %i\n", errno);
		return T_EXIT_FAIL;
	}

	ro = 1;
	ret = ioctl(fd, BLKROSET, &ro);
	if (ret) {
		fprintf(stderr, "BLKROSET 1 failed %i\n", errno);
		return T_EXIT_FAIL;
	}

	ret = queue_zone_reset_all(ring, fd);
	if (ret >= 0) {
		fprintf(stderr, "discarded with O_RDONLY %i\n", ret);
		return 1;
	}

	ro = 0;
	ret = ioctl(fd, BLKROSET, &ro);
	if (ret) {
		fprintf(stderr, "BLKROSET 0 failed %i\n", errno);
		return T_EXIT_FAIL;
	}
	close(fd);
	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int fd, ret;

	if (argc != 2)
		return T_EXIT_SKIP;
	filename = argv[1];

	fd = open(filename, O_DIRECT | O_RDONLY | O_EXCL);
	if (fd < 0) {
		if (errno == EINVAL || errno == EBUSY)
			return T_EXIT_SKIP;
		fprintf(stderr, "open failed %i\n", errno);
		return T_EXIT_FAIL;
	}
	close(fd);

	ret = io_uring_queue_init(16, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = basic_cmd_test(&ring);
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "basic_cmd_test() failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_rdonly(&ring);
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test_rdonly() failed\n");
		return T_EXIT_FAIL;
	}

	if (ret != T_EXIT_SKIP)
		ret = T_EXIT_PASS;

	io_uring_queue_exit(&ring);
	return ret;
}

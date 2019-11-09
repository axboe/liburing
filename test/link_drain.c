/*
 * Description: test io_uring link io with drain io
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"

char expect[3][5] = {
	{ 0, 1, 2, 3, 4 },
	{ 0, 1, 2, 4, 3 },
	{ 0, 1, 4, 2, 3 }
};

static int test_link_drain(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe[5];
	struct iovec iovecs;
	int i, fd, ret;
	off_t off = 0;
	char data[5] = {0};

	fd = open("testfile", O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	iovecs.iov_base = malloc(4096);
	iovecs.iov_len = 4096;

	for (i = 0; i < 5; i++) {
		sqe[i] = io_uring_get_sqe(ring);
		if (!sqe[i]) {
			printf("get sqe failed\n");
			goto err;
		}
	}

	/* normal heavy io */
	io_uring_prep_writev(sqe[0], fd, &iovecs, 1, off);
	sqe[0]->user_data = 0;

	/* link io */
	io_uring_prep_nop(sqe[1]);
	sqe[1]->flags |= IOSQE_IO_LINK;
	sqe[1]->user_data = 1;

	/* link drain io */
	io_uring_prep_nop(sqe[2]);
	sqe[2]->flags |= (IOSQE_IO_LINK | IOSQE_IO_DRAIN);
	sqe[2]->user_data = 2;

	/* link io */
	io_uring_prep_nop(sqe[3]);
	sqe[3]->user_data = 3;

	/* normal nop io */
	io_uring_prep_nop(sqe[4]);
	sqe[4]->user_data = 4;

	ret = io_uring_submit(ring);
	if (ret < 5) {
		printf("Submitted only %d\n", ret);
		goto err;
	} else if (ret < 0) {
		printf("sqe submit failed\n");
		goto err;
	}

	for (i = 0; i < 5; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			printf("child: wait completion %d\n", ret);
			goto err;
		}

		data[i] = cqe->user_data;
		io_uring_cqe_seen(ring, cqe);
	}

	free(iovecs.iov_base);
	close(fd);

	for (i = 0; i < 3; i++) {
		if (memcmp(data, expect[i], 5) == 0)
			break;
	}
	if (i == 3)
		goto err;

	unlink("testfile");
	return 0;
err:
	unlink("testfile");
	return 1;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int i, ret;

	ret = io_uring_queue_init(5, &ring, 0);
	if (ret) {
		printf("ring setup failed\n");
		return 1;
	}

	for (i = 0; i < 1000; i++)
		ret |= test_link_drain(&ring);

	if (ret)
		return ret;

	return 0;
}

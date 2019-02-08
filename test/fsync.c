/*
 * Description: test io_uring fsync handling
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "../src/liburing.h"

int main(int argc, char *argv[])
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	char buf[32];
	int fd, ret;

	sprintf(buf, "./XXXXXX");
	fd = mkstemp(buf);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	
	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		printf("ring setup failed\n");
		return 1;

	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		printf("get sqe failed\n");
		return 1;
	}

	io_uring_prep_fsync(sqe, fd, 0);

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		printf("child: sqe submit failed\n");
		return 1;
	}

	ret = io_uring_wait_completion(&ring, &cqe);
	if (ret < 0) {
		printf("child: wait completion %d\n", ret);
		return 1;
	}

	unlink(buf);
	return 0;
}

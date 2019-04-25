/*
 * Description: -EAGAIN handling
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "../src/liburing.h"

static int get_file_fd(void)
{
	char *buf;
	int fd;

	fd = open("testfile", O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		perror("open file");
		return -1;
	}

	buf = malloc(4096);
	write(fd, buf, 4096);
	fsync(fd);

	if (posix_fadvise(fd, 0, 4096, POSIX_FADV_DONTNEED)) {
		perror("fadvise");
		close(fd);
		free(buf);
		return -1;
	}

	free(buf);
	return fd;
}

static void put_file_fd(int fd)
{
	close(fd);
	unlink("testfile");
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	struct iovec iov;
	int ret, fd;

	iov.iov_base = malloc(4096);
	iov.iov_len = 4096;

	ret = io_uring_queue_init(2, &ring, 0);
	if (ret) {
		printf("ring setup failed\n");
		return 1;

	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		printf("get sqe failed\n");
		return 1;
	}

	fd = get_file_fd();
	if (fd < 0)
		return 1;

	io_uring_prep_readv(sqe, fd, &iov, 1, 0);
	sqe->rw_flags = RWF_NOWAIT;

	ret = io_uring_submit(&ring);
	if (ret != -EAGAIN) {
		printf("Got submit %d, expected EAGAIN\n", ret);
		goto err;
	}

	put_file_fd(fd);
	return 0;
err:
	put_file_fd(fd);
	return 1;
}

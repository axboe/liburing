#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>

#include "liburing.h"

#define IOVECS_LEN 2

int main() {
	struct io_uring ring;
	int fd = open("fixed-link.c", O_RDONLY);

	if (fd < 0) {
		perror("open");
		assert(0);
	}

	if (io_uring_queue_init(32, &ring, 0) < 0) {
		perror("io_uring_queue_init");
		assert(0);
	}

	struct iovec iovecs[IOVECS_LEN];
	for (int i = 0; i < IOVECS_LEN; ++i) {
		iovecs[i] = (struct iovec){ .iov_base = malloc(64), .iov_len = 64 };
	};

	io_uring_register_buffers(&ring, iovecs, IOVECS_LEN);

	for (int i = 0; i < IOVECS_LEN; ++i) {
		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		const char *str = "#include <errno.h>";
		io_uring_prep_read_fixed(sqe, fd, iovecs[i].iov_base, strlen(str), 0, i);
		io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
		io_uring_sqe_set_data(sqe, (void *)str);
	}

	io_uring_submit_and_wait(&ring, IOVECS_LEN);

	for (int i = 0; i < IOVECS_LEN; ++i) {
		struct io_uring_cqe *cqe;
		io_uring_peek_cqe(&ring, &cqe);
		const char *str = io_uring_cqe_get_data(cqe);
		if (cqe->res < 0) {
			errno = -cqe->res;
			perror("cqe->res");
			fprintf(stderr, "i = %d\n", i);
			assert(0);
		}
		assert(strlen(str) == cqe->res);
		assert(strcmp(str, iovecs[i].iov_base) == 0);
		io_uring_cqe_seen(&ring, cqe);
	}

	close(fd);
	io_uring_queue_exit(&ring);

	for (int i = 0; i < IOVECS_LEN; ++i) {
		free(iovecs[i].iov_base);
	};
}

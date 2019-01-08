/*
 * Simple app that demonstrates how to setup an io_uring interface,
 * submit and complete IO against it, and then tear it down.
 *
 * gcc -Wall -O2 -D_GNU_SOURCE -o io_uring-test io_uring-test.c -luring
 */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../src/liburing.h"

int main(int argc, char *argv[])
{
	struct io_uring_params p;
	struct io_uring_sq sq;
	struct io_uring_cq cq;
	int i, fd, ring_fd, ret, pending, done;
	struct io_uring_iocb *iocb;
	struct io_uring_event *ev;
	off_t offset;
	void *buf;

	if (argc < 2) {
		printf("%s: file\n", argv[0]);
		return 1;
	}

	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_IOPOLL;

	ring_fd = io_uring_queue_init(4, &p, NULL, &sq, &cq);
	if (ring_fd < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ring_fd));
		return 1;
	}

	fd = open(argv[1], O_RDONLY | O_DIRECT);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	if (posix_memalign(&buf, 4096, 4096))
		return 1;

	offset = 0;
	do {
		iocb = io_uring_get_iocb(&sq);
		if (!iocb)
			break;
		iocb->opcode = IORING_OP_READ;
		iocb->flags = 0;
		iocb->ioprio = 0;
		iocb->fd = fd;
		iocb->off = offset;
		iocb->addr = buf;
		iocb->len = 4096;
		offset += 4096;
	} while (1);

	ret = io_uring_submit(ring_fd, &sq);
	if (ret < 0) {
		fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
		return 1;
	}

	done = 0;
	pending = ret;
	for (i = 0; i < pending; i++) {
		ev = NULL;
		ret = io_uring_get_completion(ring_fd, &cq, &ev);
		if (ret < 0) {
			fprintf(stderr, "io_uring_get_completion: %s\n", strerror(-ret));
			return 1;
		}

		done++;
		if (ev->res != 4096) {
			fprintf(stderr, "ret=%d, wanted 4096\n", ev->res);
			return 1;
		}
	}

	printf("Submitted=%d, completed=%d\n", pending, done);
	close(fd);
	io_uring_queue_exit(ring_fd, &sq, &cq);
	return 0;
}

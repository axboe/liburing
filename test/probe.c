/*
 * Description: test IORING_REGISTER_PROBE
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"

static int test_probe(struct io_uring *ring)
{
	struct io_uring_probe *p;
	size_t len;
	int ret;

	len = sizeof(*p) + 256 * sizeof(struct io_uring_probe_op);
	p = calloc(1, len);
	ret = io_uring_register_probe(ring, p, 0);
	if (ret == -EINVAL) {
		fprintf(stdout, "Probe not supported, skipping\n");
		return 0;
	} else if (ret) {
		fprintf(stdout, "Probe returned %d\n", ret);
		return 1;
	}

	if (p->ops_len) {
		fprintf(stderr, "Got ops_len=%u\n", p->ops_len);
		return 1;
	}
	if (!p->last_op) {
		fprintf(stderr, "Got last_op=%u\n", p->last_op);
		return 1;
	}

	/* now grab for all entries */
	memset(p, 0, len);
	ret = io_uring_register_probe(ring, p, 256);
	if (ret == -EINVAL) {
		fprintf(stdout, "Probe not supported, skipping\n");
		return 0;
	} else if (ret) {
		fprintf(stdout, "Probe returned %d\n", ret);
		return 1;
	}

	/* check a few ops that must be supported */
	if (!(p->ops[IORING_OP_NOP].flags & IO_URING_OP_SUPPORTED)) {
		fprintf(stderr, "NOP not supported!?\n");
		return 1;
	}
	if (!(p->ops[IORING_OP_READV].flags & IO_URING_OP_SUPPORTED)) {
		fprintf(stderr, "READV not supported!?\n");
		return 1;
	}
	if (!(p->ops[IORING_OP_WRITE].flags & IO_URING_OP_SUPPORTED)) {
		fprintf(stderr, "READV not supported!?\n");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed\n");
		return 1;
	}

	ret = test_probe(&ring);
	if (ret) {
		fprintf(stderr, "test_probe failed\n");
		return ret;
	}

	return 0;
}

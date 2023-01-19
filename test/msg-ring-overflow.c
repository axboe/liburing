/* SPDX-License-Identifier: MIT */
/*
 * Description: test ring messaging command
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"
#include "helpers.h"

static int no_msg;

static int test(struct io_uring *ring, unsigned dst_flags)
{
	struct io_uring_params p = { };
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring dst;
	int ret, i;

	p.flags = dst_flags | IORING_SETUP_CQSIZE;
	p.cq_entries = 4;
	ret = io_uring_queue_init_params(4, &dst, &p);
	if (ret) {
		fprintf(stderr, "Destination ring create failed %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (i = 0; i < 8; i++) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			fprintf(stderr, "get sqe failed\n");
			goto err;
		}

		io_uring_prep_msg_ring(sqe, dst.ring_fd, 0x10, 0x1234, 0);
		sqe->user_data = i + 1;
	}

	ret = io_uring_submit(ring);
	if (ret != 8) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	for (i = 0; i < 8; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait completion %d\n", ret);
			goto err;
		}
		switch (cqe->user_data) {
		case 1 ... 8:
			if (cqe->res == -EINVAL || cqe->res == -EOPNOTSUPP) {
				no_msg = 1;
				goto out;
			}
			if (cqe->res != 0) {
				fprintf(stderr, "cqe res %d\n", cqe->res);
				goto err;
			}
			break;
		case 0x1234:
			if (cqe->res != 0x10) {
				fprintf(stderr, "invalid len %x\n", cqe->res);
				goto err;
			}
			break;
		default:
			fprintf(stderr, "Invalid user_data\n");
			goto err;
		}
		io_uring_cqe_seen(ring, cqe);
	}

	for (i = 0; i < 8; i++) {
		ret = io_uring_wait_cqe(&dst, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait completion %d\n", ret);
			goto err;
		}
		switch (cqe->user_data) {
		case 0x1234:
			if (cqe->res != 0x10) {
				fprintf(stderr, "invalid len %x\n", cqe->res);
				goto err;
			}
			break;
		default:
			fprintf(stderr, "Invalid user_data\n");
			goto err;
		}
		io_uring_cqe_seen(&dst, cqe);
	}

out:
	io_uring_queue_exit(&dst);
	return no_msg ? T_EXIT_SKIP : T_EXIT_PASS;
err:
	io_uring_queue_exit(&dst);
	return T_EXIT_FAIL;
}


int main(int argc, char *argv[])
{
	struct io_uring src;
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = io_uring_queue_init(8, &src, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = test(&src, 0);
	if (ret) {
		fprintf(stderr, "test failed\n");
		return ret;
	}
	if (no_msg)
		return T_EXIT_SKIP;

	ret = test(&src, IORING_SETUP_IOPOLL);
	if (ret) {
		fprintf(stderr, "test IOPOLL failed\n");
		return ret;
	}

	ret = test(&src, IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER);
	if (ret) {
		fprintf(stderr, "test defer failed\n");
		return ret;
	}

	ret = test(&src, IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_IOPOLL);
	if (ret) {
		fprintf(stderr, "test defer IOPOLL failed\n");
		return ret;
	}

	return T_EXIT_PASS;
}

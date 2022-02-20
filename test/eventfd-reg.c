/* SPDX-License-Identifier: MIT */
/*
 * Description: test eventfd registration+unregistration
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>

#include "liburing.h"

int main(int argc, char *argv[])
{
	struct io_uring_params p = {};
	struct io_uring ring;
	int ret, evfd[2], i;

	if (argc > 1)
		return 0;

	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	evfd[0] = eventfd(0, EFD_CLOEXEC);
	evfd[1] = eventfd(0, EFD_CLOEXEC);
	if (evfd[0] < 0 || evfd[1] < 0) {
		perror("eventfd");
		return 1;
	}

	ret = io_uring_register_eventfd(&ring, evfd[0]);
	if (ret) {
		fprintf(stderr, "failed to register evfd: %d\n", ret);
		return 1;
	}

	/* Check that registrering again will get -EBUSY */
	ret = io_uring_register_eventfd(&ring, evfd[1]);
	if (ret != -EBUSY) {
		fprintf(stderr, "unexpected 2nd register: %d\n", ret);
		return 1;
	}
	close(evfd[1]);

	ret = io_uring_unregister_eventfd(&ring);
	if (ret) {
		fprintf(stderr, "unexpected unregister: %d\n", ret);
		return 1;
	}

	/* loop 100 registers/unregister */
	for (i = 0; i < 100; i++) {
		ret = io_uring_register_eventfd(&ring, evfd[0]);
		if (ret) {
			fprintf(stderr, "failed to register evfd: %d\n", ret);
			return 1;
		}

		ret = io_uring_unregister_eventfd(&ring);
		if (ret) {
			fprintf(stderr, "unexpected unregister: %d\n", ret);
			return 1;
		}
	}

	close(evfd[0]);
	return 0;
}

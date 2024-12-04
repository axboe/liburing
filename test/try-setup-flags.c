/* SPDX-License-Identifier: MIT */
/*
 * Description: test io_uring_try_setup_flags()
 *
 */
#include <stdio.h>

#include "liburing.h"
#include "helpers.h"

int main(int argc, char *argv[])
{
	struct io_uring_params params = {0};
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = io_uring_try_setup_flags(&params, IORING_SETUP_CLAMP);
	if (ret != 0) {
		fprintf(stderr, "IORING_SETUP_CLAMP failed\n");
		return T_EXIT_FAIL;
	}

	/* should fail without IORING_SETUP_SINGLE_ISSUER */
	ret = io_uring_try_setup_flags(&params, IORING_SETUP_DEFER_TASKRUN);
	if (ret != -EINVAL) {
		fprintf(stderr, "IORING_SETUP_DEFER_TASKRUN failed\n");
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

/* SPDX-License-Identifier: MIT */
/*
 * Description: test that using SETUP_NO_MMAP with an invalid SQ ring
 *		address fails.
 *
 */
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

#include "liburing.h"
#include "helpers.h"

int main(int argc, char *argv[])
{
	struct io_uring_params p = {
		.sq_entries	= 2,
		.cq_entries	= 4,
		.flags		= IORING_SETUP_NO_MMAP,
	};
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	p.cq_off.user_addr = (unsigned long long) (uintptr_t) valloc(8192);

	ret = io_uring_setup(2, &p);
	if (ret != -EFAULT) {
		fprintf(stderr, "Got %d, wanted -EFAULT\n", ret);
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

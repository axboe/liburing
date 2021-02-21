/* SPDX-License-Identifier: MIT */
/*
 * Description: Helpers for tests.
 */
#include <stdlib.h>
#include <assert.h>

#include "helpers.h"

/*
 * Helper for allocating memory in tests.
 */
void *io_uring_malloc(size_t size)
{
	void *ret;
	ret = malloc(size);
	assert(ret);
	return ret;
}

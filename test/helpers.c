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


/*
 * Helper for allocating size bytes aligned on a boundary.
 */
void io_uring_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret;
	ret = posix_memalign(memptr, alignment, size);
	assert(!ret);
}

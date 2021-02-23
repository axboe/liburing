/* SPDX-License-Identifier: MIT */
/*
 * Description: Helpers for tests.
 */
#ifndef LIBURING_HELPERS_H
#define LIBURING_HELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Helper for allocating memory in tests.
 */
void *io_uring_malloc(size_t size);


/*
 * Helper for allocating size bytes aligned on a boundary.
 */
void io_uring_posix_memalign(void **memptr, size_t alignment, size_t size);

#ifdef __cplusplus
}
#endif

#endif

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

#ifdef __cplusplus
}
#endif

#endif

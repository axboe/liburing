/* SPDX-License-Identifier: MIT */
#ifndef LIBURING_EX_HELPERS_H
#define LIBURING_EX_HELPERS_H

int setup_listening_socket(int port, int ipv6);

/*
 * Some Android versions lack aligned_alloc in stdlib.h.
 * To avoid making large changes in tests, define a helper
 * function that wraps posix_memalign as our own aligned_alloc.
 */
void *aligned_alloc(size_t alignment, size_t size);

#endif

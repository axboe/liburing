/* SPDX-License-Identifier: MIT */
/*
 * Description: Helpers for tests.
 */
#ifndef LIBURING_HELPERS_H
#define LIBURING_HELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "liburing.h"

enum t_setup_ret {
	T_SETUP_OK	= 0,
	T_SETUP_SKIP,
};

/*
 * Helper for allocating memory in tests.
 */
void *t_malloc(size_t size);


/*
 * Helper for allocating size bytes aligned on a boundary.
 */
void t_posix_memalign(void **memptr, size_t alignment, size_t size);


/*
 * Helper for allocating space for an array of nmemb elements
 * with size bytes for each element.
 */
void *t_calloc(size_t nmemb, size_t size);


/*
 * Helper for creating file and write @size byte buf with 0xaa value in the file.
 */
void t_create_file(const char *file, size_t size);

/*
 * Helper for creating file and write @size byte buf with @pattern value in
 * the file.
 */
void t_create_file_pattern(const char *file, size_t size, char pattern);

/*
 * Helper for creating @buf_num number of iovec
 * with @buf_size bytes buffer of each iovec.
 */
struct iovec *t_create_buffers(size_t buf_num, size_t buf_size);

/*
 * Helper for setting up a ring and checking for user privs
 */
enum t_setup_ret t_create_ring_params(int depth, struct io_uring *ring,
				      struct io_uring_params *p);
enum t_setup_ret t_create_ring(int depth, struct io_uring *ring,
			       unsigned int flags);

enum t_setup_ret t_register_buffers(struct io_uring *ring,
				    const struct iovec *iovecs,
				    unsigned nr_iovecs);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifdef __cplusplus
}
#endif

#endif

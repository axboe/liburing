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


/*
 * Helper for allocating space for an array of nmemb elements
 * with size bytes for each element.
 */
void *io_uring_calloc(size_t nmemb, size_t size);


/*
 * Helper for creating file and write @size byte buf with 0xaa value in the file.
 */
void io_uring_create_file(const char *file, size_t size);

/*
 * Helper for creating @buf_num number of iovec
 * with @buf_size bytes buffer of each iovec.
 */
struct iovec *io_uring_create_buffers(size_t buf_num, size_t buf_size);
#ifdef __cplusplus
}
#endif

#endif

/* SPDX-License-Identifier: MIT */
/*
 * Description: Helpers for tests.
 */
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "helpers.h"
#include "liburing.h"

/*
 * Helper for allocating memory in tests.
 */
void *t_malloc(size_t size)
{
	void *ret;
	ret = malloc(size);
	assert(ret);
	return ret;
}

/*
 * Helper for allocating size bytes aligned on a boundary.
 */
void t_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret;
	ret = posix_memalign(memptr, alignment, size);
	assert(!ret);
}

/*
 * Helper for allocating space for an array of nmemb elements
 * with size bytes for each element.
 */
void *t_calloc(size_t nmemb, size_t size)
{
	void *ret;
	ret = calloc(nmemb, size);
	assert(ret);
	return ret;
}

/*
 * Helper for creating file and write @size byte buf with 0xaa value in the file.
 */
void t_create_file(const char *file, size_t size)
{
	ssize_t ret;
	char *buf;
	int fd; 

	buf = t_malloc(size);
	memset(buf, 0xaa, size);

	fd = open(file, O_WRONLY | O_CREAT, 0644);
	assert(fd >= 0);

	ret = write(fd, buf, size);
	fsync(fd);
	close(fd);
	free(buf);
	assert(ret == size);
}

/*
 * Helper for creating @buf_num number of iovec
 * with @buf_size bytes buffer of each iovec.
 */
struct iovec *t_create_buffers(size_t buf_num, size_t buf_size)
{
	struct iovec *vecs;
	int i;

	vecs = t_malloc(buf_num * sizeof(struct iovec));
	for (i = 0; i < buf_num; i++) {
		t_posix_memalign(&vecs[i].iov_base, buf_size, buf_size);
		vecs[i].iov_len = buf_size; 
	}
	return vecs;
}

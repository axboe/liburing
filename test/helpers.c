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

/*
 * Helper for allocating space for an array of nmemb elements
 * with size bytes for each element.
 */
void *io_uring_calloc(size_t nmemb, size_t size)
{
	void *ret;
	ret = calloc(nmemb, size);
	assert(ret);
	return ret;
}

/*
 * Helper for creating file and write @size byte buf with 0xaa value in the file.
 */
void io_uring_create_file(const char *file, size_t size)
{
	ssize_t ret;
	char *buf;
	int fd; 

	buf = io_uring_malloc(size);
	memset(buf, 0xaa, size);

	fd = open(file, O_WRONLY | O_CREAT, 0644);
	assert(fd >= 0);

	ret = write(fd, buf, size);
	fsync(fd);
	close(fd);
	free(buf);
	assert(ret == size);
}


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
#include <sys/types.h>

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
static void __t_create_file(const char *file, size_t size, char pattern)
{
	ssize_t ret;
	char *buf;
	int fd; 

	buf = t_malloc(size);
	memset(buf, pattern, size);

	fd = open(file, O_WRONLY | O_CREAT, 0644);
	assert(fd >= 0);

	ret = write(fd, buf, size);
	fsync(fd);
	close(fd);
	free(buf);
	assert(ret == size);
}

void t_create_file(const char *file, size_t size)
{
	__t_create_file(file, size, 0xaa);
}

void t_create_file_pattern(const char *file, size_t size, char pattern)
{
	__t_create_file(file, size, pattern);
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

/*
 * Helper for setting up an io_uring instance, skipping if the given user isn't
 * allowed to.
 */
enum t_setup_ret t_create_ring_params(int depth, struct io_uring *ring,
				      struct io_uring_params *p)
{
	int ret;

	ret = io_uring_queue_init_params(depth, ring, p);
	if (!ret)
		return T_SETUP_OK;
	if ((p->flags & IORING_SETUP_SQPOLL) && ret == -EPERM && geteuid()) {
		fprintf(stdout, "SQPOLL skipped for regular user\n");
		return T_SETUP_SKIP;
	}

	fprintf(stderr, "queue_init: %s\n", strerror(-ret));
	return ret;
}

enum t_setup_ret t_create_ring(int depth, struct io_uring *ring,
			       unsigned int flags)
{
	struct io_uring_params p = { };

	p.flags = flags;
	return t_create_ring_params(depth, ring, &p);
}

enum t_setup_ret t_register_buffers(struct io_uring *ring,
				    const struct iovec *iovecs,
				    unsigned nr_iovecs)
{
	int ret;

	ret = io_uring_register_buffers(ring, iovecs, nr_iovecs);
	if (!ret)
		return T_SETUP_OK;

	if ((ret == -EPERM || ret == -ENOMEM) && geteuid()) {
		fprintf(stdout, "too large non-root buffer registration, skip\n");
		return T_SETUP_SKIP;
	}

	fprintf(stderr, "buffer register failed: %s\n", strerror(-ret));
	return ret;
}
